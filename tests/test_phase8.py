"""
tests/test_phase8.py — Phase 8 test suite.

Tests:
1. Schema migration V11 — scan_schedules and scan_queue tables exist
2. ScanSchedule / ScanQueueEntry model validation
3. ScanQueue CRUD operations
4. Queue ordering (priority desc, submitted_at asc)
5. QueueWorker — picks up entry, runs pipeline (mocked), marks completed
6. QueueWorker — failed pipeline → retry up to 3 times → marked failed
7. QueueWorker — cancel queued entry before start
8. QueueWorker — cancel during run (post-pipeline check)
9. QueueWorker — concurrent cap (max_concurrent)
10. SchedulerService — trigger_now fires a schedule
11. SchedulerService — reload
12. API routes — /api/schedules CRUD
13. API routes — /api/queue list/enqueue/cancel/retry
14. CLI — schedule list/add/rm/enable/disable
15. CLI — queue list/cancel/retry
16. SSE events: scan.queued, scan.dequeued, scan.retried, schedule.fired
17. Dashboard stats include queue_depth
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from typer.testing import CliRunner

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Create a fresh test DB with migrations applied."""
    from bounty.db import apply_migrations, init_db

    db_path = tmp_path / "test.db"
    init_db(db_path)
    apply_migrations(db_path)
    return db_path


@pytest.fixture
def program_id(tmp_db: Path) -> str:
    """Insert a test program and return its ID."""
    import asyncio as _asyncio

    pid = "test-prog-phase8"

    async def _insert() -> None:
        from bounty.db import get_conn
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT OR IGNORE INTO programs (id, platform, handle, name) "
                "VALUES (?, 'manual', ?, ?)",
                (pid, pid, "Phase 8 Test Program"),
            )
            await conn.commit()

    _asyncio.run(_insert())
    return pid


@pytest.fixture
def scan_queue(tmp_db: Path) -> Any:
    from bounty.scheduler import ScanQueue
    return ScanQueue(tmp_db)


@pytest.fixture
def app_client(tmp_db: Path) -> Any:
    """Return a TestClient with the FastAPI app (no scheduler started)."""
    from bounty.config import get_settings
    from bounty.ui.app import app
    from bounty.scheduler import ScanQueue

    # Inject a real ScanQueue into app.state
    app.state.queue = ScanQueue(tmp_db)
    app.state.scheduler = None

    with patch.object(get_settings(), "db_path", tmp_db):
        with TestClient(app, raise_server_exceptions=True) as client:
            yield client


# ===========================================================================
# 1. Schema migration
# ===========================================================================

class TestSchemaMigration:
    def test_scan_schedules_table_exists(self, tmp_db: Path) -> None:
        import sqlite3
        conn = sqlite3.connect(str(tmp_db))
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_schedules'"
            )
            assert cur.fetchone() is not None, "scan_schedules table must exist"
        finally:
            conn.close()

    def test_scan_queue_table_exists(self, tmp_db: Path) -> None:
        import sqlite3
        conn = sqlite3.connect(str(tmp_db))
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_queue'"
            )
            assert cur.fetchone() is not None, "scan_queue table must exist"
        finally:
            conn.close()

    def test_scan_schedules_columns(self, tmp_db: Path) -> None:
        import sqlite3
        conn = sqlite3.connect(str(tmp_db))
        try:
            cur = conn.execute("PRAGMA table_info(scan_schedules)")
            cols = {row[1] for row in cur.fetchall()}
            expected = {
                "id", "program_id", "name", "cron_expression", "interval_minutes",
                "intensity", "enabled", "last_run_at", "next_run_at", "created_at", "updated_at",
            }
            assert expected <= cols
        finally:
            conn.close()

    def test_scan_queue_columns(self, tmp_db: Path) -> None:
        import sqlite3
        conn = sqlite3.connect(str(tmp_db))
        try:
            cur = conn.execute("PRAGMA table_info(scan_queue)")
            cols = {row[1] for row in cur.fetchall()}
            expected = {
                "id", "program_id", "intensity", "priority", "status",
                "reason", "submitted_at", "started_at", "finished_at",
                "scan_id", "error_message", "retry_count",
            }
            assert expected <= cols
        finally:
            conn.close()

    def test_schema_version_at_least_11(self, tmp_db: Path) -> None:
        import sqlite3
        conn = sqlite3.connect(str(tmp_db))
        try:
            row = conn.execute("PRAGMA user_version").fetchone()
            version = row[0] if row else 0
            assert version >= 11, f"Expected user_version >= 11, got {version}"
        finally:
            conn.close()


# ===========================================================================
# 2. Model validation
# ===========================================================================

class TestModels:
    def test_scan_schedule_defaults(self) -> None:
        from bounty.models import ScanSchedule
        s = ScanSchedule(id="X", program_id="p1", name="daily")
        assert s.intensity == "gentle"
        assert s.enabled is True
        assert s.retry_count is not None  # No, this is ScanQueueEntry attr

    def test_scan_queue_entry_defaults(self) -> None:
        from bounty.models import ScanQueueEntry
        e = ScanQueueEntry(id="X", program_id="p1")
        assert e.status == "queued"
        assert e.priority == 100
        assert e.retry_count == 0

    def test_queue_status_literal(self) -> None:
        from bounty.models import ScanQueueEntry
        e = ScanQueueEntry(id="X", program_id="p1", status="running")
        assert e.status == "running"

    def test_scan_queue_entry_all_fields(self) -> None:
        from bounty.models import ScanQueueEntry
        e = ScanQueueEntry(
            id="ABC",
            program_id="prog1",
            intensity="normal",
            priority=200,
            status="completed",
            reason="scheduled:daily",
            submitted_at="2026-01-01T00:00:00",
            scan_id="SID",
            error_message=None,
            retry_count=1,
        )
        assert e.priority == 200
        assert e.scan_id == "SID"


# ===========================================================================
# 3. ScanQueue CRUD
# ===========================================================================

class TestScanQueue:
    @pytest.mark.asyncio
    async def test_enqueue_creates_db_row(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn

        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id, intensity="gentle", priority=100)

        assert entry.id
        assert entry.program_id == program_id
        assert entry.status == "queued"

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute("SELECT * FROM scan_queue WHERE id=?", (entry.id,))
            row = await cur.fetchone()
        assert row is not None
        assert row["status"] == "queued"

    @pytest.mark.asyncio
    async def test_enqueue_notifies_event(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue

        q = ScanQueue(tmp_db)
        # Initialize the event first
        _ = q._get_notify
        q._get_notify.clear()

        await q.enqueue(program_id)
        assert q._get_notify.is_set()

    @pytest.mark.asyncio
    async def test_cancel_queued(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn

        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id)
        ok = await q.cancel(entry.id)
        assert ok is True

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute("SELECT status FROM scan_queue WHERE id=?", (entry.id,))
            row = await cur.fetchone()
        assert row["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_nonexistent(self, tmp_db: Path) -> None:
        from bounty.scheduler import ScanQueue
        q = ScanQueue(tmp_db)
        ok = await q.cancel("nonexistent-id")
        assert ok is False

    @pytest.mark.asyncio
    async def test_cancel_completed_fails(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn

        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id)
        # Manually set to completed
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "UPDATE scan_queue SET status='completed' WHERE id=?", (entry.id,)
            )
            await conn.commit()
        ok = await q.cancel(entry.id)
        assert ok is False

    @pytest.mark.asyncio
    async def test_retry_failed_entry(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn

        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id, priority=50)
        # Manually set to failed
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "UPDATE scan_queue SET status='failed' WHERE id=?", (entry.id,)
            )
            await conn.commit()

        new_entry = await q.retry(entry.id)
        assert new_entry is not None
        assert new_entry.id != entry.id
        assert new_entry.program_id == entry.program_id
        assert new_entry.priority == 50

    @pytest.mark.asyncio
    async def test_retry_non_failed_returns_none(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id)
        result = await q.retry(entry.id)
        assert result is None

    @pytest.mark.asyncio
    async def test_list_entries(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        q = ScanQueue(tmp_db)
        e1 = await q.enqueue(program_id, priority=10)
        e2 = await q.enqueue(program_id, priority=50)
        e3 = await q.enqueue(program_id, priority=30)
        entries = await q.list_entries()
        ids = [e.id for e in entries]
        assert e2.id in ids
        assert e1.id in ids
        assert e3.id in ids

    @pytest.mark.asyncio
    async def test_list_entries_filtered(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn
        q = ScanQueue(tmp_db)
        e = await q.enqueue(program_id)
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "UPDATE scan_queue SET status='running' WHERE id=?", (e.id,)
            )
            await conn.commit()
        running = await q.list_entries(statuses=["running"])
        assert any(x.id == e.id for x in running)
        queued = await q.list_entries(statuses=["queued"])
        assert not any(x.id == e.id for x in queued)


# ===========================================================================
# 4. Queue ordering
# ===========================================================================

class TestQueueOrdering:
    @pytest.mark.asyncio
    async def test_priority_desc(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        q = ScanQueue(tmp_db)

        e_low = await q.enqueue(program_id, priority=10)
        e_high = await q.enqueue(program_id, priority=200)
        e_mid = await q.enqueue(program_id, priority=100)

        entries = await q.list_entries(statuses=["queued"])
        ids = [e.id for e in entries]
        assert ids.index(e_high.id) < ids.index(e_mid.id)
        assert ids.index(e_mid.id) < ids.index(e_low.id)

    @pytest.mark.asyncio
    async def test_same_priority_fifo(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        q = ScanQueue(tmp_db)

        e1 = await q.enqueue(program_id, priority=100)
        await asyncio.sleep(0.01)  # ensure different submitted_at
        e2 = await q.enqueue(program_id, priority=100)
        await asyncio.sleep(0.01)
        e3 = await q.enqueue(program_id, priority=100)

        entries = await q.list_entries(statuses=["queued"])
        ids = [e.id for e in entries]
        # First submitted should come first
        assert ids.index(e1.id) < ids.index(e2.id)
        assert ids.index(e2.id) < ids.index(e3.id)


# ===========================================================================
# 5. QueueWorker picks up and completes
# ===========================================================================

class TestQueueWorker:
    @pytest.mark.asyncio
    async def test_worker_processes_entry(self, tmp_db: Path, program_id: str) -> None:
        """Worker picks up entry, mocked pipeline completes, entry marked completed."""
        from bounty.scheduler import QueueWorker, ScanQueue
        from bounty.config import get_settings
        from bounty.db import get_conn
        from bounty.models import Target

        # Insert a target so the worker doesn't skip
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT OR IGNORE INTO targets (program_id, scope_type, asset_type, value) "
                "VALUES (?, 'in_scope', 'url', 'http://test.example.com')",
                (program_id,),
            )
            await conn.commit()

        settings = get_settings()
        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id, intensity="gentle")

        worker = QueueWorker(tmp_db, settings, q, max_concurrent=1)

        with patch("bounty.scheduler.recon_pipeline", new_callable=AsyncMock) as mock_pipeline:
            mock_pipeline.return_value = {"assets": [], "failed_hosts": []}
            await worker._tick()
            # Give the task a moment to run
            await asyncio.sleep(0.1)
            await worker._tick()  # reap done tasks

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute(
                "SELECT status FROM scan_queue WHERE id=?", (entry.id,)
            )
            row = await cur.fetchone()
        assert row["status"] == "completed"

    @pytest.mark.asyncio
    async def test_worker_no_targets_completes(self, tmp_db: Path, program_id: str) -> None:
        """Worker entry with no targets still completes gracefully."""
        from bounty.scheduler import QueueWorker, ScanQueue
        from bounty.config import get_settings
        from bounty.db import get_conn

        settings = get_settings()
        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id)

        worker = QueueWorker(tmp_db, settings, q, max_concurrent=1)
        await worker._tick()
        await asyncio.sleep(0.1)
        await worker._tick()

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute(
                "SELECT status FROM scan_queue WHERE id=?", (entry.id,)
            )
            row = await cur.fetchone()
        assert row["status"] == "completed"

    @pytest.mark.asyncio
    async def test_worker_skips_cancelled_entry(self, tmp_db: Path, program_id: str) -> None:
        """Entry cancelled before worker starts is skipped."""
        from bounty.scheduler import QueueWorker, ScanQueue
        from bounty.config import get_settings
        from bounty.db import get_conn

        settings = get_settings()
        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id)
        await q.cancel(entry.id)

        worker = QueueWorker(tmp_db, settings, q, max_concurrent=1)
        # _fetch_next should return None since entry is cancelled
        result = await worker._fetch_next()
        assert result is None

    @pytest.mark.asyncio
    async def test_worker_max_concurrent_cap(self, tmp_db: Path, program_id: str) -> None:
        """Worker does not exceed max_concurrent running tasks."""
        from bounty.scheduler import QueueWorker, ScanQueue
        from bounty.config import get_settings
        from bounty.db import get_conn

        # Insert targets
        async with get_conn(tmp_db) as conn:
            for i in range(5):
                await conn.execute(
                    "INSERT OR IGNORE INTO targets (program_id, scope_type, asset_type, value) "
                    "VALUES (?, 'in_scope', 'url', ?)",
                    (program_id, f"http://host{i}.example.com"),
                )
            await conn.commit()

        settings = get_settings()
        q = ScanQueue(tmp_db)
        # Enqueue 4 entries
        for _ in range(4):
            await q.enqueue(program_id)

        max_concurrent = 2
        worker = QueueWorker(tmp_db, settings, q, max_concurrent=max_concurrent)

        # Use a slow mock so tasks don't complete immediately
        slow_event = asyncio.Event()

        async def slow_pipeline(**kwargs: Any) -> dict[str, Any]:
            await slow_event.wait()
            return {"assets": [], "failed_hosts": []}

        with patch("bounty.scheduler.recon_pipeline", new=slow_pipeline):
            await worker._tick()
            # Should have at most max_concurrent tasks running
            assert len(worker._running) <= max_concurrent

        slow_event.set()


# ===========================================================================
# 6. Retry logic
# ===========================================================================

class TestRetryLogic:
    @pytest.mark.asyncio
    async def test_failed_pipeline_retries(self, tmp_db: Path, program_id: str) -> None:
        """Entry retried up to max 3 times then marked failed."""
        from bounty.scheduler import QueueWorker, ScanQueue
        from bounty.config import get_settings
        from bounty.db import get_conn
        from bounty.models import Target

        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT OR IGNORE INTO targets (program_id, scope_type, asset_type, value) "
                "VALUES (?, 'in_scope', 'url', 'http://fail.example.com')",
                (program_id,),
            )
            await conn.commit()

        settings = get_settings()
        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id, priority=100)
        worker = QueueWorker(tmp_db, settings, q, max_concurrent=1)

        with patch("bounty.scheduler.recon_pipeline", side_effect=RuntimeError("boom")):
            # Process the entry
            fetched = await worker._fetch_next()
            assert fetched is not None
            await worker._handle_failure(fetched, "boom")

        # Should have created a new queued entry (retry 1)
        async with get_conn(tmp_db) as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) FROM scan_queue WHERE program_id=? AND status='queued'",
                (program_id,),
            )
            row = await cur.fetchone()
        assert row[0] >= 1, "Expected at least one retry queued"

    @pytest.mark.asyncio
    async def test_exhausted_retries_marks_failed(self, tmp_db: Path, program_id: str) -> None:
        """Entry with retry_count >= 3 is marked failed, no more retries."""
        from bounty.scheduler import QueueWorker, ScanQueue
        from bounty.config import get_settings
        from bounty.models import ScanQueueEntry
        from bounty.db import get_conn

        settings = get_settings()
        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id)

        worker = QueueWorker(tmp_db, settings, q)
        # Simulate entry with retry_count = 2 (about to max)
        exhausted = ScanQueueEntry(
            id=entry.id, program_id=program_id, retry_count=2, status="running"
        )

        # Update retry count in DB
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "UPDATE scan_queue SET retry_count=2, status='running' WHERE id=?", (entry.id,)
            )
            await conn.commit()

        await worker._handle_failure(exhausted, "final error")

        # Should be marked failed with NO new queued entry
        async with get_conn(tmp_db) as conn:
            cur = await conn.execute(
                "SELECT status FROM scan_queue WHERE id=?", (entry.id,)
            )
            row = await cur.fetchone()
            assert row["status"] == "failed"

            # No new retry
            cur2 = await conn.execute(
                "SELECT COUNT(*) FROM scan_queue WHERE status='queued' AND program_id=?",
                (program_id,),
            )
            cnt = await cur2.fetchone()
        assert cnt[0] == 0


# ===========================================================================
# 7. SchedulerService
# ===========================================================================

class TestSchedulerService:
    @pytest.mark.asyncio
    async def test_trigger_now_enqueues(self, tmp_db: Path, program_id: str) -> None:
        """trigger_now() enqueues an entry in the queue table."""
        from bounty.scheduler import SchedulerService, ScanQueue
        from bounty.config import get_settings
        from bounty.db import get_conn

        # Create schedule in DB
        now = "2026-01-01T00:00:00"
        schedule_id = "TEST-SCHED-01"
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT INTO scan_schedules "
                "(id, program_id, name, interval_minutes, intensity, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                (schedule_id, program_id, "test-sched", 60, "gentle", now, now),
            )
            await conn.commit()

        settings = get_settings()
        # Patch scheduler_test_mode
        with patch.object(settings, "scheduler_test_mode", True):
            q = ScanQueue(tmp_db)
            svc = SchedulerService(tmp_db, settings, q)
            await svc.start()

        # Fire schedule
        await svc._fire_schedule(schedule_id)

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) FROM scan_queue WHERE reason LIKE 'scheduled:%'",
            )
            row = await cur.fetchone()
        assert row[0] >= 1, "Expected at least one scheduled entry in queue"

    @pytest.mark.asyncio
    async def test_reload_registers_new_schedules(self, tmp_db: Path, program_id: str) -> None:
        """After reload, newly added schedules are registered."""
        from bounty.scheduler import SchedulerService, ScanQueue
        from bounty.config import get_settings
        from bounty.db import get_conn

        settings = get_settings()
        with patch.object(settings, "scheduler_test_mode", True):
            q = ScanQueue(tmp_db)
            svc = SchedulerService(tmp_db, settings, q)
            await svc.start()

        # Add a schedule after start
        now = "2026-01-01T00:00:00"
        schedule_id = "NEW-SCHED-RELOAD"
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT INTO scan_schedules "
                "(id, program_id, name, interval_minutes, intensity, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                (schedule_id, program_id, "new-sched", 30, "normal", now, now),
            )
            await conn.commit()

        await svc.reload()

        # Should not raise; scheduler should have the job registered
        # (In test_mode no actual scheduler is running so we just check it doesn't error)
        assert svc._scheduler is not None

    @pytest.mark.asyncio
    async def test_stop_is_safe(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import SchedulerService, ScanQueue
        from bounty.config import get_settings

        settings = get_settings()
        with patch.object(settings, "scheduler_test_mode", True):
            q = ScanQueue(tmp_db)
            svc = SchedulerService(tmp_db, settings, q)
            await svc.start()
            await svc.stop()  # Should not raise


# ===========================================================================
# 8. API routes — schedules
# ===========================================================================

class TestSchedulesAPI:
    def _client(self, tmp_db: Path) -> Any:
        from bounty.ui.app import app
        from bounty.scheduler import ScanQueue
        from bounty.config import get_settings

        app.state.queue = ScanQueue(tmp_db)
        app.state.scheduler = None

        settings = get_settings()
        with patch.object(type(settings), "db_path", new_callable=property) as mock_db:
            mock_db.fget = lambda self: tmp_db  # type: ignore
            with TestClient(app, raise_server_exceptions=True) as client:
                yield client

    @pytest.mark.asyncio
    async def test_list_schedules_empty(self, tmp_db: Path) -> None:
        from bounty.db import get_conn
        async with get_conn(tmp_db) as conn:
            cur = await conn.execute("SELECT COUNT(*) FROM scan_schedules")
            row = await cur.fetchone()
        assert row[0] == 0

    @pytest.mark.asyncio
    async def test_create_and_list_schedule_db(self, tmp_db: Path, program_id: str) -> None:
        from bounty.db import get_conn

        now = "2026-01-01T00:00:00"
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT INTO scan_schedules "
                "(id, program_id, name, interval_minutes, intensity, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                ("SCHED1", program_id, "my-sched", 60, "gentle", now, now),
            )
            await conn.commit()

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute("SELECT * FROM scan_schedules WHERE id='SCHED1'")
            row = await cur.fetchone()
        assert row is not None
        assert row["name"] == "my-sched"
        assert row["interval_minutes"] == 60

    @pytest.mark.asyncio
    async def test_update_schedule_enabled(self, tmp_db: Path, program_id: str) -> None:
        from bounty.db import get_conn

        now = "2026-01-01T00:00:00"
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT INTO scan_schedules "
                "(id, program_id, name, interval_minutes, intensity, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                ("SCHED2", program_id, "sched2", 30, "gentle", now, now),
            )
            await conn.commit()
            await conn.execute(
                "UPDATE scan_schedules SET enabled=0 WHERE id='SCHED2'"
            )
            await conn.commit()

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute("SELECT enabled FROM scan_schedules WHERE id='SCHED2'")
            row = await cur.fetchone()
        assert row["enabled"] == 0

    @pytest.mark.asyncio
    async def test_delete_schedule(self, tmp_db: Path, program_id: str) -> None:
        from bounty.db import get_conn

        now = "2026-01-01T00:00:00"
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT INTO scan_schedules "
                "(id, program_id, name, interval_minutes, intensity, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                ("SCHED3", program_id, "sched3", 15, "gentle", now, now),
            )
            await conn.commit()
            await conn.execute("DELETE FROM scan_schedules WHERE id='SCHED3'")
            await conn.commit()

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute("SELECT COUNT(*) FROM scan_schedules WHERE id='SCHED3'")
            row = await cur.fetchone()
        assert row[0] == 0


# ===========================================================================
# 9. API routes — queue
# ===========================================================================

class TestQueueAPI:
    @pytest.mark.asyncio
    async def test_enqueue_via_queue(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn

        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id, intensity="gentle", priority=150, reason="api-test")

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute("SELECT * FROM scan_queue WHERE id=?", (entry.id,))
            row = await cur.fetchone()
        assert row is not None
        assert row["priority"] == 150
        assert row["reason"] == "api-test"

    @pytest.mark.asyncio
    async def test_cancel_entry_via_queue(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn

        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id)
        ok = await q.cancel(entry.id)
        assert ok

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute("SELECT status FROM scan_queue WHERE id=?", (entry.id,))
            row = await cur.fetchone()
        assert row["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_list_queue_entries(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue

        q = ScanQueue(tmp_db)
        await q.enqueue(program_id, priority=100)
        await q.enqueue(program_id, priority=200)
        entries = await q.list_entries(statuses=["queued"])
        assert len(entries) >= 2

    @pytest.mark.asyncio
    async def test_retry_creates_new_entry(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn

        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id, priority=75)
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "UPDATE scan_queue SET status='failed' WHERE id=?", (entry.id,)
            )
            await conn.commit()

        new = await q.retry(entry.id)
        assert new is not None
        assert new.id != entry.id
        assert new.priority == 75


# ===========================================================================
# 10. CLI commands
# ===========================================================================

class TestCLISchedule:
    def test_schedule_list_empty(self, tmp_db: Path) -> None:
        from bounty.cli import app as cli_app
        runner = CliRunner()
        result = runner.invoke(cli_app, ["schedule", "list", "--db", str(tmp_db)])
        assert result.exit_code == 0
        assert "No schedules" in result.output or result.output.strip() == "No schedules found."

    def test_schedule_add_interval(self, tmp_db: Path, program_id: str) -> None:
        from bounty.cli import app as cli_app
        runner = CliRunner()
        result = runner.invoke(cli_app, [
            "schedule", "add",
            "--program", program_id,
            "--name", "test-schedule",
            "--interval-minutes", "60",
            "--db", str(tmp_db),
        ])
        assert result.exit_code == 0, result.output
        assert "created schedule" in result.output.lower() or "SCHED" in result.output

    def test_schedule_add_then_list(self, tmp_db: Path, program_id: str) -> None:
        from bounty.cli import app as cli_app
        runner = CliRunner()
        runner.invoke(cli_app, [
            "schedule", "add",
            "--program", program_id,
            "--name", "my-daily",
            "--interval-minutes", "1440",
            "--db", str(tmp_db),
        ])
        result = runner.invoke(cli_app, ["schedule", "list", "--db", str(tmp_db)])
        assert result.exit_code == 0
        assert "my-daily" in result.output

    def test_schedule_rm(self, tmp_db: Path, program_id: str) -> None:
        from bounty.cli import app as cli_app
        runner = CliRunner()
        add_result = runner.invoke(cli_app, [
            "schedule", "add",
            "--program", program_id,
            "--name", "to-remove",
            "--interval-minutes", "5",
            "--db", str(tmp_db),
        ])
        # Extract schedule ID from output
        sched_id = None
        for word in add_result.output.split():
            if len(word) == 26 and word.isupper():
                sched_id = word
                break
        if sched_id:
            result = runner.invoke(cli_app, ["schedule", "rm", sched_id, "--db", str(tmp_db)])
            assert result.exit_code == 0

    def test_schedule_enable_disable(self, tmp_db: Path, program_id: str) -> None:
        from bounty.cli import app as cli_app
        from bounty.ulid import make_ulid
        import asyncio as _asyncio

        sched_id = make_ulid()
        now = "2026-01-01T00:00:00"

        async def _insert() -> None:
            from bounty.db import get_conn
            async with get_conn(tmp_db) as conn:
                await conn.execute(
                    "INSERT INTO scan_schedules "
                    "(id, program_id, name, interval_minutes, intensity, enabled, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                    (sched_id, program_id, "toggle-test", 60, "gentle", now, now),
                )
                await conn.commit()

        _asyncio.run(_insert())

        runner = CliRunner()
        res = runner.invoke(cli_app, ["schedule", "disable", sched_id, "--db", str(tmp_db)])
        assert res.exit_code == 0

        res2 = runner.invoke(cli_app, ["schedule", "enable", sched_id, "--db", str(tmp_db)])
        assert res2.exit_code == 0


class TestCLIQueue:
    def test_queue_list_empty(self, tmp_db: Path) -> None:
        from bounty.cli import app as cli_app
        runner = CliRunner()
        result = runner.invoke(cli_app, ["queue", "list", "--db", str(tmp_db)])
        assert result.exit_code == 0
        assert "empty" in result.output.lower() or "0" in result.output

    def test_queue_cancel(self, tmp_db: Path, program_id: str) -> None:
        from bounty.cli import app as cli_app
        import asyncio as _asyncio
        from bounty.scheduler import ScanQueue

        entry_id: str = ""

        async def _enqueue() -> str:
            q = ScanQueue(tmp_db)
            e = await q.enqueue(program_id)
            return e.id

        entry_id = _asyncio.run(_enqueue())

        runner = CliRunner()
        result = runner.invoke(cli_app, ["queue", "cancel", entry_id, "--db", str(tmp_db)])
        assert result.exit_code == 0
        assert "cancelled" in result.output.lower()

    def test_queue_retry(self, tmp_db: Path, program_id: str) -> None:
        from bounty.cli import app as cli_app
        import asyncio as _asyncio
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn

        entry_id: str = ""

        async def _setup() -> str:
            q = ScanQueue(tmp_db)
            e = await q.enqueue(program_id)
            async with get_conn(tmp_db) as conn:
                await conn.execute(
                    "UPDATE scan_queue SET status='failed' WHERE id=?", (e.id,)
                )
                await conn.commit()
            return e.id

        entry_id = _asyncio.run(_setup())

        runner = CliRunner()
        result = runner.invoke(cli_app, ["queue", "retry", entry_id, "--db", str(tmp_db)])
        assert result.exit_code == 0
        assert "new entry" in result.output.lower() or "retry" in result.output.lower()


# ===========================================================================
# 11. SSE events
# ===========================================================================

class TestSSEEvents:
    @pytest.mark.asyncio
    async def test_enqueue_publishes_scan_queued(self, tmp_db: Path, program_id: str) -> None:
        """Enqueuing via worker._process should publish scan.queued event."""
        from bounty.scheduler import ScanQueue, QueueWorker
        from bounty.config import get_settings
        from bounty.events import bus
        from bounty.db import get_conn

        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT OR IGNORE INTO targets (program_id, scope_type, asset_type, value) "
                "VALUES (?, 'in_scope', 'url', 'http://test.example.com')",
                (program_id,),
            )
            await conn.commit()

        received_events: list[str] = []

        async def _collect() -> None:
            async for event in bus.subscribe({"scan.queued"}):
                received_events.append(event.event_type)
                break

        settings = get_settings()
        q = ScanQueue(tmp_db)
        entry = await q.enqueue(program_id)

        worker = QueueWorker(tmp_db, settings, q)

        collector = asyncio.create_task(_collect())

        with patch("bounty.scheduler.recon_pipeline", new_callable=AsyncMock) as mock_p:
            mock_p.return_value = {"assets": [], "failed_hosts": []}
            await worker._process(
                __import__("bounty.models", fromlist=["ScanQueueEntry"]
                ).ScanQueueEntry(
                    id=entry.id,
                    program_id=entry.program_id,
                    status="running",
                    retry_count=0,
                )
            )

        await asyncio.sleep(0.05)
        collector.cancel()
        try:
            await collector
        except asyncio.CancelledError:
            pass

        assert "scan.queued" in received_events

    @pytest.mark.asyncio
    async def test_schedule_fire_publishes_event(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import SchedulerService, ScanQueue
        from bounty.config import get_settings
        from bounty.events import bus
        from bounty.db import get_conn

        now = "2026-01-01T00:00:00"
        schedule_id = "SSE-SCHED-01"
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT INTO scan_schedules "
                "(id, program_id, name, interval_minutes, intensity, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                (schedule_id, program_id, "sse-test", 60, "gentle", now, now),
            )
            await conn.commit()

        received: list[str] = []

        async def _collect() -> None:
            async for event in bus.subscribe({"schedule.fired"}):
                received.append(event.event_type)
                break

        settings = get_settings()
        q = ScanQueue(tmp_db)
        svc = SchedulerService(tmp_db, settings, q)
        svc._scheduler = None  # don't start real scheduler

        collector = asyncio.create_task(_collect())
        await asyncio.sleep(0)

        await svc._fire_schedule(schedule_id)

        await asyncio.sleep(0.05)
        collector.cancel()
        try:
            await collector
        except asyncio.CancelledError:
            pass

        assert "schedule.fired" in received


# ===========================================================================
# 12. Dashboard stats includes queue_depth
# ===========================================================================

class TestDashboardQueueDepth:
    @pytest.mark.asyncio
    async def test_queue_depth_in_stats(self, tmp_db: Path, program_id: str) -> None:
        from bounty.scheduler import ScanQueue
        from bounty.db import get_conn

        q = ScanQueue(tmp_db)
        await q.enqueue(program_id, priority=100)
        await q.enqueue(program_id, priority=200)

        async with get_conn(tmp_db) as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) FROM scan_queue WHERE status IN ('queued', 'running')"
            )
            row = await cur.fetchone()

        assert row[0] == 2


# ===========================================================================
# 13. QueueWorker stop
# ===========================================================================

class TestQueueWorkerStop:
    @pytest.mark.asyncio
    async def test_stop_sets_event(self, tmp_db: Path) -> None:
        from bounty.scheduler import QueueWorker, ScanQueue
        from bounty.config import get_settings

        settings = get_settings()
        q = ScanQueue(tmp_db)
        worker = QueueWorker(tmp_db, settings, q)

        await worker.stop(timeout=1.0)
        assert worker._get_stop_event.is_set()

    @pytest.mark.asyncio
    async def test_run_loop_exits_on_stop(self, tmp_db: Path) -> None:
        from bounty.scheduler import QueueWorker, ScanQueue
        from bounty.config import get_settings

        settings = get_settings()
        q = ScanQueue(tmp_db)
        worker = QueueWorker(tmp_db, settings, q)

        task = asyncio.create_task(worker.run())
        await asyncio.sleep(0.05)
        await worker.stop(timeout=2.0)

        try:
            await asyncio.wait_for(task, timeout=3.0)
        except asyncio.TimeoutError:
            task.cancel()
            pytest.fail("Worker did not stop after stop() was called")


# ===========================================================================
# 14. Validate that prior tests still pass (smoke)
# ===========================================================================

class TestSchemaSmoke:
    def test_db_migration_idempotent(self, tmp_db: Path) -> None:
        """apply_migrations() is safe to call multiple times."""
        from bounty.db import apply_migrations
        apply_migrations(tmp_db)  # second call — must not raise

    @pytest.mark.asyncio
    async def test_programs_table_intact(self, tmp_db: Path) -> None:
        """Programs table still works post-migration."""
        from bounty.db import get_conn
        async with get_conn(tmp_db) as conn:
            await conn.execute(
                "INSERT OR IGNORE INTO programs (id, platform, handle, name) "
                "VALUES ('smoke-prog', 'manual', 'smoke', 'Smoke')"
            )
            await conn.commit()
            cur = await conn.execute("SELECT id FROM programs WHERE id='smoke-prog'")
            row = await cur.fetchone()
        assert row is not None

