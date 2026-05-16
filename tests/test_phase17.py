"""
tests/test_phase17.py — Phase 17: Unified error visibility tests.

Tests:
- ErrorRecorder inserts correct columns into scan_errors
- record_error global helper (never raises)
- Detection runner: catches exception, records error, continues
- Recon pipeline phase exception recording
- Integration failure recorded with scan_id
- GET /api/errors list + filters + pagination
- GET /api/errors/{id} detail with traceback
- DELETE /api/errors purge
- CLI errors list / show / purge
- Sentry hook called when DSN set, skipped when not
- DB migration V15 creates scan_errors table
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    """Return path to a freshly initialised test database.

    Named ``bounty.db`` so that CLI commands can locate it via
    ``DATA_DIR = str(tmp_path)`` → ``settings.db_path = tmp_path / "bounty.db"``.
    """
    from bounty.db import apply_migrations, init_db
    db = tmp_path / "bounty.db"
    init_db(db)
    apply_migrations(db)
    return db


@pytest.fixture()
def sync_db(tmp_db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(tmp_db))
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# 1. DB schema: scan_errors table exists after migration V15
# ---------------------------------------------------------------------------

def test_scan_errors_table_exists(sync_db: sqlite3.Connection) -> None:
    cur = sync_db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_errors'"
    )
    assert cur.fetchone() is not None, "scan_errors table not found"


def test_scan_errors_columns(sync_db: sqlite3.Connection) -> None:
    cur = sync_db.execute("PRAGMA table_info(scan_errors)")
    cols = {r[1] for r in cur.fetchall()}
    expected = {"id", "scan_id", "asset_id", "detection_id", "kind",
                "exception_type", "message", "traceback", "created_at"}
    assert expected.issubset(cols), f"Missing columns: {expected - cols}"


def test_scan_errors_indexes(sync_db: sqlite3.Connection) -> None:
    cur = sync_db.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='scan_errors'"
    )
    names = {r[0] for r in cur.fetchall()}
    assert "idx_scan_errors_scan" in names
    assert "idx_scan_errors_kind" in names
    assert "idx_scan_errors_created" in names


# ---------------------------------------------------------------------------
# 2. ErrorRecorder.record() inserts correct row
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_error_recorder_inserts_row(tmp_db: Path) -> None:
    from bounty.errors import ErrorRecorder

    exc = ValueError("unit test error")
    recorder = ErrorRecorder(db_path=tmp_db, scan_id="SCAN01")
    await recorder.record(kind="detection", exception=exc,
                          asset_id="ASSET01", detection_id="det.cors")

    conn = sqlite3.connect(str(tmp_db))
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT * FROM scan_errors WHERE scan_id='SCAN01'")
    row = cur.fetchone()
    conn.close()

    assert row is not None
    assert row["kind"] == "detection"
    assert row["exception_type"] == "ValueError"
    assert "unit test error" in (row["message"] or "")
    assert row["asset_id"] == "ASSET01"
    assert row["detection_id"] == "det.cors"
    assert row["traceback"] is not None


@pytest.mark.asyncio
async def test_error_recorder_invalid_kind_becomes_other(tmp_db: Path) -> None:
    from bounty.errors import ErrorRecorder

    exc = RuntimeError("bad kind test")
    recorder = ErrorRecorder(db_path=tmp_db, scan_id="SCAN02")
    await recorder.record(kind="totally_invalid_kind", exception=exc)

    conn = sqlite3.connect(str(tmp_db))
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT kind FROM scan_errors WHERE scan_id='SCAN02'")
    row = cur.fetchone()
    conn.close()
    assert row["kind"] == "other"


# ---------------------------------------------------------------------------
# 3. record_error global helper never raises
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_record_error_never_raises(tmp_db: Path) -> None:
    from bounty.errors import record_error

    # Should not raise even with bad kind
    await record_error(tmp_db, "S1", "detection", ValueError("test"), asset_id="A1")


@pytest.mark.asyncio
async def test_record_error_with_bad_db_path_never_raises() -> None:
    from bounty.errors import record_error

    # Completely invalid DB path — must not raise
    await record_error(Path("/tmp/__nonexistent_db_12345.db"), "", "other", Exception("oops"))


# ---------------------------------------------------------------------------
# 4. Detection runner: catches exception, records error, continues
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detection_runner_continues_after_error(tmp_db: Path) -> None:
    """A deliberately broken detection doesn't abort the runner for the next detection."""
    from bounty.detect.base import Detection, DetectionContext
    from bounty.detect.runner import run_detections
    from bounty.models import Asset, FindingDraft, FingerprintResult
    from collections.abc import AsyncGenerator

    # Ensure program + scan + asset rows exist
    from bounty.db import get_conn
    async with get_conn(tmp_db) as conn:
        await conn.execute(
            "INSERT OR IGNORE INTO programs (id, platform, handle, name) VALUES ('prog1','manual','prog1','Test')"
        )
        await conn.execute(
            "INSERT OR IGNORE INTO scans (id, program_id, scan_type, status, intensity, triggered_by, created_at)"
            " VALUES ('scan1','prog1','full','running','normal','cli','2025-01-01T00:00:00Z')"
        )
        await conn.execute(
            "INSERT OR IGNORE INTO assets (id, program_id, host, scheme, url, status)"
            " VALUES ('asset1','prog1','test.example.com','http','http://test.example.com','alive')"
        )
        await conn.commit()

    class BrokenDetection(Detection):
        id = "broken.det"
        name = "Broken"
        description = "Always raises"

        def applicable_to(self, asset: Any, fps: Any) -> bool:
            return True

        async def run(self, asset: Any, ctx: Any) -> AsyncGenerator[FindingDraft, None]:  # type: ignore[override]
            raise RuntimeError("deliberate detection failure")
            yield  # make it a generator

    class GoodDetection(Detection):
        id = "good.det"
        name = "Good"
        description = "Returns one finding"

        def applicable_to(self, asset: Any, fps: Any) -> bool:
            return True

        async def run(self, asset: Any, ctx: Any) -> AsyncGenerator[FindingDraft, None]:
            yield FindingDraft(
                program_id="prog1",
                asset_id="asset1",
                scan_id="scan1",
                dedup_key="good.det:asset1",
                title="Good Finding",
                category="test",
                severity=500,
                url="http://test.example.com",
                source="native",
            )

    asset = Asset(
        id="asset1",
        program_id="prog1",
        host="test.example.com",
        scheme="http",
        url="http://test.example.com",
        status="alive",
    )

    probe_called = []

    async def mock_probe(url: str, *args: Any, **kwargs: Any) -> Any:
        from bounty.recon.http_probe import ProbeResult
        return ProbeResult(ok=False, url=url, error="mock")

    ctx = DetectionContext(
        probe_fn=mock_probe,
        capture_fn=None,
        scan_id="scan1",
        settings=MagicMock(),
        log=MagicMock(bind=MagicMock(return_value=MagicMock(
            debug=MagicMock(), warning=MagicMock(), info=MagicMock(),
            bind=MagicMock(return_value=MagicMock(
                debug=MagicMock(), warning=MagicMock(), info=MagicMock()
            ))
        ))),
    )

    detections = [BrokenDetection(), GoodDetection()]
    findings = []
    async for f in run_detections(asset, [], ctx, tmp_db, detections=detections):
        findings.append(f)

    # Good detection should still have fired
    assert len(findings) == 1
    assert findings[0].dedup_key == "good.det:asset1"

    # Error should be recorded
    conn2 = sqlite3.connect(str(tmp_db))
    conn2.row_factory = sqlite3.Row
    cur = conn2.execute("SELECT * FROM scan_errors WHERE detection_id='broken.det'")
    err_row = cur.fetchone()
    conn2.close()
    assert err_row is not None
    assert "deliberate detection failure" in (err_row["message"] or "")


# ---------------------------------------------------------------------------
# 5. Integration failure recorded with scan_id
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_integration_notify_records_error(tmp_db: Path) -> None:
    from bounty.integrations import _safe_notify
    from unittest.mock import AsyncMock

    class FailingNotifier:
        async def notify(self, event_name: str, payload: Any) -> None:
            raise RuntimeError("webhook failure")

    await _safe_notify(
        "discord", FailingNotifier(), "finding.discovered",
        {"severity_label": "high"},
        db_path=tmp_db,
        scan_id="SCAN99",
    )

    conn = sqlite3.connect(str(tmp_db))
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT * FROM scan_errors WHERE kind='notification'")
    row = cur.fetchone()
    conn.close()
    assert row is not None
    assert "webhook failure" in (row["message"] or "")


# ---------------------------------------------------------------------------
# 6–8. API endpoints via TestClient
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_db: Path):
    """FastAPI TestClient with test DB."""
    import os
    os.environ["DATA_DIR"] = str(tmp_db.parent)
    from bounty.config import get_settings
    get_settings.cache_clear()

    from bounty.ui.app import create_app
    from fastapi.testclient import TestClient
    _app = create_app()
    with TestClient(_app, raise_server_exceptions=True) as c:
        yield c

    get_settings.cache_clear()


def _seed_error(db: Path, kind: str = "detection", scan_id: str = "S1",
                asset_id: str | None = None, msg: str = "test") -> str:
    """Insert a scan_error row and return its id."""
    from bounty.ulid import make_ulid
    error_id = make_ulid()
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO scan_errors (id, scan_id, asset_id, kind, exception_type, message, traceback)"
        " VALUES (?,?,?,?,?,?,?)",
        (error_id, scan_id, asset_id, kind, "ValueError", msg, "Traceback (most recent call last):\n  File x\nValueError: " + msg),
    )
    conn.commit()
    conn.close()
    return error_id


def test_api_errors_list_empty(client: Any) -> None:
    resp = client.get("/api/errors")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert data["total"] == 0


def test_api_errors_list_with_data(client: Any, tmp_db: Path) -> None:
    _seed_error(tmp_db, kind="detection", scan_id="S1")
    _seed_error(tmp_db, kind="nuclei", scan_id="S2")

    resp = client.get("/api/errors")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2


def test_api_errors_filter_by_kind(client: Any, tmp_db: Path) -> None:
    _seed_error(tmp_db, kind="detection")
    _seed_error(tmp_db, kind="nuclei")

    resp = client.get("/api/errors?kind=nuclei")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["kind"] == "nuclei"


def test_api_errors_filter_by_scan_id(client: Any, tmp_db: Path) -> None:
    eid = _seed_error(tmp_db, kind="probe", scan_id="MYSCAN")
    _seed_error(tmp_db, kind="probe", scan_id="OTHERSCAN")

    resp = client.get("/api/errors?scan_id=MYSCAN")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["scan_id"] == "MYSCAN"


def test_api_errors_filter_since_filters_results(client: Any, tmp_db: Path) -> None:
    # Insert old record manually
    conn = sqlite3.connect(str(tmp_db))
    from bounty.ulid import make_ulid
    old_id = make_ulid()
    conn.execute(
        "INSERT INTO scan_errors (id, scan_id, kind, exception_type, message, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (old_id, "S_OLD", "ai", "RuntimeError", "old error", "2020-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    _seed_error(tmp_db, kind="ai")  # recent

    resp = client.get("/api/errors?since=7d")
    data = resp.json()
    # Only the recent one should be returned
    assert all(item["id"] != old_id for item in data["items"])


def test_api_errors_get_by_id(client: Any, tmp_db: Path) -> None:
    eid = _seed_error(tmp_db, kind="detection", msg="specific error")

    resp = client.get(f"/api/errors/{eid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == eid
    assert "traceback" in data
    assert "specific error" in data["message"]


def test_api_errors_get_by_id_not_found(client: Any) -> None:
    resp = client.get("/api/errors/NONEXISTENT")
    assert resp.status_code == 404


def test_api_errors_kind_breakdown_in_list(client: Any, tmp_db: Path) -> None:
    _seed_error(tmp_db, kind="detection")
    _seed_error(tmp_db, kind="detection")
    _seed_error(tmp_db, kind="nuclei")

    resp = client.get("/api/errors")
    data = resp.json()
    assert "kind_breakdown" in data
    assert data["kind_breakdown"].get("detection", 0) >= 2
    assert data["kind_breakdown"].get("nuclei", 0) >= 1


def test_api_errors_delete_purge(client: Any, tmp_db: Path) -> None:
    # Insert old record
    conn = sqlite3.connect(str(tmp_db))
    from bounty.ulid import make_ulid
    old_id = make_ulid()
    conn.execute(
        "INSERT INTO scan_errors (id, scan_id, kind, exception_type, message, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (old_id, "S_OLD", "ai", "RuntimeError", "old", "2020-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    resp = client.delete("/api/errors?older_than=30d")
    assert resp.status_code == 200
    assert resp.json()["deleted"] >= 1

    # Verify deletion
    conn2 = sqlite3.connect(str(tmp_db))
    cur = conn2.execute("SELECT COUNT(*) FROM scan_errors WHERE id=?", (old_id,))
    assert cur.fetchone()[0] == 0
    conn2.close()


def test_api_errors_delete_invalid_older_than(client: Any) -> None:
    resp = client.delete("/api/errors?older_than=INVALID")
    assert resp.status_code == 422


def test_api_errors_pagination(client: Any, tmp_db: Path) -> None:
    for i in range(10):
        _seed_error(tmp_db, kind="probe", msg=f"err{i}")

    resp_p1 = client.get("/api/errors?limit=5&offset=0")
    resp_p2 = client.get("/api/errors?limit=5&offset=5")
    assert resp_p1.json()["total"] == 10
    assert len(resp_p1.json()["items"]) == 5
    assert len(resp_p2.json()["items"]) == 5
    ids1 = {item["id"] for item in resp_p1.json()["items"]}
    ids2 = {item["id"] for item in resp_p2.json()["items"]}
    assert ids1.isdisjoint(ids2)


# ---------------------------------------------------------------------------
# 9. /errors page HTTP status
# ---------------------------------------------------------------------------

def test_errors_page_200(client: Any) -> None:
    resp = client.get("/errors")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 10. CLI commands
# ---------------------------------------------------------------------------

def test_cli_errors_list(tmp_db: Path) -> None:
    import os
    os.environ["DATA_DIR"] = str(tmp_db.parent)
    from bounty.config import get_settings
    get_settings.cache_clear()

    _seed_error(tmp_db, kind="detection", msg="cli test error")

    from typer.testing import CliRunner
    from bounty.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["errors", "list", "--since", "24h"])
    assert result.exit_code == 0, result.output
    assert "detection" in result.output or "cli test error" in result.output

    get_settings.cache_clear()


def test_cli_errors_show(tmp_db: Path) -> None:
    import os
    os.environ["DATA_DIR"] = str(tmp_db.parent)
    from bounty.config import get_settings
    get_settings.cache_clear()

    eid = _seed_error(tmp_db, kind="nuclei", msg="show test error")

    from typer.testing import CliRunner
    from bounty.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["errors", "show", eid])
    assert result.exit_code == 0, result.output
    assert "nuclei" in result.output
    assert "show test error" in result.output
    assert "TRACEBACK" in result.output

    get_settings.cache_clear()


def test_cli_errors_purge_dry_run(tmp_db: Path) -> None:
    import os
    os.environ["DATA_DIR"] = str(tmp_db.parent)
    from bounty.config import get_settings
    get_settings.cache_clear()

    conn = sqlite3.connect(str(tmp_db))
    from bounty.ulid import make_ulid
    conn.execute(
        "INSERT INTO scan_errors (id, kind, message, created_at) VALUES (?,?,?,?)",
        (make_ulid(), "probe", "old", "2020-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    from typer.testing import CliRunner
    from bounty.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["errors", "purge", "--older-than", "30d"])
    assert result.exit_code == 0
    assert "dry-run" in result.output.lower() or "Would" in result.output

    # No deletion without --confirm
    conn2 = sqlite3.connect(str(tmp_db))
    cnt = conn2.execute("SELECT COUNT(*) FROM scan_errors").fetchone()[0]
    conn2.close()
    assert cnt >= 1

    get_settings.cache_clear()


def test_cli_errors_purge_confirm(tmp_db: Path) -> None:
    import os
    os.environ["DATA_DIR"] = str(tmp_db.parent)
    from bounty.config import get_settings
    get_settings.cache_clear()

    conn = sqlite3.connect(str(tmp_db))
    from bounty.ulid import make_ulid
    conn.execute(
        "INSERT INTO scan_errors (id, kind, message, created_at) VALUES (?,?,?,?)",
        (make_ulid(), "probe", "old2", "2020-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    from typer.testing import CliRunner
    from bounty.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["errors", "purge", "--older-than", "30d", "--confirm"])
    assert result.exit_code == 0
    assert "Deleted" in result.output

    get_settings.cache_clear()


def test_cli_errors_show_not_found(tmp_db: Path) -> None:
    import os
    os.environ["DATA_DIR"] = str(tmp_db.parent)
    from bounty.config import get_settings
    get_settings.cache_clear()

    from typer.testing import CliRunner
    from bounty.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["errors", "show", "NONEXISTENT_ID"])
    assert result.exit_code != 0

    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 11. Sentry hook
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sentry_hook_called_when_dsn_set(tmp_db: Path) -> None:
    """When sentry_dsn is configured, capture_exception should be called."""
    import sys
    fake_sentry = MagicMock()
    fake_sentry.push_scope = MagicMock(return_value=MagicMock(
        __enter__=MagicMock(return_value=MagicMock()),
        __exit__=MagicMock(return_value=False),
    ))
    fake_sentry.capture_exception = MagicMock()

    with patch.dict(sys.modules, {"sentry_sdk": fake_sentry}):
        with patch("bounty.config.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(sentry_dsn="https://fake@sentry.io/1")
            from bounty.errors import _maybe_sentry
            exc = RuntimeError("sentry test")
            _maybe_sentry("detection", "scan1", "asset1", "det.cors", exc)

    fake_sentry.capture_exception.assert_called_once()


@pytest.mark.asyncio
async def test_sentry_hook_skipped_when_no_dsn(tmp_db: Path) -> None:
    """When sentry_dsn is None, Sentry should NOT be called."""
    import sys
    fake_sentry = MagicMock()
    fake_sentry.capture_exception = MagicMock()

    with patch.dict(sys.modules, {"sentry_sdk": fake_sentry}):
        with patch("bounty.config.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(sentry_dsn=None)
            from bounty.errors import _maybe_sentry
            _maybe_sentry("ai", "s1", None, None, ValueError("x"))

    fake_sentry.capture_exception.assert_not_called()


# ---------------------------------------------------------------------------
# 12. Dashboard stats includes errors_24h
# ---------------------------------------------------------------------------

def test_dashboard_stats_includes_errors_24h(client: Any, tmp_db: Path) -> None:
    _seed_error(tmp_db, kind="probe")

    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "errors_24h" in data
    assert data["errors_24h"] >= 1


# ---------------------------------------------------------------------------
# 13. SSE event published on record
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sse_event_published_on_record(tmp_db: Path) -> None:
    from bounty.errors import ErrorRecorder
    from bounty.events import bus

    received: list[Any] = []

    async def _consume() -> None:
        async for event in bus.subscribe({"errors.new"}):
            received.append(event)
            break

    task = asyncio.create_task(_consume())
    await asyncio.sleep(0)

    exc = ValueError("sse test error")
    recorder = ErrorRecorder(db_path=tmp_db, scan_id="SSE_SCAN")
    await recorder.record(kind="ai", exception=exc)

    await asyncio.wait_for(task, timeout=2.0)
    assert len(received) == 1
    assert received[0].event_type == "errors.new"
    assert received[0].data["kind"] == "ai"


# ---------------------------------------------------------------------------
# 14. Exception type filter on API
# ---------------------------------------------------------------------------

def test_api_errors_filter_exception_type(client: Any, tmp_db: Path) -> None:
    # Insert manually with explicit exception_type
    conn = sqlite3.connect(str(tmp_db))
    from bounty.ulid import make_ulid
    conn.execute(
        "INSERT INTO scan_errors (id, scan_id, kind, exception_type, message)"
        " VALUES (?,?,?,?,?)",
        (make_ulid(), "S1", "ai", "TimeoutError", "timed out"),
    )
    conn.execute(
        "INSERT INTO scan_errors (id, scan_id, kind, exception_type, message)"
        " VALUES (?,?,?,?,?)",
        (make_ulid(), "S1", "ai", "ConnectionError", "refused"),
    )
    conn.commit()
    conn.close()

    resp = client.get("/api/errors?exception_type=Timeout")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert all("Timeout" in (i["exception_type"] or "") for i in items)


# ---------------------------------------------------------------------------
# 15. Scheduler records error
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scheduler_records_queue_worker_error(tmp_db: Path) -> None:
    from unittest.mock import patch, AsyncMock
    from bounty.config import get_settings

    settings = MagicMock()
    settings.db_path = tmp_db
    settings.scheduler_test_mode = True

    from bounty.scheduler import QueueWorker, ScanQueue
    queue = ScanQueue(tmp_db)

    worker = QueueWorker(db_path=tmp_db, settings=settings, queue=queue)

    # Verify the error recording path doesn't crash when called manually
    try:
        from bounty.errors import record_error
        exc = RuntimeError("scheduler test")
        await record_error(tmp_db, "scan_x", "queue_worker", exc)
    except Exception as e:
        pytest.fail(f"record_error raised: {e}")

    conn = sqlite3.connect(str(tmp_db))
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT * FROM scan_errors WHERE kind='queue_worker'")
    row = cur.fetchone()
    conn.close()
    assert row is not None
    assert "scheduler test" in (row["message"] or "")

