"""
bounty.scheduler — Scheduler and queue worker for automated / recurring scans.

Classes:
  ScanQueue        — DB-backed async queue; creates scan_queue rows.
  QueueWorker      — Async loop that consumes scan_queue entries.
  SchedulerService — APScheduler-based service that fires scan_schedules.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from bounty.db import get_conn
from bounty.models import ScanQueueEntry, ScanSchedule
from bounty.recon import recon_pipeline  # noqa: E402  (module-level for patchability)
from bounty.ulid import make_ulid

if TYPE_CHECKING:
    from bounty.config import Settings

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# ScanQueue
# ---------------------------------------------------------------------------

class ScanQueue:
    """Async wrapper around the ``scan_queue`` DB table."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._notify: asyncio.Event | None = None

    @property
    def _get_notify(self) -> asyncio.Event:
        if self._notify is None:
            self._notify = asyncio.Event()
        return self._notify

    def _signal(self) -> None:
        try:
            self._get_notify.set()
        except RuntimeError:
            pass

    async def enqueue(
        self,
        program_id: str,
        intensity: str = "gentle",
        priority: int = 100,
        reason: str | None = None,
    ) -> ScanQueueEntry:
        entry_id = make_ulid()
        now = _now_iso()
        async with get_conn(self._db_path) as conn:
            await conn.execute(
                """
                INSERT INTO scan_queue
                    (id, program_id, intensity, priority, status, reason,
                     submitted_at, retry_count)
                VALUES (?, ?, ?, ?, 'queued', ?, ?, 0)
                """,
                (entry_id, program_id, intensity, priority, reason, now),
            )
            await conn.commit()
        entry = ScanQueueEntry(
            id=entry_id,
            program_id=program_id,
            intensity=intensity,
            priority=priority,
            status="queued",
            reason=reason,
            submitted_at=now,
        )
        self._signal()
        return entry

    async def cancel(self, entry_id: str) -> bool:
        async with get_conn(self._db_path) as conn:
            cur = await conn.execute(
                "UPDATE scan_queue SET status='cancelled' WHERE id=? AND status IN ('queued','running')",
                (entry_id,),
            )
            await conn.commit()
            return bool(cur.rowcount and cur.rowcount > 0)

    async def retry(self, entry_id: str) -> ScanQueueEntry | None:
        async with get_conn(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT program_id, intensity, priority FROM scan_queue WHERE id=? AND status='failed'",
                (entry_id,),
            )
            row = await cur.fetchone()
        if not row:
            return None
        return await self.enqueue(
            program_id=str(row["program_id"]),
            intensity=str(row["intensity"]),
            priority=int(row["priority"]),
            reason=f"manual-retry of {entry_id}",
        )

    async def list_entries(
        self,
        statuses: list[str] | None = None,
    ) -> list[ScanQueueEntry]:
        async with get_conn(self._db_path) as conn:
            if statuses:
                placeholders = ",".join("?" * len(statuses))
                cur = await conn.execute(
                    f"SELECT * FROM scan_queue WHERE status IN ({placeholders}) "
                    "ORDER BY priority DESC, submitted_at ASC",
                    statuses,
                )
            else:
                cur = await conn.execute(
                    "SELECT * FROM scan_queue ORDER BY priority DESC, submitted_at ASC"
                )
            rows = await cur.fetchall()
        return [_row_to_entry(r) for r in rows]


def _row_to_entry(row: Any) -> ScanQueueEntry:
    return ScanQueueEntry(
        id=str(row["id"]),
        program_id=str(row["program_id"]),
        intensity=str(row["intensity"] or "gentle"),
        priority=int(row["priority"]),
        status=row["status"],
        reason=row["reason"],
        submitted_at=row["submitted_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        scan_id=row["scan_id"],
        error_message=row["error_message"],
        retry_count=int(row["retry_count"]),
    )


# ---------------------------------------------------------------------------
# QueueWorker
# ---------------------------------------------------------------------------

class QueueWorker:
    """Async worker that processes scan_queue entries."""

    def __init__(
        self,
        db_path: Path,
        settings: "Settings",
        queue: ScanQueue,
        max_concurrent: int = 2,
    ) -> None:
        self._db_path = db_path
        self._settings = settings
        self._queue = queue
        self._max_concurrent = max_concurrent
        self._running: dict[str, asyncio.Task[None]] = {}
        self._stop_event: asyncio.Event | None = None

    @property
    def _get_stop_event(self) -> asyncio.Event:
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        return self._stop_event

    async def run(self) -> None:
        logger.info("QueueWorker started (max_concurrent=%d)", self._max_concurrent)
        stop = self._get_stop_event
        while not stop.is_set():
            await self._tick()
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._queue._get_notify.wait()), timeout=5.0
                )
                self._queue._get_notify.clear()
            except asyncio.TimeoutError:
                pass

    async def stop(self, timeout: float = 30.0) -> None:
        self._get_stop_event.set()
        self._queue._signal()
        if self._running:
            logger.info(
                "QueueWorker: waiting up to %.0f s for %d scan(s)",
                timeout, len(self._running),
            )
            tasks = list(self._running.values())
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True), timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning("QueueWorker stop timeout — cancelling tasks")
                for t in tasks:
                    t.cancel()

    async def _tick(self) -> None:
        done = [eid for eid, t in self._running.items() if t.done()]
        for eid in done:
            task = self._running.pop(eid)
            if not task.cancelled():
                exc = task.exception()
                if exc:
                    logger.exception("Worker task unhandled error", exc_info=exc)

        while len(self._running) < self._max_concurrent:
            entry = await self._fetch_next()
            if entry is None:
                break
            task = asyncio.create_task(self._process(entry))
            self._running[entry.id] = task

    async def _fetch_next(self) -> ScanQueueEntry | None:
        async with get_conn(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM scan_queue WHERE status='queued' "
                "ORDER BY priority DESC, submitted_at ASC LIMIT 1"
            )
            row = await cur.fetchone()
            if not row:
                return None
            entry_id = str(row["id"])
            cur2 = await conn.execute(
                "SELECT status FROM scan_queue WHERE id=?", (entry_id,)
            )
            chk = await cur2.fetchone()
            if not chk or chk["status"] != "queued":
                return None
            now = _now_iso()
            await conn.execute(
                "UPDATE scan_queue SET status='running', started_at=? WHERE id=? AND status='queued'",
                (now, entry_id),
            )
            await conn.commit()
        return ScanQueueEntry(
            id=str(row["id"]),
            program_id=str(row["program_id"]),
            intensity=str(row["intensity"] or "gentle"),
            priority=int(row["priority"]),
            status="running",
            reason=row["reason"],
            submitted_at=row["submitted_at"],
            started_at=now,
            scan_id=row["scan_id"],
            error_message=row["error_message"],
            retry_count=int(row["retry_count"]),
        )

    async def _process(self, entry: ScanQueueEntry) -> None:
        from bounty.events import publish
        from bounty.models import Target

        logger.info("QueueWorker: processing %s (program=%s)", entry.id, entry.program_id)
        await asyncio.sleep(0)  # yield so pending subscribers can register before first publish
        await publish("scan.queued", {
            "queue_id": entry.id, "program_id": entry.program_id, "intensity": entry.intensity,
        })

        scan_id = make_ulid()
        try:
            async with get_conn(self._db_path) as conn:
                cur = await conn.execute(
                    "SELECT status FROM scan_queue WHERE id=?", (entry.id,)
                )
                chk = await cur.fetchone()
                if not chk or chk["status"] == "cancelled":
                    logger.info("Entry %s cancelled before start", entry.id)
                    return

                tcur = await conn.execute(
                    "SELECT scope_type, asset_type, value FROM targets WHERE program_id=?",
                    (entry.program_id,),
                )
                target_rows = await tcur.fetchall()

            targets: list[Target] = [
                Target(
                    program_id=entry.program_id,
                    scope_type=r["scope_type"],
                    asset_type=r["asset_type"],
                    value=r["value"],
                )
                for r in target_rows
            ]

            if not targets:
                logger.warning("No targets for program %s", entry.program_id)
                await self._finish(entry.id, scan_id, "completed", None)
                return

            await recon_pipeline(
                program_id=entry.program_id,
                targets=targets,
                intensity=entry.intensity,
                db_path=self._db_path,
                scan_id=scan_id,
            )

            async with get_conn(self._db_path) as conn:
                cur = await conn.execute(
                    "SELECT status FROM scan_queue WHERE id=?", (entry.id,)
                )
                chk = await cur.fetchone()
            if chk and chk["status"] == "cancelled":
                logger.info("Entry %s cancelled during pipeline", entry.id)
                return

            await self._finish(entry.id, scan_id, "completed", None)
            await publish("scan.dequeued", {
                "queue_id": entry.id, "scan_id": scan_id, "status": "completed",
            })
            logger.info("Entry %s completed", entry.id)

        except Exception as exc:  # noqa: BLE001
            logger.exception("Entry %s failed: %s", entry.id, exc)
            await self._handle_failure(entry, str(exc))

    async def _finish(
        self,
        entry_id: str,
        scan_id: str,
        status: str,
        error_message: str | None,
    ) -> None:
        now = _now_iso()
        async with get_conn(self._db_path) as conn:
            await conn.execute(
                "UPDATE scan_queue SET status=?, scan_id=?, error_message=?, finished_at=? "
                "WHERE id=? AND status NOT IN ('cancelled')",
                (status, scan_id or None, error_message, now, entry_id),
            )
            await conn.commit()

    async def _handle_failure(self, entry: ScanQueueEntry, error: str) -> None:
        from bounty.events import publish

        new_retry = entry.retry_count + 1
        async with get_conn(self._db_path) as conn:
            await conn.execute(
                "UPDATE scan_queue SET retry_count=? WHERE id=?",
                (new_retry, entry.id),
            )
            await conn.commit()

        if new_retry < 3:
            new_entry = await self._queue.enqueue(
                program_id=entry.program_id,
                intensity=entry.intensity,
                priority=max(0, entry.priority - 10),
                reason=f"retry-{new_retry} of {entry.id}",
            )
            await self._finish(entry.id, "", "failed", error)
            await publish("scan.retried", {
                "queue_id": entry.id, "new_queue_id": new_entry.id,
                "retry_count": new_retry,
            })
        else:
            await self._finish(entry.id, "", "failed", error)
            await publish("scan.dequeued", {
                "queue_id": entry.id, "status": "failed", "error": error,
            })


# ---------------------------------------------------------------------------
# SchedulerService
# ---------------------------------------------------------------------------

class SchedulerService:
    """APScheduler-backed service that enqueues recurring scans."""

    def __init__(
        self,
        db_path: Path,
        settings: "Settings",
        queue: ScanQueue,
    ) -> None:
        self._db_path = db_path
        self._settings = settings
        self._queue = queue
        self._scheduler: AsyncIOScheduler | None = None

    async def start(self) -> None:
        self._scheduler = AsyncIOScheduler()
        await self._load_schedules()
        if not getattr(self._settings, "scheduler_test_mode", False):
            self._scheduler.start()
        logger.info(
            "SchedulerService started (test_mode=%s)",
            getattr(self._settings, "scheduler_test_mode", False),
        )

    async def stop(self) -> None:
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown(wait=False)
        logger.info("SchedulerService stopped")

    async def reload(self) -> None:
        if self._scheduler:
            self._scheduler.remove_all_jobs()
        await self._load_schedules()
        logger.info("SchedulerService reloaded")

    def trigger_now(self, schedule_id: str) -> None:
        """Manually fire a schedule (for tests / test_mode)."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._fire_schedule(schedule_id))
        except RuntimeError:
            asyncio.run(self._fire_schedule(schedule_id))

    async def _load_schedules(self) -> None:
        async with get_conn(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM scan_schedules WHERE enabled=1"
            )
            rows = await cur.fetchall()
        for row in rows:
            sched = ScanSchedule(
                id=str(row["id"]),
                program_id=str(row["program_id"]),
                name=str(row["name"]),
                cron_expression=row["cron_expression"],
                interval_minutes=row["interval_minutes"],
                intensity=str(row["intensity"] or "gentle"),
                enabled=bool(row["enabled"]),
                last_run_at=row["last_run_at"],
                next_run_at=row["next_run_at"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
            self._register_schedule(sched)

    def _register_schedule(self, schedule: ScanSchedule) -> None:
        if not self._scheduler:
            return
        job_id = f"schedule_{schedule.id}"
        if schedule.cron_expression:
            try:
                trigger: Any = CronTrigger.from_crontab(schedule.cron_expression)
            except Exception as exc:
                logger.warning("Invalid cron for %s: %s", schedule.id, exc)
                return
        elif schedule.interval_minutes:
            trigger = IntervalTrigger(minutes=schedule.interval_minutes)
        else:
            logger.warning("Schedule %s has no trigger — skipping", schedule.id)
            return
        self._scheduler.add_job(
            self._fire_schedule,
            trigger=trigger,
            args=[schedule.id],
            id=job_id,
            replace_existing=True,
            misfire_grace_time=60,
        )

    async def _fire_schedule(self, schedule_id: str) -> None:
        from bounty.events import publish

        now = _now_iso()
        async with get_conn(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM scan_schedules WHERE id=? AND enabled=1",
                (schedule_id,),
            )
            row = await cur.fetchone()
            if not row:
                return
            sched = ScanSchedule(
                id=str(row["id"]),
                program_id=str(row["program_id"]),
                name=str(row["name"]),
                cron_expression=row["cron_expression"],
                interval_minutes=row["interval_minutes"],
                intensity=str(row["intensity"] or "gentle"),
                enabled=bool(row["enabled"]),
            )
            await conn.execute(
                "UPDATE scan_schedules SET last_run_at=?, updated_at=? WHERE id=?",
                (now, now, schedule_id),
            )
            await conn.commit()

        entry = await self._queue.enqueue(
            program_id=sched.program_id,
            intensity=sched.intensity,
            priority=100,
            reason=f"scheduled:{sched.name}",
        )
        await publish("schedule.fired", {
            "schedule_id": schedule_id, "queue_id": entry.id, "name": sched.name,
        })
        logger.info("Schedule %s (%s) fired → queue entry %s", schedule_id, sched.name, entry.id)

