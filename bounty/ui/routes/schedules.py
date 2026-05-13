"""
bounty.ui.routes.schedules — /api/schedules CRUD endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bounty.db import get_conn
from bounty.models import ScanSchedule
from bounty.ui.deps import ApiAuthDep, DbPathDep
from bounty.ulid import make_ulid

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: Any) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    d["enabled"] = bool(d.get("enabled", 1))
    return d


class ScheduleCreate(BaseModel):
    program_id: str
    name: str
    cron_expression: str | None = None
    interval_minutes: int | None = None
    intensity: str = "gentle"
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: str | None = None
    cron_expression: str | None = None
    interval_minutes: int | None = None
    intensity: str | None = None
    enabled: bool | None = None


@router.get("")
async def list_schedules(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    program_id: str | None = None,
) -> JSONResponse:
    """List all scan schedules, optionally filtered by program_id."""
    async with get_conn(db_path) as conn:
        if program_id:
            cur = await conn.execute(
                "SELECT * FROM scan_schedules WHERE program_id=? ORDER BY created_at DESC",
                (program_id,),
            )
        else:
            cur = await conn.execute(
                "SELECT * FROM scan_schedules ORDER BY created_at DESC"
            )
        rows = await cur.fetchall()
    return JSONResponse([_row_to_dict(r) for r in rows])


@router.post("", status_code=201)
async def create_schedule(
    payload: ScheduleCreate,
    request: Request,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Create a new scan schedule."""
    if payload.cron_expression is None and payload.interval_minutes is None:
        raise HTTPException(422, "Either cron_expression or interval_minutes is required")

    schedule_id = make_ulid()
    now = _now_iso()

    async with get_conn(db_path) as conn:
        await conn.execute(
            """
            INSERT INTO scan_schedules
                (id, program_id, name, cron_expression, interval_minutes,
                 intensity, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                schedule_id,
                payload.program_id,
                payload.name,
                payload.cron_expression,
                payload.interval_minutes,
                payload.intensity,
                1 if payload.enabled else 0,
                now,
                now,
            ),
        )
        await conn.commit()

    # Reload scheduler if available
    _reload_scheduler(request)

    return JSONResponse({"id": schedule_id, "status": "created"}, status_code=201)


@router.patch("/{schedule_id}")
async def update_schedule(
    schedule_id: str,
    payload: ScheduleUpdate,
    request: Request,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Update a schedule (partial update)."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "SELECT * FROM scan_schedules WHERE id=?", (schedule_id,)
        )
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Schedule not found")

        now = _now_iso()
        updates: list[str] = ["updated_at=?"]
        params: list[Any] = [now]

        if payload.name is not None:
            updates.append("name=?")
            params.append(payload.name)
        if payload.cron_expression is not None:
            updates.append("cron_expression=?")
            params.append(payload.cron_expression)
        if payload.interval_minutes is not None:
            updates.append("interval_minutes=?")
            params.append(payload.interval_minutes)
        if payload.intensity is not None:
            updates.append("intensity=?")
            params.append(payload.intensity)
        if payload.enabled is not None:
            updates.append("enabled=?")
            params.append(1 if payload.enabled else 0)

        params.append(schedule_id)
        await conn.execute(
            f"UPDATE scan_schedules SET {', '.join(updates)} WHERE id=?",
            params,
        )
        await conn.commit()

    _reload_scheduler(request)
    return JSONResponse({"id": schedule_id, "status": "updated"})


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    request: Request,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> None:
    """Delete a schedule."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "DELETE FROM scan_schedules WHERE id=?", (schedule_id,)
        )
        await conn.commit()
        if not cur.rowcount:
            raise HTTPException(404, "Schedule not found")

    _reload_scheduler(request)


def _reload_scheduler(request: Request) -> None:
    """Attempt to reload the scheduler from app.state if available."""
    try:
        scheduler = getattr(request.app.state, "scheduler", None)
        if scheduler is not None:
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(scheduler.reload())
            except RuntimeError:
                pass
    except Exception:  # noqa: BLE001
        pass

