"""
bounty.ui.routes.queue — /api/queue endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bounty.db import get_conn
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/queue", tags=["queue"])


def _row_to_dict(row: Any) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


class QueueEnqueueRequest(BaseModel):
    program_id: str
    intensity: str = "gentle"
    priority: int = 100
    reason: str | None = None


@router.get("")
async def list_queue(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    status: list[str] = Query(default=[]),
) -> JSONResponse:
    """List queue entries, optionally filtered by status."""
    async with get_conn(db_path) as conn:
        if status:
            placeholders = ",".join("?" * len(status))
            cur = await conn.execute(
                f"SELECT * FROM scan_queue WHERE status IN ({placeholders}) "
                "ORDER BY priority DESC, submitted_at ASC",
                status,
            )
        else:
            cur = await conn.execute(
                "SELECT * FROM scan_queue ORDER BY priority DESC, submitted_at ASC"
            )
        rows = await cur.fetchall()
    return JSONResponse([_row_to_dict(r) for r in rows])


@router.post("", status_code=201)
async def enqueue(
    payload: QueueEnqueueRequest,
    request: Request,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Manually enqueue a scan for a program."""
    queue = getattr(request.app.state, "queue", None)
    if queue is None:
        # Fallback: create a temporary ScanQueue
        from bounty.scheduler import ScanQueue
        queue = ScanQueue(db_path)

    entry = await queue.enqueue(
        program_id=payload.program_id,
        intensity=payload.intensity,
        priority=payload.priority,
        reason=payload.reason or "manual",
    )
    return JSONResponse(entry.model_dump(), status_code=201)


@router.delete("/{entry_id}", status_code=200)
async def cancel_entry(
    entry_id: str,
    request: Request,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Cancel a queued or running entry."""
    queue = getattr(request.app.state, "queue", None)
    if queue is None:
        from bounty.scheduler import ScanQueue
        queue = ScanQueue(db_path)

    ok = await queue.cancel(entry_id)
    if not ok:
        raise HTTPException(404, "Entry not found or already in terminal state")
    return JSONResponse({"id": entry_id, "status": "cancelled"})


@router.post("/{entry_id}/retry", status_code=201)
async def retry_entry(
    entry_id: str,
    request: Request,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Re-enqueue a failed entry."""
    queue = getattr(request.app.state, "queue", None)
    if queue is None:
        from bounty.scheduler import ScanQueue
        queue = ScanQueue(db_path)

    new_entry = await queue.retry(entry_id)
    if new_entry is None:
        raise HTTPException(404, "Entry not found or not in failed state")
    return JSONResponse(new_entry.model_dump(), status_code=201)

