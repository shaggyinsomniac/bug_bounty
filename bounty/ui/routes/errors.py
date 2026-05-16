"""
bounty.ui.routes.errors — /api/errors endpoints (Phase 17).

GET  /api/errors              — paginated error list with filters
GET  /api/errors/{id}         — full error record including traceback
DELETE /api/errors            — purge errors older than N days
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from bounty.db import get_conn
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/errors", tags=["errors"])

_VALID_KINDS = frozenset({
    "detection", "probe", "fingerprint", "secret_validation",
    "notification", "scheduler", "queue_worker", "nuclei", "trufflehog",
    "ai", "other",
})


def _parse_since(since: str | None) -> str | None:
    """Convert human-readable `since` value to ISO timestamp string."""
    if not since:
        return None
    mapping = {
        "1h":  timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d":  timedelta(days=7),
        "30d": timedelta(days=30),
    }
    delta = mapping.get(since)
    if delta:
        cutoff = datetime.now(tz=timezone.utc) - delta
        return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Try ISO datetime
    try:
        dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return None


@router.get("")
async def list_errors(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    kind: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    asset_id: str | None = Query(default=None),
    exception_type: str | None = Query(default=None),
    since: str | None = Query(default=None, description="1h | 24h | 7d | 30d | ISO datetime"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """Paginated list of scan errors with optional filters."""
    clauses: list[str] = []
    params: list[Any] = []

    if kind:
        clauses.append("kind = ?")
        params.append(kind)
    if scan_id:
        clauses.append("scan_id = ?")
        params.append(scan_id)
    if asset_id:
        clauses.append("asset_id = ?")
        params.append(asset_id)
    if exception_type:
        clauses.append("exception_type LIKE ?")
        params.append(f"%{exception_type}%")
    cutoff = _parse_since(since)
    if cutoff:
        clauses.append("created_at >= ?")
        params.append(cutoff)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    params.extend([limit, offset])

    async with get_conn(db_path) as conn:
        # Kind breakdown
        kind_cur = await conn.execute(
            "SELECT kind, COUNT(*) FROM scan_errors GROUP BY kind"
        )
        kind_counts: dict[str, int] = {}
        for r in await kind_cur.fetchall():
            kind_counts[str(r[0])] = int(r[1])

        # Total count in result set
        cnt_cur = await conn.execute(
            f"SELECT COUNT(*) FROM scan_errors {where}", count_params
        )
        cnt_row = await cnt_cur.fetchone()
        total: int = cnt_row[0] if cnt_row else 0

        # Fetch page (exclude large traceback for list view)
        cur = await conn.execute(
            f"""
            SELECT id, scan_id, asset_id, detection_id, kind,
                   exception_type, message, created_at
            FROM scan_errors {where}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            params,
        )
        rows = await cur.fetchall()

    items = [
        {k: r[k] for k in r.keys()}
        for r in rows
    ]

    return JSONResponse({
        "total": total,
        "limit": limit,
        "offset": offset,
        "kind_breakdown": kind_counts,
        "items": items,
    })


@router.get("/{error_id}")
async def get_error(
    error_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Full error record including traceback."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "SELECT * FROM scan_errors WHERE id = ?", (error_id,)
        )
        row = await cur.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Error record not found")

    return JSONResponse({k: row[k] for k in row.keys()})


@router.delete("")
async def purge_errors(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    older_than: str = Query(default="30d", description="1h | 24h | 7d | 30d | ISO datetime"),
) -> JSONResponse:
    """Delete error records older than the specified duration."""
    cutoff = _parse_since(older_than)
    if not cutoff:
        raise HTTPException(status_code=422, detail="Invalid older_than value")

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "DELETE FROM scan_errors WHERE created_at < ?", (cutoff,)
        )
        deleted = cur.rowcount or 0
        await conn.commit()

    return JSONResponse({"deleted": deleted, "cutoff": cutoff})

