"""
bounty.ui.routes.findings — /api/findings endpoints.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bounty.db import get_conn
from bounty.models import FindingStatus
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/findings", tags=["findings"])

SeverityLabelLiteral = Literal["info", "low", "medium", "high", "critical"]


def _finding_row(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    if isinstance(d.get("tags"), str):
        try:
            d["tags"] = json.loads(d["tags"])
        except (json.JSONDecodeError, ValueError):
            d["tags"] = []
    d["validated"] = bool(d.get("validated"))
    return d


def _ev_row(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


# NOTE: /stats must be registered BEFORE /{finding_id} to avoid
# FastAPI matching the literal string "stats" as a path parameter.

@router.get("/stats")
async def finding_stats(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    program_id: str | None = Query(default=None),
) -> JSONResponse:
    """Counts by severity, status, and category."""
    where = "WHERE program_id = ?" if program_id else ""
    params: list[Any] = [program_id] if program_id else []

    async with get_conn(db_path) as conn:
        sev_cur = await conn.execute(
            f"SELECT severity_label, COUNT(*) AS cnt FROM findings {where} GROUP BY severity_label",
            params,
        )
        by_severity = {r["severity_label"]: r["cnt"] for r in await sev_cur.fetchall()}

        stat_cur = await conn.execute(
            f"SELECT status, COUNT(*) AS cnt FROM findings {where} GROUP BY status",
            params,
        )
        by_status = {r["status"]: r["cnt"] for r in await stat_cur.fetchall()}

        cat_cur = await conn.execute(
            f"SELECT category, COUNT(*) AS cnt FROM findings {where} GROUP BY category ORDER BY cnt DESC",
            params,
        )
        by_category = {r["category"]: r["cnt"] for r in await cat_cur.fetchall()}

    return JSONResponse(
        {"by_severity": by_severity, "by_status": by_status, "by_category": by_category}
    )


@router.get("")
async def list_findings(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    program_id: str | None = Query(default=None),
    severity_label: str | None = Query(default=None),
    category: str | None = Query(default=None),
    status: str | None = Query(default=None),
    validated_only: bool = Query(default=False),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    limit: int | None = Query(default=None, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """Paginated findings list with optional filters."""
    # Determine effective limit/offset: explicit limit/offset take precedence over page/per_page
    if limit is not None:
        _limit = limit
        _offset = offset
        _page = (_offset // _limit) + 1
        _per_page = _limit
    else:
        _per_page = per_page
        _limit = per_page
        _page = page
        _offset = (page - 1) * per_page

    clauses: list[str] = []
    params: list[Any] = []

    if program_id:
        clauses.append("program_id = ?")
        params.append(program_id)
    if severity_label:
        labels = [s.strip() for s in severity_label.split(",")]
        placeholders = ",".join("?" * len(labels))
        clauses.append(f"severity_label IN ({placeholders})")
        params.extend(labels)
    if category:
        clauses.append("category = ?")
        params.append(category)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if validated_only:
        clauses.append("validated = 1")
    if search:
        clauses.append("(title LIKE ? OR url LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    params.extend([_limit, _offset])

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"SELECT * FROM findings {where} ORDER BY severity DESC, created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        rows = await cur.fetchall()

        cnt_cur = await conn.execute(
            f"SELECT COUNT(*) FROM findings {where}",
            count_params,
        )
        cnt_row = await cnt_cur.fetchone()

    total: int = cnt_row[0] if cnt_row else 0
    return JSONResponse(
        {
            "items": [_finding_row(r) for r in rows],
            "total": total,
            "page": _page,
            "per_page": _per_page,
            "limit": _limit,
            "offset": _offset,
        }
    )


@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Finding detail with evidence packages and secret validations."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding = _finding_row(row)

        ev_cur = await conn.execute(
            "SELECT * FROM evidence_packages WHERE finding_id = ? ORDER BY captured_at",
            (finding_id,),
        )
        evidence = [_ev_row(r) for r in await ev_cur.fetchall()]

        sv_cur = await conn.execute(
            "SELECT * FROM secrets_validations WHERE finding_id = ? ORDER BY created_at",
            (finding_id,),
        )
        secrets = [{k: r[k] for k in r.keys()} for r in await sv_cur.fetchall()]

    finding["evidence"] = evidence
    finding["secrets"] = secrets
    return JSONResponse(finding)


_KanbanStatus = Literal[
    "new", "triaged", "reported", "accepted",
    "dismissed", "duplicate", "wont_fix", "resolved",
]


class FindingStatusPatch(BaseModel):
    """Thin body for the kanban DnD status update."""
    status: _KanbanStatus


@router.patch("/{finding_id}/status")
async def patch_finding_status(
    finding_id: str,
    body: FindingStatusPatch,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Update finding status — used by kanban drag-and-drop."""
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
            (body.status, ts, finding_id),
        )
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Finding not found")
        row_cur = await conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        updated = await row_cur.fetchone()
    return JSONResponse(_finding_row(updated))  # type: ignore[arg-type]


class FindingPatch(BaseModel):
    status: FindingStatus | None = None
    tags: list[str] | None = None


@router.patch("/{finding_id}")
async def patch_finding(
    finding_id: str,
    body: FindingPatch,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Update finding status and/or tags."""
    sets: list[str] = []
    params: list[Any] = []

    if body.status is not None:
        sets.append("status = ?")
        params.append(body.status)
    if body.tags is not None:
        sets.append("tags = ?")
        params.append(json.dumps(body.tags))
    if not sets:
        raise HTTPException(status_code=422, detail="No fields to update")

    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sets.append("updated_at = ?")
    params.append(ts)
    params.append(finding_id)

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"UPDATE findings SET {', '.join(sets)} WHERE id = ?",
            params,
        )
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Finding not found")

        row_cur = await conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        updated = await row_cur.fetchone()

    return JSONResponse(_finding_row(updated))  # type: ignore[arg-type]

