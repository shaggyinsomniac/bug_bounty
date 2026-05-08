"""
bounty.ui.routes.assets — /api/assets endpoints.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from bounty.db import get_conn
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/assets", tags=["assets"])


def _row(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    for field in ("tags", "seen_protocols"):
        if isinstance(d.get(field), str):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, ValueError):
                d[field] = []
    return d


@router.get("")
async def list_assets(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    program_id: str | None = Query(default=None),
    search: str | None = Query(default=None),
    has_findings: bool | None = Query(default=None),
    tech: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """Paginated asset list with optional filters."""
    clauses: list[str] = []
    params: list[Any] = []

    if program_id:
        clauses.append("a.program_id = ?")
        params.append(program_id)
    if search:
        clauses.append("(a.host LIKE ? OR a.title LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    if has_findings is True:
        clauses.append("EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id)")
    elif has_findings is False:
        clauses.append("NOT EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id)")
    if tech:
        clauses.append("EXISTS (SELECT 1 FROM fingerprints fp WHERE fp.asset_id = a.id AND fp.tech = ?)")
        params.append(tech)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.extend([limit, offset])

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"SELECT a.* FROM assets a {where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        rows = await cur.fetchall()

        count_params = params[:-2]
        cur2 = await conn.execute(
            f"SELECT COUNT(*) FROM assets a {where.replace('LIMIT ? OFFSET ?', '')}",
            count_params,
        )
        cnt_row = await cur2.fetchone()

    total: int = cnt_row[0] if cnt_row else 0
    return JSONResponse(
        {
            "items": [_row(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@router.get("/{asset_id}")
async def get_asset(
    asset_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Full asset record with fingerprints array and findings count."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Asset not found")

        asset = _row(row)

        fp_cur = await conn.execute(
            "SELECT id, tech, version, category, confidence, evidence, created_at "
            "FROM fingerprints WHERE asset_id = ? ORDER BY confidence DESC",
            (asset_id,),
        )
        fingerprints = [
            {k: r[k] for k in r.keys()} for r in await fp_cur.fetchall()
        ]

        cnt_cur = await conn.execute(
            "SELECT COUNT(*) FROM findings WHERE asset_id = ?", (asset_id,)
        )
        cnt_row = await cnt_cur.fetchone()

    asset["fingerprints"] = fingerprints
    asset["findings_count"] = cnt_row[0] if cnt_row else 0
    return JSONResponse(asset)

