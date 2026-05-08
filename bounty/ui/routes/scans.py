"""
bounty.ui.routes.scans — /api/scans endpoints.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bounty.db import get_conn
from bounty.models import Intensity, ScanType
from bounty.ui.deps import ApiAuthDep, DbPathDep
from bounty.ulid import make_ulid

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _scan_row(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    if isinstance(d.get("meta"), str):
        try:
            d["meta"] = json.loads(d["meta"])
        except (json.JSONDecodeError, ValueError):
            d["meta"] = {}
    return d


def _phase_row(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    if isinstance(d.get("detail"), str):
        try:
            d["detail"] = json.loads(d["detail"])
        except (json.JSONDecodeError, ValueError):
            d["detail"] = {}
    return d


async def _run_scan_bg(scan_id: str, program_id: str | None, db_path: Path) -> None:
    """Background task: update scan status and attempt to run the pipeline."""
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with get_conn(db_path) as conn:
        await conn.execute(
            "UPDATE scans SET status='running', started_at=? WHERE id=?",
            (ts, scan_id),
        )
        await conn.commit()

    try:
        if program_id:
            from bounty.db import get_conn as _gc
            from bounty.models import Target
            from bounty.recon import recon_pipeline

            targets: list[Target] = []
            async with _gc(db_path) as conn:
                cur = await conn.execute(
                    "SELECT scope_type, asset_type, value FROM targets WHERE program_id = ?",
                    (program_id,),
                )
                for r in await cur.fetchall():
                    targets.append(
                        Target(
                            program_id=program_id,
                            scope_type=r["scope_type"],
                            asset_type=r["asset_type"],
                            value=r["value"],
                        )
                    )

            async with get_conn(db_path) as conn:
                cur2 = await conn.execute(
                    "SELECT intensity FROM scans WHERE id=?", (scan_id,)
                )
                sc_row = await cur2.fetchone()
                intensity = sc_row["intensity"] if sc_row else "normal"

            if targets:
                await recon_pipeline(
                    program_id=program_id,
                    targets=targets,
                    intensity=intensity,
                    db_path=db_path,
                    scan_id=scan_id,
                )
                return  # recon_pipeline updates status itself

    except Exception as exc:
        ts2 = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        async with get_conn(db_path) as conn:
            await conn.execute(
                "UPDATE scans SET status='failed', finished_at=?, error=? WHERE id=?",
                (ts2, str(exc)[:500], scan_id),
            )
            await conn.commit()
        return

    ts3 = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with get_conn(db_path) as conn:
        await conn.execute(
            "UPDATE scans SET status='completed', finished_at=? WHERE id=?",
            (ts3, scan_id),
        )
        await conn.commit()


@router.get("")
async def list_scans(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    program_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """Paginated scan list."""
    clauses: list[str] = []
    params: list[Any] = []
    if program_id:
        clauses.append("program_id = ?")
        params.append(program_id)
    if status:
        clauses.append("status = ?")
        params.append(status)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    params.extend([limit, offset])

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"SELECT * FROM scans {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        rows = await cur.fetchall()
        cnt_cur = await conn.execute(
            f"SELECT COUNT(*) FROM scans {where}", count_params
        )
        cnt_row = await cnt_cur.fetchone()

    total: int = cnt_row[0] if cnt_row else 0
    return JSONResponse(
        {
            "items": [_scan_row(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Scan detail with phases, asset count, and finding count."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan = _scan_row(row)

        ph_cur = await conn.execute(
            "SELECT * FROM scan_phases WHERE scan_id = ? ORDER BY id", (scan_id,)
        )
        phases = [_phase_row(r) for r in await ph_cur.fetchall()]

        a_cur = await conn.execute(
            "SELECT COUNT(DISTINCT asset_id) FROM findings WHERE scan_id = ?", (scan_id,)
        )
        a_row = await a_cur.fetchone()

        f_cur = await conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
        )
        f_row = await f_cur.fetchone()

    scan["phases"] = phases
    scan["asset_count"] = a_row[0] if a_row else 0
    scan["finding_count_live"] = f_row[0] if f_row else 0
    return JSONResponse(scan)


class ScanCreateRequest(BaseModel):
    program_id: str | None = None
    intensity: Intensity = "normal"
    scan_type: ScanType = "full"
    target_override: str | None = None


@router.post("", status_code=201)
async def create_scan(
    body: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Trigger a new scan.  Returns scan_id immediately; pipeline runs in background."""
    scan_id = make_ulid()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    async with get_conn(db_path) as conn:
        await conn.execute(
            """
            INSERT INTO scans (id, program_id, scan_type, status, intensity, triggered_by, created_at)
            VALUES (?, ?, ?, 'queued', ?, 'ui', ?)
            """,
            (scan_id, body.program_id, body.scan_type, body.intensity, ts),
        )
        await conn.commit()

    background_tasks.add_task(_run_scan_bg, scan_id, body.program_id, db_path)
    return JSONResponse({"scan_id": scan_id, "status": "queued"}, status_code=201)


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(
    scan_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> None:
    """Cancel a running scan (best-effort: sets status to cancelled)."""
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "UPDATE scans SET status='cancelled', finished_at=? WHERE id=? AND status IN ('queued','running')",
            (ts, scan_id),
        )
        await conn.commit()
        if cur.rowcount == 0:
            # Check if it exists
            chk = await conn.execute("SELECT id FROM scans WHERE id=?", (scan_id,))
            if await chk.fetchone() is None:
                raise HTTPException(status_code=404, detail="Scan not found")

