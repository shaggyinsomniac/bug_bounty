"""
bounty.ui.routes.reports — /api/reports endpoints.
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
from bounty.report import generate_report
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/reports", tags=["reports"])

_TEMPLATES: tuple[str, ...] = ("h1", "bugcrowd", "markdown")
_STATUSES: tuple[str, ...] = ("draft", "sent", "accepted", "rejected")


def _row(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    if isinstance(d.get("finding_ids"), str):
        try:
            d["finding_ids"] = json.loads(d["finding_ids"])
        except (json.JSONDecodeError, ValueError):
            d["finding_ids"] = []
    return d


def _ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _build_report_body(
    db_path: Any,
    finding_ids: list[str],
    template: str,
) -> str:
    findings: list[dict[str, Any]] = []
    evidence_by_finding: dict[str, list[dict[str, Any]]] = {}
    secrets_by_finding: dict[str, list[dict[str, Any]]] = {}

    async with get_conn(db_path) as conn:
        for fid in finding_ids:
            cur = await conn.execute("SELECT * FROM findings WHERE id = ?", (fid,))
            row = await cur.fetchone()
            if row:
                findings.append({k: row[k] for k in row.keys()})
                ev_cur = await conn.execute(
                    "SELECT * FROM evidence_packages WHERE finding_id = ?", (fid,)
                )
                evidence_by_finding[fid] = [
                    {k: r[k] for k in r.keys()} for r in await ev_cur.fetchall()
                ]
                sv_cur = await conn.execute(
                    "SELECT * FROM secrets_validations WHERE finding_id = ?", (fid,)
                )
                secrets_by_finding[fid] = [
                    {k: r[k] for k in r.keys()} for r in await sv_cur.fetchall()
                ]

    tmpl: Literal["h1", "bugcrowd", "markdown"] = (
        "h1" if template == "h1" else ("bugcrowd" if template == "bugcrowd" else "markdown")
    )
    return generate_report(tmpl, findings, evidence_by_finding, secrets_by_finding)


@router.get("")
async def list_reports(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    program_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    template: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    clauses: list[str] = []
    params: list[Any] = []
    if program_id:
        clauses.append("program_id = ?")
        params.append(program_id)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if template:
        clauses.append("template = ?")
        params.append(template)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    params.extend([limit, offset])
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"SELECT * FROM reports {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        rows = [_row(r) for r in await cur.fetchall()]
        cnt_cur = await conn.execute(f"SELECT COUNT(*) FROM reports {where}", count_params)
        cnt_row = await cnt_cur.fetchone()
    total: int = cnt_row[0] if cnt_row else 0
    return JSONResponse({"items": rows, "total": total, "limit": limit, "offset": offset})


@router.get("/{report_id}")
async def get_report(
    report_id: int,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Report not found")
    return JSONResponse(_row(row))


class ReportCreate(BaseModel):
    program_id: str | None = None
    finding_ids: list[str] = []
    template: str = "markdown"
    title: str = ""


@router.post("", status_code=201)
async def create_report(
    body: ReportCreate,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    if body.template not in _TEMPLATES:
        raise HTTPException(status_code=422, detail=f"template must be one of {_TEMPLATES}")
    title = body.title
    if not title and body.finding_ids:
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                "SELECT title FROM findings WHERE id = ?", (body.finding_ids[0],)
            )
            r = await cur.fetchone()
            if r:
                title = str(r[0])
    if not title:
        title = f"Report {_ts()[:10]}"
    report_body = await _build_report_body(db_path, body.finding_ids, body.template)
    ts = _ts()
    finding_ids_json = json.dumps(body.finding_ids)
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            """INSERT INTO reports (program_id, finding_ids, title, template, body, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'draft', ?, ?)""",
            (body.program_id, finding_ids_json, title, body.template, report_body, ts, ts),
        )
        await conn.commit()
        report_id = cur.lastrowid
        row_cur = await conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = await row_cur.fetchone()
    return JSONResponse(_row(row), status_code=201)  # type: ignore[arg-type]


class ReportPatch(BaseModel):
    title: str | None = None
    body: str | None = None
    status: str | None = None
    template: str | None = None
    program_id: str | None = None
    finding_ids: list[str] | None = None
    platform_submission_id: str | None = None


@router.patch("/{report_id}")
async def patch_report(
    report_id: int,
    body: ReportPatch,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    sets: list[str] = []
    params: list[Any] = []
    if body.title is not None:
        sets.append("title = ?")
        params.append(body.title)
    if body.body is not None:
        sets.append("body = ?")
        params.append(body.body)
    if body.status is not None:
        if body.status not in _STATUSES:
            raise HTTPException(status_code=422, detail=f"status must be one of {_STATUSES}")
        sets.append("status = ?")
        params.append(body.status)
        if body.status == "sent":
            sets.append("sent_at = ?")
            params.append(_ts())
    if body.template is not None:
        if body.template not in _TEMPLATES:
            raise HTTPException(status_code=422, detail=f"template must be one of {_TEMPLATES}")
        sets.append("template = ?")
        params.append(body.template)
    if body.program_id is not None:
        sets.append("program_id = ?")
        params.append(body.program_id)
    if body.finding_ids is not None:
        sets.append("finding_ids = ?")
        params.append(json.dumps(body.finding_ids))
    if body.platform_submission_id is not None:
        sets.append("platform_submission_id = ?")
        params.append(body.platform_submission_id)
    if not sets:
        raise HTTPException(status_code=422, detail="No fields to update")
    sets.append("updated_at = ?")
    params.append(_ts())
    params.append(report_id)
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"UPDATE reports SET {', '.join(sets)} WHERE id = ?", params
        )
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Report not found")
        row_cur = await conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = await row_cur.fetchone()
    return JSONResponse(_row(row))  # type: ignore[arg-type]


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    report_id: int,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> None:
    async with get_conn(db_path) as conn:
        cur = await conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Report not found")


@router.post("/{report_id}/generate")
async def regenerate_report(
    report_id: int,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Report not found")
        report = _row(row)
    finding_ids: list[str] = report.get("finding_ids") or []
    template: str = str(report.get("template") or "markdown")
    new_body = await _build_report_body(db_path, finding_ids, template)
    ts = _ts()
    async with get_conn(db_path) as conn:
        await conn.execute(
            "UPDATE reports SET body = ?, updated_at = ? WHERE id = ?",
            (new_body, ts, report_id),
        )
        await conn.commit()
        row_cur = await conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        updated = await row_cur.fetchone()
    return JSONResponse(_row(updated))  # type: ignore[arg-type]

