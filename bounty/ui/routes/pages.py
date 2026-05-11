"""
bounty.ui.routes.pages — HTML page routes.

All page handlers perform direct DB queries and render Jinja2 templates.
Auth is enforced via PageAuthDep (session cookie or open when UI_TOKEN unset).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import aiosqlite
from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from bounty.db import get_conn
from bounty.ui.deps import DbPathDep, PageAuthDep

router = APIRouter(tags=["pages"])

_templates: Jinja2Templates | None = None


def set_templates(t: Jinja2Templates) -> None:
    global _templates
    _templates = t


def _tmpl(request: Request, name: str, ctx: dict[str, Any] | None = None) -> Response:
    if _templates is None:
        return HTMLResponse(f"<h1>{name}</h1>")
    context: dict[str, Any] = ctx or {}
    return _templates.TemplateResponse(request, name, context)


def _scan_row_p(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    if isinstance(d.get("meta"), str):
        try:
            d["meta"] = json.loads(d["meta"])
        except (json.JSONDecodeError, ValueError):
            d["meta"] = {}
    return d


def _phase_row_p(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    if isinstance(d.get("detail"), str):
        try:
            d["detail"] = json.loads(d["detail"])
        except (json.JSONDecodeError, ValueError):
            d["detail"] = {}
    return d


def _finding_row_p(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    if isinstance(d.get("tags"), str):
        try:
            d["tags"] = json.loads(d["tags"])
        except (json.JSONDecodeError, ValueError):
            d["tags"] = []
    d["validated"] = bool(d.get("validated"))
    return d


def _prog_row_p(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    d["active"] = bool(d.get("active"))
    return d


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
) -> Response:
    """Main dashboard page."""
    stats: dict[str, Any] = {
        "programs": 0,
        "assets": 0,
        "open_findings": 0,
        "findings_by_severity": {},
        "live_secrets": 0,
    }
    recent_scans: list[dict[str, Any]] = []
    recent_findings: list[dict[str, Any]] = []

    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT COUNT(*) FROM programs WHERE active=1")
        row = await cur.fetchone()
        stats["programs"] = row[0] if row else 0

        cur = await conn.execute("SELECT COUNT(*) FROM assets")
        row = await cur.fetchone()
        stats["assets"] = row[0] if row else 0

        cur = await conn.execute(
            "SELECT severity_label, COUNT(*) FROM findings"
            " WHERE status NOT IN ('resolved','wont_fix') GROUP BY severity_label"
        )
        by_sev: dict[str, int] = {}
        for r in await cur.fetchall():
            by_sev[r[0]] = r[1]
        stats["findings_by_severity"] = by_sev
        stats["open_findings"] = sum(by_sev.values())

        cur = await conn.execute(
            "SELECT COUNT(*) FROM secrets_validations WHERE status='live'"
        )
        row = await cur.fetchone()
        stats["live_secrets"] = row[0] if row else 0

        cur = await conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT 10"
        )
        recent_scans = [_scan_row_p(r) for r in await cur.fetchall()]

        cur = await conn.execute(
            "SELECT * FROM findings WHERE severity >= 600"
            " ORDER BY created_at DESC LIMIT 10"
        )
        recent_findings = [_finding_row_p(r) for r in await cur.fetchall()]

    return _tmpl(request, "dashboard.html", {
        "stats": stats,
        "recent_scans": recent_scans,
        "recent_findings": recent_findings,
    })


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@router.get("/scans", response_class=HTMLResponse)
async def scans_list(
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
    program_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    intensity: str | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Response:
    """Scans list page."""
    clauses: list[str] = []
    params: list[Any] = []
    if program_id:
        clauses.append("program_id = ?")
        params.append(program_id)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if intensity:
        clauses.append("intensity = ?")
        params.append(intensity)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    params.extend([limit, offset])

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"SELECT * FROM scans {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        scans = [_scan_row_p(r) for r in await cur.fetchall()]

        cnt = await conn.execute(
            f"SELECT COUNT(*) FROM scans {where}", count_params
        )
        cnt_row = await cnt.fetchone()
        total: int = cnt_row[0] if cnt_row else 0

        pcur = await conn.execute("SELECT * FROM programs ORDER BY name")
        programs = [_prog_row_p(r) for r in await pcur.fetchall()]

    return _tmpl(request, "scans/list.html", {
        "scans": scans,
        "total": total,
        "limit": limit,
        "offset": offset,
        "programs": programs,
        "filters": {
            "program_id": program_id or "",
            "status": status or "",
            "intensity": intensity or "",
        },
    })


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    scan_id: str,
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
) -> Response:
    """Scan detail page."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan = _scan_row_p(row)

        ph_cur = await conn.execute(
            "SELECT * FROM scan_phases WHERE scan_id = ? ORDER BY id", (scan_id,)
        )
        scan["phases"] = [_phase_row_p(r) for r in await ph_cur.fetchall()]

        a_cur = await conn.execute(
            "SELECT COUNT(DISTINCT asset_id) FROM findings WHERE scan_id = ?", (scan_id,)
        )
        a_row = await a_cur.fetchone()
        scan["asset_count"] = a_row[0] if a_row else 0

        f_cur = await conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
        )
        f_row = await f_cur.fetchone()
        scan["finding_count_live"] = f_row[0] if f_row else 0

        fq = await conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC LIMIT 50",
            (scan_id,),
        )
        findings = [_finding_row_p(r) for r in await fq.fetchall()]

    return _tmpl(request, "scans/detail.html", {
        "scan": scan,
        "findings": findings,
        "finding_total": scan["finding_count_live"],
    })


# ---------------------------------------------------------------------------
# Placeholder pages — assets, findings, programs, secrets, reports, settings
# ---------------------------------------------------------------------------

@router.get("/assets", response_class=HTMLResponse)
async def assets_page(request: Request, _auth: PageAuthDep) -> Response:
    return _tmpl(request, "assets/list.html", {})


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request, _auth: PageAuthDep) -> Response:
    return _tmpl(request, "findings/list.html", {})


@router.get("/programs", response_class=HTMLResponse)
async def programs_page(request: Request, _auth: PageAuthDep) -> Response:
    return _tmpl(request, "programs/list.html", {})


@router.get("/secrets", response_class=HTMLResponse)
async def secrets_page(request: Request, _auth: PageAuthDep) -> Response:
    return _tmpl(request, "secrets/list.html", {})


@router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, _auth: PageAuthDep) -> Response:
    return _tmpl(request, "reports/list.html", {})


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, _auth: PageAuthDep) -> Response:
    return _tmpl(request, "settings/list.html", {})


# ---------------------------------------------------------------------------
# Health probes
# ---------------------------------------------------------------------------

@router.get("/healthz")
async def healthz() -> JSONResponse:
    """Liveness probe — always returns 200."""
    return JSONResponse({"status": "ok"})


@router.get("/readyz")
async def readyz(db_path: DbPathDep) -> JSONResponse:
    """Readiness probe — returns 200 after DB connectivity check."""

    try:
        async with aiosqlite.connect(str(db_path)) as conn:
            await conn.execute("SELECT 1")
    except Exception as exc:
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=503)
    return JSONResponse({"status": "ready"})

