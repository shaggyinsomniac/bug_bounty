"""
bounty.ui.routes.pages — HTML page routes.

All page handlers perform direct DB queries and render Jinja2 templates.
Auth is enforced via PageAuthDep (session cookie or open when UI_TOKEN unset).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
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
async def assets_page(
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
    program_id: str | None = Query(default=None),
    has_findings: bool = Query(default=False),
    has_fingerprint: bool = Query(default=False),
    tech: str | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=200),
) -> Response:
    """Assets list page."""
    is_htmx = bool(request.headers.get("HX-Request"))

    clauses: list[str] = []
    params: list[Any] = []

    if program_id:
        clauses.append("a.program_id = ?")
        params.append(program_id)
    if search:
        clauses.append("(a.host LIKE ? OR a.title LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    if has_findings:
        clauses.append("EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id)")
    if has_fingerprint:
        clauses.append("EXISTS (SELECT 1 FROM fingerprints fp WHERE fp.asset_id = a.id)")
    if tech:
        clauses.append(
            "EXISTS (SELECT 1 FROM fingerprints fp WHERE fp.asset_id = a.id AND fp.tech = ?)"
        )
        params.append(tech)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    limit = per_page
    offset = (page - 1) * per_page

    async with get_conn(db_path) as conn:
        cnt_cur = await conn.execute(
            f"SELECT COUNT(*) FROM assets a {where}", count_params
        )
        cnt_row = await cnt_cur.fetchone()
        total: int = cnt_row[0] if cnt_row else 0

        params_q = list(count_params) + [limit, offset]
        cur = await conn.execute(
            f"SELECT a.* FROM assets a {where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?",
            params_q,
        )
        assets: list[dict[str, Any]] = []
        for r in await cur.fetchall():
            d: dict[str, Any] = {k: r[k] for k in r.keys()}
            for field in ("tags", "seen_protocols"):
                if isinstance(d.get(field), str):
                    try:
                        d[field] = json.loads(d[field])
                    except (json.JSONDecodeError, ValueError):
                        d[field] = []
            assets.append(d)

        pcur = await conn.execute("SELECT * FROM programs ORDER BY name")
        programs = [_prog_row_p(r) for r in await pcur.fetchall()]

    context: dict[str, Any] = {
        "assets": assets,
        "total": total,
        "page": page,
        "per_page": per_page,
        "programs": programs,
        "filters": {
            "program_id": program_id or "",
            "has_findings": has_findings,
            "has_fingerprint": has_fingerprint,
            "tech": tech or "",
            "search": search or "",
        },
    }
    template = "assets/_table.html" if is_htmx else "assets/list.html"
    return _tmpl(request, template, context)


@router.get("/assets/{asset_id}", response_class=HTMLResponse)
async def asset_detail(
    asset_id: str,
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
) -> Response:
    """Asset detail page."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Asset not found")

        asset: dict[str, Any] = {k: row[k] for k in row.keys()}
        for field in ("tags", "seen_protocols"):
            if isinstance(asset.get(field), str):
                try:
                    asset[field] = json.loads(asset[field])
                except (json.JSONDecodeError, ValueError):
                    asset[field] = []

        fp_cur = await conn.execute(
            "SELECT id, tech, version, category, confidence, created_at"
            " FROM fingerprints WHERE asset_id = ? ORDER BY confidence DESC",
            (asset_id,),
        )
        fingerprints: list[dict[str, Any]] = [
            {k: r[k] for k in r.keys()} for r in await fp_cur.fetchall()
        ]

        cnt_cur = await conn.execute(
            "SELECT COUNT(*) FROM findings WHERE asset_id = ?", (asset_id,)
        )
        cnt_row = await cnt_cur.fetchone()
        findings_count: int = cnt_row[0] if cnt_row else 0

        find_cur = await conn.execute(
            "SELECT * FROM findings WHERE asset_id = ? ORDER BY severity DESC LIMIT 10",
            (asset_id,),
        )
        findings = [_finding_row_p(r) for r in await find_cur.fetchall()]

    return _tmpl(request, "assets/detail.html", {
        "asset": asset,
        "fingerprints": fingerprints,
        "findings_count": findings_count,
        "findings": findings,
    })


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
    view: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    category: str | None = Query(default=None),
    validated_only: bool = Query(default=False),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=200),
) -> Response:
    """Findings list page with filtering, pagination, and HTMX partial support."""
    is_htmx = bool(request.headers.get("HX-Request"))

    # ---------------------------------------------------------------- kanban
    if view == "kanban":
        status_names = [
            "new", "triaged", "reported", "accepted",
            "dismissed", "duplicate", "wont_fix",
        ]
        kanban_columns: dict[str, list[dict[str, Any]]] = {s: [] for s in status_names}
        kcount = 0
        async with get_conn(db_path) as conn:
            kcur = await conn.execute(
                "SELECT * FROM findings ORDER BY severity DESC, created_at DESC LIMIT 500"
            )
            for kr in await kcur.fetchall():
                kf = _finding_row_p(kr)
                ks = str(kf.get("status", "new"))
                if ks in kanban_columns:
                    kanban_columns[ks].append(kf)
                else:
                    kanban_columns["new"].append(kf)
                kcount += 1
        kctx: dict[str, Any] = {
            "kanban_columns": kanban_columns,
            "status_names": status_names,
            "total": kcount,
        }
        ktmpl = "findings/_kanban.html" if is_htmx else "findings/kanban.html"
        return _tmpl(request, ktmpl, kctx)

    # ---------------------------------------------------------------- table
    severities = [s.strip() for s in severity.split(",")] if severity else []

    clauses: list[str] = []
    params: list[Any] = []

    if severities:
        placeholders = ",".join("?" * len(severities))
        clauses.append(f"severity_label IN ({placeholders})")
        params.extend(severities)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if category:
        clauses.append("category LIKE ?")
        params.append(f"%{category}%")
    if validated_only:
        clauses.append("validated = 1")
    if search:
        clauses.append("(title LIKE ? OR url LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    limit = per_page
    offset = (page - 1) * per_page
    params.extend([limit, offset])

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"SELECT * FROM findings {where} ORDER BY severity DESC, created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        findings = [_finding_row_p(r) for r in await cur.fetchall()]

        cnt = await conn.execute(f"SELECT COUNT(*) FROM findings {where}", count_params)
        cnt_row = await cnt.fetchone()
        total: int = cnt_row[0] if cnt_row else 0

    context: dict[str, Any] = {
        "findings": findings,
        "total": total,
        "page": page,
        "per_page": per_page,
        "filters": {
            "severity": severity or "",
            "status": status or "",
            "category": category or "",
            "validated_only": validated_only,
            "search": search or "",
        },
        "severities_checked": severities,
    }

    template = "findings/_table.html" if is_htmx else "findings/list.html"
    return _tmpl(request, template, context)


@router.get("/findings/{finding_id}/drawer", response_class=HTMLResponse)
async def finding_drawer(
    finding_id: str,
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
) -> Response:
    """Drawer-style partial for finding detail (always returns partial fragment)."""
    return await _finding_detail_response(finding_id, request, db_path, partial=True)


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(
    finding_id: str,
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
) -> Response:
    """Finding detail page — full page or partial depending on HX-Request."""
    is_htmx = bool(request.headers.get("HX-Request"))
    return await _finding_detail_response(finding_id, request, db_path, partial=is_htmx)


async def _finding_detail_response(
    finding_id: str,
    request: Request,
    db_path: "Path",
    partial: bool,
) -> Response:
    """Shared helper that fetches finding data and renders the appropriate template."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        finding = _finding_row_p(row)

        ev_cur = await conn.execute(
            "SELECT * FROM evidence_packages WHERE finding_id = ? ORDER BY captured_at",
            (finding_id,),
        )
        evidence = [{k: r[k] for k in r.keys()} for r in await ev_cur.fetchall()]

        sv_cur = await conn.execute(
            "SELECT * FROM secrets_validations WHERE finding_id = ? ORDER BY created_at",
            (finding_id,),
        )
        secrets: list[dict[str, Any]] = []
        for r in await sv_cur.fetchall():
            d: dict[str, Any] = {k: r[k] for k in r.keys()}
            if isinstance(d.get("scope"), str):
                try:
                    d["scope"] = json.loads(d["scope"])
                except (json.JSONDecodeError, ValueError):
                    d["scope"] = None
            secrets.append(d)

        asset: dict[str, Any] | None = None
        if finding.get("asset_id"):
            a_cur = await conn.execute(
                "SELECT * FROM assets WHERE id = ?", (finding["asset_id"],)
            )
            a_row = await a_cur.fetchone()
            if a_row:
                asset = {k: a_row[k] for k in a_row.keys()}

    ctx: dict[str, Any] = {
        "finding": finding,
        "evidence": evidence,
        "secrets": secrets,
        "asset": asset,
    }
    tmpl = "findings/_detail_partial.html" if partial else "findings/detail.html"
    return _tmpl(request, tmpl, ctx)


@router.get("/programs", response_class=HTMLResponse)
async def programs_page(
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
    platform: str | None = Query(default=None),
    active_only: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=200),
) -> Response:
    """Programs list page."""
    is_htmx = bool(request.headers.get("HX-Request"))

    clauses: list[str] = []
    params: list[Any] = []

    if platform:
        clauses.append("platform = ?")
        params.append(platform)
    if active_only:
        clauses.append("active = 1")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    limit = per_page
    offset = (page - 1) * per_page

    async with get_conn(db_path) as conn:
        cnt_cur = await conn.execute(
            f"SELECT COUNT(*) FROM programs {where}", count_params
        )
        cnt_row = await cnt_cur.fetchone()
        total: int = cnt_row[0] if cnt_row else 0

        params_q = list(count_params) + [limit, offset]
        cur = await conn.execute(
            f"SELECT * FROM programs {where} ORDER BY name LIMIT ? OFFSET ?",
            params_q,
        )
        programs_raw = [_prog_row_p(r) for r in await cur.fetchall()]

        # Enrich with asset/finding counts
        programs: list[dict[str, Any]] = []
        for p in programs_raw:
            pid = p["id"]
            a_cur = await conn.execute(
                "SELECT COUNT(*) FROM assets WHERE program_id = ?", (pid,)
            )
            a_row = await a_cur.fetchone()
            p["asset_count"] = a_row[0] if a_row else 0

            f_cur = await conn.execute(
                "SELECT COUNT(*) FROM findings WHERE program_id = ?", (pid,)
            )
            f_row = await f_cur.fetchone()
            p["finding_count"] = f_row[0] if f_row else 0
            programs.append(p)

    context: dict[str, Any] = {
        "programs": programs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "filters": {
            "platform": platform or "",
            "active_only": active_only,
        },
    }
    template = "programs/_table.html" if is_htmx else "programs/list.html"
    return _tmpl(request, template, context)


@router.get("/programs/{program_id}", response_class=HTMLResponse)
async def program_detail(
    program_id: str,
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
) -> Response:
    """Program detail page."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM programs WHERE id = ?", (program_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Program not found")

        program = _prog_row_p(row)

        t_cur = await conn.execute(
            "SELECT * FROM targets WHERE program_id = ? ORDER BY scope_type, asset_type",
            (program_id,),
        )
        program["targets"] = [{k: r[k] for k in r.keys()} for r in await t_cur.fetchall()]

        a_cur = await conn.execute(
            "SELECT COUNT(*) FROM assets WHERE program_id = ?", (program_id,)
        )
        a_row = await a_cur.fetchone()
        program["asset_count"] = a_row[0] if a_row else 0

        f_cur = await conn.execute(
            "SELECT COUNT(*) FROM findings WHERE program_id = ?", (program_id,)
        )
        f_row = await f_cur.fetchone()
        program["finding_count"] = f_row[0] if f_row else 0

        sc_cur = await conn.execute(
            "SELECT COUNT(*) FROM scans WHERE program_id = ?", (program_id,)
        )
        sc_row = await sc_cur.fetchone()
        program["scan_count"] = sc_row[0] if sc_row else 0

        sev_cur = await conn.execute(
            "SELECT severity_label, COUNT(*) FROM findings WHERE program_id = ? GROUP BY severity_label",
            (program_id,),
        )
        findings_by_severity: dict[str, int] = {}
        for r in await sev_cur.fetchall():
            findings_by_severity[r[0]] = r[1]

        scan_cur = await conn.execute(
            "SELECT * FROM scans WHERE program_id = ? ORDER BY created_at DESC LIMIT 10",
            (program_id,),
        )
        recent_scans = [_scan_row_p(r) for r in await scan_cur.fetchall()]

        find_cur = await conn.execute(
            "SELECT * FROM findings WHERE program_id = ? ORDER BY severity DESC, created_at DESC LIMIT 10",
            (program_id,),
        )
        recent_findings = [_finding_row_p(r) for r in await find_cur.fetchall()]

    return _tmpl(request, "programs/detail.html", {
        "program": program,
        "findings_by_severity": findings_by_severity,
        "recent_scans": recent_scans,
        "recent_findings": recent_findings,
    })


@router.get("/secrets", response_class=HTMLResponse)
async def secrets_page(
    request: Request,
    db_path: DbPathDep,
    _auth: PageAuthDep,
    status: str | None = Query(default=None),
    provider: str | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=25, ge=1, le=200),
) -> Response:
    """Secrets list page."""
    is_htmx = bool(request.headers.get("HX-Request"))

    clauses: list[str] = []
    params: list[Any] = []

    if status:
        clauses.append("status = ?")
        params.append(status)
    if provider:
        clauses.append("provider = ?")
        params.append(provider)
    if search:
        clauses.append("secret_preview LIKE ?")
        params.append(f"%{search}%")

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    limit = per_page
    offset = (page - 1) * per_page

    async with get_conn(db_path) as conn:
        cnt_cur = await conn.execute(
            f"SELECT COUNT(*) FROM secrets_validations {where}", count_params
        )
        cnt_row = await cnt_cur.fetchone()
        total: int = cnt_row[0] if cnt_row else 0

        params_q = list(count_params) + [limit, offset]
        cur = await conn.execute(
            f"SELECT * FROM secrets_validations {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params_q,
        )
        secrets: list[dict[str, Any]] = []
        for r in await cur.fetchall():
            d: dict[str, Any] = {k: r[k] for k in r.keys()}
            if isinstance(d.get("scope"), str):
                try:
                    d["scope"] = json.loads(d["scope"])
                except (json.JSONDecodeError, ValueError):
                    d["scope"] = None
            secrets.append(d)

        # Distinct providers for dropdown
        prov_cur = await conn.execute(
            "SELECT DISTINCT provider FROM secrets_validations ORDER BY provider"
        )
        providers: list[str] = [str(r[0]) for r in await prov_cur.fetchall()]

    context: dict[str, Any] = {
        "secrets": secrets,
        "total": total,
        "page": page,
        "per_page": per_page,
        "providers": providers,
        "filters": {
            "status": status or "",
            "provider": provider or "",
            "search": search or "",
        },
    }
    template = "secrets/_table.html" if is_htmx else "secrets/list.html"
    return _tmpl(request, template, context)


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

