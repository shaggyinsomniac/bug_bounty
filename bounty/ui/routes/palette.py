"""
bounty.ui.routes.palette — Command palette search endpoint.

GET /api/palette/search?q=<query>
Returns JSON {quick_actions: [...], results: [...]} with results from
assets, findings, scans, programs, and reports.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from bounty.db import get_conn
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/palette", tags=["palette"])

_QUICK_ACTIONS: list[dict[str, str]] = [
    {"label": "New Scan", "url": "/scans", "icon": "🔍", "action": "modal"},
    {"label": "New Report", "url": "/reports", "icon": "📄", "action": "link"},
    {"label": "New Program", "url": "/programs", "icon": "🎯", "action": "modal"},
    {"label": "Go to Dashboard", "url": "/", "icon": "📊", "action": "link"},
    {"label": "Settings", "url": "/settings", "icon": "⚙️", "action": "link"},
]


@router.get("/search")
async def palette_search(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    q: str = Query(default=""),
) -> JSONResponse:
    """Search across assets, findings, scans, programs, reports."""
    results: list[dict[str, Any]] = []

    if not q.strip():
        return JSONResponse({
            "quick_actions": _QUICK_ACTIONS,
            "results": [],
            "query": q,
        })

    like = f"%{q}%"
    max_per = 5

    async with get_conn(db_path) as conn:
        # Assets
        cur = await conn.execute(
            "SELECT id, host, http_status FROM assets WHERE host LIKE ? OR title LIKE ? LIMIT ?",
            (like, like, max_per),
        )
        for r in await cur.fetchall():
            results.append({
                "type": "asset",
                "id": str(r["id"]),
                "label": str(r["host"]),
                "url": f"/assets/{r['id']}",
                "badge": str(r["http_status"]) if r["http_status"] else None,
                "icon": "🖥️",
            })

        # Findings
        cur = await conn.execute(
            "SELECT id, title, severity_label FROM findings WHERE title LIKE ? OR url LIKE ? LIMIT ?",
            (like, like, max_per),
        )
        for r in await cur.fetchall():
            results.append({
                "type": "finding",
                "id": str(r["id"]),
                "label": str(r["title"]),
                "url": f"/findings/{r['id']}",
                "badge": str(r["severity_label"]) if r["severity_label"] else None,
                "icon": "🐛",
            })

        # Programs
        cur = await conn.execute(
            "SELECT id, name, platform FROM programs WHERE name LIKE ? OR handle LIKE ? LIMIT ?",
            (like, like, max_per),
        )
        for r in await cur.fetchall():
            results.append({
                "type": "program",
                "id": str(r["id"]),
                "label": str(r["name"]),
                "url": f"/programs/{r['id']}",
                "badge": str(r["platform"]) if r["platform"] else None,
                "icon": "🎯",
            })

        # Scans
        cur = await conn.execute(
            "SELECT id, status FROM scans WHERE id LIKE ? LIMIT ?",
            (like, max_per),
        )
        for r in await cur.fetchall():
            results.append({
                "type": "scan",
                "id": str(r["id"]),
                "label": f"Scan {str(r['id'])[:12]}…",
                "url": f"/scans/{r['id']}",
                "badge": str(r["status"]) if r["status"] else None,
                "icon": "🔍",
            })

        # Reports
        cur = await conn.execute(
            "SELECT id, title, status FROM reports WHERE title LIKE ? LIMIT ?",
            (like, max_per),
        )
        for r in await cur.fetchall():
            results.append({
                "type": "report",
                "id": str(r["id"]),
                "label": str(r["title"]),
                "url": f"/reports/{r['id']}",
                "badge": str(r["status"]) if r["status"] else None,
                "icon": "📄",
            })

    # Cap at 15 total
    results = results[:15]

    return JSONResponse({
        "quick_actions": _QUICK_ACTIONS,
        "results": results,
        "query": q,
    })

