"""
bounty.ui.routes.dashboard — /api/dashboard endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from bounty.db import get_conn
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
async def dashboard_stats(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """KPI summary used by the dashboard for live stat-card updates."""
    stats: dict[str, Any] = {
        "programs": 0,
        "assets": 0,
        "open_findings": 0,
        "findings_by_severity": {},
        "live_secrets": 0,
        "queue_depth": 0,
    }

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

        try:
            cur = await conn.execute(
                "SELECT COUNT(*) FROM scan_queue WHERE status IN ('queued','running')"
            )
            row = await cur.fetchone()
            stats["queue_depth"] = row[0] if row else 0
        except Exception:  # noqa: BLE001
            stats["queue_depth"] = 0

    return JSONResponse(stats)

