"""
bounty.ui.routes — aggregates all API and page routers.
"""

from __future__ import annotations

from fastapi import APIRouter

from bounty.ui.routes import (
    assets,
    dashboard,
    findings,
    intel,
    palette,
    programs,
    reports,
    scans,
    secrets,
    sse_routes,
    system,
)
from bounty.ui.routes.pages import router as pages_router

router = APIRouter()

router.include_router(pages_router)
router.include_router(dashboard.router)
router.include_router(assets.router)
router.include_router(findings.router)
router.include_router(scans.router)
router.include_router(programs.router)
router.include_router(secrets.router)
router.include_router(reports.router)
router.include_router(system.router)
router.include_router(palette.router)
router.include_router(intel.router)
router.include_router(sse_routes.router)
