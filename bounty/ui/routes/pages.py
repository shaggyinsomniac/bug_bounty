"""
bounty.ui.routes.pages — HTML page routes and health-check endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from bounty.ui.deps import DbPathDep, PageAuthDep, SettingsDep

router = APIRouter(tags=["pages"])

_templates: Jinja2Templates | None = None


def set_templates(t: Jinja2Templates) -> None:
    global _templates
    _templates = t


@router.get("/", response_class=HTMLResponse)
async def home(
    request: Request,
    _auth: PageAuthDep,
) -> Response:
    """Placeholder home page — replaced in phase 7.2."""
    if _templates is None:
        return HTMLResponse("<h1>Bounty UI placeholder. Run phase 7.2 to enable the real UI.</h1>")
    return _templates.TemplateResponse(request, "placeholder.html")


@router.get("/healthz")
async def healthz() -> JSONResponse:
    """Liveness probe — always returns 200."""
    return JSONResponse({"status": "ok"})


@router.get("/readyz")
async def readyz(
    db_path: DbPathDep,
    settings: SettingsDep,
) -> JSONResponse:
    """Readiness probe — returns 200 after DB connectivity check."""
    import aiosqlite

    try:
        async with aiosqlite.connect(str(db_path)) as conn:
            await conn.execute("SELECT 1")
    except Exception as exc:
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=503)
    return JSONResponse({"status": "ready"})

