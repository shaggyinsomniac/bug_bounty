"""
bounty.ui.app — FastAPI application factory.

Creates the ``app`` instance used by uvicorn.  All route routers are
mounted here.  The lifespan handler initialises the database and starts
the SSE event relay background task.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from bounty import get_logger
from bounty.db import apply_migrations, init_db
from bounty.events import bus

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Paths resolved relative to this file — always correct regardless of CWD.
# ---------------------------------------------------------------------------

_UI_DIR: Path = Path(__file__).parent
_STATIC_DIR: Path = _UI_DIR / "static"
_TEMPLATES_DIR: Path = _UI_DIR / "templates"

templates: Jinja2Templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup: initialise DB, start SSE relay.  Shutdown: cancel relay, flush bus."""
    from bounty.config import get_settings
    from bounty.ui.sse import sse_manager

    settings = get_settings()
    settings.ensure_dirs()

    # Synchronous DB init (safe before async work starts)
    init_db(settings.db_path)
    apply_migrations(settings.db_path)
    log.info("database_ready", path=str(settings.db_path))

    # Start SSE event relay
    relay_task: asyncio.Task[None] = asyncio.create_task(sse_manager.event_relay())
    # Yield control so the relay task runs until its first await (subscribes to bus).
    await asyncio.sleep(0)
    log.info("sse_relay_started")

    yield

    # Graceful shutdown
    relay_task.cancel()
    try:
        await relay_task
    except asyncio.CancelledError:
        pass
    sse_manager.shutdown()
    await bus.shutdown()
    log.info("ui_shutdown_complete")


# ---------------------------------------------------------------------------
# App instance
# ---------------------------------------------------------------------------

app: FastAPI = FastAPI(
    title="Bounty UI",
    description="Bug bounty automation system — web interface",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — permissive for local dev.  In production, restrict via UI_TOKEN.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files (skip if directory is missing — avoids startup errors in CI)
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# ---------------------------------------------------------------------------
# Custom exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Any) -> Any:
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return HTMLResponse("<h1>404 — Not Found</h1>", status_code=404)
    return JSONResponse({"detail": "Not found"}, status_code=404)


@app.exception_handler(500)
async def server_error_handler(request: Request, exc: Any) -> Any:
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return HTMLResponse("<h1>500 — Internal Server Error</h1>", status_code=500)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


# ---------------------------------------------------------------------------
# Auth routes (login / logout)
# ---------------------------------------------------------------------------

from bounty.ui.auth import router as auth_router
from bounty.ui.auth import set_templates as _auth_set_templates

app.include_router(auth_router)
_auth_set_templates(templates)

# ---------------------------------------------------------------------------
# All API + page routes
# ---------------------------------------------------------------------------

from bounty.ui.routes import router as main_router
from bounty.ui.routes.pages import set_templates as _pages_set_templates

app.include_router(main_router)
_pages_set_templates(templates)

