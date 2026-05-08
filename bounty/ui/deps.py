"""
bounty.ui.deps — FastAPI dependency injection helpers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from bounty.config import Settings, get_settings


def get_settings_dep() -> Settings:
    """Return the cached application settings."""
    return get_settings()


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


def get_db_path(settings: SettingsDep) -> Path:
    """Return the configured SQLite database path."""
    return settings.db_path


DbPathDep = Annotated[Path, Depends(get_db_path)]


def _bearer_token(request: Request) -> str | None:
    """Extract Bearer token from Authorization header, or None."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def require_api_auth(
    request: Request,
    settings: SettingsDep,
) -> None:
    """Dependency that enforces Bearer token auth on API/SSE routes.

    If ``settings.ui_token`` is None, auth is disabled (dev mode).
    """
    expected = settings.ui_token
    if expected is None:
        return  # auth disabled

    token = _bearer_token(request)
    if token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


ApiAuthDep = Annotated[None, Depends(require_api_auth)]


_SESSION_COOKIE = "bounty_session"


def require_page_auth(
    request: Request,
    settings: SettingsDep,
) -> None:
    """Dependency that enforces session-cookie auth on HTML page routes."""
    expected = settings.ui_token
    if expected is None:
        return  # auth disabled

    cookie_val = request.cookies.get(_SESSION_COOKIE, "")
    if cookie_val != expected:
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": "/login"},
        )


PageAuthDep = Annotated[None, Depends(require_page_auth)]

