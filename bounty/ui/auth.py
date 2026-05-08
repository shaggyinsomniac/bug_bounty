"""
bounty.ui.auth — Login / logout page routes and token validation helpers.

Provides:
  GET  /login  — renders a minimal login form
  POST /login  — validates token, sets session cookie, redirects to /
  GET  /logout — clears session cookie, redirects to /login
"""

from __future__ import annotations

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from bounty.ui.deps import _SESSION_COOKIE, SettingsDep

router = APIRouter(tags=["auth"])

# Templates pointer is set by app.py after Jinja2 is configured.
_templates: Jinja2Templates | None = None


def set_templates(t: Jinja2Templates) -> None:
    """Called by app.py once Jinja2Templates is created."""
    global _templates
    _templates = t


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    """Render the login form."""
    if _templates is None:
        return HTMLResponse("<form method='post' action='/login'><input name='token' type='password'><button>Login</button></form>")
    return _templates.TemplateResponse(request, "login.html")


@router.post("/login")
async def login_submit(
    request: Request,
    settings: SettingsDep,
    token: str = Form(...),
) -> Response:
    """Validate the submitted token and set the session cookie."""
    expected = settings.ui_token
    if expected is not None and token != expected:
        if _templates is None:
            return HTMLResponse("Unauthorized", status_code=401)
        return _templates.TemplateResponse(
            request,
            "login.html",
            context={"error": "Invalid token"},
            status_code=401,
        )

    resp = RedirectResponse(url="/", status_code=302)
    if expected is not None:
        resp.set_cookie(
            key=_SESSION_COOKIE,
            value=token,
            httponly=True,
            samesite="lax",
        )
    return resp


@router.get("/logout")
async def logout() -> Response:
    """Clear the session cookie and redirect to /login."""
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(_SESSION_COOKIE)
    return resp

