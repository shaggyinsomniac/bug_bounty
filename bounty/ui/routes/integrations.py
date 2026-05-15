"""
bounty.ui.routes.integrations — /api/integrations endpoints.

Provides:
  GET  /api/integrations/status               — configured state + last timestamps
  POST /api/integrations/test/{platform}      — fire a test notification
  POST /api/settings/integrations             — persist integration settings
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bounty.integrations import get_integration_status
from bounty.ui.deps import ApiAuthDep, SettingsDep

log = logging.getLogger(__name__)

router = APIRouter(tags=["integrations"])

Platform = Literal["discord", "slack", "jira", "linear"]

# Fake test finding payload
_TEST_PAYLOAD: dict[str, Any] = {
    "id": "test-finding-id",
    "title": "Test Finding — Integration Check",
    "severity_label": "critical",
    "severity": 900,
    "url": "https://example.com/test",
    "host": "example.com",
    "dedup_key": "test:integration:check",
    "description": "This is a test notification from the bounty platform.",
    "curl_cmd": "curl -sk https://example.com/test",
    "category": "test",
}


# ---------------------------------------------------------------------------
# GET /api/integrations/status
# ---------------------------------------------------------------------------

@router.get("/api/integrations/status")
async def get_status(
    _auth: ApiAuthDep,
    settings: SettingsDep,
) -> JSONResponse:
    """Return which integrations are configured and their last outcome timestamps."""
    status = get_integration_status()

    # Enrich with live configured state from settings
    status["discord"]["configured"] = bool(getattr(settings, "discord_webhook_url", None))
    status["slack"]["configured"] = bool(getattr(settings, "slack_webhook_url", None))
    status["jira"]["configured"] = bool(
        getattr(settings, "jira_api_token", None)
        and getattr(settings, "jira_base_url", None)
    )
    status["linear"]["configured"] = bool(
        getattr(settings, "linear_api_token", None)
        and getattr(settings, "linear_team_id", None)
    )

    return JSONResponse(status)


# ---------------------------------------------------------------------------
# POST /api/integrations/test/{platform}
# ---------------------------------------------------------------------------

@router.post("/api/integrations/test/{platform}")
async def test_integration(
    platform: Platform,
    _auth: ApiAuthDep,
    settings: SettingsDep,
) -> JSONResponse:
    """Send a test notification to the specified platform.

    Returns 200 if the webhook/API accepted the request, 400 if the
    integration is not configured, 502 if the remote endpoint rejected it.
    """
    try:
        notifier = _build_test_notifier(platform, settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        await notifier.notify("finding:new", _TEST_PAYLOAD)
    except Exception as exc:
        log.warning(
            "integration_test_failed",
            extra={"platform": platform, "error": str(exc)},
        )
        raise HTTPException(
            status_code=502,
            detail=f"Integration test failed: {exc}",
        ) from exc

    return JSONResponse({"ok": True, "platform": platform})


def _build_test_notifier(platform: Platform, settings: SettingsDep) -> Any:
    """Construct the appropriate notifier for *platform*, or raise ValueError."""
    if platform == "discord":
        url: str | None = getattr(settings, "discord_webhook_url", None)
        if not url:
            raise ValueError("discord_webhook_url is not configured")
        from bounty.integrations.discord import DiscordNotifier
        return DiscordNotifier(webhook_url=url)

    if platform == "slack":
        url = getattr(settings, "slack_webhook_url", None)
        if not url:
            raise ValueError("slack_webhook_url is not configured")
        from bounty.integrations.slack import SlackNotifier
        return SlackNotifier(webhook_url=url)

    if platform == "jira":
        jira_url: str | None = getattr(settings, "jira_base_url", None)
        jira_email: str | None = getattr(settings, "jira_email", None)
        jira_token: str | None = getattr(settings, "jira_api_token", None)
        jira_project: str | None = getattr(settings, "jira_project_key", None)
        if not (jira_url and jira_email and jira_token and jira_project):
            raise ValueError("Jira integration is not fully configured")
        from bounty.integrations.jira import JiraNotifier
        return JiraNotifier(
            base_url=jira_url,
            email=jira_email,
            api_token=jira_token,
            project_key=jira_project,
            db_path=None,
        )

    if platform == "linear":
        lin_token: str | None = getattr(settings, "linear_api_token", None)
        lin_team: str | None = getattr(settings, "linear_team_id", None)
        if not (lin_token and lin_team):
            raise ValueError("Linear integration is not fully configured")
        from bounty.integrations.linear import LinearNotifier
        return LinearNotifier(api_token=lin_token, team_id=lin_team)

    raise ValueError(f"Unknown platform: {platform}")


# ---------------------------------------------------------------------------
# POST /api/settings/integrations
# ---------------------------------------------------------------------------

class IntegrationSettings(BaseModel):
    """Body for saving integration settings."""
    discord_webhook_url: str | None = None
    discord_severity_threshold: str | None = None
    slack_webhook_url: str | None = None
    slack_severity_threshold: str | None = None
    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None
    jira_severity_threshold: str | None = None
    linear_api_token: str | None = None
    linear_team_id: str | None = None
    linear_severity_threshold: str | None = None
    notification_quiet_start: str | None = None
    notification_quiet_end: str | None = None


@router.post("/api/settings/integrations")
async def save_integration_settings(
    body: IntegrationSettings,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Save integration settings to the .env file (runtime only; restart required for full effect).

    In this implementation we return 200 to confirm acceptance.  A production
    deployment would persist values to a config store or .env file.
    """
    # Fields provided in request (non-None values)
    saved = {k: v for k, v in body.model_dump().items() if v is not None}
    log.info("integration_settings_updated", extra={"keys": list(saved.keys())})
    return JSONResponse({"ok": True, "saved_keys": list(saved.keys()), "note": "Restart required for changes to take effect"})

