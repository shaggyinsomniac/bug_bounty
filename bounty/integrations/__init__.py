"""
bounty.integrations — Notification and ticket-creation integrations.

Call ``start_integrations(settings)`` once at application startup.  It
subscribes to the in-process event bus and fans out ``finding:new`` events
to all enabled notifiers (Discord, Slack, Jira, Linear) in parallel.

Severity hierarchy for threshold filtering (highest → lowest):
    critical > high > medium > low > info
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from bounty.config import Settings

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "info":     0,
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}


def _severity_rank(label: str) -> int:
    """Return numeric rank for a severity label string."""
    return _SEVERITY_ORDER.get(label.lower(), -1)


def _meets_threshold(severity_label: str, threshold: str) -> bool:
    """Return True when *severity_label* is >= *threshold*."""
    return _severity_rank(severity_label) >= _severity_rank(threshold)


# ---------------------------------------------------------------------------
# Status tracker (in-memory)
# ---------------------------------------------------------------------------

# shape: { platform: { "configured": bool, "last_success": str|None, "last_error": str|None } }
_integration_status: dict[str, dict[str, Any]] = {
    "discord": {"configured": False, "last_success": None, "last_error": None},
    "slack":   {"configured": False, "last_success": None, "last_error": None},
    "jira":    {"configured": False, "last_success": None, "last_error": None},
    "linear":  {"configured": False, "last_success": None, "last_error": None},
}


def get_integration_status() -> dict[str, dict[str, Any]]:
    """Return a copy of the current in-memory integration status."""
    return {k: dict(v) for k, v in _integration_status.items()}


def _record_success(platform: str) -> None:
    if platform in _integration_status:
        _integration_status[platform]["last_success"] = _now_iso()


def _record_error(platform: str, error: str) -> None:
    if platform in _integration_status:
        _integration_status[platform]["last_error"] = f"{_now_iso()} — {error}"


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Quiet hours helper
# ---------------------------------------------------------------------------

def _in_quiet_hours(quiet_start: str | None, quiet_end: str | None) -> bool:
    """Return True if the current UTC time falls in [quiet_start, quiet_end).

    Both are HH:MM strings.  If either is None, quiet hours are disabled.
    Handles overnight windows (e.g. 22:00–08:00).
    """
    if not quiet_start or not quiet_end:
        return False
    try:
        now = datetime.now(tz=timezone.utc)
        now_minutes = now.hour * 60 + now.minute

        sh, sm = (int(x) for x in quiet_start.split(":"))
        eh, em = (int(x) for x in quiet_end.split(":"))
        start = sh * 60 + sm
        end = eh * 60 + em

        if start <= end:
            return start <= now_minutes < end
        else:
            # Overnight: e.g. 22:00–08:00
            return now_minutes >= start or now_minutes < end
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Core dispatcher
# ---------------------------------------------------------------------------

async def _safe_notify(
    platform: str,
    notifier: Any,
    event_name: str,
    payload: dict[str, Any],
    db_path: Any = None,
    scan_id: str = "",
) -> None:
    """Call notifier.notify(), catching all exceptions to protect the event loop."""
    try:
        await notifier.notify(event_name, payload)
        _record_success(platform)
        log.info("integration_notify_ok", extra={"platform": platform, "event": event_name})
    except Exception as exc:
        _record_error(platform, str(exc))
        log.warning(
            "integration_notify_failed",
            extra={"platform": platform, "event": event_name, "error": str(exc)},
        )
        if db_path is not None:
            try:
                from bounty.errors import record_error as _rec_err
                await _rec_err(db_path, scan_id, "notification", exc)
            except Exception:  # noqa: BLE001
                pass


async def _handle_finding_event(
    event_name: str,
    payload: dict[str, Any],
    settings: Settings,
) -> None:
    """Fan out a single finding event to all enabled, threshold-passing notifiers."""
    severity = str(payload.get("severity_label", "info")).lower()
    _event_scan_id: str = str(payload.get("scan_id") or "")
    _event_db_path: Any = getattr(settings, "db_path", None)

    quiet_start: str | None = getattr(settings, "notification_quiet_start", None)
    quiet_end: str | None = getattr(settings, "notification_quiet_end", None)
    if _in_quiet_hours(quiet_start, quiet_end):
        log.debug("integration_quiet_hours_suppressed", extra={"event": event_name})
        return

    tasks: list[asyncio.Task[None]] = []

    # --- Discord ---
    discord_url: str | None = getattr(settings, "discord_webhook_url", None)
    discord_threshold: str = getattr(settings, "discord_severity_threshold", "high")
    if discord_url and _meets_threshold(severity, discord_threshold):
        from bounty.integrations.discord import DiscordNotifier
        notifier = DiscordNotifier(webhook_url=discord_url)
        tasks.append(asyncio.create_task(_safe_notify("discord", notifier, event_name, payload,
                                                       db_path=_event_db_path, scan_id=_event_scan_id)))

    # --- Slack ---
    slack_url: str | None = getattr(settings, "slack_webhook_url", None)
    slack_threshold: str = getattr(settings, "slack_severity_threshold", "high")
    if slack_url and _meets_threshold(severity, slack_threshold):
        from bounty.integrations.slack import SlackNotifier
        notifier_s = SlackNotifier(webhook_url=slack_url)
        tasks.append(asyncio.create_task(_safe_notify("slack", notifier_s, event_name, payload,
                                                       db_path=_event_db_path, scan_id=_event_scan_id)))

    # --- Jira ---
    jira_url: str | None = getattr(settings, "jira_base_url", None)
    jira_email: str | None = getattr(settings, "jira_email", None)
    jira_token: str | None = getattr(settings, "jira_api_token", None)
    jira_project: str | None = getattr(settings, "jira_project_key", None)
    jira_threshold: str = getattr(settings, "jira_severity_threshold", "critical")
    if jira_url and jira_email and jira_token and jira_project and _meets_threshold(severity, jira_threshold):
        from bounty.integrations.jira import JiraNotifier
        db_path = settings.db_path
        notifier_j = JiraNotifier(
            base_url=jira_url,
            email=jira_email,
            api_token=jira_token,
            project_key=jira_project,
            db_path=db_path,
        )
        tasks.append(asyncio.create_task(_safe_notify("jira", notifier_j, event_name, payload,
                                                       db_path=_event_db_path, scan_id=_event_scan_id)))

    # --- Linear ---
    linear_token: str | None = getattr(settings, "linear_api_token", None)
    linear_team: str | None = getattr(settings, "linear_team_id", None)
    linear_threshold: str = getattr(settings, "linear_severity_threshold", "critical")
    if linear_token and linear_team and _meets_threshold(severity, linear_threshold):
        from bounty.integrations.linear import LinearNotifier
        notifier_l = LinearNotifier(api_token=linear_token, team_id=linear_team)
        tasks.append(asyncio.create_task(_safe_notify("linear", notifier_l, event_name, payload,
                                                       db_path=_event_db_path, scan_id=_event_scan_id)))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


# ---------------------------------------------------------------------------
# Public startup hook
# ---------------------------------------------------------------------------

async def start_integrations(settings: Settings) -> None:
    """Subscribe to the event bus and dispatch finding events to notifiers.

    This coroutine runs indefinitely as a background task.  It should be
    started once during application lifespan startup.

    Args:
        settings: Application settings instance.
    """
    # Update configured status based on current settings
    _integration_status["discord"]["configured"] = bool(
        getattr(settings, "discord_webhook_url", None)
    )
    _integration_status["slack"]["configured"] = bool(
        getattr(settings, "slack_webhook_url", None)
    )
    _integration_status["jira"]["configured"] = bool(
        getattr(settings, "jira_api_token", None)
    )
    _integration_status["linear"]["configured"] = bool(
        getattr(settings, "linear_api_token", None)
    )

    log.info(
        "integrations_started",
        extra={
            "discord": _integration_status["discord"]["configured"],
            "slack": _integration_status["slack"]["configured"],
            "jira": _integration_status["jira"]["configured"],
            "linear": _integration_status["linear"]["configured"],
        },
    )

    from bounty.events import bus
    from bounty.models import SSEEvent

    # Subscribe to all events; filter for finding:new inside the loop.
    q: asyncio.Queue[SSEEvent | None] = asyncio.Queue(maxsize=256)
    async with bus._get_lock:
        bus._subscribers.append(q)

    try:
        while True:
            event = await q.get()
            if event is None:
                break  # bus shutdown sentinel
            if event.event_type in ("finding:new", "finding.discovered"):
                asyncio.create_task(
                    _handle_finding_event(event.event_type, dict(event.data), settings)
                )
    finally:
        async with bus._get_lock:
            try:
                bus._subscribers.remove(q)
            except ValueError:
                pass
        log.info("integrations_subscriber_removed")

