"""
bounty.integrations.slack — Slack Block Kit webhook notifier.

Posts a Block Kit message to a Slack incoming webhook URL.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from bounty.integrations._base import Notifier

log = logging.getLogger(__name__)

# Severity → Slack colour attachment sidebar (hex)
_SEVERITY_COLOURS: dict[str, str] = {
    "critical": "#FF0000",
    "high":     "#FF8C00",
    "medium":   "#FFD700",
    "low":      "#00C800",
    "info":     "#5865F2",
}

# Severity → emoji
_SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}

_TIMEOUT = httpx.Timeout(30.0)


class SlackNotifier(Notifier):
    """Posts a Block Kit message to a Slack webhook URL."""

    def __init__(self, webhook_url: str, base_url: str = "") -> None:
        """
        Args:
            webhook_url: Full Slack incoming webhook URL.
            base_url: Optional application base URL for deep-linking findings.
        """
        self.webhook_url = webhook_url
        self.base_url = base_url.rstrip("/")

    def _build_payload(self, event_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Build the Slack webhook JSON payload using Block Kit."""
        severity = str(payload.get("severity_label", "info")).lower()
        colour = _SEVERITY_COLOURS.get(severity, _SEVERITY_COLOURS["info"])
        emoji = _SEVERITY_EMOJI.get(severity, "🔵")

        finding_id = payload.get("id", "")
        title = payload.get("title", "New Finding")
        asset = payload.get("url", payload.get("host", "unknown"))
        dedup_key = payload.get("dedup_key", "")
        description = payload.get("description", "")

        link = ""
        if finding_id and self.base_url:
            link = f"{self.base_url}/findings/{finding_id}"

        title_text = f"{emoji} *{title}*"
        if link:
            title_text = f"{emoji} *<{link}|{title}>*"

        blocks: list[dict[str, Any]] = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": title_text},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Asset:*\n{asset}"},
                ],
            },
        ]

        if dedup_key:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Dedup Key:* `{dedup_key}`"},
            })

        if description:
            snippet = str(description)[:300]
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": snippet},
            })

        blocks.append({"type": "divider"})

        # Use attachments for the coloured sidebar
        return {
            "attachments": [
                {
                    "color": colour,
                    "blocks": blocks,
                    "footer": f"bounty · {event_name}",
                }
            ]
        }

    async def notify(self, event_name: str, payload: dict[str, object]) -> None:
        """POST a Block Kit message to the Slack webhook.

        Args:
            event_name: Event type string.
            payload: SSE event data dict.
        """
        body = self._build_payload(event_name, dict(payload))
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(self.webhook_url, json=body)
            resp.raise_for_status()
        log.debug("slack_notifier_sent", extra={"event": event_name, "status": resp.status_code})

