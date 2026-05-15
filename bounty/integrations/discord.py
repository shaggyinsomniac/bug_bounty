"""
bounty.integrations.discord — Discord webhook notifier.

Posts a richly-formatted embed message to a Discord webhook URL whenever a
finding is discovered (or any other event).  Embed colour is keyed to
severity label.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from bounty.integrations._base import Notifier

log = logging.getLogger(__name__)

# Severity → embed decimal colour
_SEVERITY_COLOURS: dict[str, int] = {
    "critical": 0xFF0000,   # red
    "high":     0xFF8C00,   # orange
    "medium":   0xFFD700,   # yellow/gold
    "low":      0x00C800,   # green
    "info":     0x5865F2,   # discord blurple
}

_TIMEOUT = httpx.Timeout(30.0)


class DiscordNotifier(Notifier):
    """Posts an embed to a Discord webhook URL."""

    def __init__(self, webhook_url: str, base_url: str = "") -> None:
        """
        Args:
            webhook_url: Full Discord webhook URL.
            base_url: Optional application base URL for deep-linking findings.
        """
        self.webhook_url = webhook_url
        self.base_url = base_url.rstrip("/")

    def _build_payload(self, event_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Build the Discord webhook JSON payload."""
        severity = str(payload.get("severity_label", "info")).lower()
        colour = _SEVERITY_COLOURS.get(severity, _SEVERITY_COLOURS["info"])

        finding_id = payload.get("id", "")
        title = payload.get("title", "New Finding")
        asset = payload.get("url", payload.get("host", "unknown"))
        dedup_key = payload.get("dedup_key", "")
        description = payload.get("description", "")

        fields: list[dict[str, Any]] = [
            {"name": "Severity", "value": severity.upper(), "inline": True},
            {"name": "Asset", "value": str(asset), "inline": True},
        ]
        if dedup_key:
            fields.append({"name": "Dedup Key", "value": str(dedup_key), "inline": False})

        embed: dict[str, Any] = {
            "title": str(title),
            "color": colour,
            "fields": fields,
            "footer": {"text": f"bounty · {event_name}"},
        }
        if description:
            embed["description"] = str(description)[:1024]
        if finding_id and self.base_url:
            embed["url"] = f"{self.base_url}/findings/{finding_id}"

        return {"embeds": [embed]}

    async def notify(self, event_name: str, payload: dict[str, object]) -> None:
        """POST an embed to the Discord webhook.

        Args:
            event_name: Event type string.
            payload: SSE event data dict.
        """
        body = self._build_payload(event_name, dict(payload))
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(self.webhook_url, json=body)
            resp.raise_for_status()
        log.debug("discord_notifier_sent", extra={"event": event_name, "status": resp.status_code})

