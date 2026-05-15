"""
bounty.integrations.jira — Jira Cloud issue creation notifier.

Creates a Jira issue via the Jira Cloud REST API v3 when a finding is
discovered.  On success, appends a ``"jira:<ISSUE-KEY>"`` tag to the
finding row in the database.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from bounty.integrations._base import Notifier

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(30.0)

# Severity label → Jira priority name
_PRIORITY_MAP: dict[str, str] = {
    "critical": "Highest",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Lowest",
}


class JiraNotifier(Notifier):
    """Creates Jira issues for discovered findings."""

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str,
        db_path: Path | None = None,
    ) -> None:
        """
        Args:
            base_url: Jira instance base URL (e.g. ``https://myorg.atlassian.net``).
            email: Jira account email for Basic Auth.
            api_token: Jira API token.
            project_key: Jira project key (e.g. ``"BUG"``).
            db_path: Optional path to the SQLite DB for tag back-writing.
        """
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.api_token = api_token
        self.project_key = project_key
        self.db_path = db_path

    def _build_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Build the Jira issue creation request body."""
        severity = str(payload.get("severity_label", "medium")).lower()
        priority = _PRIORITY_MAP.get(severity, "Medium")
        title = str(payload.get("title", "Bug Bounty Finding"))
        description_text = str(payload.get("description", ""))
        curl_cmd = str(payload.get("curl_cmd", ""))

        # Build Atlassian Document Format (ADF) body
        body_content: list[dict[str, Any]] = []

        if description_text:
            body_content.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": description_text}],
            })

        if curl_cmd:
            body_content.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": "Reproduction:"}],
            })
            body_content.append({
                "type": "codeBlock",
                "attrs": {"language": "bash"},
                "content": [{"type": "text", "text": curl_cmd}],
            })

        if not body_content:
            body_content.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": "No description provided."}],
            })

        return {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[{severity.upper()}] {title}",
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority},
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": body_content,
                },
            }
        }

    async def _append_tag(self, finding_id: str, tag: str) -> None:
        """Append a tag to the finding row in the SQLite DB."""
        if not self.db_path:
            return
        try:
            import aiosqlite
            async with aiosqlite.connect(str(self.db_path)) as conn:
                conn.row_factory = aiosqlite.Row
                cur = await conn.execute(
                    "SELECT tags FROM findings WHERE id = ?", (finding_id,)
                )
                row = await cur.fetchone()
                if row is None:
                    return
                raw = row["tags"] or "[]"
                try:
                    tags: list[str] = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    tags = []
                if tag not in tags:
                    tags.append(tag)
                await conn.execute(
                    "UPDATE findings SET tags = ? WHERE id = ?",
                    (json.dumps(tags), finding_id),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("jira_tag_write_failed", extra={"error": str(exc)})

    async def notify(self, event_name: str, payload: dict[str, object]) -> None:
        """Create a Jira issue for the finding.

        Args:
            event_name: Event type string.
            payload: SSE event data dict (may include ``curl_cmd`` from evidence).
        """
        data = dict(payload)
        body = self._build_payload(data)
        url = f"{self.base_url}/rest/api/3/issue"
        auth = (self.email, self.api_token)

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, json=body, auth=auth)
            resp.raise_for_status()

        issue_key: str = resp.json().get("key", "")
        log.info(
            "jira_issue_created",
            extra={"issue_key": issue_key, "event": event_name},
        )

        # Back-write tag to finding
        finding_id = str(data.get("id", ""))
        if finding_id and issue_key:
            await self._append_tag(finding_id, f"jira:{issue_key}")

