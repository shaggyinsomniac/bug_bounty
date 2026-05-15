"""
bounty.integrations.linear — Linear issue creation notifier.

Creates a Linear issue via the Linear GraphQL API when a finding is
discovered.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from bounty.integrations._base import Notifier

log = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(30.0)
_LINEAR_API_URL = "https://api.linear.app/graphql"

# Severity → Linear priority integer (0=No priority, 1=Urgent, 2=High, 3=Medium, 4=Low)
_PRIORITY_MAP: dict[str, int] = {
    "critical": 1,  # Urgent
    "high":     2,  # High
    "medium":   3,  # Medium
    "low":      4,  # Low
    "info":     0,  # No priority
}

_CREATE_ISSUE_MUTATION = """
mutation CreateIssue($teamId: String!, $title: String!, $description: String, $priority: Int) {
  issueCreate(input: {
    teamId: $teamId
    title: $title
    description: $description
    priority: $priority
  }) {
    success
    issue {
      id
      identifier
      url
    }
  }
}
"""


class LinearNotifier(Notifier):
    """Creates Linear issues for discovered findings."""

    def __init__(self, api_token: str, team_id: str) -> None:
        """
        Args:
            api_token: Linear personal API token.
            team_id: Linear team ID (UUID).
        """
        self.api_token = api_token
        self.team_id = team_id

    def _build_variables(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Build the GraphQL mutation variables."""
        severity = str(payload.get("severity_label", "medium")).lower()
        priority = _PRIORITY_MAP.get(severity, 0)
        title = str(payload.get("title", "Bug Bounty Finding"))
        description_parts: list[str] = []

        desc = str(payload.get("description", ""))
        if desc:
            description_parts.append(desc)

        url = str(payload.get("url", ""))
        if url:
            description_parts.append(f"\n**Asset:** {url}")

        dedup_key = str(payload.get("dedup_key", ""))
        if dedup_key:
            description_parts.append(f"\n**Dedup Key:** `{dedup_key}`")

        curl_cmd = str(payload.get("curl_cmd", ""))
        if curl_cmd:
            description_parts.append(f"\n**Reproduction:**\n```bash\n{curl_cmd}\n```")

        description = "\n".join(description_parts) if description_parts else None

        return {
            "teamId": self.team_id,
            "title": f"[{severity.upper()}] {title}",
            "description": description,
            "priority": priority,
        }

    async def notify(self, event_name: str, payload: dict[str, object]) -> None:
        """Create a Linear issue for the finding.

        Args:
            event_name: Event type string.
            payload: SSE event data dict.
        """
        variables = self._build_variables(dict(payload))
        headers = {
            "Authorization": self.api_token,
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {
            "query": _CREATE_ISSUE_MUTATION,
            "variables": variables,
        }

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(_LINEAR_API_URL, json=body, headers=headers)
            resp.raise_for_status()

        result = resp.json()
        errors = result.get("errors")
        if errors:
            raise RuntimeError(f"Linear API errors: {errors}")

        issue_data = result.get("data", {}).get("issueCreate", {})
        issue = issue_data.get("issue") or {}
        log.info(
            "linear_issue_created",
            extra={
                "identifier": issue.get("identifier"),
                "url": issue.get("url"),
                "event": event_name,
            },
        )

