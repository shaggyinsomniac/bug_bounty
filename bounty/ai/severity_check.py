"""
bounty.ai.severity_check — LLM-powered severity review.

Asks the LLM to review a finding's description and current severity score
and suggest an adjusted score + rationale.

Output is DECORATIVE / SUGGESTED.  The operator must click "Apply" in the
UI before the finding's severity is actually updated.
"""

from __future__ import annotations

import json
import re

from bounty import get_logger
from bounty.ai.client import AnthropicClient, get_client
from bounty.models import EvidencePackage, Finding

log = get_logger(__name__)

_SYSTEM = (
    "You are a senior security researcher that reviews bug bounty findings "
    "and suggests severity adjustments.  Severity is on a 0-1000 scale where: "
    "800-1000=critical, 600-799=high, 400-599=medium, 200-399=low, 0-199=info.  "
    "Respond ONLY with valid JSON — no prose, no markdown fences."
)

_PROMPT_TEMPLATE = """\
Review this security finding and suggest whether the severity score is appropriate.

Finding:
  Title: {title}
  Category: {category}
  Current Severity: {severity} / 1000 ({severity_label})
  URL: {url}
  Description:
    {description}
  Remediation:
    {remediation}
{evidence_section}
Reply with a JSON object in this exact schema:
{{
  "suggested_severity": <integer 0-1000>,
  "rationale": "<1-3 sentence explanation>"
}}
"""


async def review_severity(
    finding: Finding,
    evidence: list[EvidencePackage] | None = None,
    client: AnthropicClient | None = None,
) -> tuple[int, str]:
    """Ask the LLM to review and suggest a severity adjustment.

    Args:
        finding: The finding to review.
        evidence: Optional list of evidence packages for additional context.
        client: Optional pre-built client (useful for testing).

    Returns:
        ``(suggested_severity, rationale)`` where ``suggested_severity`` is
        0-1000.  When AI is disabled, returns ``(finding.severity, "AI disabled")``.

    Note:
        This function NEVER modifies the finding.  The caller (UI route or CLI)
        must explicitly apply any suggested change after operator confirmation.
    """
    ai = client or get_client()

    evidence_section = ""
    if evidence:
        snippets = []
        for i, ev in enumerate(evidence[:3], 1):
            lines: list[str] = []
            if ev.response_status:
                lines.append(f"HTTP {ev.response_status}")
            if ev.request_raw:
                lines.append(ev.request_raw[:200])
            if ev.response_raw:
                lines.append(ev.response_raw[:200])
            if lines:
                snippets.append(f"  Evidence #{i}: {' | '.join(lines)}")
        if snippets:
            evidence_section = "Evidence context:\n" + "\n".join(snippets) + "\n"

    prompt = _PROMPT_TEMPLATE.format(
        title=finding.title,
        category=finding.category,
        severity=finding.severity,
        severity_label=finding.severity_label,
        url=finding.url,
        description=(finding.description or "")[:800],
        remediation=(finding.remediation or "")[:400],
        evidence_section=evidence_section,
    )

    try:
        raw = await ai.complete(_SYSTEM, prompt, max_tokens=500)
        parsed = _parse_json(raw)
        raw_sev = parsed.get("suggested_severity", finding.severity)
        suggested = int(raw_sev) if isinstance(raw_sev, (int, float)) else finding.severity
        suggested = max(0, min(1000, suggested))
        rationale = str(parsed.get("rationale", "")).strip()
        return suggested, rationale
    except Exception as exc:  # noqa: BLE001
        log.warning("ai_severity_review_error", finding_id=finding.id, error=str(exc))
        raise


def _parse_json(text: str) -> dict[str, object]:
    """Extract JSON object from LLM response."""
    text = re.sub(r"```(?:json)?\s*", "", text).strip()
    try:
        return dict(json.loads(text))
    except json.JSONDecodeError:
        m = re.search(r"\{[^{}]+\}", text, re.DOTALL)
        if m:
            try:
                return dict(json.loads(m.group()))
            except json.JSONDecodeError:
                pass
    return {}

