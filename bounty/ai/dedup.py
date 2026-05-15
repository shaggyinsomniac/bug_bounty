"""
bounty.ai.dedup — LLM-powered duplicate finding detection.

Compares a finding against a list of candidates and returns the top-3
most likely duplicates with a confidence percentage and 1-sentence reason.

Output is DECORATIVE / SUGGESTED.  The operator must confirm any merge.
"""

from __future__ import annotations

import hashlib
import json
import re

from bounty import get_logger
from bounty.ai.client import AnthropicClient, get_client
from bounty.models import Finding

log = get_logger(__name__)

_SYSTEM = (
    "You are a security-research assistant that ONLY decides whether two "
    "vulnerability findings share the same root cause.  Respond ONLY with "
    "valid JSON — no prose, no markdown fences."
)

_PROMPT_TEMPLATE = """\
Compare these two security findings and determine if they share the same root cause.

Finding A:
  Title: {title_a}
  Category: {cat_a}
  URL: {url_a}
  Description: {desc_a}
  Dedup key: {key_a}

Finding B:
  Title: {title_b}
  Category: {cat_b}
  URL: {url_b}
  Description: {desc_b}
  Dedup key: {key_b}

Reply with a JSON object in this exact schema:
{{
  "confidence_pct": <integer 0-100>,
  "reason": "<single sentence>"
}}
"""


async def find_duplicate_findings(
    finding: Finding,
    candidates: list[Finding],
    client: AnthropicClient | None = None,
) -> list[tuple[str, int, str]]:
    """Find likely duplicates of *finding* among *candidates*.

    Args:
        finding: The target finding to compare against.
        candidates: Pool of existing findings to compare with.
        client: Optional pre-built client (useful for testing).

    Returns:
        List of ``(candidate_id, confidence_pct, reason)`` tuples, sorted by
        confidence descending, top-3 only.  Returns ``[]`` when AI is disabled
        or no candidates provided.
    """
    if not candidates:
        return []

    ai = client or get_client()
    results: list[tuple[str, int, str]] = []

    for cand in candidates:
        if cand.id == finding.id:
            continue
        cand_id = cand.id or ""
        if not cand_id:
            continue

        cache_key = _dedup_cache_key(finding, cand)
        prompt = _PROMPT_TEMPLATE.format(
            title_a=finding.title,
            cat_a=finding.category,
            url_a=finding.url,
            desc_a=(finding.description or "")[:500],
            key_a=finding.dedup_key,
            title_b=cand.title,
            cat_b=cand.category,
            url_b=cand.url,
            desc_b=(cand.description or "")[:500],
            key_b=cand.dedup_key,
        )

        try:
            # Override the prompt with a stable cache key by embedding it
            raw = await ai.complete(_SYSTEM, f"<!-- cache:{cache_key} -->\n{prompt}")
            parsed = _parse_json(raw)
            raw_conf = parsed.get("confidence_pct", 0)
            confidence = int(raw_conf) if isinstance(raw_conf, (int, float)) else 0
            reason = str(parsed.get("reason", "")).strip()
            results.append((cand_id, confidence, reason))
        except Exception as exc:  # noqa: BLE001
            log.warning("ai_dedup_error", candidate_id=cand_id, error=str(exc))
            continue

    # Sort by confidence descending, return top-3
    results.sort(key=lambda t: t[1], reverse=True)
    return results[:3]


def _dedup_cache_key(a: Finding, b: Finding) -> str:
    """Stable cache key combining both findings' dedup_keys and descriptions."""
    parts = sorted([
        a.dedup_key + (a.description or ""),
        b.dedup_key + (b.description or ""),
    ])
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _parse_json(text: str) -> dict[str, object]:
    """Extract JSON object from LLM response, stripping any surrounding prose."""
    # Strip markdown code fences if present
    text = re.sub(r"```(?:json)?\s*", "", text).strip()
    try:
        return dict(json.loads(text))
    except json.JSONDecodeError:
        # Try to find first {...} block
        m = re.search(r"\{[^{}]+\}", text, re.DOTALL)
        if m:
            try:
                return dict(json.loads(m.group()))
            except json.JSONDecodeError:
                pass
    return {}

