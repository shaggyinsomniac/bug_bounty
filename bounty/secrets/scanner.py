"""
bounty.secrets.scanner — Secret scanning: extract credential patterns from text.

Scans arbitrary text (HTTP response bodies, request headers, file contents)
for known credential patterns and returns deduped SecretCandidate objects.

Pairing strategy:
  AWS: when AKIA/ASIA key found, look ±200 chars for a 40-char base64 secret.
  Twilio: when AC-prefixed SID found, look ±200 chars for 32-hex auth token.
  For paired providers, a single SecretCandidate is emitted with value=anchor
  and paired_value=secret.

Scanner never logs raw secret values — only previews.
"""

from __future__ import annotations

import hashlib
import re as _re
from dataclasses import dataclass
from pathlib import Path

from bounty.models import EvidencePackage
from bounty.secrets.patterns import PATTERNS

_CONTEXT_WINDOW = 80
_PROXIMITY = 200
_MAX_FILE_BYTES = 2 * 1024 * 1024

_LOOSE_PAIRED_SECONDARIES: dict[str, _re.Pattern[str]] = {
    "aws": _re.compile(r"(?<![A-Za-z0-9/+])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
    "twilio": _re.compile(r"(?<![0-9a-f])([0-9a-f]{32})(?![0-9a-f])"),
}


@dataclass
class SecretCandidate:
    """A potential secret found in scanned text."""

    provider: str
    pattern_name: str
    value: str
    paired_value: str | None = None
    context_before: str = ""
    context_after: str = ""

    @property
    def secret_hash(self) -> str:
        raw = self.value + (self.paired_value or "")
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def secret_preview(self) -> str:
        v = self.value
        if len(v) <= 8:
            return v + "…"
        return v[:8] + "…"


def _extract_context(text: str, start: int, end: int) -> tuple[str, str]:
    cb = text[max(0, start - _CONTEXT_WINDOW): start]
    ca = text[end: end + _CONTEXT_WINDOW]
    return cb, ca


def _dedup_key(c: SecretCandidate) -> tuple[str, str, str | None]:
    return (c.provider, c.value, c.paired_value)


def _find_paired(provider: str, text: str, anchor_start: int, anchor_end: int) -> str | None:
    secondary = _LOOSE_PAIRED_SECONDARIES.get(provider)
    if secondary is None:
        return None
    search_start = max(0, anchor_start - _PROXIMITY)
    search_end = min(len(text), anchor_end + _PROXIMITY)
    window = text[search_start:search_end]
    # Iterate all matches in the window; skip any that overlap with the anchor
    # in absolute text coordinates.
    for sm in secondary.finditer(window):
        abs_match_start = search_start + sm.start()
        abs_match_end = search_start + sm.end()
        # Reject overlap with anchor span
        if abs_match_start < anchor_end and abs_match_end > anchor_start:
            continue
        candidate = sm.group(1) if sm.lastindex else sm.group(0)
        anchor_val = text[anchor_start:anchor_end]
        if candidate == anchor_val:
            continue
        return candidate
    return None


def scan(text: str) -> list[SecretCandidate]:
    """Scan text for all registered secret patterns. Returns deduped candidates."""
    seen: dict[tuple[str, str, str | None], SecretCandidate] = {}
    for provider, patterns in PATTERNS.items():
        for pat in patterns:
            for m in pat.regex.finditer(text):
                value = m.group(0)
                start, end = m.start(), m.end()
                cb, ca = _extract_context(text, start, end)
                paired = _find_paired(provider, text, start, end)
                candidate = SecretCandidate(
                    provider=provider,
                    pattern_name=pat.name,
                    value=value,
                    paired_value=paired,
                    context_before=cb,
                    context_after=ca,
                )
                key = _dedup_key(candidate)
                if key not in seen:
                    seen[key] = candidate
    return list(seen.values())


def scan_evidence_package(ep: EvidencePackage) -> list[SecretCandidate]:
    """Scan an EvidencePackage for secrets (request, response, and body file)."""
    texts: list[str] = []
    if ep.request_raw:
        texts.append(ep.request_raw)
    if ep.response_raw:
        texts.append(ep.response_raw)
    if ep.response_body_path:
        try:
            p = Path(ep.response_body_path)
            content = p.read_bytes()[:_MAX_FILE_BYTES]
            texts.append(content.decode("utf-8", errors="replace"))
        except OSError:
            pass
    combined = "\n".join(texts)
    return scan(combined)

