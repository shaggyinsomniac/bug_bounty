"""
bounty.detect.admin_panels._common — Shared response-validation helpers.

Lightweight validators used by all admin panel detections to confirm that a
response is actually from the target panel and not a generic error page.
"""

from __future__ import annotations

import json

from bounty.models import ProbeResult

__all__ = [
    "is_json_response",
    "json_has_keys",
    "is_admin_panel_html",
    "parse_json_body",
]

# Maximum bytes to include in evidence to avoid PII/credential exposure.
EVIDENCE_BODY_LIMIT = 4096


def is_json_response(probe_result: ProbeResult) -> bool:
    """Return True if Content-Type is application/json AND body parses as JSON.

    Args:
        probe_result: The HTTP probe response.

    Returns:
        True if the response is valid JSON.
    """
    ct = probe_result.content_type
    if not ct.startswith("application/json"):
        return False
    try:
        json.loads(probe_result.body_text)
        return True
    except (ValueError, UnicodeDecodeError):
        return False


def parse_json_body(probe_result: ProbeResult) -> object:
    """Parse and return the JSON body, or None on failure.

    Args:
        probe_result: The HTTP probe response.

    Returns:
        Parsed JSON value (dict, list, etc.) or None.
    """
    try:
        return json.loads(probe_result.body_text)
    except (ValueError, UnicodeDecodeError):
        return None


def json_has_keys(probe_result: ProbeResult, required_keys: list[str]) -> bool:
    """Return True if the JSON body (top-level dict) contains all *required_keys*.

    Args:
        probe_result: The HTTP probe response.
        required_keys: Keys that must all be present in the top-level dict.

    Returns:
        True when all keys are found.
    """
    data = parse_json_body(probe_result)
    if not isinstance(data, dict):
        return False
    return all(k in data for k in required_keys)


def is_admin_panel_html(
    probe_result: ProbeResult,
    vendor_markers: list[str],
) -> bool:
    """Return True if the response is HTML and contains any of *vendor_markers*.

    Args:
        probe_result: The HTTP probe response.
        vendor_markers: Strings to look for in the response body (case-insensitive).

    Returns:
        True if any marker is found in the HTML body.
    """
    if probe_result.status_code != 200:
        return False
    body_lower = probe_result.body_text.lower()
    return any(m.lower() in body_lower for m in vendor_markers)

