"""
bounty.detect.exposed_files._common — Shared validation helpers.

These utilities prevent false positives that are the #1 source of noise in
path-based detections.  The two main problems they solve:

1. Soft-404 sites: modern SPAs return 200 + HTML for every unknown path.
   ``soft_404_check()`` probes a random path first; if that also returns 200
   we skip all path-based checks on this asset.

2. HTML catch-all routes: some servers return 200 + the homepage HTML for
   any unknown path, even for non-SPA sites.
   ``is_real_file_response()`` validates that the body actually contains one
   of the expected file signatures and is not merely an HTML page wrapper.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable

from bounty.models import Asset, ProbeResult

# Common SPA / framework HTML markers that indicate a catch-all fallback page.
_HTML_FALLBACK_PATTERNS: tuple[bytes, ...] = (
    b"<!DOCTYPE html>",
    b"<!doctype html>",
    b"<html",
    b"<HTML",
)

# Minimum body length to consider a response non-trivial.
_MIN_BODY_BYTES = 10

# Random path used for soft-404 detection (unlikely to be a real path).
_SOFT_404_PROBE_SUFFIX = "/bounty-soft404-probe-xj7k9m3p"


def is_real_file_response(
    probe_result: ProbeResult,
    expected_signatures: list[bytes],
    *,
    allow_html: bool = False,
) -> bool:
    """Return True if ``probe_result`` looks like a real file, not a fallback.

    Checks (all must pass):
    1. Status code is 200.
    2. Body is at least ``_MIN_BODY_BYTES`` bytes.
    3. Body contains at least one of ``expected_signatures``.
    4. If ``allow_html=False``, body must NOT start with an HTML DOCTYPE/tag
       (catches catch-all SPA routes).

    Args:
        probe_result: The HTTP probe response to validate.
        expected_signatures: List of byte strings at least one of which must
            appear in the body.
        allow_html: Set True for detections that legitimately expect HTML
            responses (e.g. /.gitlab-ci.yml content check).

    Returns:
        True if the response looks like a genuine file, False otherwise.
    """
    if probe_result.status_code != 200:
        return False

    body = probe_result.body
    if len(body) < _MIN_BODY_BYTES:
        return False

    # Reject HTML catch-all pages unless we explicitly allow them.
    if not allow_html:
        body_start = body[:200].lower()
        for pattern in _HTML_FALLBACK_PATTERNS:
            if pattern.lower() in body_start:
                return False

    # At least one expected content signature must be present in the body.
    return any(sig in body for sig in expected_signatures)


async def soft_404_check(
    asset: Asset,
    probe_fn: Callable[[str], Awaitable[ProbeResult]],
) -> bool:
    """Return True if this asset has a catch-all route that returns 200.

    Technique: probe a random path that almost certainly does not exist on
    any real site.  If the server responds with 200 + non-trivial body, the
    site is a soft-404 site and path-based detections should be skipped.

    Args:
        asset: The asset to test.
        probe_fn: HTTP probe callable.

    Returns:
        True if the site appears to be a soft-404 site.
    """
    url = asset.url.rstrip("/") + _SOFT_404_PROBE_SUFFIX
    try:
        result = await probe_fn(url)
    except Exception:  # noqa: BLE001
        return False  # Assume real 404 behaviour on probe failure

    if result.status_code != 200:
        return False

    # Body must be non-trivial (not just an empty 200).
    return len(result.body) >= 200


def _has_credential_markers(body: bytes) -> bool:
    """Return True if the body contains strings that look like real secrets."""
    patterns = [
        rb"AWS_",
        rb"STRIPE_",
        rb"DB_PASSWORD",
        rb"DB_PASS",
        rb"SECRET_KEY",
        rb"SECRET=",
        rb"PASSWORD=",
        rb"API_KEY=",
        rb"TOKEN=",
        rb"PRIVATE_KEY",
        rb"BEGIN.*PRIVATE KEY",
        rb"password\s*[:=]",
        rb"secret\s*[:=]",
    ]
    for pat in patterns:
        if re.search(pat, body, re.IGNORECASE):
            return True
    return False

