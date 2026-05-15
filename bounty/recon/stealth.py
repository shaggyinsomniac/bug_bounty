"""
bounty.recon.stealth — UA rotation, request jitter, and WAF block detection.

Utilities that make scanner traffic look more like organic browser traffic so
cloud-hosted IPs are less likely to be rate-limited or permanently blocked.

Key design decisions
--------------------
- ``get_rotating_ua(host)`` derives a UA deterministically (MD5 hash) so a
  single host always sees the same browser string across the scan run, while
  different hosts see different UAs.  This avoids the "same UA keeps changing"
  heuristic that some WAFs use.

- ``jitter(base_delay)`` adds ±30% random variance to prevent the robotic
  fixed-interval timing pattern that fingerprints automated scanners.

- ``is_waf_block_response(status_code, body)`` is a best-effort heuristic and
  intentionally has some false-positive tolerance: it requires EITHER a WAF
  status code AND a body marker, OR a high-confidence body marker alone.
  Plain 403s without WAF body markers do NOT trigger the flag.
"""

from __future__ import annotations

import hashlib
import random

# ---------------------------------------------------------------------------
# UA pool — ~10 realistic current browser strings (Chrome/Firefox/Safari,
# Win/Mac/Linux/Android/iPhone).  Updated to 2024 versions.
# ---------------------------------------------------------------------------

USER_AGENTS: list[str] = [
    # Chrome 124 – Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    # Chrome 124 – macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    # Chrome 124 – Linux
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    # Firefox 125 – Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    # Firefox 125 – macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    # Firefox 125 – Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    # Safari 17 – macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4.1 Safari/605.1.15",
    # Safari 17 – iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4.1 Mobile/15E148 Safari/604.1",
    # Edge 124 – Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Chrome 124 – Android / Pixel 8
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.60 Mobile Safari/537.36",
]

# ---------------------------------------------------------------------------
# WAF detection markers
# ---------------------------------------------------------------------------

# Body substrings (lowercased) that indicate a WAF block page.
WAF_BODY_MARKERS: list[str] = [
    "attention required",
    "access denied",
    "request blocked",
    "cloudflare",
    "akamai",
    "captcha",
    "are you a robot",
    "bot detection",
    "ddos protection",
    "incapsula",
    "sucuri",
    "mod_security",
    "web application firewall",
    "__cf_chl",   # Cloudflare challenge JS variable
    "ray id",     # Cloudflare Ray ID footer
]

# Markers so specific that their presence alone (regardless of status code)
# is high-confidence evidence of a WAF block page.
_HIGH_CONF_MARKERS: list[str] = [
    "__cf_chl",
    "ray id",
    "incapsula",
    "are you a robot",
]

# HTTP status codes that indicate throttling/blocking (when combined with body).
WAF_STATUS_CODES: frozenset[int] = frozenset({403, 429, 503})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_rotating_ua(host: str) -> str:
    """Return a deterministic UA string for *host*.

    The same host always maps to the same UA (consistent browser identity),
    but different hosts map to different UAs (varied fingerprint across targets).

    Args:
        host: Bare hostname (no scheme/port).

    Returns:
        A realistic browser User-Agent string.
    """
    digest = int(hashlib.md5(host.encode(), usedforsecurity=False).hexdigest(), 16)
    return USER_AGENTS[digest % len(USER_AGENTS)]


def jitter(base_delay: float) -> float:
    """Apply ±30% uniformly-random jitter to *base_delay*.

    If *base_delay* is zero or negative the function returns 0.0 (no sleep).

    Args:
        base_delay: Base inter-request delay in seconds.

    Returns:
        Jittered delay in the range ``[base_delay * 0.7, base_delay * 1.3]``.
    """
    if base_delay <= 0:
        return 0.0
    return base_delay * random.uniform(0.7, 1.3)


def is_waf_block_response(status_code: int, body: str) -> bool:
    """Heuristic WAF block detection.

    Returns ``True`` when the response looks like a WAF interception page.

    Logic:
    1. If a WAF-status-code (403/429/503) AND a body marker → True.
    2. If any high-confidence marker is present in the body → True (even on 200).
    3. Otherwise → False.  Plain 403s without WAF body markers are *not* flagged.

    Args:
        status_code: HTTP response status code.
        body:        Response body as a (possibly truncated) UTF-8 string.

    Returns:
        ``True`` if the response is likely a WAF block page.
    """
    body_lower = body.lower()
    has_any_marker = any(m in body_lower for m in WAF_BODY_MARKERS)

    if status_code in WAF_STATUS_CODES and has_any_marker:
        return True

    if any(m in body_lower for m in _HIGH_CONF_MARKERS):
        return True

    return False

