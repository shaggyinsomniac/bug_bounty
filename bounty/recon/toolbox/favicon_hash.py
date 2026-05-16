"""
bounty.recon.toolbox.favicon_hash — Shodan-style MurmurHash3 of /favicon.ico.

The hash is computed identically to Shodan's favicon hashing:
  1. Fetch /favicon.ico
  2. Base64-encode the raw bytes (standard alphabet, with newlines every 76
     chars as Python's base64.encodebytes produces)
  3. Apply mmh3.hash() (signed 32-bit MurmurHash3) to the base64 string

The result is an integer converted to a string — matching the value you
would search for on Shodan with ``http.favicon.hash:<n>``.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
import mmh3

from bounty import get_logger

log = get_logger(__name__)

_TIMEOUT = 10.0
_MAX_BYTES = 256 * 1024  # 256 KiB


async def favicon_hash(url: str) -> str | None:
    """Fetch /favicon.ico from *url* and return the Shodan-style mmh3 hash.

    Args:
        url: Base URL (scheme + host, e.g. "https://example.com").

    Returns:
        String representation of the signed 32-bit MurmurHash3 of the
        base64-encoded favicon bytes, or ``None`` on failure.
    """
    # Normalise URL: strip trailing slash, append /favicon.ico
    base = url.rstrip("/")
    favicon_url = f"{base}/favicon.ico"

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=_TIMEOUT,
            verify=False,  # consistent with rest of scanner
        ) as client:
            resp = await client.get(favicon_url)
            if resp.status_code != 200:
                log.debug("favicon_not_found", url=favicon_url, status=resp.status_code)
                return None
            raw: bytes = resp.content[:_MAX_BYTES]
    except (httpx.HTTPError, OSError) as exc:
        log.debug("favicon_fetch_error", url=favicon_url, error=str(exc))
        return None

    if not raw:
        return None

    # Shodan-compatible: base64 with newlines (encodebytes), then mmh3
    b64: bytes = base64.encodebytes(raw)
    b64_str: str = b64.decode("utf-8")
    h: int = mmh3.hash(b64_str)
    return str(h)

