"""
bounty.fingerprint.favicon — Favicon hash-based technology detection.

Uses the Shodan/FOFA-compatible murmur3 hash of the base64-encoded favicon body.
Hash DB is loaded once from bounty/fingerprint/data/favicon_db.json.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any, Callable, Coroutine

import mmh3

from bounty.models import Asset, FingerprintResult, ProbeResult

FingerprintCategory = str  # local alias to avoid importing for type checks

# ---------------------------------------------------------------------------
# Favicon DB (module-level cache)
# ---------------------------------------------------------------------------

_DB_PATH = Path(__file__).parent / "data" / "favicon_db.json"
_FAVICON_DB: dict[int, dict[str, Any]] | None = None


def _load_db() -> dict[int, dict[str, Any]]:
    global _FAVICON_DB
    if _FAVICON_DB is None:
        try:
            raw: list[dict[str, Any]] = json.loads(_DB_PATH.read_text())
            _FAVICON_DB = {
                int(entry["hash"]): entry
                for entry in raw
                if entry.get("hash") is not None
            }
        except Exception:  # noqa: BLE001
            _FAVICON_DB = {}
    return _FAVICON_DB


def favicon_hash(body: bytes) -> int:
    """Compute Shodan/FOFA-compatible murmur3 favicon hash."""
    encoded = base64.encodebytes(body)
    return int(mmh3.hash(encoded))


def lookup_favicon_db(hash_val: int) -> FingerprintResult | None:
    """Return a FingerprintResult if the hash matches a known tech, else None."""
    db = _load_db()
    entry = db.get(hash_val)
    if not entry:
        return None
    cat_raw = entry.get("category", "other")
    cat: str = cat_raw if isinstance(cat_raw, str) else "other"
    return FingerprintResult(
        tech=str(entry["tech"]),
        category=cat,  # type: ignore[arg-type]
        confidence="definitive",  # favicon hash match is unmistakable
        evidence=f"favicon:hash={hash_val}",
    )


# ---------------------------------------------------------------------------
# Per-scan favicon URL cache (populated by hash_favicon, keyed by favicon URL)
# ---------------------------------------------------------------------------

_ProbeFn = Callable[[str], Coroutine[Any, Any, ProbeResult]]

_ICON_LINK_RE = re.compile(
    r'<link[^>]+rel=["\'](?:shortcut icon|icon)["\'][^>]+'
    r'href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_ICON_LINK_RE2 = re.compile(
    r'<link[^>]+href=["\']([^"\']+)["\'][^>]+'
    r'rel=["\'](?:shortcut icon|icon)["\']',
    re.IGNORECASE,
)


def _resolve_url(base: str, href: str) -> str:
    """Resolve a potentially relative href against a base URL."""
    if href.startswith("http://") or href.startswith("https://"):
        return href
    if href.startswith("//"):
        scheme = base.split("://")[0]
        return f"{scheme}:{href}"
    if href.startswith("/"):
        # Absolute path — combine with scheme+host
        parts = base.split("/", 3)
        origin = "/".join(parts[:3])  # scheme://host
        return f"{origin}{href}"
    # Relative path
    base_dir = base.rsplit("/", 1)[0]
    return f"{base_dir}/{href}"


async def hash_favicon(
    asset: Asset,
    probe_result: ProbeResult,
    probe_fn: _ProbeFn,
    _cache: dict[str, tuple[int, str]] | None = None,
) -> tuple[int, str] | None:
    """Fetch and hash the favicon for an asset.

    Args:
        asset: The asset being fingerprinted.
        probe_result: The HTTP probe result for the asset's main URL.
        probe_fn: Async callable that takes a URL and returns a ProbeResult.
        _cache: Optional shared dict keyed by favicon URL for dedup within a scan.

    Returns:
        ``(hash, favicon_url)`` on success, ``None`` if favicon not found/empty.
    """
    if _cache is None:
        _cache = {}

    # 1. Search HTML for <link rel="icon"> or <link rel="shortcut icon">
    href: str | None = None
    for rex in (_ICON_LINK_RE, _ICON_LINK_RE2):
        m = rex.search(probe_result.body_text)
        if m:
            href = m.group(1)
            break

    favicon_url: str
    if href:
        favicon_url = _resolve_url(asset.url, href)
    else:
        # 2. Fallback: /favicon.ico
        parts = asset.url.split("/", 3)
        origin = "/".join(parts[:3])
        favicon_url = f"{origin}/favicon.ico"

    # Check cache
    if favicon_url in _cache:
        return _cache[favicon_url]

    # Fetch
    try:
        result = await probe_fn(favicon_url)
    except Exception:  # noqa: BLE001
        return None

    if not result.ok or result.status_code != 200 or not result.body:
        return None

    h = favicon_hash(result.body)
    _cache[favicon_url] = (h, favicon_url)
    return (h, favicon_url)

