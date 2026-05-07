"""
bounty.intel.cache — file-based JSON cache for Shodan / intel API results.

Cache keys are SHA-256 hashes of the query string (or IP address for host
lookups).  Each entry is stored as a ``.json`` file under
``settings.intel_cache_dir``.  Entries older than ``settings.intel_cache_ttl_days``
days are considered expired and return ``None`` on read.

Usage::

    cache = IntelCache(settings.intel_cache_dir, settings.intel_cache_ttl_days)
    data = cache.get("my-query")
    if data is None:
        data = await fetch_from_api(...)
        cache.put("my-query", data)
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from bounty import get_logger

log = get_logger(__name__)


class IntelCache:
    """Simple file-backed JSON cache with a time-to-live.

    Args:
        cache_dir: Directory where ``.json`` cache files are stored.
        ttl_days:  Number of days before an entry is considered stale.
    """

    def __init__(self, cache_dir: Path, ttl_days: int = 7) -> None:
        self._cache_dir = cache_dir
        self._ttl_seconds = ttl_days * 86_400
        cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _path(self, key: str) -> Path:
        """Return the file path for *key*, hashing to avoid FS restrictions."""
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self._cache_dir / f"{digest}.json"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str) -> dict[str, Any] | None:
        """Return cached data for *key*, or ``None`` if missing / expired.

        Args:
            key: Cache key (query string, IP address, etc.).

        Returns:
            Cached JSON object or ``None``.
        """
        p = self._path(key)
        if not p.exists():
            return None
        try:
            age = time.time() - p.stat().st_mtime
            if age > self._ttl_seconds:
                log.debug(
                    "cache_expired",
                    key_prefix=key[:32],
                    age_hours=round(age / 3600, 1),
                )
                return None
            return dict(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            log.warning("cache_read_failed", key_prefix=key[:32], error=str(exc))
            return None

    def put(self, key: str, data: dict[str, Any]) -> None:
        """Write *data* to the cache for *key* (atomic rename).

        Args:
            key:  Cache key.
            data: JSON-serialisable dictionary to store.
        """
        p = self._path(key)
        tmp = p.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.rename(p)
        except OSError as exc:
            log.warning("cache_write_failed", key_prefix=key[:32], error=str(exc))

    def invalidate(self, key: str) -> None:
        """Delete the cache entry for *key* if it exists.

        Args:
            key: Cache key to remove.
        """
        p = self._path(key)
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass

