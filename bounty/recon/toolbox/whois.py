"""
bounty.recon.toolbox.whois — WHOIS lookup for domains.

Uses python-whois if installed; falls back to subprocess ``whois``.
Results are cached in-memory per domain for the lifetime of the process.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from datetime import datetime
from typing import Any

from bounty import get_logger

log = get_logger(__name__)

# In-memory cache: domain → result dict
_CACHE: dict[str, dict[str, Any]] = {}


def _parse_whois_obj(w: Any) -> dict[str, Any]:
    """Convert a python-whois WhoisEntry to a plain dict."""

    def _dt(v: object) -> str | None:
        if isinstance(v, list):
            v = v[0] if v else None
        if isinstance(v, datetime):
            return v.strftime("%Y-%m-%dT%H:%M:%SZ")
        if isinstance(v, str):
            return v
        return None

    def _list_of_str(v: object) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v if x]
        return []

    return {
        "registrar": getattr(w, "registrar", None) or None,
        "created": _dt(getattr(w, "creation_date", None)),
        "expires": _dt(getattr(w, "expiration_date", None)),
        "name_servers": _list_of_str(getattr(w, "name_servers", None)),
        "registrant_org": getattr(w, "org", None) or None,
        "emails": _list_of_str(getattr(w, "emails", None)),
        "abuse_contact": None,
    }


def _parse_whois_text(text: str, domain: str) -> dict[str, Any]:
    """Parse raw WHOIS text into a structured dict (best-effort)."""
    result: dict[str, Any] = {
        "registrar": None,
        "created": None,
        "expires": None,
        "name_servers": [],
        "registrant_org": None,
        "emails": [],
        "abuse_contact": None,
    }
    ns: list[str] = []
    emails: list[str] = []

    import re

    for line in text.splitlines():
        low = line.lower().strip()
        val = line.split(":", 1)[1].strip() if ":" in line else ""

        if low.startswith("registrar:") and not result["registrar"]:
            result["registrar"] = val or None
        elif low.startswith("creation date:") and not result["created"]:
            result["created"] = val or None
        elif low.startswith("registrar registration expiration date:") and not result["expires"]:
            result["expires"] = val or None
        elif low.startswith("registry expiry date:") and not result["expires"]:
            result["expires"] = val or None
        elif low.startswith("expiry date:") and not result["expires"]:
            result["expires"] = val or None
        elif low.startswith("name server:") and val:
            ns.append(val.lower())
        elif low.startswith("registrant organization:") and not result["registrant_org"]:
            result["registrant_org"] = val or None
        elif low.startswith("abuse contact email:") and val:
            result["abuse_contact"] = val

        # Collect emails
        for m in re.findall(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", line, re.IGNORECASE):
            if m not in emails:
                emails.append(m)

    result["name_servers"] = list(dict.fromkeys(ns))
    result["emails"] = emails
    return result


async def whois_lookup(domain: str) -> dict[str, Any]:
    """Perform a WHOIS lookup for *domain*.

    Tries python-whois first; falls back to subprocess ``whois``.
    Results are cached per-process (in-memory).

    Args:
        domain: Apex or sub-domain to look up.

    Returns:
        Dict with keys: registrar, created, expires, name_servers,
        registrant_org, emails, abuse_contact.
    """
    apex = domain.lstrip("*.").lower()
    if apex in _CACHE:
        return _CACHE[apex]

    result: dict[str, Any] = {
        "registrar": None,
        "created": None,
        "expires": None,
        "name_servers": [],
        "registrant_org": None,
        "emails": [],
        "abuse_contact": None,
    }

    # ── Try python-whois ─────────────────────────────────────────────────────
    try:
        import whois as _whois  # type: ignore[import-untyped]

        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, _whois.whois, apex)
        result = _parse_whois_obj(w)
        log.debug("whois_lookup_python_whois", domain=apex)
    except ImportError:
        # No python-whois — fall back to subprocess
        try:
            proc = await asyncio.create_subprocess_exec(
                "whois", apex,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            text = stdout.decode("utf-8", errors="replace")
            result = _parse_whois_text(text, apex)
            log.debug("whois_lookup_subprocess", domain=apex)
        except (FileNotFoundError, asyncio.TimeoutError, OSError) as exc:
            log.warning("whois_lookup_failed", domain=apex, error=str(exc))
    except Exception as exc:  # noqa: BLE001
        log.warning("whois_lookup_error", domain=apex, error=str(exc))

    _CACHE[apex] = result
    return result


def clear_cache() -> None:
    """Clear the in-memory whois cache (useful for tests)."""
    _CACHE.clear()

