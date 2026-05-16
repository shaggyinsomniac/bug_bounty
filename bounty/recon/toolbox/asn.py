"""
bounty.recon.toolbox.asn — ASN / organisation / CIDR lookup via Team Cymru.

Queries whois.cymru.com on TCP port 43 using the bulk whois protocol.
Results are cached per /24 prefix.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from bounty import get_logger

log = get_logger(__name__)

# Cache keyed by /24 prefix string (e.g. "8.8.8")
_CACHE: dict[str, dict[str, Any]] = {}

_CYMRU_HOST = "whois.cymru.com"
_CYMRU_PORT = 43
_CONNECT_TIMEOUT = 10.0
_READ_TIMEOUT = 10.0


def _cidr24(ip: str) -> str:
    """Return the /24 prefix of *ip* (e.g. '8.8.8' for '8.8.8.8')."""
    parts = ip.split(".")
    if len(parts) >= 3:
        return ".".join(parts[:3])
    return ip


async def asn_lookup(ip: str) -> dict[str, Any]:
    """Look up ASN, org, country, and CIDR for *ip* via Cymru whois.

    Results are cached per /24.  Returns an empty dict on failure.

    Args:
        ip: IPv4 address to look up.

    Returns:
        Dict with keys: asn, asn_org, country, cidr.
    """
    prefix = _cidr24(ip)
    if prefix in _CACHE:
        return _CACHE[prefix]

    empty: dict[str, Any] = {"asn": None, "asn_org": None, "country": None, "cidr": None}

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(_CYMRU_HOST, _CYMRU_PORT),
            timeout=_CONNECT_TIMEOUT,
        )
        try:
            query = f"verbose\nbegin\n{ip}\nend\n"
            writer.write(query.encode())
            await writer.drain()

            buf = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=_READ_TIMEOUT)
                    if not chunk:
                        break
                    buf += chunk
            except asyncio.TimeoutError:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

        text = buf.decode("utf-8", errors="replace")
        result = _parse_cymru(text)
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as exc:
        log.warning("asn_lookup_failed", ip=ip, error=str(exc))
        _CACHE[prefix] = empty
        return empty
    except Exception as exc:  # noqa: BLE001
        log.warning("asn_lookup_error", ip=ip, error=str(exc))
        _CACHE[prefix] = empty
        return empty

    _CACHE[prefix] = result
    return result


def _parse_cymru(text: str) -> dict[str, Any]:
    """Parse Cymru bulk whois verbose output.

    The verbose format looks like:
        AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
        15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2000-03-30 | GOOGLE - Google LLC, US
    """
    result: dict[str, Any] = {"asn": None, "asn_org": None, "country": None, "cidr": None}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("AS") or line.startswith("Bulk") or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 7:
            asn_raw = parts[0].strip()
            cidr_raw = parts[2].strip()
            cc_raw = parts[3].strip()
            org_raw = parts[6].strip() if len(parts) > 6 else ""

            # Clean ASN (remove "AS" prefix if present)
            asn = re.sub(r"^AS", "", asn_raw, flags=re.IGNORECASE)
            result["asn"] = asn if asn else None
            result["cidr"] = cidr_raw or None
            result["country"] = cc_raw or None
            result["asn_org"] = org_raw or None
            break

    return result


def clear_cache() -> None:
    """Clear the in-memory ASN cache (useful for tests)."""
    _CACHE.clear()

