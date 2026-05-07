"""
bounty.recon.ip_ranges — IPv4/CIDR/ASN expansion and IP classification helpers.

Public API:
  expand_cidr(cidr)   — expand an IPv4 CIDR to individual host IP strings.
  expand_asn(asn)     — fetch IPv4 CIDR prefixes announced by an ASN via BGPView.
  is_internal_ip(ip)  — return True for RFC-1918 / loopback / link-local addresses.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import httpx

from bounty import get_logger
from bounty.config import get_settings

log = get_logger(__name__)

_BGPVIEW_URL = "https://api.bgpview.io/asn/{asn}/prefixes"
_BGPVIEW_RETRIES = 3
_BGPVIEW_BACKOFF = (1.0, 2.0, 4.0)


async def expand_cidr(cidr: str) -> list[str]:
    """Expand an IPv4 CIDR block to individual host IP strings.

    Enforces a minimum prefix length configured via ``settings.cidr_max_size``
    (default ``16``).  Any CIDR with a prefix length *smaller* than that value
    (e.g. /15, /8) is refused with ``ValueError`` to prevent accidentally
    enumerating millions of hosts.

    For prefixes >= /31 (RFC 3021 point-to-point), all addresses are returned.
    For wider prefixes the network and broadcast addresses are excluded.

    IPv6 CIDRs are not supported and raise ``NotImplementedError``.

    Args:
        cidr: CIDR notation string, e.g. ``"203.0.113.0/24"``.

    Returns:
        List of IP address strings in the CIDR range.

    Raises:
        ValueError:         Invalid CIDR or prefix too large (too few bits).
        NotImplementedError: IPv6 CIDR expansion is not supported.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR {cidr!r}: {exc}") from exc

    if isinstance(net, ipaddress.IPv6Network):
        raise NotImplementedError(f"IPv6 CIDR expansion not supported: {cidr!r}")

    settings = get_settings()
    min_prefix = settings.cidr_max_size  # default 16 — refuse /15 and below

    if net.prefixlen < min_prefix:
        raise ValueError(
            f"CIDR {cidr!r} has prefix /{net.prefixlen} which is larger than the "
            f"configured minimum /{min_prefix} (would produce {net.num_addresses:,} addresses). "
            f"Set CIDR_MAX_SIZE to a lower number to allow this."
        )

    # /31 and /32: include all addresses (RFC 3021); others: exclude net + broadcast
    if net.prefixlen >= 31:
        return [str(addr) for addr in net]
    return [str(host) for host in net.hosts()]


async def expand_asn(asn: str) -> list[str]:
    """Return a list of IPv4 CIDR prefix strings announced by the given ASN.

    Queries the BGPView API (https://api.bgpview.io/asn/{N}/prefixes).
    Strips a leading "AS" or "as" prefix from the input.
    Retries up to three times with exponential backoff on transient errors.
    Returns an empty list (and logs a warning) on persistent failure.

    Args:
        asn: ASN string, e.g. ``"AS15169"`` or ``"15169"``.

    Returns:
        List of IPv4 CIDR prefix strings, e.g. ``["8.8.8.0/24", ...]``.

    Raises:
        ValueError: If the ASN string is not a valid integer after normalisation.
    """
    settings = get_settings()
    timeout = settings.asn_resolve_timeout

    # Normalise: strip AS / as prefix, then validate digits
    asn_digits = asn.strip().upper().lstrip("AS")
    if not asn_digits.isdigit():
        raise ValueError(
            f"Invalid ASN {asn!r}: expected 'AS12345' or '12345' (only digits after AS prefix)"
        )

    url = _BGPVIEW_URL.format(asn=asn_digits)
    bound_log = log.bind(asn=asn, url=url)
    bound_log.debug("expand_asn_start")

    for attempt in range(_BGPVIEW_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers={"Accept": "application/json"})
                resp.raise_for_status()
                data: dict[str, Any] = resp.json()

            raw_block: Any = data.get("data") or {}
            raw_prefixes: list[Any] = (raw_block.get("ipv4_prefixes") or []) if isinstance(raw_block, dict) else []
            prefixes: list[str] = [
                str(p["prefix"])
                for p in raw_prefixes
                if isinstance(p, dict) and p.get("prefix")
            ]
            bound_log.info("expand_asn_done", prefixes=len(prefixes))
            return prefixes

        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            if attempt < _BGPVIEW_RETRIES - 1:
                delay = _BGPVIEW_BACKOFF[attempt]
                bound_log.debug("expand_asn_retry", attempt=attempt + 1, delay=delay, error=str(exc))
                await asyncio.sleep(delay)
            else:
                bound_log.warning("expand_asn_timeout_final", error=str(exc))
        except httpx.HTTPStatusError as exc:
            bound_log.warning("expand_asn_http_error", status=exc.response.status_code)
            break
        except Exception as exc:  # noqa: BLE001
            bound_log.warning("expand_asn_unexpected_error", error=str(exc))
            break

    return []


def is_internal_ip(ip: str) -> bool:
    """Return True if the address is non-routable (RFC-1918, loopback, link-local, etc.).

    Uses Python's ``ipaddress`` stdlib.  Covers:
    - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
    - 127.0.0.0/8 (loopback)
    - 169.254.0.0/16 (link-local)
    - And all other ranges Python marks as private / reserved / multicast.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        ``True`` if the address is non-routable, ``False`` if publicly routable.
        Returns ``False`` for invalid input (safe default).
    """
    try:
        addr = ipaddress.ip_address(ip)
        return bool(
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return False

