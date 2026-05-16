"""
bounty.recon.toolbox.reverse_dns — PTR lookups for IP addresses.

Uses dnspython's async resolver to perform reverse DNS resolution.
"""

from __future__ import annotations

import ipaddress

import dns.asyncresolver
import dns.exception
import dns.reversename

from bounty import get_logger

log = get_logger(__name__)

_TIMEOUT = 5.0


async def reverse_dns(ip: str) -> str | None:
    """Resolve *ip* to its PTR hostname.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        The PTR hostname (trailing dot stripped) or ``None`` if not found
        or on error.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        log.debug("reverse_dns_invalid_ip", ip=ip)
        return None

    try:
        rev_name = dns.reversename.from_address(str(addr))
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = _TIMEOUT
        answer = await resolver.resolve(rev_name, "PTR")
        for rdata in answer:
            hostname: str = str(rdata.target).rstrip(".")
            return hostname
    except (dns.exception.DNSException, OSError) as exc:
        log.debug("reverse_dns_nxdomain", ip=ip, error=str(exc))
    except Exception as exc:  # noqa: BLE001
        log.debug("reverse_dns_error", ip=ip, error=str(exc))

    return None

