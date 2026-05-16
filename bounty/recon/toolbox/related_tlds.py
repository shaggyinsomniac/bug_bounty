"""
bounty.recon.toolbox.related_tlds — Find TLD variants that resolve for a domain.

Takes a bare domain label (e.g. "example") or full domain (e.g. "example.com")
and checks ~30 common TLDs via DNS A/AAAA resolution.

Resolving variants are returned as informational asset candidates.
"""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception

from bounty import get_logger

log = get_logger(__name__)

_COMMON_TLDS = [
    "com", "net", "org", "io", "co", "dev", "app", "ai",
    "xyz", "info", "biz", "us", "uk", "co.uk", "ca", "de",
    "fr", "nl", "eu", "au", "com.au", "in", "co.in", "jp",
    "br", "com.br", "ru", "ch", "se", "me",
]

_RESOLVE_TIMEOUT = 5.0
_CONCURRENCY = 20


async def _resolves(fqdn: str) -> bool:
    """Return True if *fqdn* resolves to at least one A or AAAA record."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = _RESOLVE_TIMEOUT
    for rrtype in ("A", "AAAA"):
        try:
            await resolver.resolve(fqdn, rrtype)
            return True
        except (dns.exception.DNSException, OSError):
            pass
    return False


def _apex_label(domain: str) -> str:
    """Extract the bare label from a domain for TLD substitution.

    Examples:
        "example.com"  → "example"
        "example"      → "example"
        "sub.example.com" → "example"
    """
    parts = domain.strip().lower().lstrip("*.").split(".")
    # Take the second-to-last component as the apex label
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


async def find_related_tlds(domain: str) -> list[str]:
    """Find TLD variants of *domain* that resolve via DNS.

    Args:
        domain: Domain name (with or without TLD) or bare label.

    Returns:
        Sorted list of FQDNs (e.g. ["example.io", "example.net"]) that
        have at least one DNS A/AAAA record.  Does NOT include the original
        domain itself.
    """
    label = _apex_label(domain)
    if not label:
        return []

    # Determine original TLD to skip it
    parts = domain.strip().lower().split(".")
    original_tld = ".".join(parts[1:]) if len(parts) >= 2 else ""

    sem = asyncio.Semaphore(_CONCURRENCY)
    resolving: list[str] = []

    async def _check(tld: str) -> None:
        if tld == original_tld:
            return
        fqdn = f"{label}.{tld}"
        async with sem:
            try:
                if await _resolves(fqdn):
                    resolving.append(fqdn)
            except Exception as exc:  # noqa: BLE001
                log.debug("related_tld_check_error", fqdn=fqdn, error=str(exc))

    await asyncio.gather(*[_check(tld) for tld in _COMMON_TLDS])
    return sorted(resolving)

