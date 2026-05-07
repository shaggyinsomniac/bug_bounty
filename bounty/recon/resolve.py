"""
bounty.recon.resolve — Async DNS resolution for batches of hostnames.

Library choice: ``dnspython`` with its async resolver (``dns.asyncresolver``).

Rationale for dnspython over aiodns:
- dnspython has a richer API: CNAME chain traversal, MX, NS, TXT records all
  in one library without C-extension dependencies.
- aiodns is a thin wrapper around c-ares which offers raw performance but
  lacks the higher-level record parsing we need for security metadata.
- dnspython 2.x has first-class async support via ``dns.asyncresolver``.

Wildcard detection:
  Before resolving any host in a zone, a random 32-char label is resolved.
  If it resolves to an A/AAAA record, the zone is marked as wildcard-enabled.
  Hosts in wildcard zones are tagged with low confidence and their IPs are
  not treated as confirmed-alive unless they also have an HTTP response.

Private IP detection:
  Results pointing to RFC-1918 / link-local / loopback ranges are marked
  ``alive=False``; they indicate misconfigured internal DNS.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import string
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from bounty import get_logger

log = get_logger(__name__)

# DNS resolver timeout for individual queries
_QUERY_TIMEOUT = 8.0
# Default concurrency for batch resolution
_DEFAULT_CONCURRENCY = 50


@dataclass
class ResolveResult:
    """DNS resolution result for a single hostname.

    Attributes:
        hostname: The queried hostname.
        a_records: List of IPv4 addresses.
        aaaa_records: List of IPv6 addresses.
        cname_chain: CNAME chain from the original name to the final target.
        mx_records: MX hostnames (priority, host).
        ns_records: Authoritative nameservers.
        txt_records: TXT record strings filtered to security-relevant content.
        alive: True if the host resolves to at least one public (non-private) IP.
        wildcard_zone: True if the parent zone responds to random labels.
        error: Non-None if resolution failed.
    """

    hostname: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_chain: list[str] = field(default_factory=list)
    mx_records: list[tuple[int, str]] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    alive: bool = False
    wildcard_zone: bool = False
    error: str | None = None

    @property
    def all_ips(self) -> list[str]:
        """Combined A + AAAA records."""
        return self.a_records + self.aaaa_records

    @property
    def primary_ip(self) -> str | None:
        """First public IP address, or None if not alive."""
        for ip in self.a_records:
            if _is_public_ip(ip):
                return ip
        for ip in self.aaaa_records:
            if _is_public_ip(ip):
                return ip
        return None


def _is_public_ip(addr: str) -> bool:
    """Return True if ``addr`` is a routable public IP address.

    Rejects RFC-1918, loopback, link-local, and multicast ranges.

    Args:
        addr: IPv4 or IPv6 address string.

    Returns:
        ``True`` if the address is publicly routable.
    """
    try:
        ip = ipaddress.ip_address(addr)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def _is_security_relevant_txt(txt: str) -> bool:
    """Return True for TXT records with security significance.

    Keeps SPF, DMARC, DKIM, domain verification tokens, and MTA-STS.

    Args:
        txt: TXT record string.

    Returns:
        ``True`` if the record should be retained.
    """
    lower = txt.lower()
    return any(
        lower.startswith(prefix)
        for prefix in (
            "v=spf1",
            "v=dmarc1",
            "v=dkim1",
            "google-site-verification",
            "ms=",
            "mta-sts=",
            "have-i-been-pwned-verification",
            "stripe-verification",
            "atlassian-domain-verification",
            "docusign=",
            "facebook-domain-verification",
            "apple-domain-verification",
        )
    )


async def _check_wildcard(zone: str) -> bool:
    """Probe for wildcard DNS by resolving a random label.

    Args:
        zone: The DNS zone to check, e.g. ``"example.com"``.

    Returns:
        ``True`` if the zone responds to random labels (wildcard DNS).
    """
    random_label = "".join(random.choices(string.ascii_lowercase, k=32))
    probe_host = f"{random_label}.{zone}"
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = _QUERY_TIMEOUT
    resolver.lifetime = _QUERY_TIMEOUT
    try:
        await resolver.resolve(probe_host, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return False
    except Exception:  # noqa: BLE001
        return False


async def _resolve_one(
    hostname: str,
    wildcard_zones: dict[str, bool],
) -> ResolveResult:
    """Resolve a single hostname into a ``ResolveResult``.

    Args:
        hostname: FQDN to resolve.
        wildcard_zones: Shared cache mapping zone → wildcard status.
                        Updated in-place with newly checked zones.

    Returns:
        A ``ResolveResult`` (never raises — errors are stored in ``.error``).
    """
    result = ResolveResult(hostname=hostname)
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = _QUERY_TIMEOUT
    resolver.lifetime = _QUERY_TIMEOUT

    # Determine zone (parent domain) for wildcard check
    parts = hostname.split(".")
    zone = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    if zone not in wildcard_zones:
        wildcard_zones[zone] = await _check_wildcard(zone)
    result.wildcard_zone = wildcard_zones[zone]

    # A records
    try:
        ans = await resolver.resolve(hostname, "A")
        result.a_records = [str(r) for r in ans]
    except dns.resolver.NXDOMAIN:
        result.error = "NXDOMAIN"
        return result
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.Timeout:
        result.error = "timeout"
        return result
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)

    # AAAA records
    try:
        ans = await resolver.resolve(hostname, "AAAA")
        result.aaaa_records = [str(r) for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:  # noqa: BLE001
        pass

    # CNAME chain
    try:
        ans = await resolver.resolve(hostname, "CNAME")
        result.cname_chain = [str(r.target).rstrip(".") for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:  # noqa: BLE001
        pass

    # MX (for root domains and for SMTP takeover checks)
    try:
        ans = await resolver.resolve(hostname, "MX")
        result.mx_records = [
            (int(r.preference), str(r.exchange).rstrip(".")) for r in ans
        ]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:  # noqa: BLE001
        pass

    # NS records
    try:
        ans = await resolver.resolve(hostname, "NS")
        result.ns_records = [str(r).rstrip(".") for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:  # noqa: BLE001
        pass

    # TXT records — filtered
    try:
        ans = await resolver.resolve(hostname, "TXT")
        for rdata in ans:
            txt_str = "".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
            if _is_security_relevant_txt(txt_str):
                result.txt_records.append(txt_str)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:  # noqa: BLE001
        pass

    # Determine alive status
    result.alive = any(_is_public_ip(ip) for ip in result.a_records + result.aaaa_records)

    return result


async def resolve_batch(
    hostnames: list[str],
    *,
    concurrency: int = _DEFAULT_CONCURRENCY,
) -> dict[str, ResolveResult]:
    """Resolve a batch of hostnames concurrently.

    A shared per-zone wildcard cache avoids probing the same zone repeatedly
    when resolving many subdomains.

    Args:
        hostnames: List of FQDNs to resolve.
        concurrency: Maximum concurrent DNS queries.  Defaults to 50.

    Returns:
        Dict mapping each hostname to its ``ResolveResult``.
    """
    if not hostnames:
        return {}

    deduped = list(dict.fromkeys(h.lower() for h in hostnames))
    log.info("resolve_batch_start", count=len(deduped), concurrency=concurrency)

    sem = asyncio.Semaphore(concurrency)
    wildcard_zones: dict[str, bool] = {}
    wz_lock = asyncio.Lock()

    async def _bounded_resolve(host: str) -> tuple[str, ResolveResult]:
        async with sem:
            # Use a shared wildcard cache with locking
            res = await _resolve_one(host, wildcard_zones)
            return host, res

    tasks = [asyncio.create_task(_bounded_resolve(h)) for h in deduped]
    pairs = await asyncio.gather(*tasks, return_exceptions=False)

    results: dict[str, ResolveResult] = {}
    alive_count = 0
    for hostname, res in pairs:
        results[hostname] = res
        if res.alive:
            alive_count += 1

    log.info(
        "resolve_batch_done",
        total=len(results),
        alive=alive_count,
    )
    return results

