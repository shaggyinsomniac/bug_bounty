"""
bounty.detect.dns.zone_transfer — DNS zone transfer (AXFR) detection.

For the asset's apex domain, queries NS records then attempts an AXFR against
each nameserver.  If AXFR succeeds (returns zone data) → finding, severity 700.
Uses dnspython exclusively; runs the blocking dns.query.xfr in a thread pool.
Runs at most once per apex domain via ctx.claim_apex.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections.abc import AsyncGenerator

import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from bounty.detect.base import Detection, DetectionContext
from bounty.detect.mail.mail_config import _apex_domain
from bounty.models import Asset, FindingDraft, FingerprintResult, ProbeResult

__all__ = ["ZoneTransferAllowed"]

_DEDUP_CATEGORY = "dns"
_AXFR_TIMEOUT = 5.0  # seconds


def _sync_axfr(ns_host: str, domain: str) -> bool:
    """Attempt AXFR against *ns_host* for *domain* (synchronous, run in executor).

    Returns True if the zone transfer succeeds and the zone contains nodes.
    """
    try:
        xfr_gen = dns.query.xfr(
            ns_host,
            domain,
            timeout=_AXFR_TIMEOUT,
            lifetime=_AXFR_TIMEOUT * 2,
        )
        zone = dns.zone.from_xfr(xfr_gen)
        return len(list(zone.nodes.keys())) > 0
    except Exception:  # noqa: BLE001
        return False


async def _check_axfr(ns_host: str, domain: str) -> bool:
    """Async wrapper that runs _sync_axfr in a thread pool."""
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return await loop.run_in_executor(pool, _sync_axfr, ns_host, domain)


async def _get_nameservers(apex: str) -> list[str]:
    """Return the nameserver hostnames for *apex*."""
    try:
        answers = await dns.asyncresolver.resolve(apex, "NS")
        return [str(rdata.target).rstrip(".")
                for rdata in answers]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        return []


class ZoneTransferAllowed(Detection):
    """DNS zone transfer (AXFR) allowed — reveals entire DNS zone."""

    id = "dns.zone_transfer_allowed"
    name = "DNS Zone Transfer Allowed (AXFR)"
    category = "dns_misconfiguration"
    severity_default = 700
    cwe = "CWE-200"
    tags = ("dns", "axfr", "zone-transfer", "recon")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        # Run for any HTTP asset (port 80/443) once per apex
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        apex = _apex_domain(asset.host)
        if not ctx.claim_apex(_DEDUP_CATEGORY, apex):
            return

        nameservers = await _get_nameservers(apex)
        if not nameservers:
            return

        vulnerable_ns: list[str] = []
        for ns in nameservers:
            try:
                success = await _check_axfr(ns, apex)
            except Exception:  # noqa: BLE001
                continue
            if success:
                vulnerable_ns.append(ns)

        if not vulnerable_ns:
            return

        # Build a synthetic ProbeResult for evidence capture
        ns_list = ", ".join(vulnerable_ns)
        fake_pr = ProbeResult(
            url=f"dns://{apex}/AXFR",
            final_url=f"dns://{apex}/AXFR",
            status_code=200,
            headers={},
            body=f"AXFR succeeded from: {ns_list}".encode(),
            body_text=f"AXFR succeeded from: {ns_list}",
        )
        await ctx.capture_evidence(f"dns://{apex}/AXFR", fake_pr)

        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{apex}",
            title=f"DNS zone transfer allowed for {apex}",
            category=self.category,
            severity=self.severity_default,
            url=asset.url,
            path="",
            description=(
                f"The nameserver(s) {ns_list} for '{apex}' allow unauthenticated "
                "AXFR (zone transfer) requests.  This exposes the entire DNS zone, "
                "including internal hostnames, IP addresses, and infrastructure "
                "layout, which an attacker can use for targeted reconnaissance."
            ),
            remediation=(
                "Configure your nameservers to restrict AXFR to authorised "
                "secondary nameservers only (ACLs / TSIG).  Most authoritative "
                "DNS providers disable AXFR to arbitrary clients by default."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )



