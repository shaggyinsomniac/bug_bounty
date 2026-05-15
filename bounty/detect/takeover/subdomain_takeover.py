"""
bounty.detect.takeover.subdomain_takeover — Subdomain takeover detection.

Resolves the CNAME chain for the asset's host with dnspython.  If the chain
points to a known-takeover-vulnerable service AND the HTTP response body
contains that service's "unclaimed" fingerprint → finding, severity 800.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = ["SubdomainTakeover"]

# ---------------------------------------------------------------------------
# Load fingerprint database once at import time
# ---------------------------------------------------------------------------

_FP_PATH = Path(__file__).parent / "fingerprints.json"

def _load_fingerprints() -> list[dict[str, Any]]:
    with _FP_PATH.open() as fh:
        data: list[dict[str, Any]] = json.load(fh)
    return data


_FINGERPRINTS: list[dict[str, Any]] = _load_fingerprints()


# ---------------------------------------------------------------------------
# CNAME resolution helper
# ---------------------------------------------------------------------------

async def _resolve_cname_chain(host: str) -> list[str]:
    """Return the full CNAME chain starting from *host* (up to 10 hops)."""
    chain: list[str] = []
    current = host.rstrip(".")
    for _ in range(10):
        try:
            answers = await dns.asyncresolver.resolve(current, "CNAME")
            target = str(answers[0].target).rstrip(".")
            if target == current:
                break
            chain.append(target)
            current = target
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.DNSException,
        ):
            break
    return chain


def _cname_matches(cname: str, patterns: list[str]) -> bool:
    """Return True if *cname* ends with any of the CNAME patterns."""
    cname_lower = cname.lower()
    return any(cname_lower.endswith(pat.lower()) for pat in patterns)


def _body_matches(body_text: str, fingerprints: list[str]) -> bool:
    """Return True if *body_text* contains any of the unclaimed-page fingerprints."""
    body_lower = body_text.lower()
    return any(fp.lower() in body_lower for fp in fingerprints)


# ---------------------------------------------------------------------------
# Detection class
# ---------------------------------------------------------------------------

class SubdomainTakeover(Detection):
    """Subdomain takeover — CNAME points to an unclaimed third-party service."""

    id = "takeover.subdomain"
    name = "Subdomain Takeover"
    category = "subdomain_takeover"
    severity_default = 800
    cwe = "CWE-350"
    tags = ("takeover", "dns", "cname")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        # Run on any asset that has a resolvable host (not raw IPs).
        host = asset.host.split(":")[0]
        return not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        host = asset.host.split(":")[0]

        try:
            cname_chain = await _resolve_cname_chain(host)
        except Exception as exc:  # noqa: BLE001
            ctx.log.debug("takeover_cname_resolve_error", host=host, error=str(exc))
            return

        if not cname_chain:
            return

        # Check each CNAME hop against known services
        for service_fp in _FINGERPRINTS:
            service: str = str(service_fp["service"])
            cname_patterns: list[str] = list(service_fp["cname_patterns"])
            body_fps: list[str] = list(service_fp["body_fingerprints"])
            vulnerable_status: list[int] = list(service_fp["vulnerable_status"])

            matched_cname = next(
                (c for c in cname_chain if _cname_matches(c, cname_patterns)),
                None,
            )
            if not matched_cname:
                continue

            # There's a matching CNAME — probe the asset URL to check body
            pr = await ctx.probe_fn(asset.url)
            if pr.error:
                continue

            status_match = (
                pr.status_code in vulnerable_status
                or not vulnerable_status  # empty list = match any status
            )
            if not status_match:
                continue

            if not _body_matches(pr.body_text, body_fps):
                continue

            # Confirmed takeover
            await ctx.capture_evidence(asset.url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{service}",
                title=f"Subdomain takeover via {service} at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=asset.url,
                path="",
                description=(
                    f"The host '{asset.host}' has a CNAME record pointing to "
                    f"'{matched_cname}' ({service}), but the service account is "
                    f"unclaimed. An attacker can register the {service} account "
                    f"and serve arbitrary content on '{asset.host}'."
                ),
                remediation=(
                    f"Remove the dangling CNAME record for '{asset.host}' or "
                    f"claim the {service} account referenced by '{matched_cname}'."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return  # one finding per asset max



