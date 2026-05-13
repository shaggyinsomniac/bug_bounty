"""
bounty.detect.nuclei_detection — Nuclei-based CVE and misconfiguration detection.

Integrates the Nuclei community template library (~10,000 templates) as a
detection source.  Templates are selected based on asset fingerprints; assets
with no fingerprints fall back to broad exposure/misconfig scanning.

Filtered: ``dos``, ``intrusive``, ``fuzz``, and ``brute-force`` templates are
always excluded to avoid disrupting production systems.
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator
from typing import Any, ClassVar

from bounty import get_logger
from bounty.config import get_settings
from bounty.detect.base import Detection, DetectionContext
from bounty.detect.nuclei_runner import NucleiRunner
from bounty.models import Asset, FindingDraft, FingerprintResult

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Severity mapping (re-exported from runner for convenience)
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, int] = {
    "info": 200,
    "low": 400,
    "medium": 600,
    "high": 800,
    "critical": 950,
}

# Tech categories indicating a meaningful web app worth scanning
_SCANNABLE_CATEGORIES: frozenset[str] = frozenset({
    "cms",
    "framework",
    "web-server",
    "language",
    "admin-panel",
    "ecommerce",
    "ci-cd",
    "database",
    "devops",
    "container",
    "cloud",
    "monitoring",
    "analytics",
    "other",
})

# Simple IPv4 pattern
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class NucleiCveCheck(Detection):
    """Nuclei-based CVE, misconfiguration, and exposure detection.

    Scans assets using the Nuclei community template library.  Templates are
    selected based on fingerprinted technologies; assets with no fingerprints
    default to exposure/misconfig scanning.
    """

    id: ClassVar[str] = "nuclei.cve_check"
    name: ClassVar[str] = "Nuclei CVE / Misconfiguration Check"
    category: ClassVar[str] = "nuclei_cve"
    severity_default: ClassVar[int] = 500

    def applicable_to(
        self,
        asset: Asset,
        fingerprints: list[FingerprintResult],
    ) -> bool:
        """Return ``True`` if the asset is worth scanning with Nuclei.

        Skips bare IPv4 addresses with no fingerprints to reduce noise.
        Returns ``True`` for:
        - Any asset with at least one fingerprint.
        - Hostnames (non-IP) even without fingerprints.
        """
        if fingerprints:
            return True
        host: str = str(getattr(asset, "host", "") or "")
        # Bare IP with no fingerprints → skip (too noisy)
        if _IPV4_RE.match(host):
            return False
        # Hostname with no fingerprint is still worth scanning
        return bool(host)

    async def run(
        self,
        asset: Asset,
        ctx: DetectionContext,
    ) -> AsyncGenerator[FindingDraft, None]:
        """Execute a Nuclei scan and yield findings for each template match."""

        settings = get_settings()

        if not settings.nuclei_enabled:
            return

        runner = NucleiRunner(
            timeout=settings.nuclei_timeout_seconds,
            rate_limit=settings.nuclei_rate_limit,
        )

        fingerprints = getattr(ctx, "fingerprints", []) or []

        try:
            nuclei_findings = await runner.scan(
                asset,
                fingerprints,
                severities=tuple(settings.nuclei_severities),
            )
        except Exception as exc:  # noqa: BLE001
            ctx.log.warning(
                "nuclei_detection_error",
                asset_id=asset.id,
                error=str(exc),
            )
            return

        for nf in nuclei_findings:
            severity_int = _SEVERITY_MAP.get(nf.severity.lower(), 500)

            classification: dict[str, Any] = (
                nf.info_dict.get("classification") or {}
            )
            cve_raw = (
                classification.get("cve-id")
                or classification.get("cve_id")
            )
            cwe_raw = (
                classification.get("cwe-id")
                or classification.get("cwe_id")
            )

            cve_id: str | None = None
            cwe_id: str | None = None
            if isinstance(cve_raw, list):
                cve_id = str(cve_raw[0]) if cve_raw else None
            elif cve_raw:
                cve_id = str(cve_raw)

            if isinstance(cwe_raw, list):
                cwe_id = str(cwe_raw[0]) if cwe_raw else None
            elif cwe_raw:
                cwe_id = str(cwe_raw)

            category_str = f"nuclei.{cve_id}" if cve_id else "nuclei.misc"

            tags = (
                ["nuclei", f"nuclei-template:{nf.template_id}"] + nf.tags
            )

            yield FindingDraft(
                program_id=asset.program_id,
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=(
                    f"nuclei.{nf.template_id}"
                    f":{asset.id or ''}"
                    f":{nf.matched_at}"
                ),
                title=f"[Nuclei] {nf.name}",
                category=category_str,
                severity=severity_int,
                url=nf.matched_at,
                description=str(nf.info_dict.get("description") or ""),
                remediation=str(nf.info_dict.get("remediation") or ""),
                cve=cve_id,
                cwe=cwe_id,
                tags=tags,
                source="nuclei",
            )


