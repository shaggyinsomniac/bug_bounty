"""
bounty.detect.admin_panels.sonarqube — SonarQube anonymous access detection.

One detection:
- SonarQubeAnonymousAccess  (/api/projects/search returns project list)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class SonarQubeAnonymousAccess(Detection):
    """SonarQube anonymous access — /api/projects/search returns project list."""

    id = "admin_panel.sonarqube.anonymous"
    name = "SonarQube Anonymous Access"
    category = "admin_panel_exposure"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("admin-panel", "sonarqube", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "sonarqube")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/projects/search"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["components"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/projects/search",
            title=f"SonarQube anonymous access at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/api/projects/search",
            description=(
                f"The SonarQube instance at {asset.url} allows unauthenticated access. "
                "The /api/projects/search endpoint returned a list of projects without "
                "authentication. SonarQube stores code quality analysis results, "
                "security hotspots, and vulnerability findings — exposing this data "
                "aids attackers in identifying exploitable weaknesses."
            ),
            remediation=(
                "Disable anonymous access in SonarQube: Administration → Security → "
                "Force user authentication. Restrict access to SonarQube to "
                "internal networks or VPN-authenticated users."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

