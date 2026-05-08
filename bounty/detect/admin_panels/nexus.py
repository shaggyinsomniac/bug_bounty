"""
bounty.detect.admin_panels.nexus — Sonatype Nexus repository manager detection.

One detection:
- NexusRepositoryExposed  (/service/rest/v1/repositories returns repo list)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class NexusRepositoryExposed(Detection):
    """Sonatype Nexus Repository Manager accessible without authentication."""

    id = "admin_panel.nexus.repository_exposed"
    name = "Nexus Repository Manager Exposed"
    category = "admin_panel_exposure"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("admin-panel", "nexus", "artifact-registry", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "nexus")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/service/rest/v1/repositories"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        data = parse_json_body(pr)
        if not isinstance(data, list):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/service/rest/v1/repositories",
            title=f"Nexus repository manager exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/service/rest/v1/repositories",
            description=(
                f"The Sonatype Nexus Repository Manager at {asset.url} exposes its "
                f"repository list via /service/rest/v1/repositories without authentication "
                f"({len(data)} repository(s)). Repository names and types reveal artifact "
                "storage structure and may allow unauthenticated artifact downloads."
            ),
            remediation=(
                "In Nexus, disable anonymous access: Administration → Security → "
                "Anonymous Access → uncheck 'Allow anonymous users to access the server'. "
                "Configure authentication for all repository groups."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

