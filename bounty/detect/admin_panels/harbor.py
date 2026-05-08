"""
bounty.detect.admin_panels.harbor — Harbor container registry detection.

One detection:
- HarborRegistryExposed  (/api/v2.0/projects returns project list)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class HarborRegistryExposed(Detection):
    """Harbor container registry API accessible without authentication."""

    id = "admin_panel.harbor.registry_exposed"
    name = "Harbor Registry Exposed"
    category = "admin_panel_exposure"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("admin-panel", "harbor", "container-registry", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "harbor")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/v2.0/projects"
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
            dedup_key=f"{self.id}:{asset.id}:/api/v2.0/projects",
            title=f"Harbor registry exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/api/v2.0/projects",
            description=(
                f"The Harbor container registry at {asset.url} exposes its project list "
                f"via /api/v2.0/projects without authentication ({len(data)} project(s)). "
                "Exposed registry projects reveal container image names, tags, and "
                "potentially sensitive application configurations embedded in images."
            ),
            remediation=(
                "In Harbor configuration, set `auth_mode` to a non-anonymous backend. "
                "Disable anonymous pull access for all projects: "
                "Project Settings → Access Level → Private. "
                "Restrict Harbor API access to internal networks."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

