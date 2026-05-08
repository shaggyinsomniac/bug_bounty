"""
bounty.detect.admin_panels.gitlab — GitLab public project listing detection.

One detection:
- GitLabPublicProjectsExposed  (/api/v4/projects reveals project metadata)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class GitLabPublicProjectsExposed(Detection):
    """GitLab project listing via /api/v4/projects — private projects in public listing."""

    id = "admin_panel.gitlab.public_projects"
    name = "GitLab Project Listing Exposed"
    category = "admin_panel_exposure"
    severity_default = 300
    cwe = "CWE-284"
    tags = ("admin-panel", "gitlab", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "gitlab")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/v4/projects"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        data = parse_json_body(pr)
        if not isinstance(data, list) or not data:
            return

        # Check if any project has "private" visibility (configuration bug)
        has_private = any(
            isinstance(p, dict) and p.get("visibility") == "private"
            for p in data
        )
        sev = 700 if has_private else self.severity_default

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/v4/projects",
            title=f"GitLab project listing exposed at {asset.host}",
            category=self.category,
            severity=sev,
            url=url,
            path="/api/v4/projects",
            description=(
                f"The GitLab instance at {asset.url} exposes a project listing via "
                f"/api/v4/projects without authentication ({len(data)} project(s)). "
                + (
                    "CRITICAL: Private projects appear in the public listing — this is "
                    "likely a GitLab visibility misconfiguration."
                    if has_private else
                    "Public project listings are often intentional but verify that no "
                    "sensitive repositories are inadvertently public."
                )
            ),
            remediation=(
                "Review GitLab instance settings: Admin Area → Settings → Visibility "
                "and access controls. Ensure 'Restricted visibility levels' are "
                "configured appropriately. Audit all projects for correct visibility settings."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

