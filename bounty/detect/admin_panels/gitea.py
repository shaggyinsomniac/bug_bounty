"""
bounty.detect.admin_panels.gitea — Gitea public repository listing detection.

One detection:
- GiteaPublicReposExposed  (/api/v1/repos/search reveals repository metadata)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class GiteaPublicReposExposed(Detection):
    """Gitea repository search listing — private repos in public listing."""

    id = "admin_panel.gitea.public_repos"
    name = "Gitea Repository Listing Exposed"
    category = "admin_panel_exposure"
    severity_default = 300
    cwe = "CWE-284"
    tags = ("admin-panel", "gitea", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "gitea")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/v1/repos/search"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["data", "ok"]):
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict):
            return
        repos = data.get("data")
        if not isinstance(repos, list) or not repos:
            return

        # Check if any repo has private flag set
        has_private = any(
            isinstance(r, dict) and r.get("private") is True
            for r in repos
        )
        sev = 700 if has_private else self.severity_default

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/v1/repos/search",
            title=f"Gitea repository listing exposed at {asset.host}",
            category=self.category,
            severity=sev,
            url=url,
            path="/api/v1/repos/search",
            description=(
                f"The Gitea instance at {asset.url} exposes a repository listing via "
                f"/api/v1/repos/search without authentication ({len(repos)} repository(s)). "
                + (
                    "CRITICAL: Private repositories appear in the public listing — "
                    "this is a Gitea visibility misconfiguration."
                    if has_private else
                    "Verify that no sensitive repositories are inadvertently public."
                )
            ),
            remediation=(
                "In Gitea Site Administration → Configuration, set "
                "`service.DEFAULT_REPO_UNITS` appropriately. "
                "Audit all repositories for correct visibility settings. "
                "Consider requiring authentication before showing any repository listings."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

