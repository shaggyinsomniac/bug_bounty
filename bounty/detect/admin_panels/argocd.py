"""
bounty.detect.admin_panels.argocd — Argo CD admin panel detection.

One detection:
- ArgoCDAnonymousAccess  (/api/v1/applications returns app list without auth)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class ArgoCDAnonymousAccess(Detection):
    """Argo CD anonymous access — /api/v1/applications returns Kubernetes app list."""

    id = "admin_panel.argocd.anonymous"
    name = "Argo CD Anonymous Access"
    category = "admin_panel_exposure"
    severity_default = 900
    cwe = "CWE-284"
    tags = ("admin-panel", "argocd", "kubernetes", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "argocd")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/v1/applications"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["items"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/v1/applications",
            title=f"Argo CD anonymous access at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/api/v1/applications",
            description=(
                f"The Argo CD instance at {asset.url} allows unauthenticated access "
                "to its API. The /api/v1/applications endpoint returned a list of "
                "Kubernetes applications without requiring authentication. Argo CD "
                "manages Kubernetes deployments — anonymous access reveals application "
                "names, Git repository URLs, sync status, and cluster targets."
            ),
            remediation=(
                "In argocd-cm ConfigMap, ensure `accounts.anonymous.enabled: 'false'`. "
                "Configure SSO (Dex, OIDC) or local users with passwords. "
                "Apply RBAC policies via argocd-rbac-cm."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

