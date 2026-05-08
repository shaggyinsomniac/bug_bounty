"""
bounty.detect.admin_panels.kubernetes_dashboard — Kubernetes Dashboard detection.

One detection:
- K8sDashboardExposed  (dashboard accessible without authentication)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_admin_panel_html, is_json_response, json_has_keys
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_K8S_HTML_MARKERS = [
    "kubernetes-dashboard",
    "Kubernetes Dashboard",
    "kube-dashboard",
]


class K8sDashboardExposed(Detection):
    """Kubernetes Dashboard accessible without authentication."""

    id = "admin_panel.k8s_dashboard.exposed"
    name = "Kubernetes Dashboard Exposed"
    category = "admin_panel_exposure"
    severity_default = 950
    cwe = "CWE-284"
    tags = ("admin-panel", "kubernetes", "k8s-dashboard", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "k8s-dashboard")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        # Try the login status API first
        api_url = asset.url.rstrip("/") + "/api/v1/login/status"
        pr = await ctx.probe_fn(api_url)

        confirmed = False
        url = api_url
        if pr.status_code == 200 and is_json_response(pr) and json_has_keys(pr, ["tokenPresent"]):
            confirmed = True
        else:
            # Fall back to checking the root for HTML markers
            root_url = asset.url.rstrip("/") + "/"
            pr2 = await ctx.probe_fn(root_url)
            if is_admin_panel_html(pr2, _K8S_HTML_MARKERS):
                confirmed = True
                url = root_url
                pr = pr2

        if not confirmed:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/",
            title=f"Kubernetes Dashboard exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/",
            description=(
                f"The Kubernetes Dashboard at {asset.url} is publicly accessible. "
                "The Kubernetes Dashboard allows full cluster management including "
                "reading secrets, creating/deleting deployments, and accessing pod "
                "exec/log functionality — unauthenticated exposure is critical."
            ),
            remediation=(
                "Enable authentication for the Kubernetes Dashboard. Do not pass "
                "`--enable-skip-login` or `--disable-settings-authorizer` flags. "
                "Use a ClusterRoleBinding with minimal permissions. "
                "Expose the dashboard only via `kubectl proxy` or a VPN-protected ingress."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

