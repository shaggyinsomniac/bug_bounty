"""
bounty.detect.admin_panels.portainer — Portainer Docker management detection.

One detection:
- PortainerAPIExposed  (/api/endpoints returns Docker endpoint list)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class PortainerAPIExposed(Detection):
    """Portainer Docker management API accessible without authentication."""

    id = "admin_panel.portainer.api_exposed"
    name = "Portainer API Exposed"
    category = "admin_panel_exposure"
    severity_default = 800
    cwe = "CWE-284"
    tags = ("admin-panel", "portainer", "docker", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "portainer")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/endpoints"
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
            dedup_key=f"{self.id}:{asset.id}:/api/endpoints",
            title=f"Portainer API exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/api/endpoints",
            description=(
                f"The Portainer Docker management API at {url} is publicly accessible "
                f"without authentication, returning {len(data)} endpoint(s). "
                "Portainer provides full Docker/Kubernetes management capabilities — "
                "unauthenticated access can allow container creation, secret access, "
                "and host-level privilege escalation."
            ),
            remediation=(
                "Ensure Portainer requires authentication: do not start with "
                "`--admin-password-file` pointing to an empty file. "
                "Restrict access to Portainer to administrative networks. "
                "Enable RBAC and audit logging."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

