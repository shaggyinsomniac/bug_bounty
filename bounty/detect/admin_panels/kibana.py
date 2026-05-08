"""
bounty.detect.admin_panels.kibana — Kibana admin panel detection.

One detection:
- KibanaAnonymousAccess  (/api/status returns version + cluster info without auth)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class KibanaAnonymousAccess(Detection):
    """Kibana anonymous access — /api/status exposes version and cluster info."""

    id = "admin_panel.kibana.anonymous"
    name = "Kibana Anonymous Access"
    category = "admin_panel_exposure"
    severity_default = 800
    cwe = "CWE-284"
    tags = ("admin-panel", "kibana", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "kibana")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/status"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["version", "name"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/status",
            title=f"Kibana anonymous access at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/api/status",
            description=(
                f"The Kibana instance at {asset.url} allows unauthenticated access. "
                "The /api/status endpoint returned version and node information without "
                "authentication. Kibana provides access to Elasticsearch data via "
                "Discover and Dev Tools, exposing potentially sensitive log and "
                "metric data."
            ),
            remediation=(
                "Enable Kibana security features: set `xpack.security.enabled: true` "
                "in kibana.yml (or elasticsearch.yml). Configure authentication via "
                "X-Pack security, SAML, or reverse proxy authentication."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

