"""
bounty.detect.admin_panels.consul — HashiCorp Consul API detection.

One detection:
- ConsulAPIExposed  (/v1/agent/self returns cluster configuration)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class ConsulAPIExposed(Detection):
    """HashiCorp Consul agent API accessible without authentication."""

    id = "admin_panel.consul.api_exposed"
    name = "HashiCorp Consul API Exposed"
    category = "admin_panel_exposure"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("admin-panel", "consul", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "consul")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/v1/agent/self"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["Config"]):
            return

        # Bump severity if significant cluster info is present
        sev = self.severity_default
        data = parse_json_body(pr)
        if isinstance(data, dict):
            config = data.get("Config", {})
            if (
                isinstance(config, dict)
                and config.get("Datacenter")
                and config.get("NodeName")
            ):
                sev = 850

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/v1/agent/self",
            title=f"HashiCorp Consul API exposed at {asset.host}",
            category=self.category,
            severity=sev,
            url=url,
            path="/v1/agent/self",
            description=(
                f"The HashiCorp Consul agent API at {url} is publicly accessible "
                "without authentication. The /v1/agent/self endpoint returned cluster "
                "configuration including datacenter name, node name, and agent configuration. "
                "Unauthenticated Consul access can allow service enumeration and "
                "potentially key-value store access."
            ),
            remediation=(
                "Enable Consul ACLs: set `acl.enabled = true` and `acl.default_policy = deny` "
                "in consul.hcl. Generate and distribute agent tokens. "
                "Bind the Consul HTTP API to a non-public interface or use a firewall."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

