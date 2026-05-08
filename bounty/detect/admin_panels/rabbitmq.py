"""
bounty.detect.admin_panels.rabbitmq — RabbitMQ Management API detection.

One detection:
- RabbitMQManagementExposed  (/api/overview returns cluster info)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class RabbitMQManagementExposed(Detection):
    """RabbitMQ Management API accessible without authentication."""

    id = "admin_panel.rabbitmq.mgmt_exposed"
    name = "RabbitMQ Management API Exposed"
    category = "admin_panel_exposure"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("admin-panel", "rabbitmq", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "rabbitmq-mgmt")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/overview"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["rabbitmq_version"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/overview",
            title=f"RabbitMQ Management API exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/api/overview",
            description=(
                f"The RabbitMQ Management Plugin API at {url} is accessible without "
                "authentication. The /api/overview endpoint returned RabbitMQ version, "
                "cluster name, node information, and queue statistics."
            ),
            remediation=(
                "Disable the default guest user (`rabbitmqctl delete_user guest`) or "
                "restrict it to localhost in rabbitmq.conf: "
                "`loopback_users.guest = true`. "
                "Place the management UI behind a reverse proxy with authentication."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

