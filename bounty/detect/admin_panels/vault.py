"""
bounty.detect.admin_panels.vault — HashiCorp Vault UI / health detection.

One detection:
- VaultUIExposed  (/v1/sys/health returns sealed/initialized status)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class VaultUIExposed(Detection):
    """HashiCorp Vault health endpoint exposes initialization and seal status."""

    id = "admin_panel.vault.ui_exposed"
    name = "HashiCorp Vault UI/Health Exposed"
    category = "admin_panel_exposure"
    severity_default = 500
    cwe = "CWE-284"
    tags = ("admin-panel", "vault", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "vault")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/v1/sys/health"
        pr = await ctx.probe_fn(url)
        # Vault returns 200 (active), 429 (standby), 472 (dr), 473 (perf), 501 (uninitialized), 503 (sealed)
        # We accept any response that carries the expected JSON structure
        if pr.status_code not in (200, 429, 472, 473, 501, 503):
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["sealed", "initialized"]):
            return

        # Bump severity for unsealed, initialized vault
        sev = self.severity_default
        data = parse_json_body(pr)
        if isinstance(data, dict):
            if data.get("initialized") is True and data.get("sealed") is False:
                sev = 700

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/v1/sys/health",
            title=f"HashiCorp Vault health endpoint exposed at {asset.host}",
            category=self.category,
            severity=sev,
            url=url,
            path="/v1/sys/health",
            description=(
                f"The HashiCorp Vault health endpoint at {url} is publicly accessible. "
                "The /v1/sys/health endpoint reveals whether Vault is initialized, "
                "sealed/unsealed, and the server version. "
                + (
                    "The Vault instance appears to be ACTIVE (initialized and unsealed), "
                    "increasing the severity of this exposure."
                    if sev == 700 else
                    "Vault status information aids attackers in targeting the instance."
                )
            ),
            remediation=(
                "Place Vault behind a reverse proxy that restricts /v1/sys/health to "
                "monitoring/internal networks. Consider setting "
                "`listener.tcp.unauthenticated_metrics_access = false` in Vault config."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

