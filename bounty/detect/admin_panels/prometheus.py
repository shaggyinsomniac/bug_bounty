"""
bounty.detect.admin_panels.prometheus — Prometheus metrics API detection.

One detection:
- PrometheusMetricsExposed  (/api/v1/status/config returns full configuration)
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_CREDENTIAL_RE = re.compile(
    r"(password|token|secret|api_key|bearer|username|user)\s*[:=]",
    re.IGNORECASE,
)


class PrometheusMetricsExposed(Detection):
    """Prometheus config endpoint exposes scrape targets and credentials."""

    id = "admin_panel.prometheus.metrics_exposed"
    name = "Prometheus Configuration Exposed"
    category = "admin_panel_exposure"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("admin-panel", "prometheus", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "prometheus")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/v1/status/config"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["status", "data"]):
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict) or not isinstance(data.get("data"), dict):
            return
        inner = data["data"]
        if not isinstance(inner, dict) or "yaml" not in inner:
            return

        # Bump severity if config contains credential-like patterns
        sev = self.severity_default
        config_yaml = str(inner.get("yaml", ""))
        if _CREDENTIAL_RE.search(config_yaml):
            sev = 800

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/v1/status/config",
            title=f"Prometheus configuration exposed at {asset.host}",
            category=self.category,
            severity=sev,
            url=url,
            path="/api/v1/status/config",
            description=(
                f"The Prometheus instance at {asset.url} exposes its full configuration "
                "via /api/v1/status/config without authentication. The configuration "
                "includes scrape target URLs, service discovery settings, "
                + (
                    "and appears to contain credential-like patterns (passwords, tokens, or API keys)."
                    if sev == 800 else
                    "and scrape job names."
                )
            ),
            remediation=(
                "Enable Prometheus authentication using a reverse proxy (nginx, Caddy) "
                "with Basic Auth or OAuth2 proxy. Restrict access to /api/v1/status/* "
                "to administrative networks."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

