"""
bounty.detect.admin_panels.grafana — Grafana admin panel detections.

Two detections:
- GrafanaAnonymousAccess   (anonymous read via /api/datasources)
- GrafanaSnapshotExposed   (public snapshots via /api/snapshots)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class GrafanaAnonymousAccess(Detection):
    """Grafana anonymous access — /api/datasources returns data source listing."""

    id = "admin_panel.grafana.anonymous"
    name = "Grafana Anonymous Access"
    category = "admin_panel_exposure"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("admin-panel", "grafana", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "grafana")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/datasources"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        data = parse_json_body(pr)
        if not isinstance(data, list):
            return

        # Bump if actual datasource entries are present
        sev = self.severity_default
        if data and isinstance(data[0], dict) and "type" in data[0]:
            sev = 800

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/datasources",
            title=f"Grafana anonymous access at {asset.host}",
            category=self.category,
            severity=sev,
            url=url,
            path="/api/datasources",
            description=(
                f"The Grafana instance at {asset.url} allows unauthenticated access. "
                f"The /api/datasources endpoint returned a list of "
                f"{'configured data sources' if sev == 800 else 'data (anonymous access enabled)'}. "
                "Exposed data source names reveal backend infrastructure."
            ),
            remediation=(
                "In grafana.ini, set `[auth.anonymous] enabled = false`. "
                "If anonymous access is required, set `org_role = Viewer` and disable "
                "data source browsing via `[auth.anonymous] hide_version = true`."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class GrafanaSnapshotExposed(Detection):
    """Grafana public snapshots accessible — dashboard data leak."""

    id = "admin_panel.grafana.snapshots"
    name = "Grafana Public Snapshots Exposed"
    category = "admin_panel_exposure"
    severity_default = 500
    cwe = "CWE-284"
    tags = ("admin-panel", "grafana", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "grafana")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/snapshots"
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
            dedup_key=f"{self.id}:{asset.id}:/api/snapshots",
            title=f"Grafana public snapshots exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/api/snapshots",
            description=(
                f"The Grafana instance at {asset.url} exposes public dashboard snapshots "
                f"via the /api/snapshots endpoint ({len(data)} snapshot(s) found). "
                "These may contain metric data, service names, or infrastructure topology."
            ),
            remediation=(
                "Review and remove sensitive public snapshots via Grafana UI. "
                "Restrict snapshot creation and public sharing in grafana.ini: "
                "`[snapshots] external_enabled = false`."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

