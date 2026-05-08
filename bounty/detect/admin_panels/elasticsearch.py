"""
bounty.detect.admin_panels.elasticsearch — Elasticsearch API detections.

Two detections:
- ElasticsearchClusterExposed  (/ returns cluster info)
- ElasticsearchIndicesExposed  (/_cat/indices reveals index names)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class ElasticsearchClusterExposed(Detection):
    """Elasticsearch root endpoint returns cluster name and version without auth."""

    id = "admin_panel.elasticsearch.cluster_exposed"
    name = "Elasticsearch Cluster Info Exposed"
    category = "admin_panel_exposure"
    severity_default = 800
    cwe = "CWE-284"
    tags = ("admin-panel", "elasticsearch", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "elasticsearch")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["version", "cluster_name"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/",
            title=f"Elasticsearch cluster exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/",
            description=(
                f"The Elasticsearch instance at {asset.url} is accessible without "
                "authentication. The root endpoint returned cluster name, version, "
                "and node information. Unauthenticated Elasticsearch is a critical "
                "data exposure risk — any stored data can be read, modified, or deleted."
            ),
            remediation=(
                "Enable X-Pack security: set `xpack.security.enabled: true` in "
                "elasticsearch.yml. Configure TLS for transport and HTTP layers. "
                "Bind Elasticsearch to localhost or a private network interface. "
                "Never expose Elasticsearch directly to the internet."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class ElasticsearchIndicesExposed(Detection):
    """Elasticsearch /_cat/indices returns all index names without authentication."""

    id = "admin_panel.elasticsearch.indices_exposed"
    name = "Elasticsearch Indices Exposed"
    category = "admin_panel_exposure"
    severity_default = 900
    cwe = "CWE-284"
    tags = ("admin-panel", "elasticsearch", "unauthenticated", "data-exposure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "elasticsearch")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/_cat/indices?format=json"
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
            dedup_key=f"{self.id}:{asset.id}:/_cat/indices",
            title=f"Elasticsearch indices exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/_cat/indices",
            description=(
                f"The Elasticsearch instance at {asset.url} exposes a list of all "
                f"indices ({len(data)} index(es)) via /_cat/indices without authentication. "
                "Index names reveal data architecture, application names, and may "
                "indicate the presence of sensitive data stores (e.g. user_accounts, "
                "payment_logs, audit_events)."
            ),
            remediation=(
                "Enable X-Pack security and configure index-level permissions. "
                "Restrict access to /_cat/* endpoints to administrative roles only."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

