"""
bounty.detect.admin_panels.solr — Apache Solr admin panel detections.

Two detections:
- SolrAdminConsole   (admin UI at /solr/ is accessible)
- SolrCoresExposed   (/solr/admin/cores returns core status JSON)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import (
    is_admin_panel_html,
    is_json_response,
    json_has_keys,
)
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_SOLR_HTML_MARKERS = ["solr", "Apache Solr", "solr-logo"]


class SolrAdminConsole(Detection):
    """Apache Solr admin console is publicly accessible."""

    id = "admin_panel.solr.admin_console"
    name = "Apache Solr Admin Console Exposed"
    category = "admin_panel_exposure"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("admin-panel", "solr", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "solr")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/solr/"
        pr = await ctx.probe_fn(url)
        if not is_admin_panel_html(pr, _SOLR_HTML_MARKERS):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/solr/",
            title=f"Apache Solr admin console exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/solr/",
            description=(
                f"The Apache Solr administration console at {url} is publicly accessible "
                "without authentication. The Solr admin UI provides index management, "
                "schema inspection, query execution, and configuration access."
            ),
            remediation=(
                "Add authentication to Solr using the BasicAuthPlugin or Kerberos. "
                "Place Solr behind a reverse proxy with IP restrictions. "
                "Do not expose Solr directly to the internet."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class SolrCoresExposed(Detection):
    """Apache Solr core status API accessible without authentication."""

    id = "admin_panel.solr.cores_exposed"
    name = "Apache Solr Cores API Exposed"
    category = "admin_panel_exposure"
    severity_default = 800
    cwe = "CWE-284"
    tags = ("admin-panel", "solr", "unauthenticated", "data-structure-exposure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "solr")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/solr/admin/cores?action=STATUS"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["status"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/solr/admin/cores",
            title=f"Apache Solr cores exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/solr/admin/cores",
            description=(
                f"The Apache Solr core status API at {url} is accessible without "
                "authentication, revealing all configured cores including their names, "
                "data directory paths, and index metadata."
            ),
            remediation=(
                "Enable Solr authentication and restrict the /solr/admin/* endpoints. "
                "Use a reverse proxy to deny access to /_solr/_admin/* from untrusted networks."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

