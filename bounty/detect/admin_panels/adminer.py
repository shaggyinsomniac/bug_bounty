"""
bounty.detect.admin_panels.adminer — Adminer database admin login detection.

One detection:
- AdminerLoginExposed  (Adminer login page is publicly reachable)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_admin_panel_html
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_ADMINER_MARKERS = ["adminer", "Adminer"]


class AdminerLoginExposed(Detection):
    """Adminer database administration login page is publicly accessible."""

    id = "admin_panel.adminer.login_exposed"
    name = "Adminer Login Page Exposed"
    category = "admin_panel_exposure"
    severity_default = 400
    cwe = "CWE-284"
    tags = ("admin-panel", "adminer", "database")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "adminer")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/"
        pr = await ctx.probe_fn(url)
        if not is_admin_panel_html(pr, _ADMINER_MARKERS):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/",
            title=f"Adminer login page exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/",
            description=(
                f"An Adminer database administration interface is publicly accessible "
                f"at {asset.url}. The login page is reachable from the internet. "
                "Adminer supports MySQL, PostgreSQL, SQLite, MS SQL and Oracle. "
                "Public exposure of database management interfaces increases attack surface."
            ),
            remediation=(
                "Restrict Adminer access via IP allowlist or move behind a VPN. "
                "Serve Adminer only from a non-guessable path. "
                "Ensure strong, non-default credentials are configured for all databases."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

