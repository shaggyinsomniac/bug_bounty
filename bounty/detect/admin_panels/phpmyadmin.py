"""
bounty.detect.admin_panels.phpmyadmin — phpMyAdmin login page detection.

One detection:
- PhpMyAdminLoginExposed  (login page is publicly reachable)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_admin_panel_html
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_PHPMYADMIN_MARKERS = [
    "phpmyadmin",
    "pma_username",
    "pma_password",
    "phpMyAdmin",
]


class PhpMyAdminLoginExposed(Detection):
    """phpMyAdmin login page is publicly accessible."""

    id = "admin_panel.phpmyadmin.login_exposed"
    name = "phpMyAdmin Login Page Exposed"
    category = "admin_panel_exposure"
    severity_default = 400
    cwe = "CWE-284"
    tags = ("admin-panel", "phpmyadmin", "database")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "phpmyadmin")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/"
        pr = await ctx.probe_fn(url)
        if not is_admin_panel_html(pr, _PHPMYADMIN_MARKERS):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/",
            title=f"phpMyAdmin login page exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/",
            description=(
                f"A phpMyAdmin database administration interface is publicly accessible "
                f"at {asset.url}. The login page is reachable from the internet. "
                "Consider testing common default credentials manually. "
                "Public exposure of database management interfaces increases attack surface."
            ),
            remediation=(
                "Restrict phpMyAdmin access via IP allowlist (Apache: `Require ip 10.0.0.0/8`). "
                "Move phpMyAdmin to a non-standard path and serve it only over a VPN. "
                "Ensure strong, non-default credentials are configured."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

