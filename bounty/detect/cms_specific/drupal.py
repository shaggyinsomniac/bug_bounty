"""
bounty.detect.cms_specific.drupal — Drupal-specific detections.

Three detections:
- DrupalChangelogExposed — /CHANGELOG.txt reveals Drupal version
- DrupalCron             — /cron.php accessible without key (old Drupal)
- DrupalUpdatePhp        — /update.php exposed without authentication
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_DRUPAL_VERSION_RE = re.compile(rb"Drupal (\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


class DrupalChangelogExposed(Detection):
    """Drupal CHANGELOG.txt exposes exact version information."""

    id = "cms.drupal.changelog_exposed"
    name = "Drupal CHANGELOG.txt Version Disclosure"
    category = "cms_misconfiguration"
    severity_default = 200
    cwe = "CWE-200"
    tags = ("drupal", "version-disclosure", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "Drupal")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/CHANGELOG.txt"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body = pr.body
        if b"Drupal" not in body:
            return
        version = ""
        m = _DRUPAL_VERSION_RE.search(body)
        if m:
            version = m.group(1).decode("utf-8", errors="replace")

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Drupal CHANGELOG.txt exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                f"The Drupal CHANGELOG.txt file is publicly accessible"
                + (f" and reveals version {version}" if version else "")
                + ". Version disclosure helps attackers identify unpatched CVEs."
            ),
            remediation=(
                "Delete CHANGELOG.txt, INSTALL.txt, INSTALL.mysql.txt, "
                "INSTALL.pgsql.txt, and LICENSE.txt from the web root."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class DrupalCron(Detection):
    """Drupal cron.php accessible without a cron key (old Drupal 6/7 behavior)."""

    id = "cms.drupal.cron_exposed"
    name = "Drupal cron.php Exposed"
    category = "cms_misconfiguration"
    severity_default = 400
    cwe = "CWE-284"
    tags = ("drupal", "cron", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "Drupal")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/cron.php"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_lower = pr.body_text.lower()
        # Drupal 6/7 cron outputs blank or "cron has been run successfully"
        # Drupal 8+ requires a cron_key param — if it returns 200 without key it's exposed
        sigs = ["cron has been", "cron run", "drupal_cron_run", "cron"]
        if not any(s in body_lower for s in sigs) and len(pr.body) > 5:
            # Any non-error 200 from cron.php is suspicious
            if len(pr.body) > 200:
                return
            # Accept empty 200 — old Drupal returns empty body on cron success
        if len(pr.body) > 500 and "drupal" not in body_lower:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Drupal cron.php exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Drupal cron.php script is accessible without a cron key. "
                "An attacker can trigger cron runs, potentially causing information "
                "disclosure of internal processing state or resource exhaustion."
            ),
            remediation=(
                "Upgrade to Drupal 8+ which requires a cron_key. For older versions, "
                "restrict access to cron.php via server config and use Drush cron "
                "instead of the web endpoint."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class DrupalUpdatePhp(Detection):
    """Drupal update.php exposed without authentication."""

    id = "cms.drupal.update_php_exposed"
    name = "Drupal update.php Exposed"
    category = "cms_misconfiguration"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("drupal", "update", "authentication-bypass")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "Drupal")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/update.php"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_lower = pr.body_text.lower()
        if "drupal" not in body_lower:
            return
        if not any(m in body_lower for m in ["database update", "update script", "drupal database", "apply pending"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Drupal update.php exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Drupal update.php database migration script is accessible without "
                "authentication. This could allow an attacker to run arbitrary "
                "database updates, potentially corrupting or modifying the database."
            ),
            remediation=(
                "Restrict access to /update.php. In Drupal 8+, it requires admin "
                "credentials. For added security, block it at the server level "
                "after updates are complete."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

