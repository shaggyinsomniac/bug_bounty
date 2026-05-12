"""
bounty.detect.cms_specific.joomla — Joomla-specific detections.

Two detections:
- JoomlaConfigBackup  — /configuration.php.bak exposes site credentials
- JoomlaAdminVersion  — /administrator/manifests/files/joomla.xml reveals version
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_JOOMLA_VERSION_RE = re.compile(rb"<version>([^<]+)</version>", re.IGNORECASE)


class JoomlaConfigBackup(Detection):
    """Joomla configuration.php.bak exposes database credentials."""

    id = "cms.joomla.config_backup"
    name = "Joomla configuration.php Backup Exposed"
    category = "cms_misconfiguration"
    severity_default = 900
    cwe = "CWE-312"
    tags = ("joomla", "credentials", "database", "backup")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "Joomla")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        for path in ["/configuration.php.bak", "/configuration.php~", "/configuration.php.old"]:
            url = asset.url.rstrip("/") + path
            pr = await ctx.probe_fn(url)
            if pr.status_code != 200:
                continue
            body = pr.body
            if len(body) < 20:
                continue
            # Joomla config contains these keys
            sigs = [b"JConfig", b"$secret", b"$password", b"$db", b"$dbprefix",
                    b"$user", b"$host", b"joomla"]
            if not any(sig in body for sig in sigs):
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Joomla config backup exposed at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    f"A Joomla configuration backup file ({path}) is publicly accessible. "
                    "It typically contains database credentials, secret keys, and "
                    "SMTP passwords."
                ),
                remediation=(
                    "Delete all .bak, .old, and ~ backup files from the web root. "
                    "Rotate all exposed credentials immediately."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return


class JoomlaAdminVersion(Detection):
    """Joomla administrator manifest XML exposes version information."""

    id = "cms.joomla.admin_version"
    name = "Joomla Version Disclosure via Manifest XML"
    category = "cms_misconfiguration"
    severity_default = 200
    cwe = "CWE-200"
    tags = ("joomla", "version-disclosure", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "Joomla")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/administrator/manifests/files/joomla.xml"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body = pr.body
        if b"<version>" not in body and b"joomla" not in body.lower():
            return

        version = ""
        m = _JOOMLA_VERSION_RE.search(body)
        if m:
            version = m.group(1).decode("utf-8", errors="replace").strip()

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Joomla version disclosure at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Joomla manifest XML file is publicly accessible"
                + (f" and reveals version {version}" if version else "")
                + ". Version disclosure enables targeted CVE exploitation."
            ),
            remediation=(
                "Block access to /administrator/manifests/ via server configuration. "
                "Add a deny rule for .xml files in admin directories."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

