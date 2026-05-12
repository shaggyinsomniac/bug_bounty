"""
bounty.detect.cms_specific.magento — Magento-specific detections.

Three detections:
- MagentoLocalXml          — /app/etc/local.xml exposes DB credentials
- MagentoDownloader        — /downloader/ Magento Connect accessible
- MagentoVersionDisclosure — /magento_version exposes version string
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class MagentoLocalXml(Detection):
    """Magento /app/etc/local.xml exposed — contains DB credentials."""

    id = "cms.magento.local_xml"
    name = "Magento local.xml Credentials Exposed"
    category = "cms_misconfiguration"
    severity_default = 900
    cwe = "CWE-312"
    tags = ("magento", "credentials", "database")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "Magento")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/app/etc/local.xml"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body = pr.body
        if len(body) < 20:
            return
        sigs = [b"<config>", b"<connection>", b"<username>", b"<password>",
                b"<dbname>", b"<host>", b"<crypt>", b"<key>"]
        if not any(sig in body for sig in sigs):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Magento local.xml exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Magento local.xml configuration file is publicly accessible. "
                "It typically contains database credentials, encryption keys, and "
                "cache server connection strings."
            ),
            remediation=(
                "Immediately restrict access to /app/etc/local.xml via server "
                "configuration. Rotate all exposed credentials. Add the path to "
                "your web server's deny rules."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class MagentoDownloader(Detection):
    """Magento Connect downloader UI accessible at /downloader/."""

    id = "cms.magento.downloader"
    name = "Magento Downloader Exposed"
    category = "cms_misconfiguration"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("magento", "admin-panel", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "Magento")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/downloader/"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_lower = pr.body_text.lower()
        if not any(m in body_lower for m in ["magento connect", "downloader", "magento", "connect manager"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Magento downloader exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Magento Connect Downloader is publicly accessible. "
                "It can be used to install arbitrary extensions, potentially "
                "leading to remote code execution."
            ),
            remediation=(
                "Remove or restrict access to the /downloader/ directory. "
                "Apply IP whitelisting via server configuration."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class MagentoVersionDisclosure(Detection):
    """Magento /magento_version endpoint reveals exact version string."""

    id = "cms.magento.version_disclosure"
    name = "Magento Version Disclosure"
    category = "cms_misconfiguration"
    severity_default = 200
    cwe = "CWE-200"
    tags = ("magento", "version-disclosure", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "Magento")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/magento_version"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body = pr.body.strip()
        if len(body) < 3 or len(body) > 50:
            return
        # Body is typically just a version string like "2.4.6" or "Magento/2.4.6"
        import re
        if not re.match(rb"[\w./\-]+\d+\.\d+", body):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Magento version disclosure at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                f"The /magento_version endpoint reveals the exact Magento version: "
                f"{body.decode('utf-8', errors='replace')}. This aids targeted exploit selection."
            ),
            remediation=(
                "Block the /magento_version endpoint at the server or WAF level."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

