"""
bounty.detect.php_specific.server_status — Apache server status/info detections.

Two detections:
- ServerStatus — /server-status reveals Apache status, active connections, IPs
- ServerInfo   — /server-info reveals Apache configuration details
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class ServerStatus(Detection):
    """Apache /server-status exposes active requests, IPs, and process info."""

    id = "php_specific.apache.server_status"
    name = "Apache Server-Status Exposed"
    category = "php_exposure"
    severity_default = 400
    cwe = "CWE-200"
    tags = ("apache", "server-status", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True  # Apache can run with or without PHP fingerprint

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/server-status"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_lower = pr.body_text.lower()
        if not any(m in body_lower for m in [
            "apache server status", "server version", "server uptime",
            "requests/sec", "server status for"
        ]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Apache server-status exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Apache /server-status page is publicly accessible. "
                "It reveals active HTTP requests, client IP addresses, server "
                "uptime, number of active workers, and URL paths being requested, "
                "including potentially sensitive internal API calls."
            ),
            remediation=(
                "Restrict /server-status to localhost or trusted IPs: "
                "add 'Require local' or 'Require ip 10.0.0.0/8' in the Apache conf. "
                "Or disable ExtendedStatus if not needed."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class ServerInfo(Detection):
    """Apache /server-info exposes full server configuration details."""

    id = "php_specific.apache.server_info"
    name = "Apache Server-Info Exposed"
    category = "php_exposure"
    severity_default = 300
    cwe = "CWE-200"
    tags = ("apache", "server-info", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/server-info"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_lower = pr.body_text.lower()
        if not any(m in body_lower for m in [
            "apache server information", "server information", "module information",
            "loaded modules", "configuration files"
        ]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Apache server-info exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Apache /server-info page is publicly accessible. "
                "It reveals loaded modules, virtual host configuration, "
                "configuration file paths, and server build details."
            ),
            remediation=(
                "Restrict /server-info to localhost: add 'Require local' in "
                "the Apache server-info handler configuration."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

