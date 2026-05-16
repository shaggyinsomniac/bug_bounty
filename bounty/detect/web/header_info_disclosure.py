from __future__ import annotations
from typing import ClassVar
import re
from collections.abc import AsyncGenerator
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = ["XPoweredByVerbose", "ServerVerbose", "InternalIpInHeader"]

# Matches version strings like PHP/7.4.0, Python/3.x, Express/4.x
_VERSION_RE = re.compile(r'[A-Za-z][A-Za-z0-9._-]*/\d+\.\d+', re.IGNORECASE)

# RFC1918 IPv4 ranges
_RFC1918_RE = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})\b'
)


class XPoweredByVerbose(Detection):
    id = "web.header_info_disclosure.x_powered_by_verbose"
    name = "Verbose X-Powered-By Header"
    category = "information_disclosure"
    severity_default = 200
    cwe = "CWE-200"
    tags: ClassVar[tuple[str, ...]] = ("information-disclosure", "x-powered-by")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        val = pr.headers.get("x-powered-by", "").strip()
        if not val or not _VERSION_RE.search(val):
            return
        await ctx.capture_evidence(asset.url, pr)
        yield FindingDraft(
            asset_id=asset.id, scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"Verbose X-Powered-By header at {asset.host}",
            category=self.category, severity=self.severity_default,
            url=asset.url, path="",
            description=f"X-Powered-By header reveals exact version: {val}",
            remediation="Remove or generalise the X-Powered-By header.",
            cwe=self.cwe, tags=list(self.tags),
        )


class ServerVerbose(Detection):
    id = "web.header_info_disclosure.server_verbose"
    name = "Verbose Server Header"
    category = "information_disclosure"
    severity_default = 200
    cwe = "CWE-200"
    tags: ClassVar[tuple[str, ...]] = ("information-disclosure", "server-header")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        val = pr.headers.get("server", "").strip()
        if not val or not _VERSION_RE.search(val):
            return
        await ctx.capture_evidence(asset.url, pr)
        yield FindingDraft(
            asset_id=asset.id, scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"Verbose Server header at {asset.host}",
            category=self.category, severity=self.severity_default,
            url=asset.url, path="",
            description=f"Server header reveals exact version: {val}",
            remediation="Remove version information from the Server header.",
            cwe=self.cwe, tags=list(self.tags),
        )


class InternalIpInHeader(Detection):
    id = "web.header_info_disclosure.internal_ip_in_header"
    name = "Internal IP Address Leaked in Response Header"
    category = "information_disclosure"
    severity_default = 400
    cwe = "CWE-200"
    tags: ClassVar[tuple[str, ...]] = ("information-disclosure", "internal-ip")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        for header_name, header_val in pr.headers.items():
            m = _RFC1918_RE.search(header_val)
            if m:
                await ctx.capture_evidence(asset.url, pr)
                yield FindingDraft(
                    asset_id=asset.id, scan_id=ctx.scan_id,
                    dedup_key=f"{self.id}:{asset.id}",
                    title=f"Internal IP in response header at {asset.host}",
                    category=self.category, severity=self.severity_default,
                    url=asset.url, path="",
                    description=(
                        f"Header '{header_name}' contains RFC1918 IP: {m.group(0)}. "
                        "Internal network topology is leaked."
                    ),
                    remediation="Strip internal IPs from response headers (proxy/server config).",
                    cwe=self.cwe, tags=list(self.tags),
                )
                return
