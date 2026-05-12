"""
bounty.detect.cloud.generic — Generic CDN/cloud header misconfigurations.

Two detections:
- CdnCacheBackend    — X-Backend-Server or Via header reveals origin IP/hostname
- CloudfrontMisconfig — CloudFront cache header leaks diagnostic paths
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

# Headers that may expose backend origin
_BACKEND_HEADERS = [
    "x-backend-server",
    "x-served-by",
    "x-origin",
    "x-cache-hits",
    "x-real-server",
    "x-amz-cf-id",
]


class CdnCacheBackend(Detection):
    """CDN response headers reveal the origin backend server address."""

    id = "cloud.generic.cdn_backend_disclosure"
    name = "CDN Backend Origin Disclosed in Headers"
    category = "cloud_misconfiguration"
    severity_default = 300
    cwe = "CWE-200"
    tags = ("cloud", "cdn", "information-disclosure", "origin-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url
        pr = await ctx.probe_fn(url)
        if pr.status_code not in range(200, 400):
            return

        headers_lower = {k.lower(): v for k, v in pr.headers.items()}
        exposed_header = ""
        exposed_value = ""

        # X-Backend-Server header directly reveals origin
        backend = headers_lower.get("x-backend-server", "")
        if backend and _looks_like_internal_host(backend):
            exposed_header = "X-Backend-Server"
            exposed_value = backend

        # Via header with internal hostname
        if not exposed_header:
            via = headers_lower.get("via", "")
            if via and _looks_like_internal_host(via):
                exposed_header = "Via"
                exposed_value = via

        # X-Served-By with internal hostname
        if not exposed_header:
            served_by = headers_lower.get("x-served-by", "")
            if served_by and _looks_like_internal_host(served_by):
                exposed_header = "X-Served-By"
                exposed_value = served_by

        if not exposed_header:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{exposed_header}",
            title=f"CDN backend origin disclosed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/",
            description=(
                f"The HTTP response header '{exposed_header}: {exposed_value}' "
                "reveals the internal origin server address. This can expose "
                "internal hostnames, IP addresses, or infrastructure topology."
            ),
            remediation=(
                f"Configure the CDN/proxy to strip the '{exposed_header}' header "
                "from responses before forwarding to clients."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


def _looks_like_internal_host(value: str) -> bool:
    """Return True if the header value contains an internal hostname or IP."""
    lower = value.lower()
    # Internal IP ranges / TLDs
    internal_markers = [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
        "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
        ".internal", ".local", ".corp", ".priv", ".intranet",
    ]
    return any(marker in lower for marker in internal_markers)


class CloudfrontMisconfig(Detection):
    """CloudFront configuration leaks diagnostic info via X-Cache header."""

    id = "cloud.generic.cloudfront_misconfig"
    name = "CloudFront Cache Headers Leak Diagnostic Info"
    category = "cloud_misconfiguration"
    severity_default = 300
    cwe = "CWE-200"
    tags = ("cloud", "cloudfront", "cdn", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url
        pr = await ctx.probe_fn(url)
        if pr.status_code not in range(200, 400):
            return

        headers_lower = {k.lower(): v for k, v in pr.headers.items()}
        # Must be CloudFront (check X-Cache or X-Amz-Cf-Id)
        x_cache = headers_lower.get("x-cache", "")
        cf_id = headers_lower.get("x-amz-cf-id", "")
        cf_pop = headers_lower.get("x-amz-cf-pop", "")

        is_cloudfront = (
            "cloudfront" in x_cache.lower()
            or bool(cf_id)
            or bool(cf_pop)
            or "cloudfront.net" in pr.final_url
        )
        if not is_cloudfront:
            return

        # Look for diagnostic info leakage: X-Cache with origin path, CF-Ray with internal details
        leaking_value = ""
        if x_cache and ("error" in x_cache.lower() or "miss from" in x_cache.lower()):
            # "Miss from cloudfront (origin: 10.0.0.5)" type patterns
            if any(m in x_cache for m in ["origin:", "backend:", "10.", "192.168."]):
                leaking_value = f"X-Cache: {x_cache}"

        if not leaking_value and cf_pop:
            # X-Amz-Cf-Pop normally shows PoP code (e.g. LAX1) — not a vuln
            # But unusual paths reveal extended internal info
            pass

        # Also check for X-Forwarded-Server or X-Forwarded-Host revealing internals
        fwd_server = headers_lower.get("x-forwarded-server", "")
        if fwd_server and _looks_like_internal_host(fwd_server):
            leaking_value = f"X-Forwarded-Server: {fwd_server}"

        if not leaking_value:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"CloudFront misconfiguration leaks backend info at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/",
            description=(
                f"CloudFront response headers expose internal diagnostic information: "
                f"{leaking_value}. This can reveal origin server addresses or "
                "infrastructure details."
            ),
            remediation=(
                "Configure CloudFront to remove sensitive response headers via "
                "a Response Headers Policy. Audit CloudFront distributions for "
                "header forwarding rules."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

