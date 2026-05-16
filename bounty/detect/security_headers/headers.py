
from __future__ import annotations
from typing import ClassVar
import re
from collections.abc import AsyncGenerator
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult
__all__ = [
    "CspMissing", "CspUnsafeInline", "HstsMissing", "HstsShortMaxAge",
    "XFrameOptionsMissing", "XContentTypeOptionsMissing",
    "ReferrerPolicyMissing", "PermissionsPolicyMissing",
]
_SIX_MONTHS_SECONDS = 15_552_000
def _is_html(asset: Asset) -> bool:
    return asset.scheme in ("http", "https")
def _fd(det: "Detection", asset: Asset, ctx: DetectionContext,
        title: str, desc: str, remed: str) -> FindingDraft:
    return FindingDraft(
        asset_id=asset.id, scan_id=ctx.scan_id,
        dedup_key=f"{det.id}:{asset.id}",
        title=title, category=det.category,
        severity=det.severity_default, url=asset.url, path="",
        description=desc, remediation=remed,
        cwe=det.cwe, tags=list(det.tags),
    )
class CspMissing(Detection):
    id = "security_headers.csp_missing"
    name = "Content-Security-Policy Header Missing"
    category = "security_headers"
    severity_default = 300
    cwe = "CWE-693"
    tags: ClassVar[tuple[str, ...]] = ("csp", "security-headers")
    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _is_html(asset)
    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error or pr.headers.get("content-security-policy", "").strip():
            return
        await ctx.capture_evidence(asset.url, pr)
        yield _fd(self, asset, ctx,
                  f"Content-Security-Policy header missing at {asset.host}",
                  "No CSP header increases XSS risk.",
                  "Add a restrictive Content-Security-Policy header.")
class CspUnsafeInline(Detection):
    id = "security_headers.csp_unsafe_inline"
    name = "Content-Security-Policy Contains unsafe-inline"
    category = "security_headers"
    severity_default = 400
    cwe = "CWE-693"
    tags: ClassVar[tuple[str, ...]] = ("csp", "unsafe-inline", "security-headers")
    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _is_html(asset)
    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        csp = pr.headers.get("content-security-policy", "").strip()
        if not csp or "unsafe-inline" not in csp.lower():
            return
        await ctx.capture_evidence(asset.url, pr)
        yield _fd(self, asset, ctx,
                  f"CSP contains unsafe-inline at {asset.host}",
                  "unsafe-inline in CSP weakens XSS protection.",
                  "Remove unsafe-inline; use nonces or hashes.")
class HstsMissing(Detection):
    id = "security_headers.hsts_missing"
    name = "HSTS Header Missing"
    category = "security_headers"
    severity_default = 400
    cwe = "CWE-319"
    tags: ClassVar[tuple[str, ...]] = ("hsts", "tls", "security-headers")
    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.scheme == "https" or asset.primary_scheme == "https"
    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error or pr.headers.get("strict-transport-security", "").strip():
            return
        await ctx.capture_evidence(asset.url, pr)
        yield _fd(self, asset, ctx,
                  f"HSTS header missing on HTTPS asset {asset.host}",
                  "No Strict-Transport-Security enables downgrade attacks.",
                  "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
class HstsShortMaxAge(Detection):
    id = "security_headers.hsts_short_max_age"
    name = "HSTS max-age Too Short"
    category = "security_headers"
    severity_default = 200
    cwe = "CWE-319"
    tags: ClassVar[tuple[str, ...]] = ("hsts", "tls", "security-headers")
    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.scheme == "https" or asset.primary_scheme == "https"
    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        hsts = pr.headers.get("strict-transport-security", "").strip()
        if not hsts:
            return
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if not m:
            return
        max_age = int(m.group(1))
        if max_age >= _SIX_MONTHS_SECONDS:
            return
        await ctx.capture_evidence(asset.url, pr)
        yield _fd(self, asset, ctx,
                  f"HSTS max-age too short ({max_age}s) at {asset.host}",
                  f"HSTS max-age {max_age}s below recommended {_SIX_MONTHS_SECONDS}s.",
                  f"Increase max-age to at least {_SIX_MONTHS_SECONDS}.")
class XFrameOptionsMissing(Detection):
    id = "security_headers.x_frame_options_missing"
    name = "X-Frame-Options Header Missing"
    category = "security_headers"
    severity_default = 300
    cwe = "CWE-1021"
    tags: ClassVar[tuple[str, ...]] = ("clickjacking", "x-frame-options", "security-headers")
    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _is_html(asset)
    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        if pr.headers.get("x-frame-options", "").strip():
            return
        if "frame-ancestors" in pr.headers.get("content-security-policy", "").lower():
            return
        await ctx.capture_evidence(asset.url, pr)
        yield _fd(self, asset, ctx,
                  f"X-Frame-Options missing at {asset.host}",
                  "No X-Frame-Options or CSP frame-ancestors enables clickjacking.",
                  "Add: X-Frame-Options: DENY  or CSP: frame-ancestors 'self'")
class XContentTypeOptionsMissing(Detection):
    id = "security_headers.x_content_type_options_missing"
    name = "X-Content-Type-Options Header Missing"
    category = "security_headers"
    severity_default = 200
    cwe = "CWE-430"
    tags: ClassVar[tuple[str, ...]] = ("mime-sniffing", "x-content-type-options", "security-headers")
    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _is_html(asset)
    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        if pr.headers.get("x-content-type-options", "").strip().lower() == "nosniff":
            return
        await ctx.capture_evidence(asset.url, pr)
        yield _fd(self, asset, ctx,
                  f"X-Content-Type-Options missing at {asset.host}",
                  "Missing X-Content-Type-Options: nosniff enables MIME-sniffing.",
                  "Add: X-Content-Type-Options: nosniff")
class ReferrerPolicyMissing(Detection):
    id = "security_headers.referrer_policy_missing"
    name = "Referrer-Policy Header Missing"
    category = "security_headers"
    severity_default = 100
    cwe = "CWE-200"
    tags: ClassVar[tuple[str, ...]] = ("referrer-policy", "information-disclosure", "security-headers")
    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _is_html(asset)
    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error or pr.headers.get("referrer-policy", "").strip():
            return
        await ctx.capture_evidence(asset.url, pr)
        yield _fd(self, asset, ctx,
                  f"Referrer-Policy header missing at {asset.host}",
                  "No Referrer-Policy; browsers may leak URL paths in Referer.",
                  "Add: Referrer-Policy: strict-origin-when-cross-origin")
class PermissionsPolicyMissing(Detection):
    id = "security_headers.permissions_policy_missing"
    name = "Permissions-Policy Header Missing"
    category = "security_headers"
    severity_default = 100
    cwe = "CWE-693"
    tags: ClassVar[tuple[str, ...]] = ("permissions-policy", "feature-policy", "security-headers")
    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return _is_html(asset)
    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        if (pr.headers.get("permissions-policy", "").strip()
                or pr.headers.get("feature-policy", "").strip()):
            return
        await ctx.capture_evidence(asset.url, pr)
        yield _fd(self, asset, ctx,
                  f"Permissions-Policy header missing at {asset.host}",
                  "No Permissions-Policy; browser features accessible to embedded content.",
                  "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()")
