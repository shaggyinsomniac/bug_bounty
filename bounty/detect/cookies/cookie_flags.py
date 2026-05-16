from __future__ import annotations
from typing import ClassVar
from collections.abc import AsyncGenerator
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = ["CookieMissingSecure", "CookieMissingHttpOnly", "CookieMissingSameSite"]


def _get_cookies(headers: dict[str, str]) -> list[str]:
    return [v for k, v in headers.items() if k.lower() == "set-cookie"]


def _cookie_name(cookie: str) -> str:
    return cookie.split("=")[0].strip()


class CookieMissingSecure(Detection):
    id = "cookies.missing_secure_flag"
    name = "Cookie Missing Secure Flag"
    category = "cookie_security"
    severity_default = 400
    cwe = "CWE-614"
    tags: ClassVar[tuple[str, ...]] = ("cookies", "secure-flag", "https")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.scheme == "https" or asset.primary_scheme == "https"

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        for cookie in _get_cookies(pr.headers):
            parts = [p.strip().lower() for p in cookie.split(";")]
            if "secure" not in parts:
                await ctx.capture_evidence(asset.url, pr)
                yield FindingDraft(
                    asset_id=asset.id, scan_id=ctx.scan_id,
                    dedup_key=f"{self.id}:{asset.id}:{_cookie_name(cookie)}",
                    title=f"Cookie missing Secure flag at {asset.host}",
                    category=self.category, severity=self.severity_default,
                    url=asset.url, path="",
                    description=(
                        f"Cookie '{_cookie_name(cookie)}' set without Secure flag "
                        "on HTTPS asset; may be transmitted over HTTP."
                    ),
                    remediation="Add Secure flag to all cookies on HTTPS endpoints.",
                    cwe=self.cwe, tags=list(self.tags),
                )
                return


class CookieMissingHttpOnly(Detection):
    id = "cookies.missing_httponly_flag"
    name = "Cookie Missing HttpOnly Flag"
    category = "cookie_security"
    severity_default = 300
    cwe = "CWE-1004"
    tags: ClassVar[tuple[str, ...]] = ("cookies", "httponly-flag")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        for cookie in _get_cookies(pr.headers):
            parts = [p.strip().lower() for p in cookie.split(";")]
            if "httponly" not in parts:
                await ctx.capture_evidence(asset.url, pr)
                yield FindingDraft(
                    asset_id=asset.id, scan_id=ctx.scan_id,
                    dedup_key=f"{self.id}:{asset.id}:{_cookie_name(cookie)}",
                    title=f"Cookie missing HttpOnly flag at {asset.host}",
                    category=self.category, severity=self.severity_default,
                    url=asset.url, path="",
                    description=(
                        f"Cookie '{_cookie_name(cookie)}' lacks HttpOnly, "
                        "accessible via JavaScript (XSS risk)."
                    ),
                    remediation="Add HttpOnly to session and sensitive cookies.",
                    cwe=self.cwe, tags=list(self.tags),
                )
                return


class CookieMissingSameSite(Detection):
    id = "cookies.missing_samesite_flag"
    name = "Cookie Missing SameSite Attribute"
    category = "cookie_security"
    severity_default = 200
    cwe = "CWE-352"
    tags: ClassVar[tuple[str, ...]] = ("cookies", "samesite", "csrf")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        for cookie in _get_cookies(pr.headers):
            parts = [p.strip().lower() for p in cookie.split(";")]
            if not any(p.startswith("samesite") for p in parts):
                await ctx.capture_evidence(asset.url, pr)
                yield FindingDraft(
                    asset_id=asset.id, scan_id=ctx.scan_id,
                    dedup_key=f"{self.id}:{asset.id}:{_cookie_name(cookie)}",
                    title=f"Cookie missing SameSite at {asset.host}",
                    category=self.category, severity=self.severity_default,
                    url=asset.url, path="",
                    description=(
                        f"Cookie '{_cookie_name(cookie)}' lacks SameSite attribute, "
                        "increasing CSRF risk."
                    ),
                    remediation="Add SameSite=Strict or SameSite=Lax.",
                    cwe=self.cwe, tags=list(self.tags),
                )
                return
