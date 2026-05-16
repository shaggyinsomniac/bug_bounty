from __future__ import annotations
from collections.abc import AsyncGenerator
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = ["ClickjackingMissingProtection"]


class ClickjackingMissingProtection(Detection):
    id = "web.clickjacking.missing_protection"
    name = "Clickjacking Protection Missing"
    category = "clickjacking"
    severity_default = 300
    cwe = "CWE-1021"
    tags: tuple[str, ...] = ("clickjacking", "x-frame-options", "csp")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.scheme in ("http", "https")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        xfo = pr.headers.get("x-frame-options", "").strip()
        csp = pr.headers.get("content-security-policy", "").lower()
        if xfo or "frame-ancestors" in csp:
            return
        await ctx.capture_evidence(asset.url, pr)
        yield FindingDraft(
            asset_id=asset.id, scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"Clickjacking protection missing at {asset.host}",
            category=self.category, severity=self.severity_default,
            url=asset.url, path="",
            description=(
                "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                "The page can be framed by attacker-controlled sites."
            ),
            remediation=(
                "Add X-Frame-Options: DENY  or  CSP: frame-ancestors 'none'."
            ),
            cwe=self.cwe, tags=list(self.tags),
        )
