from __future__ import annotations
import re
from collections.abc import AsyncGenerator
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = ["MixedContentHttpResources"]

# Match http:// in src= or href= attributes (scripts, stylesheets, iframes)
_MIXED_RE = re.compile(
    r'(?:src|href)\s*=\s*["\'](http://[^"\'>\s]+)',
    re.IGNORECASE,
)


class MixedContentHttpResources(Detection):
    id = "web.mixed_content.http_resources"
    name = "Mixed Content — HTTP Resources on HTTPS Page"
    category = "mixed_content"
    severity_default = 300
    cwe = "CWE-319"
    tags: tuple[str, ...] = ("mixed-content", "tls", "https")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.scheme == "https" or asset.primary_scheme == "https"

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        pr = await ctx.probe_fn(asset.url)
        if pr.error:
            return
        ct = pr.headers.get("content-type", "").lower()
        if "html" not in ct and not pr.body_text.strip().startswith("<"):
            return
        matches = _MIXED_RE.findall(pr.body_text)
        if not matches:
            return
        await ctx.capture_evidence(asset.url, pr)
        sample = matches[0]
        yield FindingDraft(
            asset_id=asset.id, scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"Mixed content HTTP resources at {asset.host}",
            category=self.category, severity=self.severity_default,
            url=asset.url, path="",
            description=(
                f"HTTPS page loads {len(matches)} HTTP resource(s). "
                f"First: {sample}. Mixed content exposes users to MITM attacks."
            ),
            remediation="Update all resource URLs to HTTPS.",
            cwe=self.cwe, tags=list(self.tags),
        )
