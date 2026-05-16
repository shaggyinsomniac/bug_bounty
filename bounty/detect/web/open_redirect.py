from __future__ import annotations
from typing import ClassVar
from collections.abc import AsyncGenerator
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = ["OpenRedirectReflected"]

_REDIRECT_PARAMS = ["url", "redirect", "return", "next", "dest",
                    "destination", "redir", "callback", "goto", "to"]
_EVIL_URL = "https://evil-test.example.org"


class OpenRedirectReflected(Detection):
    id = "web.open_redirect.reflected"
    name = "Open Redirect — Reflected Query Parameter"
    category = "open_redirect"
    severity_default = 500
    cwe = "CWE-601"
    tags: ClassVar[tuple[str, ...]] = ("open-redirect", "redirect")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.scheme in ("http", "https")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        for param in _REDIRECT_PARAMS:
            test_url = f"{asset.url}?{urlencode({param: _EVIL_URL})}"
            pr = await ctx.probe_fn(test_url)
            if pr.error:
                continue
            if pr.status_code not in range(300, 400):
                continue
            location = pr.headers.get("location", "")
            parsed = urlparse(location)
            evil_parsed = urlparse(_EVIL_URL)
            if parsed.netloc == evil_parsed.netloc:
                await ctx.capture_evidence(test_url, pr)
                yield FindingDraft(
                    asset_id=asset.id, scan_id=ctx.scan_id,
                    dedup_key=f"{self.id}:{asset.id}:{param}",
                    title=f"Open redirect via '{param}' parameter at {asset.host}",
                    category=self.category, severity=self.severity_default,
                    url=test_url, path=f"?{param}=",
                    description=(
                        f"The '{param}' query parameter is reflected in a 3xx redirect "
                        "Location header without validation, enabling phishing attacks."
                    ),
                    remediation=(
                        "Validate redirect destinations against an allowlist of trusted URLs. "
                        "Reject any destination that does not match your domain."
                    ),
                    cwe=self.cwe, tags=list(self.tags),
                )
                return
