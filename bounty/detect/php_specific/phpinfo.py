"""
bounty.detect.php_specific.phpinfo — PHP info page exposure detection.

One detection:
- PhpinfoExposed — phpinfo() output at /info.php, /phpinfo.php, /test.php, etc.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_PHPINFO_PATHS = [
    "/info.php",
    "/phpinfo.php",
    "/test.php",
    "/php.php",
    "/phpi.php",
    "/php_info.php",
]

_PHPINFO_MARKERS = [
    b"PHP Version",
    b"phpinfo()",
    b"PHP Extension",
    b"php.ini",
    b"<title>phpinfo()</title>",
]


class PhpinfoExposed(Detection):
    """PHP info page (phpinfo()) accessible — exposes server config and paths."""

    id = "php_specific.phpinfo.exposed"
    name = "PHP Info Page Exposed"
    category = "php_exposure"
    severity_default = 500
    cwe = "CWE-200"
    tags = ("php", "phpinfo", "information-disclosure", "server-config")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "PHP")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        base = asset.url.rstrip("/")
        for path in _PHPINFO_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if pr.status_code != 200:
                continue
            body = pr.body
            if len(body) < 50:
                continue
            if not any(sig in body for sig in _PHPINFO_MARKERS):
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"PHP info page exposed at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    f"A PHP info page (phpinfo()) is publicly accessible at {path}. "
                    "It exposes the PHP build configuration, loaded extensions, "
                    "server environment variables, file paths, and compilation flags "
                    "that aid in targeted exploitation."
                ),
                remediation=(
                    f"Delete {path} immediately. Never deploy phpinfo() pages to "
                    "production. Review all .php files in the web root for diagnostic "
                    "pages."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return


