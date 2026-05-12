"""
bounty.detect.php_specific.composer — Composer dependency file exposure detection.

One detection:
- ComposerFilesExposed — /composer.json and/or /composer.lock publicly accessible
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_COMPOSER_PATHS = [
    ("/composer.json", [b'"require"', b'"name"', b'"version"']),
    ("/composer.lock", [b'"packages"', b'"content-hash"', b'"name"']),
]


class ComposerFilesExposed(Detection):
    """Composer dependency files exposed — reveals package versions and structure."""

    id = "php_specific.composer.files_exposed"
    name = "Composer Files Exposed"
    category = "php_exposure"
    severity_default = 300
    cwe = "CWE-200"
    tags = ("php", "composer", "version-disclosure", "dependency")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True  # composer.json may exist in any PHP or polyglot project

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        base = asset.url.rstrip("/")
        for path, sigs in _COMPOSER_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if pr.status_code != 200:
                continue
            body = pr.body
            if len(body) < 20:
                continue
            if not any(sig in body for sig in sigs):
                continue
            # Validate it's actually JSON
            try:
                data = json.loads(pr.body_text)
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(data, dict):
                continue

            # composer.lock reveals exact package versions (higher value for attackers)
            sev = 400 if path == "/composer.lock" else self.severity_default

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Composer {path.lstrip('/')} exposed at {asset.host}",
                category=self.category,
                severity=sev,
                url=url,
                path=path,
                description=(
                    f"The {path} file is publicly accessible. "
                    + ("composer.lock reveals exact versions of all installed packages, "
                       "allowing attackers to identify packages with known CVEs. "
                       if path == "/composer.lock" else
                       "composer.json reveals the project's dependency requirements "
                       "and scripts. ")
                ),
                remediation=(
                    "Block access to composer.json and composer.lock via server "
                    "configuration. These files should never be in the web root; "
                    "move them above the public_html directory."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return

