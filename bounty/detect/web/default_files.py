from __future__ import annotations
from collections.abc import AsyncGenerator
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = ["DefaultPageDetected", "InstallScriptExposed", "PackageJsonExposed"]

_DEFAULT_PATHS = ["/test.html", "/index2.html", "/default.html", "/sample/", "/examples/"]
_INSTALL_PATHS = ["/install.php", "/setup.php", "/installer/", "/install/index.php"]
_INSTALL_KEYWORDS = [b"install", b"setup", b"wizard", b"database", b"configuration"]


def _is_soft_404(body: bytes) -> bool:
    low = body.lower()
    return b"not found" in low or b"404" in low or len(body) < 50


class DefaultPageDetected(Detection):
    id = "web.default_files.default_page"
    name = "Default/Sample Page Detected"
    category = "default_files"
    severity_default = 200
    cwe = "CWE-538"
    tags: tuple[str, ...] = ("default-files", "information-disclosure")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return
        for path in _DEFAULT_PATHS:
            url = asset.url.rstrip("/") + path
            pr = await ctx.probe_fn(url)
            if pr.error or pr.status_code not in range(200, 300):
                continue
            if _is_soft_404(pr.body):
                continue
            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id, scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Default/sample page exposed at {asset.host}{path}",
                category=self.category, severity=self.severity_default,
                url=url, path=path,
                description=f"Default page {path} is publicly accessible, indicating test content.",
                remediation="Remove or restrict default/sample pages from production.",
                cwe=self.cwe, tags=list(self.tags),
            )
            return


class InstallScriptExposed(Detection):
    id = "web.default_files.install_script"
    name = "Install/Setup Script Exposed"
    category = "default_files"
    severity_default = 600
    cwe = "CWE-538"
    tags: tuple[str, ...] = ("default-files", "install-script")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return
        for path in _INSTALL_PATHS:
            url = asset.url.rstrip("/") + path
            pr = await ctx.probe_fn(url)
            if pr.error or pr.status_code not in range(200, 300):
                continue
            body_low = pr.body.lower()
            if not any(kw in body_low for kw in _INSTALL_KEYWORDS):
                continue
            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id, scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Install/setup script exposed at {asset.host}{path}",
                category=self.category, severity=self.severity_default,
                url=url, path=path,
                description=(
                    f"Installation script at {path} is accessible. "
                    "This may allow an attacker to reconfigure or take over the application."
                ),
                remediation="Remove or protect install scripts after initial setup.",
                cwe=self.cwe, tags=list(self.tags),
            )
            return


class PackageJsonExposed(Detection):
    id = "web.default_files.package_json"
    name = "package.json Exposed"
    category = "default_files"
    severity_default = 300
    cwe = "CWE-538"
    tags: tuple[str, ...] = ("default-files", "package-json", "dependency-disclosure")

    async def run(self, asset: Asset, ctx: DetectionContext) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/package.json"
        pr = await ctx.probe_fn(url)
        if pr.error or pr.status_code not in range(200, 300):
            return
        if b'"dependencies"' not in pr.body and b'"version"' not in pr.body:
            return
        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id, scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"package.json exposed at {asset.host}",
            category=self.category, severity=self.severity_default,
            url=url, path="/package.json",
            description=(
                "package.json is publicly accessible, revealing dependency names "
                "and versions that attackers can use for targeted exploitation."
            ),
            remediation="Block access to package.json via web server configuration.",
            cwe=self.cwe, tags=list(self.tags),
        )
