"""
bounty.detect.cms_specific.wordpress — WordPress-specific detections.

Five detections:
- WpDebugLog       — /wp-content/debug.log reveals PHP errors
- WpInstallExposed — /wp-admin/install.php still accessible
- WpUserEnum       — /?author=1 redirect leaks usernames
- WpReadmeExposed  — /readme.html reveals version info
- XmlrpcExposed    — /xmlrpc.php accessible (brute-force / SSRF vector)
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class WpDebugLog(Detection):
    """WordPress debug log (/wp-content/debug.log) exposed publicly."""

    id = "cms.wordpress.debug_log"
    name = "WordPress Debug Log Exposed"
    category = "cms_misconfiguration"
    severity_default = 500
    cwe = "CWE-215"
    tags = ("wordpress", "debug", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "WordPress")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/wp-content/debug.log"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body = pr.body
        if len(body) < 20:
            return
        # Must contain PHP error/notice markers
        sigs = [b"PHP Notice", b"PHP Warning", b"PHP Fatal", b"PHP Deprecated",
                b"PHP Parse error", b"WordPress", b"wp-content", b"Stack trace"]
        if not any(sig in body for sig in sigs):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"WordPress debug log exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The WordPress debug log at /wp-content/debug.log is publicly "
                "accessible. It may reveal file paths, plugin names, database "
                "queries, and application internals useful for further attacks."
            ),
            remediation=(
                "Set WP_DEBUG_LOG to false in wp-config.php or move the log file "
                "outside the web root. Restrict access to /wp-content/debug.log "
                "via server configuration."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class WpInstallExposed(Detection):
    """WordPress install script (/wp-admin/install.php) still accessible."""

    id = "cms.wordpress.install_exposed"
    name = "WordPress Install Script Exposed"
    category = "cms_misconfiguration"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("wordpress", "install", "authentication-bypass")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "WordPress")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/wp-admin/install.php"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_lower = pr.body_text.lower()
        if "wordpress" not in body_lower and "installation" not in body_lower and "install" not in body_lower:
            return
        # Look for install-step indicators
        if not any(m in body_lower for m in ["step 1", "site title", "language", "set up", "already installed"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"WordPress install script exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The WordPress installation script at /wp-admin/install.php is "
                "accessible. If already installed it shows the 'already installed' "
                "page; on a blank DB it allows full takeover by completing setup."
            ),
            remediation=(
                "Remove or restrict access to /wp-admin/install.php after "
                "installation. Add IP-based restrictions via server config or "
                ".htaccess."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


_AUTHOR_RE = re.compile(r"/author/[^/?]+", re.IGNORECASE)


class WpUserEnum(Detection):
    """WordPress username enumeration via /?author=1 redirect."""

    id = "cms.wordpress.user_enum"
    name = "WordPress Username Enumeration via Author Redirect"
    category = "cms_misconfiguration"
    severity_default = 300
    cwe = "CWE-200"
    tags = ("wordpress", "user-enumeration", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "WordPress")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/?author=1"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        # We expect a redirect (301/302) or final URL containing /author/
        leaked_user: str | None = None

        # Check redirect_chain for /author/ URL
        for redir_url in pr.redirect_chain:
            m = _AUTHOR_RE.search(redir_url)
            if m:
                full = m.group(0)
                leaked_user = full.split("/author/", 1)[-1].strip("/") or full
                break

        # Also check the final URL
        if not leaked_user:
            m2 = _AUTHOR_RE.search(pr.final_url)
            if m2:
                full2 = m2.group(0)
                leaked_user = full2.split("/author/", 1)[-1].strip("/") or full2

        if not leaked_user:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"WordPress username enumeration at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                f"WordPress redirects /?author=1 to an author archive URL "
                f"({leaked_user}), revealing valid usernames. Attackers can iterate "
                "author IDs to enumerate all user accounts."
            ),
            remediation=(
                "Disable author archive redirects via SEO plugins (e.g. Yoast "
                "'Disable Author Sitemap'). Alternatively add a redirect rule to "
                "block /?author={n} patterns at the server level."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


_WP_VERSION_RE = re.compile(rb"version (\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


class WpReadmeExposed(Detection):
    """WordPress /readme.html exposes version information."""

    id = "cms.wordpress.readme_exposed"
    name = "WordPress readme.html Version Disclosure"
    category = "cms_misconfiguration"
    severity_default = 200
    cwe = "CWE-200"
    tags = ("wordpress", "version-disclosure", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "WordPress")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/readme.html"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_lower = pr.body_text.lower()
        if "wordpress" not in body_lower:
            return
        # Extract version if present
        version = ""
        m = _WP_VERSION_RE.search(pr.body)
        if m:
            version = m.group(1).decode("utf-8", errors="replace")

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"WordPress readme.html exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                f"The WordPress readme.html file is publicly accessible"
                + (f" and reveals version {version}" if version else "")
                + ". This aids attackers in selecting version-specific exploits."
            ),
            remediation=(
                "Delete /readme.html, /license.txt, and /wp-activate.php from the "
                "web root, or block them via server configuration."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class XmlrpcExposed(Detection):
    """WordPress xmlrpc.php accessible — brute-force and SSRF vector."""

    id = "cms.wordpress.xmlrpc_exposed"
    name = "WordPress xmlrpc.php Exposed"
    category = "cms_misconfiguration"
    severity_default = 500
    cwe = "CWE-284"
    tags = ("wordpress", "xmlrpc", "brute-force")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "WordPress")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/xmlrpc.php"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        # xmlrpc.php on GET returns 405 with "XML-RPC server accepts POST requests only"
        # or 200 if the plugin sends a proper response. Accept both.
        if pr.status_code not in (200, 405):
            return
        body_lower = pr.body_text.lower()
        if "xml-rpc" not in body_lower and "xmlrpc" not in body_lower:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"WordPress xmlrpc.php exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "WordPress xmlrpc.php is accessible. It enables credential "
                "brute-forcing via system.multicall (bypasses login attempt limits), "
                "and can be abused for SSRF attacks via pingback.ping."
            ),
            remediation=(
                "Disable XML-RPC entirely if not in use: add "
                "`add_filter('xmlrpc_enabled', '__return_false');` to functions.php, "
                "or block /xmlrpc.php at the server/WAF level."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

