"""
bounty.detect.discovery.robots_sitemap — Robots.txt and sitemap.xml mining.

Two detections:
- RobotsSensitivePaths  — Disallow entries with sensitive path keywords (severity 300)
- SitemapExposed        — sitemap.xml present and listing URLs (severity 200)
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

__all__ = ["RobotsSensitivePaths", "SitemapExposed"]

# Keywords that indicate a disallowed path is worth noting
_SENSITIVE_KEYWORDS = re.compile(
    r"(?:admin|backup|config|private|internal|api|\.git|db|sql|dev|staging|test)",
    re.IGNORECASE,
)

# Simple URL extractor for sitemaps
_LOC_RE = re.compile(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", re.IGNORECASE)
_DISALLOW_RE = re.compile(r"^Disallow:\s*(.+)$", re.MULTILINE | re.IGNORECASE)


def _parse_sensitive_disallows(robots_text: str) -> list[str]:
    """Return a list of Disallow paths that contain sensitive keywords."""
    found: list[str] = []
    for match in _DISALLOW_RE.finditer(robots_text):
        path = match.group(1).strip()
        if path and _SENSITIVE_KEYWORDS.search(path):
            found.append(path)
    return found


class RobotsSensitivePaths(Detection):
    """robots.txt Disallow entries expose sensitive path names."""

    id = "discovery.robots_sensitive_paths"
    name = "robots.txt Discloses Sensitive Paths"
    category = "information_disclosure"
    severity_default = 300
    cwe = "CWE-200"
    tags = ("robots", "discovery", "path-disclosure")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/robots.txt"
        pr = await ctx.probe_fn(url)
        if pr.error or pr.status_code != 200:
            return

        ct = pr.content_type
        if ct and "html" in ct and "text/plain" not in ct:
            # HTML response — likely a soft-404; ignore
            if b"<html" in pr.body[:200].lower() or b"<!doctype" in pr.body[:200].lower():
                return

        text = pr.body_text
        if "user-agent" not in text.lower() and "disallow" not in text.lower():
            return

        sensitive = _parse_sensitive_disallows(text)
        if not sensitive:
            return

        paths_str = ", ".join(sensitive[:20])  # cap at 20 in title
        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"robots.txt discloses sensitive paths at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/robots.txt",
            description=(
                f"The robots.txt file at '{asset.host}' lists Disallow entries "
                f"that reveal sensitive internal paths: {paths_str}.  "
                "While robots.txt is publicly readable, explicitly listing "
                "sensitive paths aids attackers in targeting hidden endpoints."
            ),
            remediation=(
                "Remove sensitive path references from robots.txt.  "
                "Access controls on sensitive endpoints should not rely on "
                "robots.txt for security — implement proper authentication."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class SitemapExposed(Detection):
    """sitemap.xml is publicly accessible and lists application URLs."""

    id = "discovery.sitemap_exposed"
    name = "sitemap.xml Exposed"
    category = "information_disclosure"
    severity_default = 200
    cwe = "CWE-200"
    tags = ("sitemap", "discovery", "url-disclosure")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        for sitemap_path in ("/sitemap.xml", "/sitemap_index.xml"):
            url = asset.url.rstrip("/") + sitemap_path
            pr = await ctx.probe_fn(url)
            if pr.error or pr.status_code != 200:
                continue

            body = pr.body_text
            # Must look like XML sitemap content
            if "<urlset" not in body and "<sitemapindex" not in body and "<url>" not in body:
                continue

            urls = _LOC_RE.findall(body)
            if not urls:
                continue

            url_count = len(urls)
            preview = urls[:5]
            preview_str = "\n".join(preview)

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}",
                title=f"sitemap.xml exposed at {asset.host} ({url_count} URLs)",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=sitemap_path,
                description=(
                    f"The sitemap at '{url}' is publicly accessible and lists "
                    f"{url_count} URL(s).  This provides a complete map of the "
                    f"application's content, accelerating further enumeration.\n\n"
                    f"Sample URLs:\n{preview_str}"
                ),
                remediation=(
                    "Sitemap.xml is usually intentional; ensure it does not "
                    "reference private or authenticated-only pages that could "
                    "aid attackers in mapping the application."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return  # one finding per asset (first sitemap found)

