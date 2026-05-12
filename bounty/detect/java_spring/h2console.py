"""
bounty.detect.java_spring.h2console — H2 in-process database console detection.

One detection:
- H2Console — /h2-console exposed without authentication
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class H2Console(Detection):
    """Spring Boot H2 in-memory database console accessible at /h2-console."""

    id = "java_spring.h2_console"
    name = "H2 Database Console Exposed"
    category = "java_spring_exposure"
    severity_default = 800
    cwe = "CWE-284"
    tags = ("spring", "h2", "database", "rce", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return (
            has_tech(fingerprints, "Spring")
            or has_tech(fingerprints, "Spring Boot")
            or has_tech(fingerprints, "spring")
            or has_tech(fingerprints, "spring-boot")
        )

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/h2-console"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_lower = pr.body_text.lower()
        if not any(m in body_lower for m in ["h2 console", "h2-console", "jdbc url", "h2 database"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"H2 database console exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The H2 in-memory database console is publicly accessible at /h2-console. "
                "It allows unauthenticated SQL execution against the application database. "
                "H2's CREATE ALIAS feature enables Java code execution (RCE)."
            ),
            remediation=(
                "Set spring.h2.console.enabled=false in production. "
                "If H2 is needed, restrict access: spring.h2.console.settings.web-allow-others=false. "
                "Apply authentication middleware to /h2-console."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

