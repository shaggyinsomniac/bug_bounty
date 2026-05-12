"""
bounty.detect.java_spring.actuator — Spring Boot Actuator exposure detections.

Four detections:
- ActuatorExposed   — /actuator lists all enabled endpoints
- ActuatorEnv       — /actuator/env exposes config & credentials (severity 900)
- ActuatorHeapdump  — /actuator/heapdump downloads JVM memory (severity 950)
- ActuatorLoggers   — /actuator/loggers lists logger configuration
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


def _is_spring(fingerprints: list[FingerprintResult]) -> bool:
    """Return True if the asset is fingerprinted as a Spring application."""
    return (
        has_tech(fingerprints, "Spring")
        or has_tech(fingerprints, "Spring Boot")
        or has_tech(fingerprints, "spring")
        or has_tech(fingerprints, "spring-boot")
    )


class ActuatorExposed(Detection):
    """Spring Boot /actuator endpoint accessible — reveals all enabled sub-endpoints."""

    id = "java_spring.actuator.exposed"
    name = "Spring Boot Actuator Exposed"
    category = "java_spring_exposure"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("spring", "actuator", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return _is_spring(fingerprints)

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/actuator"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict):
            return
        # Spring Boot actuator returns {"_links": {"self": {...}, "health": {...}, ...}}
        if "_links" not in data:
            return
        links = data["_links"]
        if not isinstance(links, dict) or not links:
            return

        # Bump severity if dangerous endpoints are listed
        sev = self.severity_default
        dangerous = {"env", "heapdump", "threaddump", "logfile", "shutdown", "restart"}
        exposed_dangerous = dangerous & set(links.keys())
        if exposed_dangerous:
            sev = 800

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Spring Boot Actuator exposed at {asset.host}",
            category=self.category,
            severity=sev,
            url=url,
            path=path,
            description=(
                f"The Spring Boot Actuator is publicly accessible at /actuator and "
                f"exposes {len(links)} endpoint(s): {', '.join(sorted(links.keys())[:10])}. "
                + (f"Critical endpoints exposed: {', '.join(sorted(exposed_dangerous))}. " if exposed_dangerous else "")
                + "Actuator endpoints can leak configuration data, heap dumps, and "
                "in some configurations enable RCE via /shutdown or /restart."
            ),
            remediation=(
                "Restrict Actuator access behind authentication: add "
                "management.endpoints.web.exposure.include=health,info "
                "in application.properties. Require ADMIN role for all others. "
                "Consider binding the management port to localhost only."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class ActuatorEnv(Detection):
    """Spring Boot /actuator/env exposes application config including credentials."""

    id = "java_spring.actuator.env"
    name = "Spring Boot Actuator /env Exposed"
    category = "java_spring_exposure"
    severity_default = 900
    cwe = "CWE-312"
    tags = ("spring", "actuator", "credentials", "configuration")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return _is_spring(fingerprints)

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/actuator/env"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict):
            return
        # Spring Boot env contains "propertySources" list
        if "propertySources" not in data and "activeProfiles" not in data:
            return

        # Check if any values are asterisked out or plaintext
        body_lower = pr.body_text.lower()
        has_masked = "******" in pr.body_text or "****" in pr.body_text
        has_plaintext_creds = any(k in body_lower for k in [
            "password", "secret", "key", "token", "credential", "apikey"
        ])

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Spring Boot Actuator /env exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Spring Boot /actuator/env endpoint is publicly accessible. "
                "It exposes all application configuration properties including "
                + ("plaintext credentials and API keys. " if has_plaintext_creds and not has_masked else "")
                + "database connection strings, AWS credentials, and other secrets."
            ),
            remediation=(
                "Immediately disable public access to /actuator/env. "
                "Require authentication for all Actuator endpoints. "
                "Rotate any credentials that appear in the output. "
                "Upgrade to Spring Boot 2.x+ which masks sensitive values by default."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class ActuatorHeapdump(Detection):
    """Spring Boot /actuator/heapdump downloads JVM memory — critical data exposure."""

    id = "java_spring.actuator.heapdump"
    name = "Spring Boot Actuator /heapdump Exposed"
    category = "java_spring_exposure"
    severity_default = 950
    cwe = "CWE-312"
    tags = ("spring", "actuator", "heapdump", "memory-disclosure", "critical")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return _is_spring(fingerprints)

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/actuator/heapdump"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        # Heapdump is a binary file; check Content-Type or magic bytes
        ct = pr.content_type
        body = pr.body
        if len(body) < 100:
            return
        is_heapdump = (
            # HPROF magic: "JAVA PROFILE" at start
            body[:12].startswith(b"JAVA PROFILE")
            # gzip-compressed HPROF
            or (body[:2] == b"\x1f\x8b" and len(body) > 1024)
            # Large binary response (> 100KB) with octet-stream or hprof content-type
            or (len(body) > 1024 * 100 and ("octet-stream" in ct or "hprof" in ct or "java" in ct))
            # Any file claiming to be java hprof
            or "application/x-java-hprof" in ct
        )
        if not is_heapdump:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Spring Boot Actuator /heapdump exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                "The Spring Boot /actuator/heapdump endpoint is publicly accessible. "
                "It downloads a full JVM heap memory dump containing all objects "
                "currently in memory: plaintext passwords, session tokens, API keys, "
                "database credentials, and user PII."
            ),
            remediation=(
                "Immediately disable /actuator/heapdump. "
                "Restrict all Actuator endpoints behind authentication. "
                "Assume all in-memory credentials are compromised and rotate them."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class ActuatorLoggers(Detection):
    """Spring Boot /actuator/loggers exposes logger configuration."""

    id = "java_spring.actuator.loggers"
    name = "Spring Boot Actuator /loggers Exposed"
    category = "java_spring_exposure"
    severity_default = 500
    cwe = "CWE-284"
    tags = ("spring", "actuator", "loggers", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return _is_spring(fingerprints)

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/actuator/loggers"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict):
            return
        # Spring Boot loggers endpoint returns {"levels": [...], "loggers": {...}}
        if "loggers" not in data and "levels" not in data:
            return

        loggers = data.get("loggers", {})
        logger_count = len(loggers) if isinstance(loggers, dict) else 0

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:{path}",
            title=f"Spring Boot Actuator /loggers exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path=path,
            description=(
                f"The Spring Boot /actuator/loggers endpoint is publicly accessible. "
                f"It exposes {logger_count} logger configurations revealing internal "
                "package structure and can be abused to dynamically change log levels."
            ),
            remediation=(
                "Restrict access to /actuator/loggers with authentication. "
                "Only allow POST to /actuator/loggers for admin users."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


