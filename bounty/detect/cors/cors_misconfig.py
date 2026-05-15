"""
bounty.detect.cors.cors_misconfig — CORS misconfiguration detections.

Three detections:
- CorsWildcardWithCredentials  — reflected Origin + ACAC: true (severity 700)
- CorsNullOrigin               — null Origin reflected (severity 500)
- CorsPreflightWildcard        — ACAO: * present (severity 300)

All checks send a read-only GET with a custom Origin header using
``ctx.probe_fn_with_headers``.  When that callable is not set the detections
fall back to inspecting the standard probe (no custom header).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult, ProbeResult

__all__ = [
    "CorsWildcardWithCredentials",
    "CorsNullOrigin",
    "CorsPreflightWildcard",
]

_EVIL_ORIGIN = "https://evil.example.com"


async def _probe_with_origin(
    ctx: DetectionContext,
    url: str,
    origin: str,
) -> ProbeResult:
    """Send a GET to *url* with Origin: *origin*, honouring the context's
    probe_fn_with_headers if available, otherwise falling back to plain probe_fn."""
    if ctx.probe_fn_with_headers is not None:
        return await ctx.probe_fn_with_headers(url, {"Origin": origin})
    # Fallback — no custom headers; callers handle None.
    return await ctx.probe_fn(url)


def _acao(pr: ProbeResult) -> str:
    """Return the Access-Control-Allow-Origin header value (lower-cased)."""
    return pr.headers.get("access-control-allow-origin", "").strip()


def _acac(pr: ProbeResult) -> bool:
    """Return True if Access-Control-Allow-Credentials: true is present."""
    return pr.headers.get("access-control-allow-credentials", "").strip().lower() == "true"


# ---------------------------------------------------------------------------
# Detection 1 — Reflected Origin + Credentials
# ---------------------------------------------------------------------------

class CorsWildcardWithCredentials(Detection):
    """CORS: origin reflection with credentials — allows credential theft."""

    id = "cors.reflected_origin_with_credentials"
    name = "CORS: Reflected Origin with Access-Control-Allow-Credentials"
    category = "cors_misconfiguration"
    severity_default = 700
    cwe = "CWE-942"
    tags = ("cors", "credentials", "acao")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.http_status is None or asset.http_status < 500

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url
        pr = await _probe_with_origin(ctx, url, _EVIL_ORIGIN)
        if pr.error:
            return

        acao = _acao(pr)
        if acao != _EVIL_ORIGIN.lower() and acao != _EVIL_ORIGIN:
            return
        if not _acac(pr):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"CORS reflects arbitrary Origin with credentials at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="",
            description=(
                "The server reflects any Origin in Access-Control-Allow-Origin "
                "and also sends Access-Control-Allow-Credentials: true.  This "
                "allows a malicious origin to make credentialed cross-origin "
                "requests and steal session tokens or sensitive data."
            ),
            remediation=(
                "Restrict ACAO to an explicit allowlist of trusted origins.  "
                "Never combine a dynamically reflected (or wildcard) ACAO with "
                "Access-Control-Allow-Credentials: true."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


# ---------------------------------------------------------------------------
# Detection 2 — Null Origin Reflected
# ---------------------------------------------------------------------------

class CorsNullOrigin(Detection):
    """CORS: null origin reflected — sandbox / file:// bypass."""

    id = "cors.null_origin_reflected"
    name = "CORS: Null Origin Reflected"
    category = "cors_misconfiguration"
    severity_default = 500
    cwe = "CWE-942"
    tags = ("cors", "null-origin", "acao")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.http_status is None or asset.http_status < 500

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url
        pr = await _probe_with_origin(ctx, url, "null")
        if pr.error:
            return

        acao = _acao(pr)
        if acao != "null":
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"CORS reflects null Origin at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="",
            description=(
                "The server returns Access-Control-Allow-Origin: null when "
                "presented with Origin: null.  Pages sandboxed via the "
                "sandbox attribute or loaded from file:// can exploit this "
                "to make credentialed cross-origin requests."
            ),
            remediation=(
                "Do not reflect 'null' in ACAO.  Only allow explicitly listed "
                "trusted origins."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


# ---------------------------------------------------------------------------
# Detection 3 — ACAO: * (wildcard)
# ---------------------------------------------------------------------------

class CorsPreflightWildcard(Detection):
    """CORS: Access-Control-Allow-Origin: * (wildcard) — low-severity signal."""

    id = "cors.preflight_wildcard"
    name = "CORS: Wildcard Access-Control-Allow-Origin"
    category = "cors_misconfiguration"
    severity_default = 300
    cwe = "CWE-942"
    tags = ("cors", "wildcard", "acao")

    def applicable_to(self, asset: Asset, fingerprints: list[FingerprintResult]) -> bool:
        return asset.http_status is None or asset.http_status < 500

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url
        pr = await ctx.probe_fn(url)
        if pr.error:
            return

        acao = _acao(pr)
        if acao != "*":
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}",
            title=f"CORS wildcard ACAO at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="",
            description=(
                "The server sends Access-Control-Allow-Origin: * allowing any "
                "origin to read the response.  This is often intentional for "
                "public APIs but warrants review for endpoints serving "
                "sensitive data."
            ),
            remediation=(
                "Restrict ACAO to known trusted origins unless the endpoint "
                "is a deliberately public API serving only non-sensitive data."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

