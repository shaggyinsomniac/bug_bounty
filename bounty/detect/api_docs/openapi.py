"""
bounty.detect.api_docs.openapi — Swagger UI and OpenAPI spec exposure detections.

Two detections:
- SwaggerUiExposed   — Swagger UI HTML accessible at common paths
- OpenApiJsonExposed — OpenAPI/Swagger JSON spec accessible with endpoint data
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_SWAGGER_UI_PATHS = [
    "/swagger-ui.html",
    "/swagger/index.html",
    "/swagger-ui/index.html",
    "/api/swagger-ui.html",
    "/swagger",
    "/api-docs",
    "/docs",
]

_SWAGGER_UI_MARKERS = ["swagger-ui", "swagger ui", "swaggerui", "api documentation"]


class SwaggerUiExposed(Detection):
    """Swagger UI accessible publicly — reveals full API surface."""

    id = "api_docs.swagger_ui.exposed"
    name = "Swagger UI Exposed"
    category = "api_docs_exposure"
    severity_default = 300
    cwe = "CWE-200"
    tags = ("api-docs", "swagger", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        base = asset.url.rstrip("/")
        for path in _SWAGGER_UI_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if pr.status_code != 200:
                continue
            body_lower = pr.body_text.lower()
            if not any(m in body_lower for m in _SWAGGER_UI_MARKERS):
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Swagger UI exposed at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    f"The Swagger UI is publicly accessible at {path}. "
                    "It provides an interactive browser for all API endpoints, "
                    "parameters, and authentication schemes, dramatically reducing "
                    "the effort required to attack the API."
                ),
                remediation=(
                    "Restrict Swagger UI to authenticated users or internal networks. "
                    "Disable it entirely in production environments, or add "
                    "IP-based access controls."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return


_OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api-docs/swagger.json",
    "/v1/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
]


def _has_auth_or_internal_endpoints(data: object) -> bool:
    """Check if OpenAPI spec contains auth schemes or internal-looking paths."""
    if not isinstance(data, dict):
        return False
    # Check for security schemes
    components = data.get("components", {})
    if isinstance(components, dict):
        security_schemes = components.get("securitySchemes", {})
        if security_schemes:
            return True
    # Old swagger 2.0
    sec_defs = data.get("securityDefinitions", {})
    if sec_defs:
        return True
    # Check paths for internal-looking endpoints
    paths = data.get("paths", {})
    if isinstance(paths, dict) and len(paths) > 0:
        return True
    return False


class OpenApiJsonExposed(Detection):
    """OpenAPI / Swagger JSON spec accessible publicly."""

    id = "api_docs.openapi_json.exposed"
    name = "OpenAPI / Swagger JSON Spec Exposed"
    category = "api_docs_exposure"
    severity_default = 400
    cwe = "CWE-200"
    tags = ("api-docs", "openapi", "swagger", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        base = asset.url.rstrip("/")
        for path in _OPENAPI_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if pr.status_code != 200:
                continue
            body_text = pr.body_text.strip()
            if not body_text or body_text[0] not in "{[":
                continue
            try:
                data = json.loads(body_text)
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            # Must look like an OpenAPI spec
            is_openapi = (
                "openapi" in data
                or "swagger" in data
                or ("info" in data and "paths" in data)
            )
            if not is_openapi:
                continue

            # Severity bump if it has auth schemes (+100)
            sev = self.severity_default
            if _has_auth_or_internal_endpoints(data):
                sev = min(600, sev + 100)

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"OpenAPI spec exposed at {asset.host}",
                category=self.category,
                severity=sev,
                url=url,
                path=path,
                description=(
                    f"The OpenAPI specification is publicly accessible at {path}. "
                    "It exposes the complete API surface including all endpoints, "
                    "parameters, authentication mechanisms, and data models."
                ),
                remediation=(
                    "Restrict the OpenAPI spec to authenticated users. "
                    "Remove the spec endpoint from production deployments or "
                    "add authentication middleware."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return

