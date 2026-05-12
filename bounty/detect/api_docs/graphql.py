"""
bounty.detect.api_docs.graphql — GraphQL endpoint exposure detections.

Two detections:
- GraphqlIntrospection — POST /graphql with __schema query returns schema
- GraphqlPlayground    — GraphiQL / Playground UI accessible publicly
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql"]
_PLAYGROUND_PATHS = ["/playground", "/graphiql", "/graphql/playground", "/api/graphiql"]

_INTROSPECTION_QUERY = {
    "query": "{ __schema { queryType { name } mutationType { name } types { name } } }"
}


class GraphqlIntrospection(Detection):
    """GraphQL endpoint has introspection enabled — schema disclosure.

    Uses POST with an introspection query (semantically read-only).
    Falls back to checking GET response for GraphQL indicators if post_json_fn
    is not available in the context.
    """

    id = "api_docs.graphql.introspection"
    name = "GraphQL Introspection Enabled"
    category = "api_docs_exposure"
    severity_default = 500
    cwe = "CWE-200"
    tags = ("api-docs", "graphql", "introspection", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        base = asset.url.rstrip("/")
        for path in _GRAPHQL_PATHS:
            url = base + path

            # Try POST introspection if available
            if ctx.post_json_fn is not None:
                pr = await ctx.post_json_fn(url, _INTROSPECTION_QUERY)
            else:
                # Fall back to GET probe to check endpoint existence + indicators
                pr = await ctx.probe_fn(url)

            if pr.status_code not in (200, 400):
                continue

            body_text = pr.body_text
            if not body_text:
                continue

            # Must look like a GraphQL response
            is_introspection_response = False
            try:
                data = json.loads(body_text)
                if isinstance(data, dict):
                    # Introspection succeeded
                    if "data" in data and "__schema" in str(data.get("data", {})):
                        is_introspection_response = True
                    # Some servers return errors that confirm introspection exists
                    elif "errors" in data and "introspection" in str(data).lower():
                        # Introspection is explicitly mentioned in errors — it exists but may be disabled
                        continue
                    # GraphQL endpoint with valid response structure
                    elif "data" in data or "errors" in data:
                        if "queryType" in body_text or "__schema" in body_text or "types" in body_text:
                            is_introspection_response = True
            except (ValueError, UnicodeDecodeError):
                pass

            if not is_introspection_response:
                # Try to infer from body content
                if "graphql" in body_text.lower() and "__schema" in body_text:
                    is_introspection_response = True

            if not is_introspection_response:
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"GraphQL introspection enabled at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    f"GraphQL introspection is enabled at {path}. "
                    "An attacker can enumerate the entire schema including all "
                    "types, queries, mutations, and field names without authentication."
                ),
                remediation=(
                    "Disable introspection in production: set introspection=False "
                    "in your GraphQL server configuration. Use field-level "
                    "authorization and depth-limiting for the API."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return


class GraphqlPlayground(Detection):
    """GraphQL Playground or GraphiQL UI accessible publicly."""

    id = "api_docs.graphql.playground"
    name = "GraphQL Playground / GraphiQL Exposed"
    category = "api_docs_exposure"
    severity_default = 300
    cwe = "CWE-200"
    tags = ("api-docs", "graphql", "playground", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        base = asset.url.rstrip("/")
        for path in _PLAYGROUND_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if pr.status_code != 200:
                continue
            body_lower = pr.body_text.lower()
            # Playground/GraphiQL HTML markers
            if not any(m in body_lower for m in [
                "graphiql", "graphql playground", "graphqlplayground",
                "graphql-playground", "altair graphql"
            ]):
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"GraphQL Playground exposed at {asset.host}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    f"A GraphQL interactive playground (GraphiQL/Playground) is "
                    f"accessible at {path}. It provides a full IDE for exploring "
                    "and executing GraphQL queries, making it trivial to attack the API."
                ),
                remediation=(
                    "Disable GraphQL Playground in production environments. "
                    "If needed, restrict access to authenticated users or "
                    "internal IP ranges only."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return

