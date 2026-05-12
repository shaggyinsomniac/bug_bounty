"""
bounty.detect.api_docs.postman — Postman collection exposure detection.

One detection:
- PostmanCollectionExposed — *.postman_collection.json accessible publicly
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_POSTMAN_PATHS = [
    "/postman_collection.json",
    "/api.postman_collection.json",
    "/collection.postman_collection.json",
    "/.postman_collection.json",
    "/postman/collection.json",
    "/api/postman_collection.json",
    "/docs/postman_collection.json",
]


class PostmanCollectionExposed(Detection):
    """Postman collection JSON file accessible publicly — full API blueprint."""

    id = "api_docs.postman.collection_exposed"
    name = "Postman Collection Exposed"
    category = "api_docs_exposure"
    severity_default = 500
    cwe = "CWE-200"
    tags = ("api-docs", "postman", "credentials", "information-disclosure")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return True

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        base = asset.url.rstrip("/")
        for path in _POSTMAN_PATHS:
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
            # Postman collection v2 has "info" with "_postman_id" and "item"
            # v1 has "id", "name", "requests"
            is_postman = (
                ("info" in data and "item" in data)
                or ("_postman_id" in str(data))
                or ("requests" in data and "name" in data)
                or "postman" in pr.body_text.lower()
            )
            if not is_postman:
                continue

            # Check for credentials in the collection (severity bump)
            has_creds = any(m in pr.body_text for m in [
                "Bearer ", "Authorization", "api_key", "apikey", "token", "password", "secret"
            ])
            sev = 700 if has_creds else self.severity_default

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Postman collection exposed at {asset.host}",
                category=self.category,
                severity=sev,
                url=url,
                path=path,
                description=(
                    f"A Postman collection file is publicly accessible at {path}. "
                    "It may contain complete API documentation, authentication headers, "
                    "API keys, and pre-configured attack payloads."
                    + (" The collection appears to contain credentials." if has_creds else "")
                ),
                remediation=(
                    "Remove the Postman collection from publicly accessible paths. "
                    "Review the collection for embedded credentials and rotate any found. "
                    "Store Postman collections privately in your team workspace."
                ),
                cwe=self.cwe,
                tags=list(self.tags),
            )
            return

