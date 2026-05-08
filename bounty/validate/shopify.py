"""
bounty.validate.shopify — Shopify admin access token validator.

shpat_ tokens are shop-scoped. We attempt to extract the shop domain from
context_before/context_after; if none found, we return status=skipped.
"""

from __future__ import annotations

import re

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator

_SHOP_DOMAIN_RE = re.compile(r"([a-z0-9][a-z0-9\-]{0,60}[a-z0-9])\.myshopify\.com", re.IGNORECASE)


def _extract_shop_domain(candidate: SecretCandidate) -> str | None:
    context = candidate.context_before + candidate.context_after
    m = _SHOP_DOMAIN_RE.search(context)
    if m:
        return m.group(0).lower()
    return None


class ShopifyValidator(Validator):
    provider = "shopify"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        token = candidate.value
        shop_domain = _extract_shop_domain(candidate)

        if not shop_domain:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="Shop domain unknown — cannot validate without it",
            )

        try:
            resp = await http.get(
                f"https://{shop_domain}/admin/api/2024-01/shop.json",
                headers={"X-Shopify-Access-Token": token},
                timeout=15,
            )
            if resp.status_code in (401, 403):
                return ValidationResult(
                    provider=self.provider,
                    secret_preview=candidate.secret_preview,
                    secret_hash=candidate.secret_hash,
                    secret_pattern=candidate.pattern_name,
                    status="invalid",
                )
            resp.raise_for_status()
            data = resp.json()
            shop = data.get("shop", {})
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="live",
                identity=shop.get("name"),
                scope={
                    "shop_id": shop.get("id"),
                    "domain": shop_domain,
                    "plan": shop.get("plan_name"),
                },
                raw_response=shop,
            )
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="error",
                error_message=str(exc),
            )

