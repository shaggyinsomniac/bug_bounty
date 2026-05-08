"""
bounty.validate.stripe — Stripe secret key validator via /v1/balance.

Uses HTTP Basic auth with the key as username and empty password.
"""

from __future__ import annotations

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator


class StripeValidator(Validator):
    provider = "stripe"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key = candidate.value
        try:
            resp = await http.get(
                "https://api.stripe.com/v1/balance",
                auth=(key, ""),
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
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="live",
                identity=key[:20] + "…",
                scope={"livemode": data.get("livemode", False)},
                raw_response=data,
            )
        except httpx.HTTPStatusError as exc:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="error",
                error_message=str(exc),
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

