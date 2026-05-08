"""
bounty.validate.razorpay — Razorpay key validator via /v1/payments.

Paired credentials: rzp_live_/rzp_test_ key_id + 24-char secret.
GET /v1/payments?count=1 is a minimal read-only call.
"""

from __future__ import annotations

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator


class RazorpayValidator(Validator):
    provider = "razorpay"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key_id = candidate.value
        secret = candidate.paired_value or ""

        if not secret:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="Secret key not found near key ID — cannot validate",
            )

        try:
            resp = await http.get(
                "https://api.razorpay.com/v1/payments?count=1",
                auth=(key_id, secret),
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
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="live",
                identity=key_id,
                scope={"livemode": key_id.startswith("rzp_live_")},
                raw_response=resp.json() if resp.content else None,
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

