"""
bounty.validate.braintree — Braintree key validator.

Braintree uses a public_key:private_key pair with merchant_id.
We look for merchant_id in context. If key contains `:` it is
treated as public_key:private_key. Without both merchant_id and
paired credentials, validation is skipped.
"""

from __future__ import annotations

import base64
import re

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator

_MERCHANT_RE = re.compile(r"merchant[_\s-]?id[\"'\s:=]+([a-z0-9]{10,20})", re.IGNORECASE)


class BraintreeValidator(Validator):
    provider = "braintree"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key = candidate.value
        # Expect key in format public_key:private_key
        if ":" not in key:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="needs braintree public_key:private_key pair",
            )
        context = candidate.context_before + " " + candidate.context_after
        m = _MERCHANT_RE.search(context)
        if not m:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="needs braintree merchant_id context",
            )
        merchant_id = m.group(1)
        public_key, private_key = key.split(":", 1)
        creds = base64.b64encode(f"{public_key}:{private_key}".encode()).decode()
        try:
            resp = await http.get(
                f"https://api.braintreegateway.com/merchants/{merchant_id}",
                headers={"Authorization": f"Basic {creds}"},
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
                identity=merchant_id,
                scope={"merchant_id": merchant_id},
                raw_response={"merchant_id": merchant_id},
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

