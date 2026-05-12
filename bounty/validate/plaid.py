"""
bounty.validate.plaid — Plaid client_id:secret validator.

Key must be in format client_id:secret.
A 400 "INVALID_ACCESS_TOKEN" response means credentials are valid (auth passed).
A 400 "INVALID_API_KEYS" means credentials are invalid.
"""

from __future__ import annotations

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator


class PlaidValidator(Validator):
    provider = "plaid"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key = candidate.value
        if ":" not in key:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="needs plaid client_id:secret pair",
            )
        client_id, secret = key.split(":", 1)
        try:
            resp = await http.post(
                "https://sandbox.plaid.com/items/get",
                json={"client_id": client_id, "secret": secret, "access_token": "access-sandbox-test"},
                timeout=15,
            )
            if resp.status_code == 400:
                data = resp.json()
                error_code = data.get("error_code", "")
                if error_code == "INVALID_ACCESS_TOKEN":
                    # Auth passed; credentials are valid
                    return ValidationResult(
                        provider=self.provider,
                        secret_preview=candidate.secret_preview,
                        secret_hash=candidate.secret_hash,
                        secret_pattern=candidate.pattern_name,
                        status="live",
                        identity=client_id,
                        scope={"environment": "sandbox"},
                        raw_response=data,
                    )
                # Any other 400 (including INVALID_API_KEYS) = invalid creds
                return ValidationResult(
                    provider=self.provider,
                    secret_preview=candidate.secret_preview,
                    secret_hash=candidate.secret_hash,
                    secret_pattern=candidate.pattern_name,
                    status="invalid",
                    raw_response=data,
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
                identity=client_id,
                scope={"environment": "sandbox"},
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

