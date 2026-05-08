"""
bounty.validate.twilio — Twilio credentials validator.

Requires paired SID (AC-prefixed) + auth token (32-hex).
"""

from __future__ import annotations

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator


class TwilioValidator(Validator):
    provider = "twilio"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        sid = candidate.value
        auth_token = candidate.paired_value or ""

        if not auth_token:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="Auth token not found near SID — cannot validate without paired credentials",
            )

        try:
            resp = await http.get(
                f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
                auth=(sid, auth_token),
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
                identity=sid,
                scope={
                    "friendly_name": data.get("friendly_name"),
                    "status": data.get("status"),
                    "type": data.get("type"),
                },
                raw_response=data,
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

