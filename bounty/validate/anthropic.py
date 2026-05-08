"""
bounty.validate.anthropic — Anthropic API key validator.

Sends a minimal messages POST. A 200 or a 400 that contains the model name
in the error body (auth passed, quota/model issue) means the key is live.
A 401 means invalid.
"""

from __future__ import annotations

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator

_MODEL = "claude-haiku-4-5"


class AnthropicValidator(Validator):
    provider = "anthropic"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key = candidate.value
        try:
            resp = await http.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": _MODEL,
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                timeout=15,
            )
            if resp.status_code == 401:
                return ValidationResult(
                    provider=self.provider,
                    secret_preview=candidate.secret_preview,
                    secret_hash=candidate.secret_hash,
                    secret_pattern=candidate.pattern_name,
                    status="invalid",
                )
            # 200 = live; 400 with auth-passing error message = live
            if resp.status_code == 200 or (
                resp.status_code == 400 and resp.status_code != 401
            ):
                return ValidationResult(
                    provider=self.provider,
                    secret_preview=candidate.secret_preview,
                    secret_hash=candidate.secret_hash,
                    secret_pattern=candidate.pattern_name,
                    status="live",
                    identity=None,
                    scope={"model_responded": _MODEL},
                    raw_response=resp.json() if resp.content else None,
                )
            if resp.status_code == 403:
                return ValidationResult(
                    provider=self.provider,
                    secret_preview=candidate.secret_preview,
                    secret_hash=candidate.secret_hash,
                    secret_pattern=candidate.pattern_name,
                    status="invalid",
                )
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="error",
                error_message=f"HTTP {resp.status_code}",
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

