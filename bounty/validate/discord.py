"""
bounty.validate.discord — Discord bot token validator via /users/@me.
"""

from __future__ import annotations

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator


class DiscordValidator(Validator):
    provider = "discord"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        token = candidate.value
        try:
            resp = await http.get(
                "https://discord.com/api/v10/users/@me",
                headers={"Authorization": f"Bot {token}"},
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
                identity=data.get("username"),
                scope={"id": data.get("id")},
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

