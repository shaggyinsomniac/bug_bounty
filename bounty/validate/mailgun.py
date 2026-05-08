"""
bounty.validate.mailgun — Mailgun API key validator via /v3/domains.

Uses HTTP Basic auth with "api" as username and the key as password.
"""

from __future__ import annotations

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator


class MailgunValidator(Validator):
    provider = "mailgun"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key = candidate.value
        try:
            resp = await http.get(
                "https://api.mailgun.net/v3/domains",
                auth=("api", key),
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
            items = data.get("items", [])
            domain_names = [d.get("name") for d in items[:5] if d.get("name")]
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="live",
                identity=None,
                scope={
                    "domains_count": len(items),
                    "domains": domain_names,
                },
                raw_response={"domains_count": len(items)},
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

