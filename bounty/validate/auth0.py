"""
bounty.validate.auth0 — Auth0 Management API token validator.

Requires the auth0 tenant domain from context. Looks for pattern
like <tenant>.auth0.com in context_before/context_after.
"""

from __future__ import annotations

import re

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator

_TENANT_RE = re.compile(r"([\w-]+\.auth0\.com)", re.IGNORECASE)


class Auth0Validator(Validator):
    provider = "auth0"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key = candidate.value
        context = candidate.context_before + " " + candidate.context_after
        m = _TENANT_RE.search(context)
        if not m:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="needs auth0 tenant URL context",
            )
        tenant = m.group(1)
        try:
            resp = await http.get(
                f"https://{tenant}/api/v2/users?per_page=1",
                headers={"Authorization": f"Bearer {key}"},
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
                identity=tenant,
                scope={"tenant": tenant, "users_returned": len(data) if isinstance(data, list) else 0},
                raw_response={"tenant": tenant, "count": len(data) if isinstance(data, list) else 0},
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

