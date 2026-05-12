"""
bounty.validate.okta — Okta API token validator via /api/v1/users/me.

Requires the Okta domain from context (e.g. myorg.okta.com).
"""

from __future__ import annotations

import re

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator

_DOMAIN_RE = re.compile(r"([\w-]+\.okta\.com)", re.IGNORECASE)


class OktaValidator(Validator):
    provider = "okta"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key = candidate.value
        context = candidate.context_before + " " + candidate.context_after
        m = _DOMAIN_RE.search(context)
        if not m:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="needs okta domain URL context",
            )
        domain = m.group(1)
        try:
            resp = await http.get(
                f"https://{domain}/api/v1/users/me",
                headers={"Authorization": f"SSWS {key}"},
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
            profile = data.get("profile", {})
            identity = profile.get("login") or profile.get("email") or data.get("id")
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="live",
                identity=str(identity) if identity else None,
                scope={"domain": domain, "status": data.get("status")},
                raw_response={"id": data.get("id"), "status": data.get("status")},
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

