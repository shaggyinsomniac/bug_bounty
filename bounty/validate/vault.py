"""
bounty.validate.vault — HashiCorp Vault token validator via /v1/auth/token/lookup-self.

Requires the Vault URL from context (VAULT_ADDR env mention or http(s)://hostname:port).
"""

from __future__ import annotations

import re

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator

_VAULT_URL_RE = re.compile(
    r"(https?://[\w.-]+(?::\d+)?)(?:/v1)?",
    re.IGNORECASE,
)
_VAULT_ADDR_RE = re.compile(
    r"VAULT_ADDR[\"'\s:=]+(https?://[\w.-]+(?::\d+)?)",
    re.IGNORECASE,
)


def _find_vault_url(context: str) -> str | None:
    m = _VAULT_ADDR_RE.search(context)
    if m:
        return m.group(1).rstrip("/")
    # Fall back: look for any http URL
    m = _VAULT_URL_RE.search(context)
    if m:
        url = m.group(1).rstrip("/")
        # Filter out well-known non-vault domains
        if any(d in url for d in ("github.com", "google.com", "amazon", "microsoft")):
            return None
        return url
    return None


class VaultValidator(Validator):
    provider = "vault"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key = candidate.value
        context = candidate.context_before + " " + candidate.context_after
        vault_url = _find_vault_url(context)
        if not vault_url:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="needs vault URL context",
            )
        try:
            resp = await http.get(
                f"{vault_url}/v1/auth/token/lookup-self",
                headers={"X-Vault-Token": key},
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
            d = data.get("data", {})
            identity = d.get("display_name") or d.get("id") or d.get("accessor")
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="live",
                identity=str(identity) if identity else None,
                scope={"policies": d.get("policies"), "renewable": d.get("renewable")},
                raw_response={"display_name": d.get("display_name"), "policies": d.get("policies")},
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

