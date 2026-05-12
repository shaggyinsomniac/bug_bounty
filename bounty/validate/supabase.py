"""
bounty.validate.supabase — Supabase service role key validator.

Attempts to extract project ref from context URL pattern <ref>.supabase.co,
or falls back to decoding the JWT iss claim. Skips if no ref found.
"""

from __future__ import annotations

import base64
import json
import re

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator

_REF_RE = re.compile(r"([\w-]+)\.supabase\.co", re.IGNORECASE)


def _extract_ref_from_jwt(token: str) -> str | None:
    """Try to parse the iss claim from a JWT to get the project ref."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        # Add padding
        payload += "=" * (4 - len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        iss = decoded.get("iss", "")
        m = _REF_RE.search(iss)
        return m.group(1) if m else None
    except Exception:  # noqa: BLE001
        return None


class SupabaseValidator(Validator):
    provider = "supabase"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,
    ) -> ValidationResult:
        key = candidate.value
        context = candidate.context_before + " " + candidate.context_after
        m = _REF_RE.search(context)
        ref = m.group(1) if m else _extract_ref_from_jwt(key)
        if not ref:
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="skipped",
                error_message="needs supabase project ref URL context",
            )
        try:
            resp = await http.get(
                f"https://{ref}.supabase.co/rest/v1/",
                headers={
                    "apikey": key,
                    "Authorization": f"Bearer {key}",
                },
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
                identity=ref,
                scope={"project_ref": ref},
                raw_response={"project_ref": ref, "status_code": resp.status_code},
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

