"""
bounty.validate.aws — AWS access key validator via STS GetCallerIdentity.

Uses boto3.  Call is cost-free and requires no IAM permissions.

ASIA-prefixed keys (STS temporary credentials) require a session token;
without one the call will fail — we treat that as invalid.
"""

from __future__ import annotations

import httpx

from bounty.models import ValidationResult
from bounty.secrets.scanner import SecretCandidate
from bounty.validate._base import Validator


class AWSValidator(Validator):
    provider = "aws"

    async def validate(
        self,
        candidate: SecretCandidate,
        http: httpx.AsyncClient,  # noqa: ARG002  boto3 is used, not httpx
    ) -> ValidationResult:
        import asyncio

        access_key = candidate.value
        secret_key = candidate.paired_value or ""

        def _call() -> dict:  # type: ignore[type-arg]
            import boto3

            client = boto3.client(
                "sts",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name="us-east-1",
            )
            return client.get_caller_identity()  # type: ignore[no-any-return]

        try:
            resp = await asyncio.get_event_loop().run_in_executor(None, _call)
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="live",
                identity=resp.get("Arn", ""),
                scope={
                    "account": resp.get("Account", ""),
                    "user_id": resp.get("UserId", ""),
                },
                raw_response=resp,
            )
        except Exception as exc:
            msg = str(exc)
            if any(
                k in msg
                for k in ("InvalidClientTokenId", "AuthFailure", "NotAuthorized",
                          "ExpiredTokenException", "AccessDenied")
            ):
                return ValidationResult(
                    provider=self.provider,
                    secret_preview=candidate.secret_preview,
                    secret_hash=candidate.secret_hash,
                    secret_pattern=candidate.pattern_name,
                    status="invalid",
                    error_message=msg,
                )
            return ValidationResult(
                provider=self.provider,
                secret_preview=candidate.secret_preview,
                secret_hash=candidate.secret_hash,
                secret_pattern=candidate.pattern_name,
                status="error",
                error_message=msg,
            )

