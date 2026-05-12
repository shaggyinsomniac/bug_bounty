"""
tests/test_phase11.py — Phase 11 token validator tests.

Each new validator gets: positive (200 → live), negative (401 → invalid),
error (500 → error), and where applicable a context/skipped test.
No real API calls — all HTTP interactions are mocked.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bounty.secrets.scanner import SecretCandidate
from bounty.validate.adyen import AdyenValidator
from bounty.validate.airtable import AirtableValidator
from bounty.validate.auth0 import Auth0Validator
from bounty.validate.azure import AzureValidator
from bounty.validate.braintree import BraintreeValidator
from bounty.validate.cloudflare import CloudflareValidator
from bounty.validate.datadog import DatadogValidator
from bounty.validate.digitalocean import DigitalOceanValidator
from bounty.validate.gcp import GCPValidator
from bounty.validate.gitlab import GitLabValidator
from bounty.validate.huggingface import HuggingFaceValidator
from bounty.validate.linear import LinearValidator
from bounty.validate.mailchimp import MailchimpValidator
from bounty.validate.mollie import MollieValidator
from bounty.validate.notion import NotionValidator
from bounty.validate.npm import NpmValidator
from bounty.validate.okta import OktaValidator
from bounty.validate.pagerduty import PagerDutyValidator
from bounty.validate.paypal import PayPalValidator
from bounty.validate.payu import PayUValidator
from bounty.validate.plaid import PlaidValidator
from bounty.validate.sentry import SentryValidator
from bounty.validate.square import SquareValidator
from bounty.validate.supabase import SupabaseValidator
from bounty.validate.telegram import TelegramValidator
from bounty.validate.twitch import TwitchValidator
from bounty.validate.vault import VaultValidator


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _candidate(
    provider: str,
    value: str,
    pattern_name: str = "test-pattern",
    context_before: str = "",
    context_after: str = "",
) -> SecretCandidate:
    return SecretCandidate(
        provider=provider,
        pattern_name=pattern_name,
        value=value,
        context_before=context_before,
        context_after=context_after,
    )


def _mock_response(status_code: int, json_data: Any) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    if status_code >= 400:
        import httpx
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}", request=MagicMock(), response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


def _mock_http(status_code: int, json_data: Any) -> AsyncMock:
    http = AsyncMock()
    resp = _mock_response(status_code, json_data)
    http.get = AsyncMock(return_value=resp)
    http.post = AsyncMock(return_value=resp)
    return http


# ===========================================================================
# Adyen
# ===========================================================================

@pytest.mark.asyncio
async def test_adyen_live():
    v = AdyenValidator()
    c = _candidate("adyen", "AQEfak3key00000")
    http = _mock_http(200, {"name": "Test Company", "companyId": "comp123", "username": "admin"})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "Test Company"


@pytest.mark.asyncio
async def test_adyen_invalid():
    v = AdyenValidator()
    c = _candidate("adyen", "badkey")
    http = _mock_http(401, {"error": "Unauthorized"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_adyen_error():
    v = AdyenValidator()
    c = _candidate("adyen", "AQEfakekey")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("network error"))
    result = await v.validate(c, http)
    assert result.status == "error"
    assert "network error" in result.error_message


@pytest.mark.asyncio
async def test_adyen_5xx():
    v = AdyenValidator()
    c = _candidate("adyen", "AQEfakekey")
    http = _mock_http(500, {"error": "server error"})
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Airtable
# ===========================================================================

@pytest.mark.asyncio
async def test_airtable_live():
    v = AirtableValidator()
    c = _candidate("airtable", "patABCDEFGHIJKLMN.abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
    http = _mock_http(200, {"id": "usr123", "email": "user@example.com", "scopes": ["data.records:read"]})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "usr123"


@pytest.mark.asyncio
async def test_airtable_invalid():
    v = AirtableValidator()
    c = _candidate("airtable", "badkey")
    http = _mock_http(401, {"error": {"type": "AUTHENTICATION_REQUIRED"}})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_airtable_error():
    v = AirtableValidator()
    c = _candidate("airtable", "patFakeKey")
    import httpx
    http = AsyncMock()
    http.get = AsyncMock(side_effect=httpx.ConnectTimeout("timeout"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Auth0
# ===========================================================================

@pytest.mark.asyncio
async def test_auth0_skipped_no_context():
    v = Auth0Validator()
    c = _candidate("auth0", "eyJfakeJWT.eyJpayload.signature")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "auth0 tenant" in result.error_message


@pytest.mark.asyncio
async def test_auth0_live_with_context():
    v = Auth0Validator()
    c = _candidate(
        "auth0",
        "eyJfakeJWT.eyJpayload.signature",
        context_before="https://mycompany.auth0.com/api/v2/",
    )
    http = _mock_http(200, [{"user_id": "auth0|123", "email": "user@example.com"}])
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "mycompany.auth0.com"


@pytest.mark.asyncio
async def test_auth0_invalid_with_context():
    v = Auth0Validator()
    c = _candidate(
        "auth0",
        "eyJfakeJWT.eyJpayload.signature",
        context_after="tenant.auth0.com/api",
    )
    http = _mock_http(401, {"error": "Unauthorized"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_auth0_error_with_context():
    v = Auth0Validator()
    c = _candidate(
        "auth0",
        "eyJfakeJWT.eyJpayload.signature",
        context_before="https://mytenant.auth0.com",
    )
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("connection refused"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Azure
# ===========================================================================

@pytest.mark.asyncio
async def test_azure_live():
    v = AzureValidator()
    c = _candidate("azure", "eyJfakeAzureBearer.payload.sig")
    http = _mock_http(200, {"value": [{"tenantId": "tenant-abc-123", "displayName": "My Org"}]})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "tenant-abc-123"
    assert result.scope["tenant_count"] == 1


@pytest.mark.asyncio
async def test_azure_invalid():
    v = AzureValidator()
    c = _candidate("azure", "badbearer")
    http = _mock_http(401, {"error": {"code": "InvalidAuthenticationToken"}})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_azure_error():
    v = AzureValidator()
    c = _candidate("azure", "fakebearertoken")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("DNS resolution failed"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Braintree
# ===========================================================================

@pytest.mark.asyncio
async def test_braintree_skipped_no_colon():
    v = BraintreeValidator()
    c = _candidate("braintree", "justasinglekey")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "public_key:private_key" in result.error_message


@pytest.mark.asyncio
async def test_braintree_skipped_no_merchant():
    v = BraintreeValidator()
    c = _candidate("braintree", "publickey123:privatekey456")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "merchant_id" in result.error_message


@pytest.mark.asyncio
async def test_braintree_live():
    v = BraintreeValidator()
    c = _candidate(
        "braintree",
        "publickey123:privatekey456",
        context_before='merchant_id = "testmerchantx1"',
    )
    http = _mock_http(200, {"merchant": {"id": "testmerchantx1"}})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "testmerchantx1"


@pytest.mark.asyncio
async def test_braintree_invalid():
    v = BraintreeValidator()
    c = _candidate(
        "braintree",
        "pub:priv",
        context_before='merchant_id = "testmerchantx1"',
    )
    http = _mock_http(401, {"error": "Unauthorized"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


# ===========================================================================
# Cloudflare
# ===========================================================================

@pytest.mark.asyncio
async def test_cloudflare_live():
    v = CloudflareValidator()
    c = _candidate("cloudflare", "FakeCloudflareToken1234567890abcdef12345")
    http = _mock_http(200, {
        "success": True,
        "result": {"id": "token-id-123", "status": "active"},
    })
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "token-id-123"


@pytest.mark.asyncio
async def test_cloudflare_not_success():
    v = CloudflareValidator()
    c = _candidate("cloudflare", "FakeCloudflareToken1234567890abcdef12345")
    http = _mock_http(200, {
        "success": False,
        "result": {},
        "errors": [{"code": 1000, "message": "Invalid API Token"}],
    })
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_cloudflare_invalid():
    v = CloudflareValidator()
    c = _candidate("cloudflare", "badtoken")
    http = _mock_http(401, {"errors": [{"message": "Unknown X-Auth-Key or X-Auth-Email"}]})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_cloudflare_error():
    v = CloudflareValidator()
    c = _candidate("cloudflare", "FakeCloudflareToken1234567890abcdef12345")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("timeout"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Datadog
# ===========================================================================

@pytest.mark.asyncio
async def test_datadog_live():
    v = DatadogValidator()
    c = _candidate("datadog", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
    http = _mock_http(200, {"valid": True})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.scope["valid"] is True


@pytest.mark.asyncio
async def test_datadog_not_valid():
    v = DatadogValidator()
    c = _candidate("datadog", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
    http = _mock_http(200, {"valid": False})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_datadog_invalid_401():
    v = DatadogValidator()
    c = _candidate("datadog", "badkey")
    http = _mock_http(403, {"errors": ["Forbidden"]})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_datadog_error():
    v = DatadogValidator()
    c = _candidate("datadog", "fakekey1234567890123456789012345")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("connection error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# DigitalOcean
# ===========================================================================

@pytest.mark.asyncio
async def test_digitalocean_live():
    v = DigitalOceanValidator()
    c = _candidate("digitalocean", "dop_v1_" + "a" * 64)
    http = _mock_http(200, {"account": {"email": "user@example.com", "uuid": "uuid-123", "status": "active"}})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "user@example.com"


@pytest.mark.asyncio
async def test_digitalocean_invalid():
    v = DigitalOceanValidator()
    c = _candidate("digitalocean", "dop_v1_badtoken")
    http = _mock_http(401, {"id": "unauthorized", "message": "Unable to authenticate you."})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_digitalocean_error():
    v = DigitalOceanValidator()
    c = _candidate("digitalocean", "dop_v1_faketoken")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("timeout"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# GCP
# ===========================================================================

@pytest.mark.asyncio
async def test_gcp_api_key_live():
    v = GCPValidator()
    c = _candidate("gcp", "AIzaFakeGCPKeyABCDEFGHIJKLMNOPQRSTUVWXYZ0")
    http = _mock_http(200, {"status": "OK", "results": []})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.scope["maps_status"] == "OK"


@pytest.mark.asyncio
async def test_gcp_api_key_denied():
    v = GCPValidator()
    c = _candidate("gcp", "AIzaFakeGCPKeyABCDEFGHIJKLMNOPQRSTUVWXYZ0")
    http = _mock_http(200, {"status": "REQUEST_DENIED", "error_message": "API key not valid."})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_gcp_service_account_skipped():
    v = GCPValidator()
    c = _candidate("gcp", '{"type": "service_account", "project_id": "myproject"}')
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "service account" in result.error_message


@pytest.mark.asyncio
async def test_gcp_error():
    v = GCPValidator()
    c = _candidate("gcp", "AIzaFakeGCPKey1234567890123456789012345")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("connection error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# GitLab
# ===========================================================================

@pytest.mark.asyncio
async def test_gitlab_live():
    v = GitLabValidator()
    c = _candidate("gitlab", "glpat-FakeGitLabToken12345")
    http = _mock_http(200, {"id": 42, "username": "hacker", "name": "H4cker"})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "hacker"


@pytest.mark.asyncio
async def test_gitlab_invalid():
    v = GitLabValidator()
    c = _candidate("gitlab", "glpat-badtoken")
    http = _mock_http(401, {"message": "401 Unauthorized"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_gitlab_error():
    v = GitLabValidator()
    c = _candidate("gitlab", "glpat-FakeToken123456")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("SSL error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# HuggingFace
# ===========================================================================

@pytest.mark.asyncio
async def test_huggingface_live():
    v = HuggingFaceValidator()
    c = _candidate("huggingface", "hf_FakeHuggingFaceTokenABCDEFGHIJKL")
    http = _mock_http(200, {"name": "myuser", "orgs": [{"name": "myorg"}]})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "myuser"
    assert "myorg" in result.scope["orgs"]


@pytest.mark.asyncio
async def test_huggingface_invalid():
    v = HuggingFaceValidator()
    c = _candidate("huggingface", "hf_badtoken")
    http = _mock_http(401, {"error": "Invalid credentials in Authorization header"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_huggingface_error():
    v = HuggingFaceValidator()
    c = _candidate("huggingface", "hf_FakeToken12345678901234567890123456")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("network error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Linear
# ===========================================================================

@pytest.mark.asyncio
async def test_linear_live():
    v = LinearValidator()
    c = _candidate("linear", "lin_api_FakeLinearApiKey1234567890123456789012345")
    http = _mock_http(200, {"data": {"viewer": {"id": "usr_abc", "email": "user@example.com", "name": "Alice"}}})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "user@example.com"


@pytest.mark.asyncio
async def test_linear_no_viewer():
    v = LinearValidator()
    c = _candidate("linear", "lin_api_FakeKey")
    http = _mock_http(200, {"data": {"viewer": None}, "errors": [{"message": "Not authenticated"}]})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_linear_invalid():
    v = LinearValidator()
    c = _candidate("linear", "lin_api_badkey")
    http = _mock_http(401, {"errors": [{"message": "Unauthorized"}]})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_linear_error():
    v = LinearValidator()
    c = _candidate("linear", "lin_api_FakeLinearApiKey1234567890123456789012345")
    http = AsyncMock()
    http.post = AsyncMock(side_effect=Exception("timeout"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Mailchimp
# ===========================================================================

@pytest.mark.asyncio
async def test_mailchimp_skipped_no_dc():
    v = MailchimpValidator()
    c = _candidate("mailchimp", "abcdefabcdefabcdefabcdefabcdefab")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "datacenter" in result.error_message


@pytest.mark.asyncio
async def test_mailchimp_live():
    v = MailchimpValidator()
    c = _candidate("mailchimp", "abcdefabcdefabcdefabcdefabcdefab-us12")
    http = _mock_http(200, {"health_status": "Everything's Chimpy!"})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "us12"
    assert result.scope["datacenter"] == "us12"


@pytest.mark.asyncio
async def test_mailchimp_invalid():
    v = MailchimpValidator()
    c = _candidate("mailchimp", "0000000000000000000000000000000-us1")
    http = _mock_http(401, {"detail": "Your API key may be invalid, or you've attempted to access the wrong datacenter."})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_mailchimp_error():
    v = MailchimpValidator()
    c = _candidate("mailchimp", "fakekey00000000000000000000000000-us3")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("DNS error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Mollie
# ===========================================================================

@pytest.mark.asyncio
async def test_mollie_live():
    v = MollieValidator()
    c = _candidate("mollie", "live_FakeMollieKey1234567890ABCDEFGH")
    http = _mock_http(200, {"count": 8, "_embedded": {"methods": []}})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.scope["methods_count"] == 8
    assert result.scope["mode"] == "live"


@pytest.mark.asyncio
async def test_mollie_test_key():
    v = MollieValidator()
    c = _candidate("mollie", "test_FakeMollieKey1234567890ABCDEFGH")
    http = _mock_http(200, {"count": 3})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.scope["mode"] == "test"


@pytest.mark.asyncio
async def test_mollie_invalid():
    v = MollieValidator()
    c = _candidate("mollie", "badkey")
    http = _mock_http(401, {"status": 401, "title": "Unauthorized Request"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_mollie_error():
    v = MollieValidator()
    c = _candidate("mollie", "live_FakeKey123")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("network error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Notion
# ===========================================================================

@pytest.mark.asyncio
async def test_notion_live():
    v = NotionValidator()
    c = _candidate("notion", "secret_FakeNotionTokenABCDEFGHIJKLMNOPQRSTUVWXYZ0123")
    http = _mock_http(200, {
        "object": "user",
        "id": "abc123",
        "type": "bot",
        "name": "My Integration",
        "bot": {"owner": {"type": "workspace"}},
    })
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "My Integration"


@pytest.mark.asyncio
async def test_notion_invalid():
    v = NotionValidator()
    c = _candidate("notion", "secret_badtoken")
    http = _mock_http(401, {"object": "error", "status": 401, "message": "API token is invalid."})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_notion_error():
    v = NotionValidator()
    c = _candidate("notion", "secret_FakeNotionToken1234567890ABCDEFGHIJKLMNOPQ")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("timeout"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# NPM
# ===========================================================================

@pytest.mark.asyncio
async def test_npm_live():
    v = NpmValidator()
    c = _candidate("npm", "npm_FakeNpmTokenABCDEFGHIJKLMNOPQRSTUVWXY")
    http = _mock_http(200, {"username": "mypublisher"})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "mypublisher"


@pytest.mark.asyncio
async def test_npm_invalid():
    v = NpmValidator()
    c = _candidate("npm", "npm_badtoken")
    http = _mock_http(401, {"error": "Invalid token"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_npm_error():
    v = NpmValidator()
    c = _candidate("npm", "npm_FakeToken1234567890123456789012345")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("connection refused"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Okta
# ===========================================================================

@pytest.mark.asyncio
async def test_okta_skipped_no_context():
    v = OktaValidator()
    c = _candidate("okta", "00FakeOktaApiToken12345678901234567890XXX")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "okta domain" in result.error_message


@pytest.mark.asyncio
async def test_okta_live_with_context():
    v = OktaValidator()
    c = _candidate(
        "okta",
        "00FakeOktaApiToken12345678901234567890XXX",
        context_before="OKTA_DOMAIN=mycompany.okta.com",
    )
    http = _mock_http(200, {
        "id": "00u1a2b3c4d5",
        "status": "ACTIVE",
        "profile": {"login": "admin@example.com", "email": "admin@example.com"},
    })
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "admin@example.com"


@pytest.mark.asyncio
async def test_okta_invalid_with_context():
    v = OktaValidator()
    c = _candidate(
        "okta",
        "00FakeOktaApiToken12345678901234567890XXX",
        context_after="https://dev-123456.okta.com/api",
    )
    http = _mock_http(401, {"errorCode": "E0000011", "errorSummary": "Invalid token provided"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_okta_error_with_context():
    v = OktaValidator()
    c = _candidate(
        "okta",
        "00FakeOktaToken",
        context_before="OKTA_DOMAIN=myorg.okta.com",
    )
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("connection error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# PagerDuty
# ===========================================================================

@pytest.mark.asyncio
async def test_pagerduty_live():
    v = PagerDutyValidator()
    c = _candidate("pagerduty", "FakePagerDutyKey1234")
    http = _mock_http(200, {"user": {"id": "P1234", "name": "Alice", "email": "alice@example.com", "role": "admin"}})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "alice@example.com"


@pytest.mark.asyncio
async def test_pagerduty_invalid():
    v = PagerDutyValidator()
    c = _candidate("pagerduty", "badkey")
    http = _mock_http(401, {"error": {"message": "Unauthorized"}})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_pagerduty_error():
    v = PagerDutyValidator()
    c = _candidate("pagerduty", "FakePagerDutyKey1234")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("timeout"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# PayPal
# ===========================================================================

@pytest.mark.asyncio
async def test_paypal_skipped_no_colon():
    v = PayPalValidator()
    c = _candidate("paypal", "AKlongclientid")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "client_id:client_secret" in result.error_message


@pytest.mark.asyncio
async def test_paypal_live():
    v = PayPalValidator()
    c = _candidate("paypal", "FakeClientId12345:FakeClientSecret12345")
    http = _mock_http(200, {"access_token": "faketoken", "token_type": "Bearer", "app_id": "APP-123", "scope": "openid"})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.scope["app_id"] == "APP-123"


@pytest.mark.asyncio
async def test_paypal_invalid():
    v = PayPalValidator()
    c = _candidate("paypal", "FakeId:FakeSecret")
    http = _mock_http(401, {"error": "invalid_client", "error_description": "Client Authentication failed"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_paypal_error():
    v = PayPalValidator()
    c = _candidate("paypal", "FakeClientId:FakeSecret")
    http = AsyncMock()
    http.post = AsyncMock(side_effect=Exception("timeout"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# PayU
# ===========================================================================

@pytest.mark.asyncio
async def test_payu_skipped_no_colon():
    v = PayUValidator()
    c = _candidate("payu", "singleblobkey")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "client_id:client_secret" in result.error_message


@pytest.mark.asyncio
async def test_payu_live():
    v = PayUValidator()
    c = _candidate("payu", "clientid123:clientsecret456")
    http = _mock_http(200, {"access_token": "tokenvalue", "token_type": "bearer", "expires_in": 3600})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "clientid123"


@pytest.mark.asyncio
async def test_payu_invalid():
    v = PayUValidator()
    c = _candidate("payu", "wrong:creds")
    http = _mock_http(401, {"error": "Unauthorized"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_payu_error():
    v = PayUValidator()
    c = _candidate("payu", "cid:secret")
    http = AsyncMock()
    http.post = AsyncMock(side_effect=Exception("connection error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Plaid
# ===========================================================================

@pytest.mark.asyncio
async def test_plaid_skipped_no_colon():
    v = PlaidValidator()
    c = _candidate("plaid", "abcdef123456789012345678")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "client_id:secret" in result.error_message


@pytest.mark.asyncio
async def test_plaid_live_invalid_access_token():
    """A 400 INVALID_ACCESS_TOKEN means credentials are valid."""
    v = PlaidValidator()
    c = _candidate("plaid", "myclientid123456789012:mysecret123456789012345678901")
    resp = MagicMock()
    resp.status_code = 400
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"error_code": "INVALID_ACCESS_TOKEN", "error_message": "access token not valid"}
    http = AsyncMock()
    http.post = AsyncMock(return_value=resp)
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "myclientid123456789012"


@pytest.mark.asyncio
async def test_plaid_invalid_api_keys():
    v = PlaidValidator()
    c = _candidate("plaid", "badclientid:badsecret")
    resp = MagicMock()
    resp.status_code = 400
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"error_code": "INVALID_API_KEYS", "error_message": "invalid client_id or secret"}
    http = AsyncMock()
    http.post = AsyncMock(return_value=resp)
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_plaid_error():
    v = PlaidValidator()
    c = _candidate("plaid", "clientid:secret")
    http = AsyncMock()
    http.post = AsyncMock(side_effect=Exception("connection error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Sentry
# ===========================================================================

@pytest.mark.asyncio
async def test_sentry_live():
    v = SentryValidator()
    c = _candidate("sentry", "sntrys_FakeSentryTokenABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890fakefakefakefake==")
    http = _mock_http(200, [{"id": "1", "name": "my-project"}, {"id": "2", "name": "another"}])
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.scope["project_count"] == 2


@pytest.mark.asyncio
async def test_sentry_invalid():
    v = SentryValidator()
    c = _candidate("sentry", "badtoken")
    http = _mock_http(401, {"detail": "Authentication credentials were not provided."})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_sentry_error():
    v = SentryValidator()
    c = _candidate("sentry", "sntrys_FakeToken")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("connection error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Square
# ===========================================================================

@pytest.mark.asyncio
async def test_square_live():
    v = SquareValidator()
    c = _candidate("square", "EAAAEFakeSquareToken1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab")
    http = _mock_http(200, {"locations": [{"id": "LXYZ", "merchant_id": "M123", "name": "My Shop"}]})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "M123"
    assert result.scope["location_count"] == 1


@pytest.mark.asyncio
async def test_square_invalid():
    v = SquareValidator()
    c = _candidate("square", "EAAAEbadtoken")
    http = _mock_http(401, {"errors": [{"category": "AUTHENTICATION_ERROR", "code": "UNAUTHORIZED"}]})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_square_error():
    v = SquareValidator()
    c = _candidate("square", "EAAAEfaketoken")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("timeout"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Supabase
# ===========================================================================

@pytest.mark.asyncio
async def test_supabase_skipped_no_context_or_jwt():
    v = SupabaseValidator()
    c = _candidate("supabase", "notajwtatall")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "project ref" in result.error_message


@pytest.mark.asyncio
async def test_supabase_live_with_context():
    v = SupabaseValidator()
    c = _candidate(
        "supabase",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.fakeSignature",
        context_before="SUPABASE_URL=https://abcxyz123.supabase.co",
    )
    http = _mock_http(200, {"paths": {}})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "abcxyz123"


@pytest.mark.asyncio
async def test_supabase_invalid():
    v = SupabaseValidator()
    c = _candidate(
        "supabase",
        "eyJfake.eyJpayload.sig",
        context_before="https://myproject.supabase.co",
    )
    http = _mock_http(401, {"message": "Invalid API key"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_supabase_error():
    v = SupabaseValidator()
    c = _candidate(
        "supabase",
        "eyJfake.eyJpayload.sig",
        context_before="myref.supabase.co",
    )
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("connection refused"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Telegram
# ===========================================================================

@pytest.mark.asyncio
async def test_telegram_live():
    v = TelegramValidator()
    c = _candidate("telegram", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
    http = _mock_http(200, {"ok": True, "result": {"id": 123456789, "is_bot": True, "username": "my_test_bot", "first_name": "TestBot"}})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "my_test_bot"


@pytest.mark.asyncio
async def test_telegram_not_ok():
    v = TelegramValidator()
    c = _candidate("telegram", "123456789:badtoken123456789012345678901234567")
    http = _mock_http(200, {"ok": False, "error_code": 401, "description": "Unauthorized"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_telegram_invalid_401():
    v = TelegramValidator()
    c = _candidate("telegram", "123456789:badtoken123456789012345678901234567")
    http = _mock_http(401, {"ok": False, "error_code": 401, "description": "Unauthorized"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_telegram_error():
    v = TelegramValidator()
    c = _candidate("telegram", "987654321:FakeToken1234567890ABCDEFGHIJKLMNOP")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("timeout"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Twitch
# ===========================================================================

@pytest.mark.asyncio
async def test_twitch_live():
    v = TwitchValidator()
    c = _candidate("twitch", "faketwitchoauthtoken1234567890abc")
    http = _mock_http(200, {"client_id": "abc123", "login": "streamer42", "scopes": ["user:read:email"]})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "streamer42"
    assert "user:read:email" in result.scope["scopes"]


@pytest.mark.asyncio
async def test_twitch_invalid():
    v = TwitchValidator()
    c = _candidate("twitch", "badoauthtoken")
    http = _mock_http(401, {"status": 401, "message": "invalid access token"})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_twitch_error():
    v = TwitchValidator()
    c = _candidate("twitch", "faketwitchoauthtoken1234567890abc")
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("network error"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Vault
# ===========================================================================

@pytest.mark.asyncio
async def test_vault_skipped_no_context():
    v = VaultValidator()
    c = _candidate("vault", "hvs.FakeVaultTokenWithNoContextPresent1234567890ABCDEFGHIJKLMNO")
    http = AsyncMock()
    result = await v.validate(c, http)
    assert result.status == "skipped"
    assert "vault URL" in result.error_message


@pytest.mark.asyncio
async def test_vault_live_with_context():
    v = VaultValidator()
    c = _candidate(
        "vault",
        "hvs.FakeToken",
        context_before="VAULT_ADDR=http://vault.internal:8200",
    )
    http = _mock_http(200, {"data": {"display_name": "admin", "policies": ["default", "admin"], "renewable": True}})
    result = await v.validate(c, http)
    assert result.status == "live"
    assert result.identity == "admin"


@pytest.mark.asyncio
async def test_vault_invalid_with_context():
    v = VaultValidator()
    c = _candidate(
        "vault",
        "s.FakeVaultLegacyToken12345",
        context_before="VAULT_ADDR=http://localhost:8200",
    )
    http = _mock_http(403, {"errors": ["permission denied"]})
    result = await v.validate(c, http)
    assert result.status == "invalid"


@pytest.mark.asyncio
async def test_vault_error():
    v = VaultValidator()
    c = _candidate(
        "vault",
        "hvs.FakeToken",
        context_before="VAULT_ADDR=http://vault.corp:8200",
    )
    http = AsyncMock()
    http.get = AsyncMock(side_effect=Exception("connection refused"))
    result = await v.validate(c, http)
    assert result.status == "error"


# ===========================================================================
# Registry completeness check
# ===========================================================================

def test_registry_has_all_phase11_providers():
    """Verify all new validators are registered."""
    import bounty.validate.registry  # noqa: F401 (side effects: populates REGISTRY)
    from bounty.validate._base import REGISTRY

    expected = {
        # Phase 5
        "aws", "github", "stripe", "openai", "anthropic", "slack", "discord",
        "twilio", "sendgrid", "mailgun", "razorpay", "shopify",
        # Phase 11
        "adyen", "airtable", "auth0", "azure", "braintree", "cloudflare",
        "datadog", "digitalocean", "gcp", "gitlab", "huggingface", "linear",
        "mailchimp", "mollie", "notion", "npm", "okta", "pagerduty", "paypal",
        "payu", "plaid", "sentry", "square", "supabase", "telegram", "twitch",
        "vault",
    }
    registered = set(REGISTRY.all_providers())
    missing = expected - registered
    assert not missing, f"Missing providers: {missing}"


def test_registry_provider_count():
    """At least 27 providers registered total."""
    import bounty.validate.registry  # noqa: F401
    from bounty.validate._base import REGISTRY
    assert len(REGISTRY.all_providers()) >= 27

