"""
bounty.secrets.patterns — Compiled regex patterns for secret detection.

Each pattern is named and associated with a provider.  The PATTERNS dict maps
provider name → list of (pattern_name, compiled_re) tuples.

Proximity-based pairing: AWS secret-access-key and Twilio auth-token are only
emitted when their respective anchor patterns (AKIA/ASIA, AC prefix) are found
within 200 characters.  The scanner enforces this constraint; patterns for the
secondary keys are listed here for reference / documentation only — the scanner
handles the pairing logic.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class Pattern(NamedTuple):
    name: str
    regex: re.Pattern[str]


def _p(name: str, pattern: str, flags: int = 0) -> Pattern:
    return Pattern(name=name, regex=re.compile(pattern, flags))


# ── AWS ─────────────────────────────────────────────────────────────────────
AWS_ACCESS_KEY_ID = _p(
    "aws-access-key-id",
    r"(?<![A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
)
AWS_SECRET_ACCESS_KEY = _p(
    "aws-secret-access-key",
    # High FP rate — only used with proximity pairing in scanner.
    r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
)

# ── GitHub ───────────────────────────────────────────────────────────────────
GITHUB_PAT = _p("github-pat", r"\b(ghp_[A-Za-z0-9]{36})\b")
GITHUB_OAUTH = _p("github-oauth", r"\b(gho_[A-Za-z0-9]{36})\b")
GITHUB_APP_USER = _p("github-app-user", r"\b(ghu_[A-Za-z0-9]{36})\b")
GITHUB_APP_SERVER = _p("github-app-server", r"\b(ghs_[A-Za-z0-9]{36})\b")
GITHUB_REFRESH = _p("github-refresh", r"\b(ghr_[A-Za-z0-9]{36})\b")
GITHUB_FINE_GRAINED = _p("github-fine-grained", r"\b(github_pat_[A-Za-z0-9_]{80,})\b")

# ── Stripe ───────────────────────────────────────────────────────────────────
STRIPE_LIVE_SECRET = _p("stripe-live-secret", r"\b(sk_live_[A-Za-z0-9]{24,})\b")
STRIPE_TEST_SECRET = _p("stripe-test-secret", r"\b(sk_test_[A-Za-z0-9]{24,})\b")
STRIPE_RESTRICTED = _p("stripe-restricted", r"\b(rk_live_[A-Za-z0-9]{24,})\b")

# ── OpenAI ───────────────────────────────────────────────────────────────────
OPENAI_CLASSIC = _p("openai-classic", r"\b(sk-[A-Za-z0-9]{48})\b")
OPENAI_PROJECT = _p("openai-project", r"\b(sk-proj-[A-Za-z0-9_-]{60,})\b")
OPENAI_SERVICE_ACCOUNT = _p("openai-service-account", r"\b(sk-svcacct-[A-Za-z0-9_-]{50,})\b")

# ── Anthropic ────────────────────────────────────────────────────────────────
ANTHROPIC = _p("anthropic", r"\b(sk-ant-api03-[A-Za-z0-9_-]{93,})\b")

# ── Slack ────────────────────────────────────────────────────────────────────
SLACK_BOT = _p(
    "slack-bot",
    r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32})\b",
)
SLACK_USER = _p("slack-user", r"\b(xoxp-[A-Za-z0-9-]+)\b")
SLACK_APP = _p("slack-app", r"\b(xapp-1-[A-Za-z0-9-]+)\b")

# ── Discord ──────────────────────────────────────────────────────────────────
DISCORD_BOT = _p(
    "discord-bot",
    r"\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b",
)

# ── Twilio ───────────────────────────────────────────────────────────────────
TWILIO_ACCOUNT_SID = _p("twilio-account-sid", r"\b(AC[0-9a-f]{32})\b")
TWILIO_AUTH_TOKEN = _p(
    "twilio-auth-token",
    # High FP rate — only used with proximity pairing.
    r"\b([0-9a-f]{32})\b",
)

# ── SendGrid ─────────────────────────────────────────────────────────────────
SENDGRID = _p("sendgrid", r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b")

# ── Mailgun ──────────────────────────────────────────────────────────────────
MAILGUN_LEGACY = _p("mailgun-legacy", r"\b(key-[a-f0-9]{32})\b")

# ── Razorpay ─────────────────────────────────────────────────────────────────
RAZORPAY_LIVE_KEY = _p("razorpay-live-key", r"\b(rzp_live_[A-Za-z0-9]{14})\b")
RAZORPAY_TEST_KEY = _p("razorpay-test-key", r"\b(rzp_test_[A-Za-z0-9]{14})\b")

# ── Shopify ──────────────────────────────────────────────────────────────────
SHOPIFY_ADMIN = _p("shopify-admin", r"\b(shpat_[a-f0-9]{32})\b")
SHOPIFY_STOREFRONT_SECRET = _p("shopify-storefront-secret", r"\b(shpss_[a-f0-9]{32})\b")
SHOPIFY_CUSTOM_APP = _p("shopify-custom-app", r"\b(shpca_[a-f0-9]{32})\b")

# ── Adyen ─────────────────────────────────────────────────────────────────────
ADYEN_API_KEY = _p("adyen-api-key", r"\b(AQE[a-zA-Z0-9/+]{50,})\b")

# ── Airtable ──────────────────────────────────────────────────────────────────
AIRTABLE_PAT = _p("airtable-pat", r"\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b")
AIRTABLE_LEGACY = _p("airtable-legacy", r"\b(key[A-Za-z0-9]{14})\b")

# ── Auth0 ─────────────────────────────────────────────────────────────────────
AUTH0_TOKEN = _p("auth0-token", r"(?:eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})")

# ── Azure ─────────────────────────────────────────────────────────────────────
AZURE_CLIENT_SECRET = _p("azure-client-secret", r"(?<![A-Za-z0-9_-])([A-Za-z0-9_\-~.]{34,44})(?![A-Za-z0-9_-])")

# ── Braintree ─────────────────────────────────────────────────────────────────
BRAINTREE_KEY = _p("braintree-key", r"(?:braintree|BRAINTREE)[^\"'\s]{0,50}([a-zA-Z0-9]{32})")

# ── Cloudflare ────────────────────────────────────────────────────────────────
CLOUDFLARE_API_TOKEN = _p("cloudflare-api-token", r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{40})(?![A-Za-z0-9_-])")

# ── Datadog ───────────────────────────────────────────────────────────────────
DATADOG_API_KEY = _p("datadog-api-key", r"(?:datadog|DD_API_KEY|dd-api-key)[^\"'\s]{0,30}([a-f0-9]{32})")

# ── GCP ───────────────────────────────────────────────────────────────────────
GCP_API_KEY = _p("gcp-api-key", r"\b(AIza[0-9A-Za-z_-]{35})\b")
GCP_SERVICE_ACCOUNT = _p("gcp-service-account", r'"type"\s*:\s*"service_account"')

# ── GitLab ────────────────────────────────────────────────────────────────────
GITLAB_PAT = _p("gitlab-pat", r"\b(glpat-[A-Za-z0-9_-]{20})\b")

# ── HuggingFace ───────────────────────────────────────────────────────────────
HUGGINGFACE_TOKEN = _p("huggingface-token", r"\b(hf_[A-Za-z0-9]{34,})\b")

# ── Linear ────────────────────────────────────────────────────────────────────
LINEAR_API_KEY = _p("linear-api-key", r"\b(lin_api_[A-Za-z0-9]{40})\b")

# ── Mailchimp ─────────────────────────────────────────────────────────────────
MAILCHIMP_API_KEY = _p("mailchimp-api-key", r"\b([a-f0-9]{32}-us\d{1,2})\b")

# ── Mollie ────────────────────────────────────────────────────────────────────
MOLLIE_API_KEY = _p("mollie-api-key", r"\b((?:live|test)_[A-Za-z0-9]{30,})\b")

# ── Notion ────────────────────────────────────────────────────────────────────
NOTION_TOKEN = _p("notion-token", r"\b(secret_[A-Za-z0-9]{43})\b")
NOTION_TOKEN_NEW = _p("notion-token-new", r"\b(ntn_[A-Za-z0-9]{40,})\b")

# ── Okta ─────────────────────────────────────────────────────────────────────
OKTA_API_TOKEN = _p("okta-api-token", r"\b(00[A-Za-z0-9_-]{40})\b")

# ── PagerDuty ─────────────────────────────────────────────────────────────────
PAGERDUTY_API_KEY = _p("pagerduty-api-key", r"(?:pagerduty|PAGERDUTY)[^\"'\s]{0,30}([A-Za-z0-9_+/-]{20})")

# ── PayPal ────────────────────────────────────────────────────────────────────
PAYPAL_CLIENT_ID = _p("paypal-client-id", r"\b(A[A-Za-z0-9_-]{68,80})\b")

# ── PayU ─────────────────────────────────────────────────────────────────────
PAYU_KEY = _p("payu-key", r"(?:payu|PAYU)[^\"'\s]{0,30}([A-Za-z0-9]{16,40})")

# ── Plaid ─────────────────────────────────────────────────────────────────────
PLAID_CLIENT_ID = _p("plaid-client-id", r"\b([a-f0-9]{24})\b")

# ── Sentry ────────────────────────────────────────────────────────────────────
SENTRY_AUTH_TOKEN = _p("sentry-auth-token", r"\b(sntrys_[A-Za-z0-9/+]{88}={0,2})\b")
SENTRY_LEGACY_TOKEN = _p("sentry-legacy-token", r"(?:sentry|SENTRY)[^\"'\s]{0,30}([a-f0-9]{64})")

# ── Square ────────────────────────────────────────────────────────────────────
SQUARE_ACCESS_TOKEN = _p("square-access-token", r"\b(EAAAE[A-Za-z0-9_-]{60,})\b")
SQUARE_SANDBOX_TOKEN = _p("square-sandbox-token", r"\b(sandbox-sq0atb-[A-Za-z0-9_-]{22,})\b")

# ── Supabase ──────────────────────────────────────────────────────────────────
SUPABASE_KEY = _p("supabase-key", r"\b(eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b")

# ── Telegram ──────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = _p("telegram-bot-token", r"\b(\d{8,10}:[A-Za-z0-9_-]{35})\b")

# ── Vault ─────────────────────────────────────────────────────────────────────
VAULT_TOKEN = _p("vault-token", r"\b(hvs\.[A-Za-z0-9_-]{90,})\b")
VAULT_TOKEN_LEGACY = _p("vault-token-legacy", r"\b(s\.[A-Za-z0-9]{24})\b")

# ── Twitch ────────────────────────────────────────────────────────────────────
TWITCH_OAUTH_TOKEN = _p("twitch-oauth-token", r"(?:twitch|TWITCH)[^\"'\s]{0,30}([a-z0-9]{30})")

# ── DigitalOcean ──────────────────────────────────────────────────────────────
DIGITALOCEAN_TOKEN = _p("digitalocean-token", r"\b(dop_v1_[a-f0-9]{64})\b")

# ── NPM ───────────────────────────────────────────────────────────────────────
NPM_TOKEN = _p("npm-token", r"\b(npm_[A-Za-z0-9]{36})\b")


# ── Master registry ──────────────────────────────────────────────────────────
# For the scanner: provider → patterns to scan for.
# Paired secondary patterns (aws-secret-access-key, twilio-auth-token) are
# handled by dedicated proximity logic; they are NOT in this list to avoid
# standalone false positives.
PATTERNS: dict[str, list[Pattern]] = {
    "aws": [AWS_ACCESS_KEY_ID],
    "github": [GITHUB_PAT, GITHUB_OAUTH, GITHUB_APP_USER, GITHUB_APP_SERVER, GITHUB_REFRESH, GITHUB_FINE_GRAINED],
    "stripe": [STRIPE_LIVE_SECRET, STRIPE_TEST_SECRET, STRIPE_RESTRICTED],
    "openai": [OPENAI_CLASSIC, OPENAI_PROJECT, OPENAI_SERVICE_ACCOUNT],
    "anthropic": [ANTHROPIC],
    "slack": [SLACK_BOT, SLACK_USER, SLACK_APP],
    "discord": [DISCORD_BOT],
    "twilio": [TWILIO_ACCOUNT_SID],
    "sendgrid": [SENDGRID],
    "mailgun": [MAILGUN_LEGACY],
    "razorpay": [RAZORPAY_LIVE_KEY, RAZORPAY_TEST_KEY],
    "shopify": [SHOPIFY_ADMIN, SHOPIFY_STOREFRONT_SECRET, SHOPIFY_CUSTOM_APP],
    "adyen": [ADYEN_API_KEY],
    "airtable": [AIRTABLE_PAT, AIRTABLE_LEGACY],
    "auth0": [AUTH0_TOKEN],
    "gcp": [GCP_API_KEY],
    "gitlab": [GITLAB_PAT],
    "huggingface": [HUGGINGFACE_TOKEN],
    "linear": [LINEAR_API_KEY],
    "mailchimp": [MAILCHIMP_API_KEY],
    "mollie": [MOLLIE_API_KEY],
    "notion": [NOTION_TOKEN, NOTION_TOKEN_NEW],
    "okta": [OKTA_API_TOKEN],
    "pagerduty": [PAGERDUTY_API_KEY],
    "sentry": [SENTRY_AUTH_TOKEN],
    "square": [SQUARE_ACCESS_TOKEN, SQUARE_SANDBOX_TOKEN],
    "telegram": [TELEGRAM_BOT_TOKEN],
    "vault": [VAULT_TOKEN, VAULT_TOKEN_LEGACY],
    "digitalocean": [DIGITALOCEAN_TOKEN],
    "npm": [NPM_TOKEN],
}

# Expose paired secondary patterns for the scanner pairing logic.
_PAIRED_SECONDARIES: dict[str, Pattern] = {
    "aws": AWS_SECRET_ACCESS_KEY,
    "twilio": TWILIO_AUTH_TOKEN,
}

__all__ = [
    "Pattern",
    "PATTERNS",
    "_PAIRED_SECONDARIES",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_PAT",
    "GITHUB_OAUTH",
    "GITHUB_APP_USER",
    "GITHUB_APP_SERVER",
    "GITHUB_REFRESH",
    "GITHUB_FINE_GRAINED",
    "STRIPE_LIVE_SECRET",
    "STRIPE_TEST_SECRET",
    "STRIPE_RESTRICTED",
    "OPENAI_CLASSIC",
    "OPENAI_PROJECT",
    "OPENAI_SERVICE_ACCOUNT",
    "ANTHROPIC",
    "SLACK_BOT",
    "SLACK_USER",
    "SLACK_APP",
    "DISCORD_BOT",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "SENDGRID",
    "MAILGUN_LEGACY",
    "RAZORPAY_LIVE_KEY",
    "RAZORPAY_TEST_KEY",
    "SHOPIFY_ADMIN",
    "SHOPIFY_STOREFRONT_SECRET",
    "SHOPIFY_CUSTOM_APP",
    "ADYEN_API_KEY",
    "AIRTABLE_PAT",
    "AIRTABLE_LEGACY",
    "AUTH0_TOKEN",
    "AZURE_CLIENT_SECRET",
    "BRAINTREE_KEY",
    "CLOUDFLARE_API_TOKEN",
    "DATADOG_API_KEY",
    "GCP_API_KEY",
    "GCP_SERVICE_ACCOUNT",
    "GITLAB_PAT",
    "HUGGINGFACE_TOKEN",
    "LINEAR_API_KEY",
    "MAILCHIMP_API_KEY",
    "MOLLIE_API_KEY",
    "NOTION_TOKEN",
    "NOTION_TOKEN_NEW",
    "OKTA_API_TOKEN",
    "PAGERDUTY_API_KEY",
    "PAYPAL_CLIENT_ID",
    "PAYU_KEY",
    "PLAID_CLIENT_ID",
    "SENTRY_AUTH_TOKEN",
    "SENTRY_LEGACY_TOKEN",
    "SQUARE_ACCESS_TOKEN",
    "SQUARE_SANDBOX_TOKEN",
    "SUPABASE_KEY",
    "TELEGRAM_BOT_TOKEN",
    "VAULT_TOKEN",
    "VAULT_TOKEN_LEGACY",
    "TWITCH_OAUTH_TOKEN",
    "DIGITALOCEAN_TOKEN",
    "NPM_TOKEN",
]

