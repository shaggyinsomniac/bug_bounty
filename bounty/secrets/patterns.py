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
]

