"""
bounty.validate.registry — Imports and registers all Phase 5 validators.

Import this module at application startup to populate REGISTRY.
"""

from __future__ import annotations

from bounty.validate._base import REGISTRY
from bounty.validate.anthropic import AnthropicValidator
from bounty.validate.aws import AWSValidator
from bounty.validate.discord import DiscordValidator
from bounty.validate.github import GitHubValidator
from bounty.validate.mailgun import MailgunValidator
from bounty.validate.openai import OpenAIValidator
from bounty.validate.razorpay import RazorpayValidator
from bounty.validate.sendgrid import SendGridValidator
from bounty.validate.shopify import ShopifyValidator
from bounty.validate.slack import SlackValidator
from bounty.validate.stripe import StripeValidator
from bounty.validate.twilio import TwilioValidator

_VALIDATORS = [
    AWSValidator(),
    GitHubValidator(),
    StripeValidator(),
    OpenAIValidator(),
    AnthropicValidator(),
    SlackValidator(),
    DiscordValidator(),
    TwilioValidator(),
    SendGridValidator(),
    MailgunValidator(),
    RazorpayValidator(),
    ShopifyValidator(),
]

for _v in _VALIDATORS:
    REGISTRY.register(_v)

__all__ = ["REGISTRY"]

