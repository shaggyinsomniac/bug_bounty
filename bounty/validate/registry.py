"""
bounty.validate.registry — Imports and registers all validators (Phase 5 + Phase 11).

Import this module at application startup to populate REGISTRY.
"""

from __future__ import annotations

from bounty.validate._base import REGISTRY
from bounty.validate.adyen import AdyenValidator
from bounty.validate.airtable import AirtableValidator
from bounty.validate.anthropic import AnthropicValidator
from bounty.validate.auth0 import Auth0Validator
from bounty.validate.aws import AWSValidator
from bounty.validate.azure import AzureValidator
from bounty.validate.braintree import BraintreeValidator
from bounty.validate.cloudflare import CloudflareValidator
from bounty.validate.datadog import DatadogValidator
from bounty.validate.digitalocean import DigitalOceanValidator
from bounty.validate.discord import DiscordValidator
from bounty.validate.gcp import GCPValidator
from bounty.validate.github import GitHubValidator
from bounty.validate.gitlab import GitLabValidator
from bounty.validate.huggingface import HuggingFaceValidator
from bounty.validate.linear import LinearValidator
from bounty.validate.mailchimp import MailchimpValidator
from bounty.validate.mailgun import MailgunValidator
from bounty.validate.mollie import MollieValidator
from bounty.validate.notion import NotionValidator
from bounty.validate.npm import NpmValidator
from bounty.validate.okta import OktaValidator
from bounty.validate.openai import OpenAIValidator
from bounty.validate.pagerduty import PagerDutyValidator
from bounty.validate.paypal import PayPalValidator
from bounty.validate.payu import PayUValidator
from bounty.validate.plaid import PlaidValidator
from bounty.validate.razorpay import RazorpayValidator
from bounty.validate.sendgrid import SendGridValidator
from bounty.validate.sentry import SentryValidator
from bounty.validate.shopify import ShopifyValidator
from bounty.validate.slack import SlackValidator
from bounty.validate.square import SquareValidator
from bounty.validate.stripe import StripeValidator
from bounty.validate.supabase import SupabaseValidator
from bounty.validate.telegram import TelegramValidator
from bounty.validate.twilio import TwilioValidator
from bounty.validate.twitch import TwitchValidator
from bounty.validate.vault import VaultValidator

_VALIDATORS = [
    # Phase 5
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
    # Phase 11
    AdyenValidator(),
    AirtableValidator(),
    Auth0Validator(),
    AzureValidator(),
    BraintreeValidator(),
    CloudflareValidator(),
    DatadogValidator(),
    DigitalOceanValidator(),
    GCPValidator(),
    GitLabValidator(),
    HuggingFaceValidator(),
    LinearValidator(),
    MailchimpValidator(),
    MollieValidator(),
    NotionValidator(),
    NpmValidator(),
    OktaValidator(),
    PagerDutyValidator(),
    PayPalValidator(),
    PayUValidator(),
    PlaidValidator(),
    SentryValidator(),
    SquareValidator(),
    SupabaseValidator(),
    TelegramValidator(),
    TwitchValidator(),
    VaultValidator(),
]

for _v in _VALIDATORS:
    REGISTRY.register(_v)

__all__ = ["REGISTRY"]

