"""
bounty.secrets.trufflehog — TruffleHog subprocess wrapper.

Runs TruffleHog OSS as a subprocess to scan arbitrary text for secrets.
This gives access to ~800 community-maintained secret patterns without
importing any Python dependencies.

Usage::

    from bounty.secrets.trufflehog import scan_with_trufflehog

    results = await scan_with_trufflehog(response_body_bytes)
    for r in results:
        print(r.detector_name, r.verified)

TruffleHog must be installed first::

    bounty tools install-trufflehog
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bounty import get_logger
from bounty.tools import get_trufflehog_path, trufflehog_install_hint

log = get_logger(__name__)


@dataclass
class TrufflehogResult:
    """A single secret detection result from TruffleHog.

    All fields map directly from TruffleHog's ``--json`` output format.
    """

    detector_name: str
    """The TruffleHog detector that matched (e.g. ``"AWS"``, ``"Stripe"``)."""

    decoded_secret: str
    """The decoded / normalised secret value."""

    raw_secret: str
    """The raw matched string from the scanned text."""

    verified: bool
    """True if TruffleHog confirmed the secret is live via API call."""

    extra_data: dict[str, Any] = field(default_factory=dict)
    """Additional metadata returned by the detector (identity, account, etc.)."""


# ---------------------------------------------------------------------------
# TruffleHog detector_name → bounty provider key
# ---------------------------------------------------------------------------

_DETECTOR_TO_PROVIDER: dict[str, str] = {
    # AWS
    "aws": "aws",
    "awsaccesskey": "aws",
    "amazonaws": "aws",
    "awssessiontoken": "aws",
    # GCP / Google
    "gcp": "gcp",
    "gcpapplicationdefaultcredentials": "gcp",
    "googlecloudplatform": "gcp",
    "googleapis": "gcp",
    "googleapplicationcredentials": "gcp",
    "googlestorage": "gcp",
    # Azure
    "azure": "azure",
    "azurestorage": "azure",
    "microsoftazure": "azure",
    "azureactivedirectory": "azure",
    # GitHub
    "github": "github",
    "githubtoken": "github",
    "githubapp": "github",
    "githuboauth": "github",
    "githubv2": "github",
    # GitLab
    "gitlab": "gitlab",
    "gitlabtoken": "gitlab",
    "gitlabv2": "gitlab",
    # Stripe
    "stripe": "stripe",
    "stripeapikey": "stripe",
    # Slack
    "slack": "slack",
    "slackwebhook": "slack",
    "slackapitoken": "slack",
    # Discord
    "discord": "discord",
    "discordwebhook": "discord",
    "discordtoken": "discord",
    # Twilio
    "twilio": "twilio",
    "twilioaccountsid": "twilio",
    # SendGrid
    "sendgrid": "sendgrid",
    "sendgridapikey": "sendgrid",
    # Mailgun
    "mailgun": "mailgun",
    "mailgunapikey": "mailgun",
    # Shopify
    "shopify": "shopify",
    "shopifytoken": "shopify",
    "shopifypartnertoken": "shopify",
    # Razorpay
    "razorpay": "razorpay",
    "razorpayapikey": "razorpay",
    # PayPal / Braintree
    "paypal": "paypal",
    "braintree": "braintree",
    # OpenAI
    "openai": "openai",
    "openaiapikey": "openai",
    # Anthropic
    "anthropic": "anthropic",
    "anthropicapikey": "anthropic",
    # Cloudflare
    "cloudflare": "cloudflare",
    "cloudflareapplicationtoken": "cloudflare",
    # Datadog
    "datadog": "datadog",
    "datadogapikey": "datadog",
    # DigitalOcean
    "digitalocean": "digitalocean",
    "digitaloceantoken": "digitalocean",
    # HuggingFace
    "huggingface": "huggingface",
    "huggingfacetoken": "huggingface",
    # Mailchimp
    "mailchimp": "mailchimp",
    "mailchimpapikey": "mailchimp",
    # Notion
    "notion": "notion",
    "notionapikey": "notion",
    "notionintegrationtoken": "notion",
    # Okta
    "okta": "okta",
    "oktaapitoken": "okta",
    # PagerDuty
    "pagerduty": "pagerduty",
    "pagerdutytokenv2": "pagerduty",
    # Plaid
    "plaid": "plaid",
    "plaidsecret": "plaid",
    # Sentry
    "sentry": "sentry",
    "sentrytoken": "sentry",
    # Square
    "square": "square",
    "squareapikey": "square",
    # Supabase
    "supabase": "supabase",
    "supabaseapikey": "supabase",
    # Telegram
    "telegram": "telegram",
    "telegrambot": "telegram",
    "telegrambottoken": "telegram",
    # Twitch
    "twitch": "twitch",
    "twitchoauthtoken": "twitch",
    # Vault / HashiCorp
    "vault": "vault",
    "hashicorpvault": "vault",
    "vaulttoken": "vault",
    # Linear
    "linear": "linear",
    "linearapitoken": "linear",
    # NPM
    "npm": "npm",
    "npmtoken": "npm",
    "npmv2": "npm",
    # Airtable
    "airtable": "airtable",
    "airtableapikey": "airtable",
    # Adyen
    "adyen": "adyen",
    "adyenapikey": "adyen",
    # Auth0
    "auth0": "auth0",
    "auth0managementapitoken": "auth0",
    # Mollie
    "mollie": "mollie",
    "mollieapikey": "mollie",
    # PayU
    "payu": "payu",
    "payusalt": "payu",
}


def map_detector_to_provider(detector_name: str) -> str:
    """Map a TruffleHog detector name to a bounty provider key.

    Performs a case-insensitive lookup against the known detector name table.
    If no mapping is found, returns the lowercase detector name as-is so that
    novel detectors are still recorded (just without a native validator).

    Args:
        detector_name: The ``DetectorName`` string from TruffleHog JSON output.

    Returns:
        Lowercase bounty provider key string.
    """
    return _DETECTOR_TO_PROVIDER.get(detector_name.lower(), detector_name.lower())


def _parse_trufflehog_line(line: str) -> TrufflehogResult | None:
    """Parse a single JSON line from TruffleHog stdout.

    Args:
        line: A single line of TruffleHog ``--json`` output.

    Returns:
        A :class:`TrufflehogResult` or ``None`` on parse failure.
    """
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    # TruffleHog v3 JSON schema
    source_metadata = obj.get("SourceMetadata") or {}
    data_block = source_metadata.get("Data") or {}

    # Extract detector name — try multiple key spellings used across versions
    detector_name: str = (
        obj.get("DetectorName")
        or obj.get("detector_name")
        or obj.get("Source")
        or ""
    )
    if not detector_name:
        return None

    # Decoded / raw secret
    decoded_secret: str = (
        obj.get("Raw")
        or obj.get("raw")
        or obj.get("DecodedSecret")
        or ""
    )
    raw_secret: str = (
        obj.get("RawV2")
        or obj.get("rawV2")
        or decoded_secret
    )

    verified: bool = bool(obj.get("Verified") or obj.get("verified"))

    # Extra data — merge SourceMetadata Data block with top-level extras
    extra: dict[str, Any] = {}
    extra.update({k: v for k, v in data_block.items() if isinstance(v, (str, int, float, bool))})
    if "ExtraData" in obj and isinstance(obj["ExtraData"], dict):
        extra.update(obj["ExtraData"])
    if "extra_data" in obj and isinstance(obj["extra_data"], dict):
        extra.update(obj["extra_data"])

    # Identity — look for common field names
    identity: str | None = (
        extra.get("account")  # type: ignore[assignment]
        or extra.get("username")
        or extra.get("identity")
        or extra.get("email")
    )
    if identity:
        extra["identity"] = str(identity)

    return TrufflehogResult(
        detector_name=detector_name,
        decoded_secret=decoded_secret,
        raw_secret=raw_secret,
        verified=verified,
        extra_data=extra,
    )


async def scan_with_trufflehog(
    text: str | bytes,
    binary_path: Path | None = None,
    timeout: int = 60,
) -> list[TrufflehogResult]:
    """Scan text for secrets using the TruffleHog binary.

    Writes ``text`` to a temporary file, invokes TruffleHog in filesystem mode
    with ``--json`` output, and parses each stdout line as a detection result.

    Args:
        text: Text or bytes to scan (e.g. an HTTP response body).
        binary_path: Override for the TruffleHog binary path.  Falls back to
                     the managed path under ``~/.bounty/tools/trufflehog``.
        timeout: Maximum seconds to wait for the subprocess.  Default: 60.

    Returns:
        List of :class:`TrufflehogResult` objects.  Returns an empty list if
        TruffleHog is not installed, fails to run, or finds nothing.
    """
    from bounty.config import get_settings

    settings = get_settings()
    effective_timeout = timeout or settings.trufflehog_timeout_seconds

    effective_path = binary_path or get_trufflehog_path(
        Path(str(settings.trufflehog_binary_path)).expanduser()
        if settings.trufflehog_binary_path
        else None
    )

    if effective_path is None or not effective_path.exists():
        log.warning("trufflehog_not_found", hint=trufflehog_install_hint())
        return []

    raw_bytes: bytes = text if isinstance(text, bytes) else text.encode("utf-8", errors="replace")

    results: list[TrufflehogResult] = []

    try:
        # Write to a temp file so TruffleHog can scan it via filesystem mode
        with tempfile.NamedTemporaryFile(
            suffix=".txt",
            prefix="bounty_th_",
            delete=False,
        ) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name

        try:
            proc = await asyncio.create_subprocess_exec(
                str(effective_path),
                "filesystem",
                "--json",
                "--no-update",
                "--only-verified=false",
                "--include-detectors",
                "all",
                tmp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(effective_timeout),
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                log.warning(
                    "trufflehog_timeout",
                    timeout=effective_timeout,
                )
                return []

            if stderr_bytes:
                stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
                if stderr_text:
                    log.debug("trufflehog_stderr", stderr=stderr_text[:500])

            for line in stdout_bytes.decode("utf-8", errors="replace").splitlines():
                result = _parse_trufflehog_line(line)
                if result is not None:
                    results.append(result)

        finally:
            # Clean up temp file
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass

    except FileNotFoundError:
        log.warning("trufflehog_binary_missing", path=str(effective_path),
                    hint=trufflehog_install_hint())
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("trufflehog_error", error=str(exc))
        return []

    log.debug("trufflehog_scan_complete", results=len(results))
    return results

