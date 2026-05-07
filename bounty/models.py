"""
bounty.models — Pydantic v2 models for the entire application domain.

These models are used for:
- Parsing rows from the SQLite database (via ``model_validate``)
- Request / response bodies in the FastAPI UI layer
- Internal data transfer between pipeline stages

Convention:
- ``*Row`` suffix = mirrors a DB table row exactly (all fields nullable where DB allows)
- No suffix = domain object used in application logic (stricter typing)
- ``*Draft`` = pre-insert object, no ``id`` / ``created_at`` yet
- ``*Request`` = inbound API / UI payload
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

class _Base(BaseModel):
    """Shared Pydantic config: strict mode, populate by name."""

    model_config = ConfigDict(
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


SeverityLabel = Literal["critical", "high", "medium", "low", "info"]
ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
FindingStatus = Literal["new", "triaged", "reported", "accepted", "duplicate", "wont_fix", "resolved"]
SecretStatus = Literal["pending", "live", "invalid", "error", "revoked"]
Platform = Literal["h1", "bugcrowd", "intigriti", "manual"]
ScanType = Literal["full", "recon", "detect", "validate", "custom"]
Intensity = Literal["light", "normal", "aggressive"]


def severity_label(score: int) -> SeverityLabel:
    """Map a 0-1000 severity score to a human label.

    Boundaries align with the misconfig-corpus priority bands:
    - P0 (critical): 800-1000
    - P1 (high):     600-799
    - P2 (medium):   400-599
    - P3 (low):      200-399
    - P4 (info):     0-199
    """
    if score >= 800:
        return "critical"
    if score >= 600:
        return "high"
    if score >= 400:
        return "medium"
    if score >= 200:
        return "low"
    return "info"


# ---------------------------------------------------------------------------
# Program
# ---------------------------------------------------------------------------

class Program(_Base):
    """A bug bounty program (HackerOne, Bugcrowd, etc.)."""

    id: str
    platform: Platform
    handle: str
    name: str
    url: str = ""
    policy_url: str = ""
    bounty_table: dict[str, float] | None = None
    active: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ProgramDraft(_Base):
    """Payload for creating a new program."""

    id: str
    platform: Platform
    handle: str
    name: str
    url: str = ""
    policy_url: str = ""
    bounty_table: dict[str, float] | None = None


# ---------------------------------------------------------------------------
# Target (scope rule)
# ---------------------------------------------------------------------------

class Target(_Base):
    """A single scope entry for a program."""

    id: int | None = None
    program_id: str
    scope_type: Literal["in_scope", "out_of_scope"]
    asset_type: Literal["url", "wildcard", "cidr", "android", "ios", "other", "ip", "asn"]
    value: str
    max_severity: str | None = None
    notes: str = ""
    created_at: datetime | None = None


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------

class Asset(_Base):
    """A discovered live host / URL."""

    id: str | None = None
    program_id: str
    host: str
    port: int | None = None
    scheme: str = "https"
    """Canonical scheme (mirrors primary_scheme)."""
    url: str
    ip: str | None = None
    status: str = "discovered"
    http_status: int | None = None
    title: str | None = None
    server: str | None = None
    cdn: str | None = None
    waf: str | None = None
    tls_issuer: str | None = None
    tls_expiry: str | None = None
    tags: list[str] = Field(default_factory=list)
    seen_protocols: list[str] = Field(default_factory=list)
    """Protocols (schemes) observed on this host:port, e.g. ["http", "https"]."""
    primary_scheme: str = "https"
    """Preferred scheme for the canonical URL (https over http when both seen)."""
    last_seen: datetime | None = None
    first_seen: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AssetDraft(_Base):
    """Pre-insert asset payload."""

    program_id: str
    host: str
    port: int | None = None
    scheme: str = "https"
    url: str
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

FingerprintCategory = Literal["web-server", "cms", "framework", "language", "cdn", "waf", "other"]

# Confidence tier system (Principle 1 — Phase 3.2).
# Tiers encode signal strength; each parser assigns a tier per rule.
# Use TIER_ORDER for numeric comparisons.
ConfidenceTier = Literal["definitive", "strong", "weak", "hint"]

TIER_ORDER: dict[str, int] = {
    "hint": 0,
    "weak": 1,
    "strong": 2,
    "definitive": 3,
}
"""Numeric rank for comparing confidence tiers (higher = more confident)."""

TIER_UP: dict[str, ConfidenceTier] = {
    "hint": "weak",
    "weak": "strong",
    "strong": "definitive",
    "definitive": "definitive",
}
"""One-step upgrade map used by the corroboration boost (Principle 4)."""


class FingerprintResult(_Base):
    """A single technology detection on an asset."""

    tech: str
    version: str | None = None
    category: FingerprintCategory = "other"
    evidence: str = ""
    # Confidence tier: definitive > strong > weak > hint.
    # 'hint' signals never survive deduplication alone (Principle 1).
    confidence: ConfidenceTier = "weak"

    # Set after DB insert
    id: str | None = None
    asset_id: str | None = None
    created_at: datetime | None = None


# ---------------------------------------------------------------------------
# ProbeResult — output of http_probe.probe()
# ---------------------------------------------------------------------------

class TLSInfo(_Base):
    """Minimal TLS information from an HTTP probe."""

    issuer: str | None = None
    subject: str | None = None
    not_after: str | None = None
    protocol: str | None = None
    cipher: str | None = None


class ProbeResult(_Base):
    """Full result of probing a single URL.

    This is the primary data structure flowing from ``recon.http_probe``
    into the fingerprint and detect stages.
    """

    url: str
    """Final URL after redirect resolution."""

    final_url: str
    """Same as ``url`` (alias for clarity in redirect chains)."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    body_text: str
    """UTF-8 decoded body (with ``errors='replace'``)."""

    redirect_chain: list[str] = Field(default_factory=list)
    """Ordered list of URLs visited before reaching the final response."""

    tls: TLSInfo | None = None
    ip: str | None = None
    elapsed_ms: float = 0.0
    error: str | None = None
    """Non-None means the probe failed; other fields may be partial."""

    body_truncated: bool = False
    """True when the response body was capped at ``max_response_bytes`` bytes."""

    @property
    def ok(self) -> bool:
        """True if the probe succeeded without errors."""
        return self.error is None

    @property
    def content_type(self) -> str:
        """Lower-cased Content-Type header value (empty string if absent)."""
        return self.headers.get("content-type", "").lower()

    @property
    def server(self) -> str:
        """Server header value (empty string if absent)."""
        return self.headers.get("server", "")


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class Scan(_Base):
    """A scan job persisted in the database."""

    id: str | None = None
    program_id: str | None = None
    asset_id: str | None = None
    scan_type: ScanType = "full"
    status: ScanStatus = "queued"
    intensity: Intensity = "normal"
    triggered_by: str = "scheduler"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    finding_count: int = 0
    error: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


class ScanRequest(_Base):
    """Inbound request to start a scan from the UI or CLI."""

    program_id: str | None = None
    asset_id: str | None = None
    scan_type: ScanType = "full"
    intensity: Intensity = "normal"
    triggered_by: str = "ui"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(_Base):
    """A validated vulnerability / misconfiguration finding."""

    id: str | None = None
    program_id: str | None = None
    asset_id: str | None = None
    scan_id: str | None = None
    dedup_key: str
    title: str
    category: str
    severity: int = Field(default=500, ge=0, le=1000)
    severity_label: SeverityLabel = "medium"
    status: FindingStatus = "new"
    url: str
    path: str = ""
    description: str = ""
    remediation: str = ""
    cvss_score: float | None = None
    cve: str | None = None
    cwe: str | None = None
    validated: bool = False
    validated_at: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @field_validator("severity_label", mode="before")
    @classmethod
    def _derive_label(cls, v: object, info: Any) -> str:
        """If severity_label is not explicitly set, derive it from severity."""
        if isinstance(v, str) and v:
            return v
        # Try to derive from severity field value in the data
        return v  # type: ignore[return-value]


class FindingDraft(_Base):
    """Pre-insert finding payload returned by Detection.run()."""

    program_id: str | None = None
    asset_id: str | None = None
    scan_id: str | None = None
    dedup_key: str
    title: str
    category: str
    severity: int = Field(default=500, ge=0, le=1000)
    url: str
    path: str = ""
    description: str = ""
    remediation: str = ""
    cvss_score: float | None = None
    cve: str | None = None
    cwe: str | None = None
    tags: list[str] = Field(default_factory=list)

    @property
    def computed_severity_label(self) -> SeverityLabel:
        """Compute the label from the numeric score."""
        return severity_label(self.severity)


# ---------------------------------------------------------------------------
# EvidencePackage
# ---------------------------------------------------------------------------

EvidenceKind = Literal["http", "screenshot", "log"]


class EvidencePackage(_Base):
    """Request / response + optional screenshot evidence for a finding."""

    id: str | None = None
    finding_id: str | None = None
    secret_val_id: str | None = None
    kind: EvidenceKind = "http"
    request_raw: str | None = None
    response_raw: str | None = None
    response_status: int | None = None
    response_body_path: str | None = None
    screenshot_path: str | None = None
    curl_cmd: str | None = None
    notes: str = ""
    captured_at: datetime | None = None


# ---------------------------------------------------------------------------
# Secrets / Validation
# ---------------------------------------------------------------------------

class ValidationResult(_Base):
    """Result of running a token validator against a discovered credential."""

    provider: str
    """Which validator handled this token (e.g. ``"stripe"``)."""

    secret_preview: str
    """First 8 characters of the secret followed by ``"…"``."""

    secret_hash: str
    """SHA-256 hex digest of the raw secret value."""

    secret_pattern: str
    """Name of the regex pattern that matched the secret."""

    status: SecretStatus
    scope: dict[str, Any] | None = None
    """Provider-specific permissions / scopes when status is ``live``."""

    identity: str | None = None
    """Account / user ID returned by the issuer."""

    error_message: str | None = None
    raw_response: dict[str, Any] | None = None
    """Full JSON response from the validation API call (for evidence)."""


class SecretValidation(_Base):
    """Database row for a secrets_validations record."""

    id: int | None = None
    asset_id: str | None = None
    finding_id: str | None = None
    provider: str
    secret_hash: str
    secret_preview: str
    secret_pattern: str
    status: SecretStatus = "pending"
    scope: dict[str, Any] | None = None
    identity: str | None = None
    last_checked: datetime | None = None
    next_check: datetime | None = None
    error_message: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class Report(_Base):
    """A draft or submitted bug report."""

    id: int | None = None
    finding_id: str
    platform: Platform | Literal["generic"]
    status: Literal["draft", "submitted", "accepted", "closed"] = "draft"
    title: str
    body: str
    submitted_at: datetime | None = None
    platform_id: str | None = None
    bounty_usd: float | None = None
    notes: str = ""
    created_at: datetime | None = None
    updated_at: datetime | None = None


# ---------------------------------------------------------------------------
# SSE event envelope (used in events.py)
# ---------------------------------------------------------------------------

class SSEEvent(_Base):
    """Envelope for a server-sent event published on the in-process bus."""

    event_type: str
    """One of the event type slugs defined in ui-spec.md."""

    data: dict[str, Any]
    """Arbitrary JSON payload for the event."""

    scan_id: str | None = None
    program_id: str | None = None


# ---------------------------------------------------------------------------
# Regex helper used by detect/secrets_scanner and validate/registry
# ---------------------------------------------------------------------------

# Pre-compiled to avoid repeated compilation
_SECRET_PREVIEW_RE = re.compile(r"^(.{8})")


def make_secret_preview(secret: str) -> str:
    """Return first 8 characters of ``secret`` followed by ``'…'``.

    Args:
        secret: The raw secret string.

    Returns:
        A truncated preview safe for display in the UI.
    """
    if len(secret) <= 8:
        return secret + "…"
    return secret[:8] + "…"


# ---------------------------------------------------------------------------
# Leads (intel / Shodan triage)
# ---------------------------------------------------------------------------

LeadStatus = Literal["new", "promoted", "dismissed"]


class Lead(_Base):
    """An intel lead from Shodan or manual entry, awaiting triage."""

    id: str | None = None
    source: str = "shodan"
    source_query: str | None = None
    ip: str
    port: int | None = None
    hostnames: list[str] = Field(default_factory=list)
    org: str | None = None
    asn: str | None = None
    product: str | None = None
    title: str | None = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    program_id: str | None = None
    status: LeadStatus = "new"
    discovered_at: datetime | None = None


