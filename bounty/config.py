"""
bounty.config — application configuration via pydantic-settings.

All configuration is loaded from environment variables and / or a ``.env``
file in the project root.  No secrets are hard-coded here.

Usage::

    from bounty.config import get_settings

    settings = get_settings()
    print(settings.data_dir)
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings.

    All fields can be overridden via environment variables (uppercased) or a
    ``.env`` file at the project root.  Pydantic-settings handles coercion.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------ paths
    data_dir: Path = Path("data")
    """Root directory for SQLite DB and evidence files."""

    tools_dir: Path = Path("tools")
    """Directory containing ProjectDiscovery binaries (subfinder, httpx, etc.)."""

    nuclei_templates_dir: Path = Path("tools/nuclei-templates")
    """Path to the nuclei templates directory."""

    # --------------------------------------------------------- notifications
    discord_webhook_findings: str = ""
    """Discord webhook URL for P0/P1 finding alerts.  Empty string = disabled."""

    discord_webhook_secrets: str = ""
    """Discord webhook URL for live-secret alerts.  Empty string = disabled."""

    # ----------------------------------------------------- HTTP / scan tuning
    http_timeout: float = 15.0
    """Default per-request timeout in seconds for recon/validation HTTP calls."""

    max_concurrent_per_target: int = 10
    """Maximum number of concurrent in-flight requests against a single target."""

    # Bug bounty programs accept browser-like UAs; identifiable scanner UAs get
    # blocked by WAFs and reduce coverage.  Override via USER_AGENT env var.
    user_agent: str = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    """User-Agent header sent with all HTTP probes."""

    max_response_bytes: int = 5_000_000
    """Maximum response body bytes kept in memory per probe (5 MB default)."""

    default_intensity: str = "normal"
    """Scan intensity level.  One of: ``light``, ``normal``, ``aggressive``."""

    # --------------------------------------------------------- logging
    log_level: str = "INFO"
    """Python logging level name: DEBUG, INFO, WARNING, ERROR, CRITICAL."""

    log_format: str = "console"
    """Log output format: ``console`` (pretty) or ``json`` (structured)."""

    # --------------------------------------------------------- platform
    host: str = "127.0.0.1"
    """Interface the UI server binds to.  Default is localhost-only."""

    port: int = 8000
    """TCP port for the FastAPI UI server."""

    # --------------------------------------------------------- UI / auth
    ui_token: str | None = None
    """Bearer token protecting the UI and API routes.  None = auth disabled (dev mode)."""

    dev_mode: bool = True
    """Enable development mode: permissive CORS, auth disabled when ui_token is unset."""

    # --------------------------------------------------------- intel / Shodan
    shodan_api_key: str = ""
    """Shodan API key.  Empty string disables Shodan features.  Set via SHODAN_API_KEY env var."""

    shodan_min_credits: int = 5
    """Minimum Shodan query credits required before running search/host queries."""

    intel_cache_ttl_days: int = 7
    """Time-to-live for file-based intel/Shodan result cache, in days."""

    cidr_max_size: int = 16
    """Minimum allowed CIDR prefix length (e.g. 16 means /16 is OK but /15 is refused)."""

    asn_resolve_timeout: float = 30.0
    """Timeout in seconds for ASN → CIDR prefix lookups via BGPView API."""

    # --------------------------------------------------------- secret scanning
    secret_validation_enabled: bool = True
    """Enable inline secret scanning + token validation during detect phase."""

    secret_validation_cache_ttl_days: int = 7
    """Re-validation window: skip re-validation if last_checked within this many days."""

    secret_validation_max_concurrent: int = 5
    """Maximum number of concurrent token-validation API calls."""

    # --------------------------------------------------------- trufflehog
    trufflehog_enabled: bool = True
    """Run TruffleHog on evidence bodies to inherit ~800 community secret patterns."""

    trufflehog_binary_path: Path = Path("~/.bounty/tools/trufflehog")
    """Path to the TruffleHog binary.  Resolved with expanduser() at runtime."""

    trufflehog_timeout_seconds: int = 60
    """Maximum seconds to wait for each TruffleHog subprocess invocation."""

    # --------------------------------------------------------- validators
    @field_validator("default_intensity")
    @classmethod
    def _validate_intensity(cls, v: str) -> str:
        allowed = {"light", "normal", "aggressive"}
        if v not in allowed:
            raise ValueError(f"default_intensity must be one of {allowed}, got {v!r}")
        return v

    @field_validator(
        "data_dir", "tools_dir", "nuclei_templates_dir", "trufflehog_binary_path",
        mode="before",
    )
    @classmethod
    def _expand_path(cls, v: object) -> Path:
        """Resolve ``~`` and relative paths to absolute ``Path`` objects."""
        return Path(str(v)).expanduser()

    # ---------------------------------------------------------- convenience
    @property
    def db_path(self) -> Path:
        """Absolute path to the SQLite database file."""
        return self.data_dir / "bounty.db"

    @property
    def evidence_dir(self) -> Path:
        """Absolute path to the evidence storage directory."""
        return self.data_dir / "evidence"

    @property
    def intel_cache_dir(self) -> Path:
        """Absolute path to the intel/Shodan result cache directory."""
        return self.data_dir / "intel_cache"

    @property
    def ui_static_dir(self) -> Path:
        """Absolute path to the UI static files directory."""
        return Path(__file__).parent / "ui" / "static"

    @property
    def ui_templates_dir(self) -> Path:
        """Absolute path to the UI Jinja2 templates directory."""
        return Path(__file__).parent / "ui" / "templates"

    def ensure_dirs(self) -> None:
        """Create data, evidence, and intel_cache directories if they do not exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.intel_cache_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton.

    Uses ``lru_cache`` so the ``.env`` file is only read once per process.
    In tests, call ``get_settings.cache_clear()`` after patching env vars.
    """
    return Settings()

