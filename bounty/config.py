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

    # --------------------------------------------------------- validators
    @field_validator("default_intensity")
    @classmethod
    def _validate_intensity(cls, v: str) -> str:
        allowed = {"light", "normal", "aggressive"}
        if v not in allowed:
            raise ValueError(f"default_intensity must be one of {allowed}, got {v!r}")
        return v

    @field_validator("data_dir", "tools_dir", "nuclei_templates_dir", mode="before")
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

    def ensure_dirs(self) -> None:
        """Create data and evidence directories if they do not exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton.

    Uses ``lru_cache`` so the ``.env`` file is only read once per process.
    In tests, call ``get_settings.cache_clear()`` after patching env vars.
    """
    return Settings()

