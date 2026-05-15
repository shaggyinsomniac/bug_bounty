"""
bounty.ai.client — Anthropic API wrapper with filesystem cache + daily cost cap.

Features:
- sha256(system + prompt) → data/ai_cache/<hash>.json (30-day TTL)
- Daily cost tracking in ai_usage SQLite table
- Refuses new requests if today's cost >= ai_daily_cost_cap_usd
- Uses claude-3-5-haiku-20241022 (cheap tier)
- Cost estimate: input_tokens * $0.000001 + output_tokens * $0.000005

Usage::

    from bounty.ai.client import get_client

    client = get_client()
    text = await client.complete("You are a helpful assistant.", "Summarise X.")
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from bounty import get_logger
from bounty.config import get_settings
from bounty.exceptions import AICostCapExceededError

log = get_logger(__name__)

_MODEL = "claude-3-5-haiku-20241022"
_ANTHROPIC_API = "https://api.anthropic.com/v1/messages"
_CACHE_TTL_DAYS = 30

# Cost per token in USD (Haiku tier, approximate)
_INPUT_COST_PER_TOKEN = 1e-6   # $0.000001 per input token
_OUTPUT_COST_PER_TOKEN = 5e-6  # $0.000005 per output token


# ---------------------------------------------------------------------------
# AnthropicClient
# ---------------------------------------------------------------------------

class AnthropicClient:
    """Thin async wrapper around the Anthropic messages API.

    Args:
        api_key: Anthropic API key.
        cache_dir: Directory for filesystem response cache (30-day TTL).
        db_path: Path to the SQLite database for ai_usage tracking.
        daily_cap: Daily spend cap in USD.  Requests refused when exceeded.
        enabled: When False, complete() returns an empty string immediately.
    """

    def __init__(
        self,
        api_key: str,
        cache_dir: Path,
        db_path: Path,
        daily_cap: float = 5.0,
        enabled: bool = True,
    ) -> None:
        self._api_key = api_key
        self._cache_dir = cache_dir
        self._db_path = db_path
        self._daily_cap = daily_cap
        self._enabled = enabled
        cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def complete(
        self,
        system: str,
        prompt: str,
        max_tokens: int = 1000,
    ) -> str:
        """Send a completion request, using cache when available.

        Args:
            system: System prompt.
            prompt: User-turn prompt.
            max_tokens: Maximum tokens to generate.

        Returns:
            The model's text response.

        Raises:
            AICostCapExceededError: If today's cost already meets/exceeds the cap.
            RuntimeError: If AI is disabled or no API key configured.
        """
        if not self._enabled:
            raise RuntimeError("AI features are disabled (ai_enabled=False).")
        if not self._api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not configured.  "
                "Set it in .env or as the ANTHROPIC_API_KEY environment variable."
            )

        # Check cost cap before hitting cache (avoid even cache reads when capped)
        await self._check_cost_cap()

        cache_key = _cache_key(system, prompt)
        cached = self._load_cache(cache_key)
        if cached is not None:
            log.debug("ai_cache_hit", key=cache_key[:16])
            return cached

        # Make real API call
        response_text, input_tok, output_tok = await self._call_api(
            system, prompt, max_tokens
        )

        # Estimate and record cost
        cost = input_tok * _INPUT_COST_PER_TOKEN + output_tok * _OUTPUT_COST_PER_TOKEN
        await self._record_usage(cost)

        # Save to cache
        self._save_cache(cache_key, response_text)

        log.info(
            "ai_complete",
            tokens_in=input_tok,
            tokens_out=output_tok,
            cost_usd=round(cost, 6),
        )
        return response_text

    async def get_today_usage(self) -> dict[str, Any]:
        """Return today's request_count and cost_estimate from ai_usage."""
        today = _today()
        from bounty.db import get_conn

        async with get_conn(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT request_count, cost_estimate FROM ai_usage WHERE date = ?",
                (today,),
            )
            row = await cur.fetchone()
        if row is None:
            return {"date": today, "request_count": 0, "cost_estimate": 0.0}
        return {
            "date": today,
            "request_count": int(row["request_count"]),
            "cost_estimate": float(row["cost_estimate"]),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _check_cost_cap(self) -> None:
        """Raise AICostCapExceededError if today's spend >= cap."""
        usage = await self.get_today_usage()
        today_cost: float = usage["cost_estimate"]
        if today_cost >= self._daily_cap:
            raise AICostCapExceededError(today_cost, self._daily_cap)

    async def _record_usage(self, cost: float) -> None:
        """Upsert today's row in ai_usage, incrementing count and cost."""
        from bounty.db import get_conn

        today = _today()
        async with get_conn(self._db_path) as conn:
            await conn.execute(
                """
                INSERT INTO ai_usage (date, request_count, cost_estimate)
                VALUES (?, 1, ?)
                ON CONFLICT(date) DO UPDATE SET
                    request_count = request_count + 1,
                    cost_estimate = cost_estimate + excluded.cost_estimate
                """,
                (today, cost),
            )
            await conn.commit()

    async def _call_api(
        self, system: str, prompt: str, max_tokens: int
    ) -> tuple[str, int, int]:
        """Call the Anthropic messages endpoint.

        Returns:
            (response_text, input_tokens, output_tokens)
        """
        payload: dict[str, Any] = {
            "model": _MODEL,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        async with httpx.AsyncClient(timeout=60.0) as http:
            resp = await http.post(
                _ANTHROPIC_API,
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
            )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Anthropic API error {resp.status_code}: {resp.text[:300]}"
            )
        data: dict[str, Any] = resp.json()
        content_blocks: list[dict[str, Any]] = data.get("content", [])
        text = "\n".join(
            b.get("text", "") for b in content_blocks if b.get("type") == "text"
        ).strip()
        usage: dict[str, Any] = data.get("usage", {})
        input_tok: int = int(usage.get("input_tokens", 0))
        output_tok: int = int(usage.get("output_tokens", 0))
        return text, input_tok, output_tok

    # ------------------------------------------------------------------
    # Cache helpers (filesystem, 30-day TTL)
    # ------------------------------------------------------------------

    def _cache_path(self, key: str) -> Path:
        return self._cache_dir / f"{key}.json"

    def _load_cache(self, key: str) -> str | None:
        """Load cached response if exists and not expired."""
        path = self._cache_path(key)
        if not path.exists():
            return None
        try:
            blob: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            created_at_str: str = blob.get("created_at", "")
            if not created_at_str:
                return None
            created_at = datetime.fromisoformat(created_at_str)
            now = datetime.now(tz=timezone.utc)
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            age_days = (now - created_at).days
            if age_days > _CACHE_TTL_DAYS:
                path.unlink(missing_ok=True)
                return None
            return str(blob.get("response", ""))
        except Exception:  # noqa: BLE001
            return None

    def _save_cache(self, key: str, response: str) -> None:
        """Write response to filesystem cache."""
        path = self._cache_path(key)
        try:
            blob = {
                "cache_key": key,
                "response": response,
                "created_at": datetime.now(tz=timezone.utc).isoformat(),
            }
            path.write_text(json.dumps(blob, indent=2), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            log.warning("ai_cache_write_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cache_key(system: str, prompt: str) -> str:
    """Return sha256 hex digest of (system + prompt)."""
    return hashlib.sha256((system + prompt).encode("utf-8")).hexdigest()


def _today() -> str:
    """Return today's date in YYYY-MM-DD format (UTC)."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

def get_client() -> AnthropicClient:
    """Return a configured AnthropicClient from application settings."""
    settings = get_settings()
    return AnthropicClient(
        api_key=settings.anthropic_api_key,
        cache_dir=settings.ai_cache_dir,
        db_path=settings.db_path,
        daily_cap=settings.ai_daily_cost_cap_usd,
        enabled=settings.ai_enabled,
    )

