"""
bounty.recon.rate_manager — Adaptive per-host rate manager for the scanner.

Maintains per-host state (delay, consecutive failure/success counters, blocked
flag, request count) so the scanner backs off gracefully when a target starts
returning 429/403 responses and recovers once the target accepts requests again.

All state is in-memory for a single scan run — not persisted across restarts.
Thread-safe via per-host asyncio.Lock objects.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HostState:
    """Per-host mutable rate-limiting state."""

    delay: float = 0.0
    """Current inter-request delay in seconds for this host."""

    consecutive_429_403: int = 0
    """Count of consecutive 429 or 403 responses (resets on success)."""

    consecutive_success: int = 0
    """Count of consecutive successful responses (resets on error)."""

    consecutive_blocked: int = 0
    """Count of consecutive blocked responses (429/403/503) for block detection."""

    blocked: bool = False
    """True when the host is considered actively blocking this scanner."""

    request_count: int = 0
    """Total requests recorded for this host in the current scan run."""


class AdaptiveRateManager:
    """Thread-safe per-host adaptive rate manager.

    Design:
    - A ``asyncio.Lock`` per host serialises state mutations.
    - A global lock protects the host-registry dicts themselves.
    - All public methods are ``async`` so they can be awaited by probe tasks.

    Tuning constants
    ----------------
    MAX_DELAY        Maximum inter-request delay (seconds).  Caps exponential back-off.
    MIN_DELAY        Floor for delay halving.  0 = no enforced minimum.
    BLOCK_THRESHOLD  Consecutive blocked responses before ``blocked`` is set.
    SUCCESS_THRESHOLD Consecutive successes before the delay is halved.
    CONSEC_LIMIT     Consecutive 429/403 before the delay is doubled.
    """

    MAX_DELAY: float = 60.0
    MIN_DELAY: float = 0.0
    BLOCK_THRESHOLD: int = 5
    SUCCESS_THRESHOLD: int = 10
    CONSEC_LIMIT: int = 3

    def __init__(self, daily_request_budget_per_host: int = 5000) -> None:
        self._states: dict[str, HostState] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._global_lock: asyncio.Lock = asyncio.Lock()
        self.daily_request_budget_per_host = daily_request_budget_per_host

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_state(self, host: str) -> tuple[HostState, asyncio.Lock]:
        """Return (or lazily create) the state + lock pair for *host*."""
        async with self._global_lock:
            if host not in self._states:
                self._states[host] = HostState()
                self._locks[host] = asyncio.Lock()
            return self._states[host], self._locks[host]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def record_response(
        self,
        host: str,
        status_code: int,
        retry_after_header: Optional[str] = None,
    ) -> None:
        """Record a completed response and update per-host state.

        Args:
            host:               Bare hostname (scheme + port stripped).
            status_code:        HTTP response status code, or 0 on error.
            retry_after_header: Value of the ``Retry-After`` response header,
                                if present.  May be a numeric string (seconds)
                                or an HTTP-date string (treated as backoff).
        """
        state, lock = await self._get_state(host)
        async with lock:
            state.request_count += 1

            # Daily budget check — treat as blocked for the rest of the run.
            if state.request_count > self.daily_request_budget_per_host:
                state.blocked = True
                return

            is_throttled = status_code in (429, 503)
            is_blocked_response = status_code in (429, 403, 503)

            # ── Retry-After handling ─────────────────────────────────────────
            if is_throttled and retry_after_header is not None:
                try:
                    delay = float(retry_after_header)
                    state.delay = min(delay, self.MAX_DELAY)
                except ValueError:
                    # HTTP-date format or unparseable — fall through to back-off
                    state.delay = min(
                        state.delay * 2 if state.delay > 0 else 5.0,
                        self.MAX_DELAY,
                    )

            # ── Failure / success counters ───────────────────────────────────
            if status_code in (429, 403):
                state.consecutive_429_403 += 1
                state.consecutive_success = 0
            elif status_code == 503:
                # 503 counts as throttled; not as 429/403 for consecutive-block
                # purposes but does feed blocked-response counter below.
                state.consecutive_success = 0
            else:
                # Any other response (200, 301, 404, 0/error, …) counts as success
                # for the throttle counter reset.
                state.consecutive_429_403 = 0
                state.consecutive_success += 1

            # ── Doubling rule ────────────────────────────────────────────────
            # 3 consecutive 429/403 → double delay (floor at 5 s if currently 0).
            if state.consecutive_429_403 >= self.CONSEC_LIMIT:
                state.delay = min(
                    state.delay * 2 if state.delay > 0 else 5.0,
                    self.MAX_DELAY,
                )

            # ── Halving rule ─────────────────────────────────────────────────
            # 10 consecutive successes → halve delay.
            if state.consecutive_success >= self.SUCCESS_THRESHOLD:
                state.delay = max(state.delay / 2, self.MIN_DELAY)
                state.consecutive_success = 0  # reset so it halves again later

            # ── Blocked-flag detection ───────────────────────────────────────
            if is_blocked_response:
                state.consecutive_blocked += 1
            else:
                state.consecutive_blocked = 0

            if state.consecutive_blocked >= self.BLOCK_THRESHOLD:
                state.blocked = True

    # ------------------------------------------------------------------
    # Read-only accessors (synchronous — safe to call without awaiting)
    # ------------------------------------------------------------------

    def get_delay(self, host: str) -> float:
        """Return the current inter-request delay for *host* (seconds)."""
        state = self._states.get(host)
        return state.delay if state else 0.0

    def is_blocked(self, host: str) -> bool:
        """Return True if *host* has been flagged as actively blocking."""
        state = self._states.get(host)
        return state.blocked if state else False

    def should_pause_scan(self, host: str) -> bool:
        """Alias for ``is_blocked`` — semantic sugar for callers."""
        return self.is_blocked(host)

    def get_request_count(self, host: str) -> int:
        """Return the total number of requests recorded for *host*."""
        state = self._states.get(host)
        return state.request_count if state else 0

    def blocked_hosts(self) -> list[str]:
        """Return a list of all hosts currently flagged as blocked."""
        return [h for h, s in self._states.items() if s.blocked]

    def all_hosts(self) -> list[str]:
        """Return all hosts that have recorded at least one response."""
        return list(self._states.keys())

