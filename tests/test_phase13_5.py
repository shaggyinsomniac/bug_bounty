"""
tests/test_phase13_5.py — Phase 13.5: Adaptive rate limiting, WAF detection,
request jitter, UA rotation.

35+ unit tests covering:
- AdaptiveRateManager: delay logic, block detection, budget enforcement
- stealth: UA rotation, jitter bounds, WAF detection heuristics
- probe() integration: UA usage, jitter sleep, blocked-host skip
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bounty.recon.rate_manager import AdaptiveRateManager, HostState
from bounty.recon.stealth import (
    USER_AGENTS,
    get_rotating_ua,
    is_waf_block_response,
    jitter,
)


# ===========================================================================
# AdaptiveRateManager tests
# ===========================================================================


@pytest.mark.asyncio
async def test_record_response_429_with_retry_after_sets_delay() -> None:
    """429 + Retry-After header sets the host delay to that value."""
    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 429, retry_after_header="30")
    assert mgr.get_delay("example.com") == 30.0


@pytest.mark.asyncio
async def test_record_response_503_with_retry_after_sets_delay() -> None:
    """503 + Retry-After header sets the host delay."""
    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 503, retry_after_header="15")
    assert mgr.get_delay("example.com") == 15.0


@pytest.mark.asyncio
async def test_retry_after_capped_at_max_delay() -> None:
    """Retry-After value larger than MAX_DELAY is capped at 60 s."""
    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 429, retry_after_header="9999")
    assert mgr.get_delay("example.com") == mgr.MAX_DELAY


@pytest.mark.asyncio
async def test_retry_after_non_numeric_triggers_backoff() -> None:
    """Non-numeric Retry-After (HTTP-date) falls back to doubling."""
    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 429, retry_after_header="Thu, 01 Jan 2099 00:00:00 GMT")
    # delay should be 5.0 (from 0 * 2 → minimum seed of 5.0)
    assert mgr.get_delay("example.com") == 5.0


@pytest.mark.asyncio
async def test_three_consecutive_429_doubles_delay() -> None:
    """3 consecutive 429 responses double the delay."""
    mgr = AdaptiveRateManager()
    # Seed delay to 5 first via Retry-After
    await mgr.record_response("example.com", 429, retry_after_header="5")
    # Now trigger consecutive_429_403 counter to threshold (3)
    await mgr.record_response("example.com", 429)
    await mgr.record_response("example.com", 429)
    await mgr.record_response("example.com", 429)
    # After 3 consecutive hits the delay should have doubled
    assert mgr.get_delay("example.com") > 5.0


@pytest.mark.asyncio
async def test_three_consecutive_403_doubles_delay() -> None:
    """3 consecutive 403 responses also trigger the doubling rule."""
    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 429, retry_after_header="5")
    for _ in range(3):
        await mgr.record_response("example.com", 403)
    assert mgr.get_delay("example.com") > 5.0


@pytest.mark.asyncio
async def test_ten_successes_halve_delay() -> None:
    """10 consecutive successes halve the delay."""
    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 429, retry_after_header="20")
    for _ in range(10):
        await mgr.record_response("example.com", 200)
    assert mgr.get_delay("example.com") == 10.0


@pytest.mark.asyncio
async def test_delay_floor_at_zero() -> None:
    """Repeated halving floors at 0, never goes negative."""
    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 429, retry_after_header="0.001")
    for _ in range(100):
        await mgr.record_response("example.com", 200)
    assert mgr.get_delay("example.com") >= 0.0


@pytest.mark.asyncio
async def test_delay_cap_at_sixty_seconds() -> None:
    """Doubling is capped at MAX_DELAY (60 seconds)."""
    mgr = AdaptiveRateManager()
    # Force high baseline
    await mgr.record_response("example.com", 429, retry_after_header="40")
    for _ in range(20):
        await mgr.record_response("example.com", 429)
    assert mgr.get_delay("example.com") == mgr.MAX_DELAY


@pytest.mark.asyncio
async def test_five_blocked_responses_sets_blocked_flag() -> None:
    """5 consecutive 429/403 responses trigger blocked=True."""
    mgr = AdaptiveRateManager()
    for _ in range(5):
        await mgr.record_response("example.com", 429)
    assert mgr.is_blocked("example.com") is True


@pytest.mark.asyncio
async def test_five_403_sets_blocked_flag() -> None:
    """5 consecutive 403s also trigger blocked=True."""
    mgr = AdaptiveRateManager()
    for _ in range(5):
        await mgr.record_response("example.com", 403)
    assert mgr.is_blocked("example.com") is True


@pytest.mark.asyncio
async def test_four_blocked_not_yet_blocked() -> None:
    """4 consecutive blocked responses do NOT trigger the blocked flag."""
    mgr = AdaptiveRateManager()
    for _ in range(4):
        await mgr.record_response("example.com", 429)
    assert mgr.is_blocked("example.com") is False


@pytest.mark.asyncio
async def test_success_resets_consecutive_blocked_counter() -> None:
    """A success between blocked responses resets the consecutive counter."""
    mgr = AdaptiveRateManager()
    for _ in range(4):
        await mgr.record_response("example.com", 429)
    await mgr.record_response("example.com", 200)  # success resets counter
    await mgr.record_response("example.com", 429)  # only 1 blocked again
    assert mgr.is_blocked("example.com") is False


@pytest.mark.asyncio
async def test_should_pause_scan_returns_true_when_blocked() -> None:
    """should_pause_scan mirrors is_blocked."""
    mgr = AdaptiveRateManager()
    for _ in range(5):
        await mgr.record_response("example.com", 429)
    assert mgr.should_pause_scan("example.com") is True


@pytest.mark.asyncio
async def test_unknown_host_get_delay_returns_zero() -> None:
    """get_delay returns 0 for hosts that have never been seen."""
    mgr = AdaptiveRateManager()
    assert mgr.get_delay("unknown.example.com") == 0.0


@pytest.mark.asyncio
async def test_unknown_host_is_blocked_returns_false() -> None:
    """is_blocked returns False for hosts that have never been seen."""
    mgr = AdaptiveRateManager()
    assert mgr.is_blocked("unknown.example.com") is False


@pytest.mark.asyncio
async def test_multiple_hosts_independent_state() -> None:
    """Each host has independent delay and block state."""
    mgr = AdaptiveRateManager()
    for _ in range(5):
        await mgr.record_response("blocked.example.com", 429)
    for _ in range(5):
        await mgr.record_response("ok.example.com", 200)
    assert mgr.is_blocked("blocked.example.com") is True
    assert mgr.is_blocked("ok.example.com") is False
    assert mgr.get_delay("ok.example.com") == 0.0


@pytest.mark.asyncio
async def test_request_count_increments() -> None:
    """request_count tracks every recorded response."""
    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 200)
    await mgr.record_response("example.com", 200)
    await mgr.record_response("example.com", 404)
    assert mgr.get_request_count("example.com") == 3


@pytest.mark.asyncio
async def test_daily_budget_exceeded_sets_blocked() -> None:
    """Host exceeding daily budget gets blocked on the next record call."""
    mgr = AdaptiveRateManager(daily_request_budget_per_host=3)
    for _ in range(4):  # one over budget
        await mgr.record_response("example.com", 200)
    assert mgr.is_blocked("example.com") is True


@pytest.mark.asyncio
async def test_daily_budget_not_exceeded_not_blocked() -> None:
    """Host within daily budget is not blocked."""
    mgr = AdaptiveRateManager(daily_request_budget_per_host=100)
    for _ in range(5):
        await mgr.record_response("example.com", 200)
    assert mgr.is_blocked("example.com") is False


@pytest.mark.asyncio
async def test_blocked_hosts_list() -> None:
    """blocked_hosts() returns all hosts that have been flagged."""
    mgr = AdaptiveRateManager()
    for _ in range(5):
        await mgr.record_response("a.example.com", 429)
    await mgr.record_response("b.example.com", 200)
    blocked = mgr.blocked_hosts()
    assert "a.example.com" in blocked
    assert "b.example.com" not in blocked


@pytest.mark.asyncio
async def test_success_after_failure_resets_429_counter() -> None:
    """A 200 response resets the consecutive_429_403 counter so doubling stops."""
    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 429, retry_after_header="5")
    await mgr.record_response("example.com", 429)
    await mgr.record_response("example.com", 200)  # reset
    delay_after_reset = mgr.get_delay("example.com")
    await mgr.record_response("example.com", 429)  # only 1 since reset
    # Delay should not have doubled again (only 1 consecutive 429 now)
    assert mgr.get_delay("example.com") == delay_after_reset


# ===========================================================================
# stealth.get_rotating_ua tests
# ===========================================================================


def test_rotating_ua_same_host_returns_same_ua() -> None:
    """The same host always maps to the same UA string."""
    ua1 = get_rotating_ua("example.com")
    ua2 = get_rotating_ua("example.com")
    assert ua1 == ua2


def test_rotating_ua_returns_string_from_pool() -> None:
    """The returned UA is a member of the USER_AGENTS list."""
    ua = get_rotating_ua("example.com")
    assert ua in USER_AGENTS


def test_rotating_ua_different_hosts_may_differ() -> None:
    """Different hosts should not all receive identical UAs (some variation)."""
    hosts = [
        "a.example.com", "b.example.com", "c.example.com",
        "d.example.com", "example.org", "test.io",
        "foo.bar", "alpha.beta", "x.y.z",
    ]
    uas = {get_rotating_ua(h) for h in hosts}
    # With 9 hosts and 10 UAs, we expect at least 2 distinct UAs in practice
    assert len(uas) >= 2


def test_rotating_ua_covers_multiple_pool_entries() -> None:
    """At least 3 different UAs are selected across many hostnames."""
    hosts = [f"host{i}.example.com" for i in range(50)]
    uas = {get_rotating_ua(h) for h in hosts}
    assert len(uas) >= 3


# ===========================================================================
# stealth.jitter tests
# ===========================================================================


def test_jitter_returns_zero_for_zero_delay() -> None:
    """jitter(0) returns 0.0 — no sleep when no delay configured."""
    assert jitter(0.0) == 0.0


def test_jitter_returns_zero_for_negative_delay() -> None:
    """jitter of a negative value returns 0."""
    assert jitter(-1.0) == 0.0


def test_jitter_within_bounds_multiple_trials() -> None:
    """jitter(base) is always in [base*0.7, base*1.3] over many samples."""
    base = 10.0
    for _ in range(500):
        result = jitter(base)
        assert base * 0.7 <= result <= base * 1.3, f"jitter({base}) = {result} out of bounds"


def test_jitter_has_variance() -> None:
    """jitter produces different values across samples (not a constant)."""
    base = 5.0
    results = {jitter(base) for _ in range(20)}
    # With high probability (random.uniform) we should see >1 distinct value
    assert len(results) > 1


# ===========================================================================
# stealth.is_waf_block_response tests
# ===========================================================================


def test_waf_cloudflare_attention_required() -> None:
    """Cloudflare 'Attention Required' page is detected."""
    body = "<html><title>Attention Required! | Cloudflare</title>Just a moment...</html>"
    assert is_waf_block_response(403, body) is True


def test_waf_403_access_denied() -> None:
    """403 with 'Access Denied' body is detected as WAF."""
    assert is_waf_block_response(403, "Access Denied - Please contact your administrator") is True


def test_waf_429_with_captcha() -> None:
    """429 with captcha body is detected as WAF."""
    assert is_waf_block_response(429, "Please complete the captcha to continue") is True


def test_waf_503_request_blocked() -> None:
    """503 with 'Request blocked' body is detected as WAF."""
    assert is_waf_block_response(503, "Request blocked. Reference #XXXXXXXXX") is True


def test_waf_akamai_reference() -> None:
    """Akamai reference string triggers WAF detection."""
    body = "This site is protected by Akamai DDoS protection."
    assert is_waf_block_response(403, body) is True


def test_waf_cloudflare_ray_id_high_conf() -> None:
    """Cloudflare Ray ID is a high-confidence marker, detected even on 200."""
    body = "Something went wrong. Ray ID: 1234567890abcdef"
    assert is_waf_block_response(200, body) is True


def test_waf_incapsula_high_conf() -> None:
    """Incapsula reference detected even on 200 status."""
    body = "Powered by Incapsula - web application security"
    assert is_waf_block_response(200, body) is True


def test_waf_plain_403_no_markers_not_blocked() -> None:
    """Plain 403 without any WAF body markers is NOT flagged."""
    assert is_waf_block_response(403, "Forbidden") is False


def test_waf_plain_404_not_flagged() -> None:
    """404 Not Found is not a WAF block."""
    assert is_waf_block_response(404, "Not Found") is False


def test_waf_200_with_normal_body_not_flagged() -> None:
    """A normal 200 page is not flagged even if it mentions 'access'."""
    assert is_waf_block_response(200, "Welcome! Access your dashboard here.") is False


def test_waf_are_you_a_robot_on_200() -> None:
    """'are you a robot' high-confidence marker detected on 200."""
    body = "Are you a robot? Please verify you are human."
    assert is_waf_block_response(200, body) is True


def test_waf_case_insensitive() -> None:
    """WAF detection is case-insensitive."""
    assert is_waf_block_response(403, "ACCESS DENIED - contact admin") is True


# ===========================================================================
# probe() integration tests (mocked httpx)
# ===========================================================================


@pytest.mark.asyncio
async def test_probe_uses_rotating_ua(monkeypatch: pytest.MonkeyPatch) -> None:
    """probe() uses get_rotating_ua instead of the fixed settings.user_agent."""
    captured_headers: dict[str, str] = {}

    class FakeResponse:
        status_code = 200
        headers: dict[str, str] = {}
        history: list[object] = []
        url = "http://example.com"
        extensions: dict[str, object] = {}

        async def aiter_bytes(self, chunk_size: int = 65536):  # type: ignore[misc]
            yield b"<html>ok</html>"

        async def __aenter__(self) -> "FakeResponse":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            h = kwargs.get("headers", {})
            assert isinstance(h, dict)
            captured_headers.update(h)

        def stream(self, method: str, url: str) -> FakeResponse:
            return FakeResponse()

        async def __aenter__(self) -> "FakeClient":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

    monkeypatch.setattr("bounty.recon.http_probe.httpx.AsyncClient", FakeClient)
    # Clear semaphore cache so tests don't share state
    import bounty.recon.http_probe as hp
    hp._semaphores.clear()
    hp._sem_lock = None

    from bounty.recon.http_probe import probe

    await probe("http://example.com")
    expected_ua = get_rotating_ua("example.com")
    assert captured_headers.get("User-Agent") == expected_ua


@pytest.mark.asyncio
async def test_probe_skips_blocked_host() -> None:
    """probe() returns an error result immediately for a blocked host."""
    mgr = AdaptiveRateManager()
    # Force host blocked
    for _ in range(5):
        await mgr.record_response("blocked.example.com", 429)

    assert mgr.is_blocked("blocked.example.com") is True

    with patch("bounty.recon.http_probe.httpx.AsyncClient") as mock_client:
        import bounty.recon.http_probe as hp
        hp._semaphores.clear()
        hp._sem_lock = None

        from bounty.recon.http_probe import probe
        result = await probe(
            "http://blocked.example.com/path",
            rate_manager=mgr,
        )

    # httpx.AsyncClient should NOT have been initialised
    mock_client.assert_not_called()
    assert result.ok is False
    assert "blocked" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_probe_applies_jitter_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """probe() sleeps when rate_manager has a non-zero delay for the host."""
    sleep_calls: list[float] = []

    async def fake_sleep(secs: float) -> None:
        sleep_calls.append(secs)

    monkeypatch.setattr("bounty.recon.http_probe.asyncio.sleep", fake_sleep)

    mgr = AdaptiveRateManager()
    await mgr.record_response("example.com", 429, retry_after_header="10")

    class FakeResponse:
        status_code = 200
        headers: dict[str, str] = {}
        history: list[object] = []
        url = "http://example.com"
        extensions: dict[str, object] = {}

        async def aiter_bytes(self, chunk_size: int = 65536):  # type: ignore[misc]
            yield b""

        async def __aenter__(self) -> "FakeResponse":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            pass

        def stream(self, method: str, url: str) -> FakeResponse:
            return FakeResponse()

        async def __aenter__(self) -> "FakeClient":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

    monkeypatch.setattr("bounty.recon.http_probe.httpx.AsyncClient", FakeClient)

    import bounty.recon.http_probe as hp
    hp._semaphores.clear()
    hp._sem_lock = None

    # Ensure adaptive_rate_enabled=True via settings patch
    from bounty.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("ADAPTIVE_RATE_ENABLED", "true")
    monkeypatch.setenv("STEALTH_JITTER_ENABLED", "true")
    get_settings.cache_clear()

    from bounty.recon.http_probe import probe
    await probe("http://example.com", rate_manager=mgr)

    # At least one sleep call for jitter
    assert len(sleep_calls) >= 1
    assert sleep_calls[0] > 0  # should be jittered from delay of 10

    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_probe_no_rate_manager_backward_compat(monkeypatch: pytest.MonkeyPatch) -> None:
    """probe() works fine when rate_manager is None — backward compat."""

    class FakeResponse:
        status_code = 200
        headers: dict[str, str] = {}
        history: list[object] = []
        url = "http://norateman.example.com"
        extensions: dict[str, object] = {}

        async def aiter_bytes(self, chunk_size: int = 65536):  # type: ignore[misc]
            yield b"hello"

        async def __aenter__(self) -> "FakeResponse":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            pass

        def stream(self, method: str, url: str) -> FakeResponse:
            return FakeResponse()

        async def __aenter__(self) -> "FakeClient":
            return self

        async def __aexit__(self, *_: object) -> None:
            pass

    monkeypatch.setattr("bounty.recon.http_probe.httpx.AsyncClient", FakeClient)
    import bounty.recon.http_probe as hp
    hp._semaphores.clear()
    hp._sem_lock = None

    from bounty.recon.http_probe import probe
    result = await probe("http://norateman.example.com")
    assert result.status_code == 200
    assert result.ok is True

