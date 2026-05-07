"""
tests/smoke.py — Phase 1 smoke test.

Verifies:
1. DB initialises without error and all expected tables exist.
2. HTTP probe against httpbin.org returns a valid ProbeResult.
3. EventBus publish/subscribe round-trips a single event.

Run with:
    pytest tests/smoke.py -v
or:
    python -m pytest tests/smoke.py -v
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from bounty.db import get_conn, init_db
from bounty.events import EventBus
from bounty.models import SSEEvent
from bounty.recon.http_probe import probe


# ---------------------------------------------------------------------------
# DB smoke
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_init_db_creates_tables() -> None:
    """init_db() should create all expected tables in a fresh database."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        init_db(db_path)

        expected_tables = {
            "programs",
            "targets",
            "assets",
            "asset_history",
            "fingerprints",
            "scans",
            "scan_phases",
            "findings",
            "evidence_packages",
            "secrets_validations",
            "reports",
            "audit_log",
        }

        async with get_conn(db_path) as conn:
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            rows = await cursor.fetchall()
            found = {row["name"] for row in rows}

        assert expected_tables.issubset(found), (
            f"Missing tables: {expected_tables - found}"
        )


@pytest.mark.asyncio
async def test_init_db_idempotent() -> None:
    """Calling init_db() twice must not raise or corrupt the schema."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        init_db(db_path)
        init_db(db_path)  # second call must not raise

        async with get_conn(db_path) as conn:
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            rows = await cursor.fetchall()
            assert len(rows) >= 12


@pytest.mark.asyncio
async def test_get_conn_row_factory() -> None:
    """get_conn() should yield rows accessible by column name."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        init_db(db_path)

        async with get_conn(db_path) as conn:
            await conn.execute(
                """
                INSERT INTO programs (id, platform, handle, name)
                VALUES ('test:prog', 'manual', 'prog', 'Test Program')
                """
            )
            await conn.commit()
            cursor = await conn.execute(
                "SELECT * FROM programs WHERE id = 'test:prog'"
            )
            row = await cursor.fetchone()

        assert row is not None
        assert row["id"] == "test:prog"
        assert row["platform"] == "manual"
        assert row["name"] == "Test Program"
        assert row["active"] == 1


# ---------------------------------------------------------------------------
# HTTP probe smoke
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_probe_httpbin() -> None:
    """probe() should return a successful ProbeResult for httpbin.org/get."""
    result = await probe("https://httpbin.org/get")

    assert result.ok, f"Probe failed: {result.error}"
    assert result.status_code == 200
    assert len(result.body) > 0
    assert result.body_text != ""
    assert "httpbin" in result.body_text.lower() or result.status_code == 200
    assert result.final_url.startswith("https://")
    assert result.elapsed_ms > 0


@pytest.mark.asyncio
async def test_probe_returns_error_result_on_failure() -> None:
    """probe() against a non-existent host must return ProbeResult with error set."""
    result = await probe("https://this-domain-does-not-exist-bounty-test.invalid/")

    assert not result.ok
    assert result.error is not None
    assert result.status_code == 0


@pytest.mark.asyncio
async def test_probe_captures_redirect_chain() -> None:
    """probe() should record the full redirect chain."""
    # httpbin /redirect/1 returns 302 → /get
    result = await probe("https://httpbin.org/redirect/1")

    assert result.ok, f"Probe failed: {result.error}"
    # There should be at least one hop in the redirect chain.
    assert len(result.redirect_chain) >= 1


@pytest.mark.asyncio
async def test_probe_respects_concurrency_limit() -> None:
    """10 concurrent probes against the same host should complete successfully."""
    urls = ["https://httpbin.org/delay/0"] * 10
    results = await asyncio.gather(*[probe(u) for u in urls])

    successes = [r for r in results if r.ok]
    # Allow some failures due to rate limiting or network issues on CI,
    # but at least 7/10 must succeed.
    assert len(successes) >= 7, f"Only {len(successes)}/10 probes succeeded"


# ---------------------------------------------------------------------------
# EventBus smoke
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_event_bus_publish_subscribe() -> None:
    """Events published on the bus must be received by subscribers."""
    eb = EventBus()
    received: list[SSEEvent] = []

    async def consumer() -> None:
        async for event in eb.subscribe():
            received.append(event)
            break  # stop after first event

    task = asyncio.create_task(consumer())
    # Give the consumer a moment to register.
    await asyncio.sleep(0)

    await eb.publish(
        SSEEvent(event_type="scan:started", data={"scan_id": 42})
    )
    await asyncio.wait_for(task, timeout=2.0)

    assert len(received) == 1
    assert received[0].event_type == "scan:started"
    assert received[0].data["scan_id"] == 42


@pytest.mark.asyncio
async def test_event_bus_filter_by_type() -> None:
    """Subscribers with an event_types filter must only see matching events."""
    eb = EventBus()
    received: list[SSEEvent] = []

    async def consumer() -> None:
        async for event in eb.subscribe(event_types={"finding:new"}):
            received.append(event)
            break

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0)

    # Publish a non-matching event first, then a matching one.
    await eb.publish(SSEEvent(event_type="scan:started", data={}))
    await eb.publish(SSEEvent(event_type="finding:new", data={"id": 1}))
    await asyncio.wait_for(task, timeout=2.0)

    assert len(received) == 1
    assert received[0].event_type == "finding:new"


@pytest.mark.asyncio
async def test_event_bus_no_subscribers_is_safe() -> None:
    """Publishing with no subscribers must not raise."""
    eb = EventBus()
    await eb.publish(SSEEvent(event_type="queue:depth", data={"depth": 0}))

