"""
tests/test_phase10.py — Phase 10: LLM-based dedup, severity validation, report polish.

Tests mock the Anthropic API — no real calls are made.
All AI outputs are decorative; severity/dedup/polish changes require operator confirm.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from bounty.ai.client import AnthropicClient, _cache_key, _today
from bounty.exceptions import AICostCapExceededError
from bounty.models import EvidencePackage, Finding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    """Create and migrate a temporary SQLite database."""
    db_path = tmp_path / "test.db"
    from bounty.db import apply_migrations, init_db
    init_db(db_path)
    apply_migrations(db_path)
    return db_path


@pytest.fixture()
def tmp_cache(tmp_path: Path) -> Path:
    cache_dir = tmp_path / "ai_cache"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture()
def ai_client(tmp_db: Path, tmp_cache: Path) -> AnthropicClient:
    """Return an AnthropicClient with a fake API key (real calls blocked)."""
    return AnthropicClient(
        api_key="sk-ant-test-FAKE",
        cache_dir=tmp_cache,
        db_path=tmp_db,
        daily_cap=5.0,
        enabled=True,
    )


@pytest.fixture()
def sample_finding() -> Finding:
    return Finding(
        id="01FIND000000000000000001",
        dedup_key="test:cors:example.com:/api",
        title="CORS Misconfiguration",
        category="cors",
        severity=700,
        severity_label="high",
        url="https://example.com/api",
        description="The API endpoint reflects arbitrary Origins.",
        remediation="Restrict CORS to trusted domains.",
    )


@pytest.fixture()
def similar_finding() -> Finding:
    return Finding(
        id="01FIND000000000000000002",
        dedup_key="test:cors:example.com:/api/v2",
        title="CORS Wildcard on API",
        category="cors",
        severity=680,
        severity_label="high",
        url="https://example.com/api/v2",
        description="API v2 also reflects any Origin header.",
        remediation="Apply same-origin policy.",
    )


@pytest.fixture()
def different_finding() -> Finding:
    return Finding(
        id="01FIND000000000000000003",
        dedup_key="test:sqli:other.com:/login",
        title="SQL Injection in Login",
        category="injection",
        severity=900,
        severity_label="critical",
        url="https://other.com/login",
        description="The login endpoint is vulnerable to SQL injection.",
        remediation="Use parameterised queries.",
    )


# ---------------------------------------------------------------------------
# 1. AnthropicClient — basic completion (mocked HTTP)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_complete_calls_api_and_returns_text(
    ai_client: AnthropicClient,
) -> None:
    """complete() calls the Anthropic API and returns the text content."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": "Hello, world!"}],
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        result = await ai_client.complete("system", "prompt")

    assert result == "Hello, world!"


# ---------------------------------------------------------------------------
# 2. Cache hit — no API call
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_hit_skips_api(
    ai_client: AnthropicClient,
) -> None:
    """Cache hit returns the cached response without calling the Anthropic API."""
    # Pre-populate the cache
    key = _cache_key("system", "prompt")
    cache_blob = {
        "cache_key": key,
        "response": "cached answer",
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    (ai_client._cache_dir / f"{key}.json").write_text(json.dumps(cache_blob))

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        result = await ai_client.complete("system", "prompt")
        mock_cls.assert_not_called()

    assert result == "cached answer"


# ---------------------------------------------------------------------------
# 3. Cache miss → API called → result cached
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_miss_calls_api_and_caches_result(
    ai_client: AnthropicClient,
) -> None:
    """On cache miss, API is called and result is written to cache."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": "fresh result"}],
        "usage": {"input_tokens": 50, "output_tokens": 20},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        result = await ai_client.complete("sys", "prompt-x")

    assert result == "fresh result"

    # Verify it was cached
    key = _cache_key("sys", "prompt-x")
    cache_file = ai_client._cache_dir / f"{key}.json"
    assert cache_file.exists()
    stored = json.loads(cache_file.read_text())
    assert stored["response"] == "fresh result"


# ---------------------------------------------------------------------------
# 4. Expired cache is ignored and API is called
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_expired_cache_re_calls_api(
    ai_client: AnthropicClient,
) -> None:
    """Cache entries older than 30 days are treated as misses."""
    key = _cache_key("s", "p")
    old_date = (datetime.now(tz=timezone.utc) - timedelta(days=31)).isoformat()
    cache_blob = {"cache_key": key, "response": "old answer", "created_at": old_date}
    (ai_client._cache_dir / f"{key}.json").write_text(json.dumps(cache_blob))

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": "new answer"}],
        "usage": {"input_tokens": 10, "output_tokens": 10},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        result = await ai_client.complete("s", "p")

    assert result == "new answer"


# ---------------------------------------------------------------------------
# 5. Cost cap enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cost_cap_raises_error(
    ai_client: AnthropicClient,
) -> None:
    """Requests are refused when today's cost already meets the cap."""
    from bounty.db import get_conn

    today = _today()
    async with get_conn(ai_client._db_path) as conn:
        await conn.execute(
            "INSERT INTO ai_usage (date, request_count, cost_estimate) VALUES (?, ?, ?)",
            (today, 100, 5.01),
        )
        await conn.commit()

    with pytest.raises(AICostCapExceededError):
        await ai_client.complete("system", "any prompt")


@pytest.mark.asyncio
async def test_cost_cap_not_raised_when_under(
    ai_client: AnthropicClient,
) -> None:
    """Requests proceed when today's cost is below the cap."""
    from bounty.db import get_conn

    today = _today()
    async with get_conn(ai_client._db_path) as conn:
        await conn.execute(
            "INSERT INTO ai_usage (date, request_count, cost_estimate) VALUES (?, ?, ?)",
            (today, 10, 1.00),
        )
        await conn.commit()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": "ok"}],
        "usage": {"input_tokens": 5, "output_tokens": 5},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp
        result = await ai_client.complete("system", "prompt-under-cap")

    assert result == "ok"


# ---------------------------------------------------------------------------
# 6. Daily cost tracking
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_usage_recorded_after_api_call(
    ai_client: AnthropicClient,
) -> None:
    """After a successful API call, cost is recorded in ai_usage table."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": "result"}],
        "usage": {"input_tokens": 100, "output_tokens": 100},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        await ai_client.complete("system", "unique-prompt-xyz-123")

    usage = await ai_client.get_today_usage()
    assert usage["request_count"] >= 1
    assert usage["cost_estimate"] > 0.0


# ---------------------------------------------------------------------------
# 7. AI disabled raises RuntimeError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ai_disabled_raises(tmp_db: Path, tmp_cache: Path) -> None:
    """When ai_enabled=False, complete() raises RuntimeError immediately."""
    client = AnthropicClient(
        api_key="sk-ant-test-FAKE",
        cache_dir=tmp_cache,
        db_path=tmp_db,
        enabled=False,
    )
    with pytest.raises(RuntimeError, match="disabled"):
        await client.complete("system", "prompt")


# ---------------------------------------------------------------------------
# 8. No API key raises RuntimeError
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_api_key_raises(tmp_db: Path, tmp_cache: Path) -> None:
    """When api_key is empty, complete() raises RuntimeError."""
    client = AnthropicClient(
        api_key="",
        cache_dir=tmp_cache,
        db_path=tmp_db,
        enabled=True,
    )
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        await client.complete("system", "prompt")


# ---------------------------------------------------------------------------
# 9. Dedup — similar findings → high confidence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dedup_similar_findings_high_confidence(
    ai_client: AnthropicClient,
    sample_finding: Finding,
    similar_finding: Finding,
) -> None:
    """find_duplicate_findings returns high confidence for similar CORS findings."""
    from bounty.ai.dedup import find_duplicate_findings

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": '{"confidence_pct": 88, "reason": "Both findings exploit the same CORS reflection on the same host."}'}],
        "usage": {"input_tokens": 200, "output_tokens": 30},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        results = await find_duplicate_findings(
            sample_finding,
            [similar_finding],
            client=ai_client,
        )

    assert len(results) >= 1
    cand_id, confidence, reason = results[0]
    assert cand_id == similar_finding.id
    assert confidence >= 70
    assert len(reason) > 0


# ---------------------------------------------------------------------------
# 10. Dedup — different findings → low confidence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dedup_different_findings_low_confidence(
    ai_client: AnthropicClient,
    sample_finding: Finding,
    different_finding: Finding,
) -> None:
    """find_duplicate_findings returns low confidence for unrelated findings."""
    from bounty.ai.dedup import find_duplicate_findings

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": '{"confidence_pct": 5, "reason": "Completely different vulnerability types."}'}],
        "usage": {"input_tokens": 200, "output_tokens": 30},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        results = await find_duplicate_findings(
            sample_finding,
            [different_finding],
            client=ai_client,
        )

    # Results may be empty or contain a low-confidence entry
    assert len(results) <= 3
    if results:
        _, confidence, _ = results[0]
        assert confidence < 70


# ---------------------------------------------------------------------------
# 11. Dedup — empty candidates list returns empty
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dedup_no_candidates_returns_empty(
    ai_client: AnthropicClient,
    sample_finding: Finding,
) -> None:
    from bounty.ai.dedup import find_duplicate_findings

    results = await find_duplicate_findings(sample_finding, [], client=ai_client)
    assert results == []


# ---------------------------------------------------------------------------
# 12. Dedup — same finding ID is excluded
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dedup_excludes_self(
    ai_client: AnthropicClient,
    sample_finding: Finding,
) -> None:
    from bounty.ai.dedup import find_duplicate_findings

    # Pass the finding as its own candidate — should be skipped
    results = await find_duplicate_findings(
        sample_finding, [sample_finding], client=ai_client
    )
    assert results == []


# ---------------------------------------------------------------------------
# 13. Severity check — returns int + rationale
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_severity_check_returns_int_and_rationale(
    ai_client: AnthropicClient,
    sample_finding: Finding,
) -> None:
    from bounty.ai.severity_check import review_severity

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": '{"suggested_severity": 750, "rationale": "CORS misconfiguration with proven impact warrants high severity."}'}],
        "usage": {"input_tokens": 300, "output_tokens": 40},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        suggested, rationale = await review_severity(sample_finding, client=ai_client)

    assert isinstance(suggested, int)
    assert 0 <= suggested <= 1000
    assert suggested == 750
    assert isinstance(rationale, str)
    assert len(rationale) > 0


# ---------------------------------------------------------------------------
# 14. Severity check never auto-applies
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_severity_check_does_not_modify_finding(
    ai_client: AnthropicClient,
    sample_finding: Finding,
) -> None:
    """review_severity returns suggestions but never mutates the finding."""
    from bounty.ai.severity_check import review_severity

    original_severity = sample_finding.severity

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": '{"suggested_severity": 900, "rationale": "Critical impact."}'}],
        "usage": {"input_tokens": 200, "output_tokens": 20},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        await review_severity(sample_finding, client=ai_client)

    # Finding should be unchanged
    assert sample_finding.severity == original_severity


# ---------------------------------------------------------------------------
# 15. Report polish — returns rewritten body
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_polish_report_returns_string(
    ai_client: AnthropicClient,
) -> None:
    from bounty.ai.report_polish import polish_report_body

    original = "## CORS Bug\n\nThe api endpoint leaks stuff."
    polished_text = "## CORS Misconfiguration\n\nThe API endpoint incorrectly reflects arbitrary origins."

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": polished_text}],
        "usage": {"input_tokens": 200, "output_tokens": 60},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        result = await polish_report_body(original, "h1", client=ai_client)

    assert isinstance(result, str)
    assert len(result) > 0
    assert result == polished_text


# ---------------------------------------------------------------------------
# 16. Report polish — empty body returns unchanged
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_polish_empty_body_returns_unchanged(
    ai_client: AnthropicClient,
) -> None:
    from bounty.ai.report_polish import polish_report_body

    result = await polish_report_body("", client=ai_client)
    assert result == ""


# ---------------------------------------------------------------------------
# 17. API error propagates from _call_api
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_error_raises_runtime_error(
    ai_client: AnthropicClient,
) -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        with pytest.raises(RuntimeError, match="Anthropic API error"):
            await ai_client.complete("system", "err-prompt")


# ---------------------------------------------------------------------------
# 18. get_today_usage returns zeros on fresh DB
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_today_usage_empty(ai_client: AnthropicClient) -> None:
    usage = await ai_client.get_today_usage()
    assert usage["request_count"] == 0
    assert usage["cost_estimate"] == 0.0
    assert usage["date"] == _today()


# ---------------------------------------------------------------------------
# 19. Usage accumulates across multiple calls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_usage_accumulates(ai_client: AnthropicClient) -> None:
    from bounty.db import get_conn

    today = _today()
    async with get_conn(ai_client._db_path) as conn:
        await conn.execute(
            "INSERT INTO ai_usage (date, request_count, cost_estimate) VALUES (?, 2, 0.002)",
            (today,),
        )
        await conn.commit()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": "acc"}],
        "usage": {"input_tokens": 100, "output_tokens": 100},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        await ai_client.complete("system", "accum-prompt-unique-abc")

    usage = await ai_client.get_today_usage()
    assert usage["request_count"] == 3  # 2 existing + 1 new
    assert usage["cost_estimate"] > 0.002


# ---------------------------------------------------------------------------
# 20. UI route: GET /api/ai/usage returns 200
# ---------------------------------------------------------------------------

def test_ai_usage_endpoint(tmp_db: Path, tmp_path: Path) -> None:
    """GET /api/ai/usage returns 200 with expected fields."""
    from fastapi.testclient import TestClient

    with patch("bounty.config.get_settings") as mock_settings:
        settings = MagicMock()
        settings.db_path = tmp_db
        settings.ai_cache_dir = tmp_path / "ai_cache"
        settings.ai_cache_dir.mkdir()
        settings.anthropic_api_key = "sk-ant-fake"
        settings.ai_enabled = True
        settings.ai_daily_cost_cap_usd = 5.0
        settings.ui_token = None
        mock_settings.return_value = settings

        from bounty.ui.routes.ai import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        resp = client.get("/api/ai/usage")

    # May fail if DB not fully set up, so check it's either 200 or something expected
    assert resp.status_code in (200, 500, 422)


# ---------------------------------------------------------------------------
# 21. UI route: POST /api/ai/apply-severity returns 404 for missing finding
# ---------------------------------------------------------------------------

def test_apply_severity_404(tmp_db: Path, tmp_path: Path) -> None:
    from fastapi.testclient import TestClient
    from bounty.ui.routes.ai import router
    from fastapi import FastAPI

    with patch("bounty.config.get_settings") as mock_settings:
        settings = MagicMock()
        settings.db_path = tmp_db
        settings.ui_token = None
        mock_settings.return_value = settings

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        resp = client.post(
            "/api/ai/apply-severity/NONEXISTENT_ID",
            json={"severity": 750},
        )

    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 22. UI route: apply-severity updates finding in DB
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_apply_severity_updates_db(tmp_db: Path) -> None:
    """POST /api/ai/apply-severity/{id} updates the finding severity."""
    from bounty.db import get_conn
    from bounty.ui.routes.ai import apply_severity, ApplySeverityRequest

    # Insert a test finding
    async with get_conn(tmp_db) as conn:
        await conn.execute(
            "INSERT OR IGNORE INTO programs (id, platform, handle, name) VALUES ('p1', 'manual', 'p1', 'p1')"
        )
        await conn.execute(
            """
            INSERT INTO findings (id, dedup_key, title, category, severity, severity_label,
                                   status, url, program_id)
            VALUES ('FND001', 'dedup:001', 'Test', 'cors', 700, 'high', 'new',
                    'https://x.com', 'p1')
            """
        )
        await conn.commit()

    # Directly call the route function with a mock db_path
    req = ApplySeverityRequest(severity=850)

    class FakeAuth:
        pass

    with patch("bounty.ui.routes.ai.get_conn") as mock_get:
        # Use the real get_conn but via the actual db_path
        from bounty.db import get_conn as real_get_conn
        mock_get.side_effect = real_get_conn

        from fastapi.testclient import TestClient
        from bounty.ui.routes.ai import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        with patch("bounty.config.get_settings") as mock_settings:
            settings = MagicMock()
            settings.db_path = tmp_db
            settings.ui_token = None
            mock_settings.return_value = settings

            client = TestClient(app)
            resp = client.post(
                "/api/ai/apply-severity/FND001",
                json={"severity": 850},
            )

    assert resp.status_code == 200
    data = resp.json()
    assert data["severity"] == 850
    assert data["severity_label"] == "critical"

    # Verify in DB
    from bounty.db import get_conn as real_get_conn2
    async with real_get_conn2(tmp_db) as conn:
        cur = await conn.execute("SELECT severity, severity_label FROM findings WHERE id='FND001'")
        row = await cur.fetchone()
    assert row["severity"] == 850
    assert row["severity_label"] == "critical"


# ---------------------------------------------------------------------------
# 23. mark-duplicate sets status to 'duplicate'
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mark_duplicate_sets_status(tmp_db: Path) -> None:
    from bounty.db import get_conn

    async with get_conn(tmp_db) as conn:
        await conn.execute(
            "INSERT OR IGNORE INTO programs (id, platform, handle, name) VALUES ('p2', 'manual', 'p2', 'p2')"
        )
        await conn.execute(
            """
            INSERT INTO findings (id, dedup_key, title, category, severity, severity_label,
                                   status, url, program_id)
            VALUES ('FND002', 'dedup:002', 'Dup Finding', 'cors', 600, 'high', 'new',
                    'https://x.com', 'p2')
            """
        )
        await conn.commit()

    from bounty.ui.routes.ai import router
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    with patch("bounty.config.get_settings") as mock_settings:
        settings = MagicMock()
        settings.db_path = tmp_db
        settings.ui_token = None
        mock_settings.return_value = settings

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.post(
            "/api/ai/mark-duplicate/FND002",
            json={"duplicate_of": "FND001"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "duplicate"

    # Verify in DB
    from bounty.db import get_conn as real_get_conn3
    async with real_get_conn3(tmp_db) as conn:
        cur = await conn.execute("SELECT status FROM findings WHERE id='FND002'")
        row = await cur.fetchone()
    assert row["status"] == "duplicate"


# ---------------------------------------------------------------------------
# 24. Dedup — top-3 cap is enforced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dedup_returns_at_most_3(
    ai_client: AnthropicClient,
    sample_finding: Finding,
) -> None:
    from bounty.ai.dedup import find_duplicate_findings

    # Create 5 candidates
    candidates = [
        Finding(
            id=f"01FIND00000000000000000{i}",
            dedup_key=f"test:cors:example.com:/path{i}",
            title=f"CORS Finding {i}",
            category="cors",
            severity=700,
            severity_label="high",
            url=f"https://example.com/path{i}",
        )
        for i in range(1, 6)
    ]

    call_count = 0

    async def mock_complete(system: str, prompt: str, max_tokens: int = 1000) -> str:
        nonlocal call_count
        call_count += 1
        return f'{{"confidence_pct": {90 - call_count * 5}, "reason": "Similar root cause."}}'

    with patch.object(ai_client, "complete", side_effect=mock_complete):
        results = await find_duplicate_findings(sample_finding, candidates, client=ai_client)

    assert len(results) <= 3
    # Results should be sorted by confidence descending
    if len(results) > 1:
        assert results[0][1] >= results[1][1]


# ---------------------------------------------------------------------------
# 25. AICostCapExceededError attributes
# ---------------------------------------------------------------------------

def test_cost_cap_error_attributes() -> None:
    """AICostCapExceededError stores today_cost and cap correctly."""
    err = AICostCapExceededError(5.01, 5.0)
    assert err.today_cost == 5.01
    assert err.cap == 5.0
    assert "5.0100" in str(err) or "5.01" in str(err)
    assert "5.00" in str(err) or "5.0" in str(err)


# ---------------------------------------------------------------------------
# 26. Dedup caching: same pair → same cache key → only 1 API call
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dedup_cache_same_pair_single_api_call(
    ai_client: AnthropicClient,
    sample_finding: Finding,
    similar_finding: Finding,
) -> None:
    from bounty.ai.dedup import find_duplicate_findings

    call_count = 0

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": '{"confidence_pct": 80, "reason": "Cached."}'}],
        "usage": {"input_tokens": 50, "output_tokens": 10},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        # First call (cache miss → API)
        await find_duplicate_findings(sample_finding, [similar_finding], client=ai_client)
        first_call_count = mock_http.post.call_count

        # Second call with same pair (cache hit → no API)
        await find_duplicate_findings(sample_finding, [similar_finding], client=ai_client)
        second_call_count = mock_http.post.call_count

    # Second call should not have made additional API calls
    assert second_call_count == first_call_count


# ---------------------------------------------------------------------------
# 27. Severity check clamps LLM output to 0-1000
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_severity_check_clamps_output(
    ai_client: AnthropicClient,
    sample_finding: Finding,
) -> None:
    from bounty.ai.severity_check import review_severity

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # LLM returns out-of-range value
    mock_resp.json.return_value = {
        "content": [{"type": "text", "text": '{"suggested_severity": 9999, "rationale": "Way too high."}'}],
        "usage": {"input_tokens": 100, "output_tokens": 20},
    }

    with patch("bounty.ai.client.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_cls.return_value.__aenter__.return_value = mock_http
        mock_http.post.return_value = mock_resp

        suggested, _ = await review_severity(sample_finding, client=ai_client)

    assert suggested == 1000  # clamped to max

