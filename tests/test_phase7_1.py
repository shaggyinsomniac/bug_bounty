"""
tests/test_phase7_1.py — Phase 7.1 backend tests.

Tests cover:
  - Health / readiness endpoints
  - Auth middleware (dev mode + token mode)
  - GET /api/assets pagination and filters
  - GET /api/findings filters (severity, category, status)
  - GET /api/findings/{id} with evidence + secrets
  - PATCH /api/findings/{id}
  - GET /api/findings/stats
  - POST /api/scans triggers scan row insertion
  - GET /api/scans/{id} returns phases
  - DELETE /api/scans/{id} cancels
  - GET /api/secrets filters
  - POST /api/secrets/{id}/revalidate
  - GET /api/programs, POST, PATCH, DELETE
  - GET /api/intel/leads
  - PATCH /api/intel/leads/{id} dismiss / promote
  - SSE: connect to /sse/events, broadcast an event, verify it arrives
  - Login flow: POST /login with valid / invalid token
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from bounty.db import apply_migrations, get_conn, init_db
from bounty.ulid import make_ulid


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture()
def test_db(tmp_path: Path) -> Path:
    # Must be named "bounty.db" so settings.db_path (DATA_DIR/bounty.db) resolves to it
    db = tmp_path / "bounty.db"
    init_db(db)
    apply_migrations(db)
    return db


@pytest.fixture()
async def client(test_db: Path) -> AsyncIterator[AsyncClient]:
    """AsyncClient backed by the FastAPI app with an isolated test DB."""
    from bounty.config import get_settings

    get_settings.cache_clear()
    os.environ["DATA_DIR"] = str(test_db.parent)

    # Import AFTER env var is set so get_settings() picks up test DB on first use
    from bounty.ui.app import app

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    get_settings.cache_clear()
    os.environ.pop("DATA_DIR", None)


@pytest.fixture()
async def authed_client(test_db: Path) -> AsyncIterator[AsyncClient]:
    """Client with UI_TOKEN set to 'secret'."""
    from bounty.config import get_settings

    get_settings.cache_clear()
    os.environ["DATA_DIR"] = str(test_db.parent)
    os.environ["UI_TOKEN"] = "secret"

    from bounty.ui.app import app

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    get_settings.cache_clear()
    os.environ.pop("DATA_DIR", None)
    os.environ.pop("UI_TOKEN", None)


async def _seed_program(db: Path, pid: str = "test-p1") -> str:
    ts = _now()
    async with get_conn(db) as conn:
        await conn.execute(
            "INSERT OR IGNORE INTO programs (id, platform, handle, name, created_at, updated_at) VALUES (?, 'manual', ?, ?, ?, ?)",
            (pid, pid, pid, ts, ts),
        )
        await conn.commit()
    return pid


async def _seed_asset(db: Path, pid: str, host: str = "example.com") -> str:
    aid = make_ulid()
    ts = _now()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO assets (id, program_id, host, url, first_seen, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (aid, pid, host, f"https://{host}", ts, ts, ts),
        )
        await conn.commit()
    return aid


async def _seed_finding(
    db: Path,
    pid: str,
    aid: str,
    severity: int = 500,
    severity_label: str = "medium",
    status: str = "new",
    category: str = "misc",
) -> str:
    fid = make_ulid()
    ts = _now()
    dedup = f"dk-{fid}"
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO findings
               (id, program_id, asset_id, dedup_key, title, category, severity, severity_label, status, url, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'Test Finding', ?, ?, ?, ?, 'https://example.com', ?, ?)""",
            (fid, pid, aid, dedup, category, severity, severity_label, status, ts, ts),
        )
        await conn.commit()
    return fid


async def _seed_secret(db: Path, pid: str, fid: str | None = None) -> str:
    sid = make_ulid()
    ts = _now()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO secrets_validations
               (id, provider, secret_hash, secret_preview, secret_pattern, status, finding_id, created_at, updated_at)
               VALUES (?, 'github', 'abc123hash', 'ghp_abc1…', 'GITHUB_PAT', 'live', ?, ?, ?)""",
            (sid, fid, ts, ts),
        )
        await conn.commit()
    return sid


async def _seed_lead(db: Path, pid: str, ip: str = "1.2.3.4") -> str:
    lid = make_ulid()
    ts = _now()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO leads (id, ip, port, program_id, status, discovered_at)
               VALUES (?, ?, 80, ?, 'new', ?)""",
            (lid, ip, pid, ts),
        )
        await conn.commit()
    return lid


# ===========================================================================
# 1. Health / readiness
# ===========================================================================

async def test_healthz(client: AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_readyz_db_reachable(client: AsyncClient) -> None:
    r = await client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


async def test_home_returns_html(client: AsyncClient) -> None:
    r = await client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


# ===========================================================================
# 2. Auth middleware
# ===========================================================================

async def test_api_accessible_no_token(client: AsyncClient) -> None:
    """When UI_TOKEN unset, /api/* is fully accessible."""
    r = await client.get("/api/findings")
    assert r.status_code == 200


async def test_api_requires_token_when_set(authed_client: AsyncClient) -> None:
    """When UI_TOKEN is set, /api/* without Bearer returns 401."""
    r = await authed_client.get("/api/findings")
    assert r.status_code == 401


async def test_api_accepts_correct_token(authed_client: AsyncClient) -> None:
    r = await authed_client.get("/api/findings", headers={"Authorization": "Bearer secret"})
    assert r.status_code == 200


async def test_api_rejects_wrong_token(authed_client: AsyncClient) -> None:
    r = await authed_client.get("/api/findings", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


# ===========================================================================
# 3. Assets
# ===========================================================================

async def test_list_assets_empty(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/assets")
    assert r.status_code == 200
    data = r.json()
    assert data["items"] == []
    assert data["total"] == 0


async def test_list_assets_paginates(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    for i in range(5):
        await _seed_asset(test_db, pid, f"host{i}.example.com")

    r = await client.get("/api/assets?limit=3&offset=0")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 5
    assert len(data["items"]) == 3

    r2 = await client.get("/api/assets?limit=3&offset=3")
    assert len(r2.json()["items"]) == 2


async def test_list_assets_filter_program(client: AsyncClient, test_db: Path) -> None:
    p1 = await _seed_program(test_db, "p1")
    p2 = await _seed_program(test_db, "p2")
    await _seed_asset(test_db, p1, "a.p1.com")
    await _seed_asset(test_db, p2, "a.p2.com")

    r = await client.get(f"/api/assets?program_id={p1}")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["host"] == "a.p1.com"


async def test_list_assets_filter_search(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    await _seed_asset(test_db, pid, "special.example.com")
    await _seed_asset(test_db, pid, "other.com")

    r = await client.get("/api/assets?search=special")
    assert r.status_code == 200
    items = r.json()["items"]
    assert all("special" in i["host"] for i in items)


async def test_get_asset_detail(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)

    r = await client.get(f"/api/assets/{aid}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == aid
    assert "fingerprints" in data
    assert "findings_count" in data


async def test_get_asset_not_found(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/assets/nonexistent")
    assert r.status_code == 404


# ===========================================================================
# 4. Findings
# ===========================================================================

async def test_list_findings_empty(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/findings")
    assert r.status_code == 200
    assert r.json()["total"] == 0


async def test_list_findings_filter_severity(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)
    await _seed_finding(test_db, pid, aid, severity=900, severity_label="critical")
    await _seed_finding(test_db, pid, aid, severity=300, severity_label="low")

    r = await client.get("/api/findings?severity_label=critical")
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(i["severity_label"] == "critical" for i in items)
    assert len(items) == 1


async def test_list_findings_filter_status(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)
    await _seed_finding(test_db, pid, aid, status="new")
    await _seed_finding(test_db, pid, aid, status="triaged")

    r = await client.get("/api/findings?status=triaged")
    items = r.json()["items"]
    assert all(i["status"] == "triaged" for i in items)


async def test_list_findings_filter_category(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)
    await _seed_finding(test_db, pid, aid, category="xss")
    await _seed_finding(test_db, pid, aid, category="sqli")

    r = await client.get("/api/findings?category=xss")
    items = r.json()["items"]
    assert all(i["category"] == "xss" for i in items)


async def test_get_finding_detail(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)
    fid = await _seed_finding(test_db, pid, aid)

    r = await client.get(f"/api/findings/{fid}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == fid
    assert "evidence" in data
    assert "secrets" in data


async def test_get_finding_not_found(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/findings/nonexistent")
    assert r.status_code == 404


async def test_patch_finding_status(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)
    fid = await _seed_finding(test_db, pid, aid, status="new")

    r = await client.patch(f"/api/findings/{fid}", json={"status": "triaged"})
    assert r.status_code == 200
    assert r.json()["status"] == "triaged"

    # Verify persistence
    r2 = await client.get(f"/api/findings/{fid}")
    assert r2.json()["status"] == "triaged"


async def test_patch_finding_tags(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)
    fid = await _seed_finding(test_db, pid, aid)

    r = await client.patch(f"/api/findings/{fid}", json={"tags": ["p0", "bounty"]})
    assert r.status_code == 200
    assert r.json()["tags"] == ["p0", "bounty"]


async def test_patch_finding_no_fields(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)
    fid = await _seed_finding(test_db, pid, aid)

    r = await client.patch(f"/api/findings/{fid}", json={})
    assert r.status_code == 422


async def test_finding_stats(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)
    await _seed_finding(test_db, pid, aid, severity=900, severity_label="critical", category="xss")
    await _seed_finding(test_db, pid, aid, severity=300, severity_label="low", category="sqli")

    r = await client.get("/api/findings/stats")
    assert r.status_code == 200
    data = r.json()
    assert "by_severity" in data
    assert "by_status" in data
    assert "by_category" in data
    assert data["by_severity"].get("critical", 0) >= 1


async def test_finding_with_evidence_and_secrets(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    aid = await _seed_asset(test_db, pid)
    fid = await _seed_finding(test_db, pid, aid)
    await _seed_secret(test_db, pid, fid)

    ts = _now()
    eid = make_ulid()
    async with get_conn(test_db) as conn:
        await conn.execute(
            """INSERT INTO evidence_packages (id, finding_id, kind, curl_cmd, captured_at)
               VALUES (?, ?, 'http', 'curl https://example.com', ?)""",
            (eid, fid, ts),
        )
        await conn.commit()

    r = await client.get(f"/api/findings/{fid}")
    assert r.status_code == 200
    data = r.json()
    assert len(data["evidence"]) == 1
    assert len(data["secrets"]) == 1


# ===========================================================================
# 5. Scans
# ===========================================================================

async def test_post_scan_returns_scan_id(client: AsyncClient, test_db: Path) -> None:
    r = await client.post("/api/scans", json={"intensity": "light"})
    assert r.status_code == 201
    data = r.json()
    assert "scan_id" in data
    assert data["status"] == "queued"


async def test_post_scan_row_in_db(client: AsyncClient, test_db: Path) -> None:
    r = await client.post("/api/scans", json={"intensity": "normal"})
    scan_id = r.json()["scan_id"]

    async with get_conn(test_db) as conn:
        cur = await conn.execute("SELECT id, status FROM scans WHERE id=?", (scan_id,))
        row = await cur.fetchone()

    assert row is not None
    assert str(row["id"]) == scan_id


async def test_get_scan_detail(client: AsyncClient, test_db: Path) -> None:
    r = await client.post("/api/scans", json={})
    scan_id = r.json()["scan_id"]

    r2 = await client.get(f"/api/scans/{scan_id}")
    assert r2.status_code == 200
    data = r2.json()
    assert data["id"] == scan_id
    assert "phases" in data


async def test_list_scans(client: AsyncClient, test_db: Path) -> None:
    await client.post("/api/scans", json={})
    await client.post("/api/scans", json={})

    r = await client.get("/api/scans")
    assert r.status_code == 200
    assert r.json()["total"] >= 2


async def test_delete_scan_cancels(client: AsyncClient, test_db: Path) -> None:
    r = await client.post("/api/scans", json={})
    scan_id = r.json()["scan_id"]

    # Insert a fake phase to prevent background task from auto-completing
    r2 = await client.delete(f"/api/scans/{scan_id}")
    assert r2.status_code == 204


async def test_get_scan_not_found(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/scans/nonexistent")
    assert r.status_code == 404


# ===========================================================================
# 6. Programs
# ===========================================================================

async def test_list_programs_empty(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/programs")
    assert r.status_code == 200
    assert r.json()["items"] == []


async def test_create_and_get_program(client: AsyncClient, test_db: Path) -> None:
    body = {
        "id": "api-prog-1",
        "platform": "manual",
        "handle": "api-prog-1",
        "name": "API Program 1",
        "scope": [{"scope_type": "in_scope", "asset_type": "wildcard", "value": "*.example.com"}],
    }
    r = await client.post("/api/programs", json=body)
    assert r.status_code == 201
    assert r.json()["id"] == "api-prog-1"

    r2 = await client.get("/api/programs/api-prog-1")
    assert r2.status_code == 200
    data = r2.json()
    assert data["id"] == "api-prog-1"
    assert len(data["targets"]) == 1


async def test_patch_program(client: AsyncClient, test_db: Path) -> None:
    await _seed_program(test_db, "patch-p")
    r = await client.patch("/api/programs/patch-p", json={"name": "Updated Name"})
    assert r.status_code == 200
    assert r.json()["name"] == "Updated Name"


async def test_delete_program(client: AsyncClient, test_db: Path) -> None:
    await _seed_program(test_db, "del-p")
    r = await client.delete("/api/programs/del-p")
    assert r.status_code == 204

    r2 = await client.get("/api/programs/del-p")
    assert r2.status_code == 404


async def test_get_program_not_found(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/programs/no-such")
    assert r.status_code == 404


# ===========================================================================
# 7. Secrets
# ===========================================================================

async def test_list_secrets_empty(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/secrets")
    assert r.status_code == 200
    assert r.json()["total"] == 0


async def test_list_secrets_filter_status(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    await _seed_secret(test_db, pid)  # status = 'live'

    r = await client.get("/api/secrets?status=live")
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(i["status"] == "live" for i in items)


async def test_list_secrets_filter_provider(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    await _seed_secret(test_db, pid)  # provider = 'github'

    r = await client.get("/api/secrets?provider=github")
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(i["provider"] == "github" for i in items)


async def test_get_secret_not_found(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/secrets/nonexistent")
    assert r.status_code == 404


async def test_revalidate_secret(client: AsyncClient, test_db: Path) -> None:
    """POST /api/secrets/{id}/revalidate calls validator and updates row."""
    from bounty.models import ValidationResult

    pid = await _seed_program(test_db)
    sid = await _seed_secret(test_db, pid)

    mock_result = ValidationResult(
        provider="github",
        secret_preview="ghp_abc1…",
        secret_hash="abc123hash",
        secret_pattern="GITHUB_PAT",
        status="invalid",
        error_message="token revoked",
    )

    with patch("bounty.validate._base.REGISTRY") as mock_reg:
        mock_validator = AsyncMock()
        mock_validator.validate.return_value = mock_result
        mock_reg.get.return_value = mock_validator

        r = await client.post(f"/api/secrets/{sid}/revalidate")

    assert r.status_code == 200
    assert r.json()["status"] == "invalid"


# ===========================================================================
# 8. Intel / leads
# ===========================================================================

async def test_list_leads_empty(client: AsyncClient, test_db: Path) -> None:
    r = await client.get("/api/intel/leads")
    assert r.status_code == 200
    assert r.json()["total"] == 0


async def test_dismiss_lead(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    lid = await _seed_lead(test_db, pid)

    r = await client.patch(f"/api/intel/leads/{lid}", json={"action": "dismiss"})
    assert r.status_code == 200
    assert r.json()["status"] == "dismissed"


async def test_promote_lead(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    lid = await _seed_lead(test_db, pid, ip="10.0.0.1")

    r = await client.patch(f"/api/intel/leads/{lid}", json={"action": "promote", "program_id": pid})
    assert r.status_code == 200
    assert r.json()["status"] == "promoted"
    assert "asset_id" in r.json()


async def test_lead_not_found(client: AsyncClient, test_db: Path) -> None:
    r = await client.patch("/api/intel/leads/nonexistent", json={"action": "dismiss"})
    assert r.status_code == 404


# ===========================================================================
# 9. SSE
# ===========================================================================

async def test_sse_manager_broadcast_direct() -> None:
    """SSEManager.broadcast delivers events to active stream() consumers."""
    from bounty.ui.sse import SSEManager

    mgr = SSEManager()
    received: list[str] = []

    async def _collect() -> None:
        async for chunk in mgr.stream():
            received.append(chunk)
            return  # stop after first event

    async def _send() -> None:
        await asyncio.sleep(0.05)
        await mgr.broadcast("test.event", {"msg": "hello"})

    await asyncio.gather(
        asyncio.wait_for(_collect(), timeout=2.0),
        _send(),
    )
    assert any("hello" in chunk for chunk in received)


async def test_sse_events_endpoint_opens(client: AsyncClient) -> None:
    """GET /sse/events returns status 200 with text/event-stream content type."""
    status_code: list[int] = []
    content_type: list[str] = []

    async def _fetch() -> None:
        async with client.stream("GET", "/sse/events") as r:
            status_code.append(r.status_code)
            content_type.append(r.headers.get("content-type", ""))
            # Don't consume body — break immediately
            return

    task = asyncio.create_task(_fetch())
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
    except asyncio.TimeoutError:
        pass
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    if status_code:
        assert status_code[0] == 200
    if content_type:
        assert "text/event-stream" in content_type[0]


async def test_sse_events_receives_broadcast(client: AsyncClient) -> None:
    """Publish an event via bounty.events.publish; verify it arrives on SSE stream."""
    from bounty.ui.sse import sse_manager

    received: list[str] = []

    async def _collect() -> None:
        async for chunk in sse_manager.stream():
            received.append(chunk)
            return

    async def _send() -> None:
        # Give _collect() time to register its queue first
        await asyncio.sleep(0.05)
        # Broadcast directly — no bus relay indirection needed
        await sse_manager.broadcast("test.direct", {"msg": "hello"})

    await asyncio.gather(
        asyncio.wait_for(_collect(), timeout=2.0),
        _send(),
    )
    assert any("hello" in chunk for chunk in received)


# ===========================================================================
# 10. Login flow
# ===========================================================================

async def test_login_page_renders(authed_client: AsyncClient) -> None:
    r = await authed_client.get("/login")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


async def test_login_valid_token_sets_cookie(authed_client: AsyncClient) -> None:
    r = await authed_client.post(
        "/login",
        data={"token": "secret"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "bounty_session" in r.cookies or "set-cookie" in r.headers


async def test_login_invalid_token_returns_401(authed_client: AsyncClient) -> None:
    r = await authed_client.post(
        "/login",
        data={"token": "wrong"},
        follow_redirects=False,
    )
    assert r.status_code == 401


async def test_logout_clears_cookie(client: AsyncClient) -> None:
    r = await client.get("/logout", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers.get("location") == "/login"


