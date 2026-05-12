"""
tests/test_phase7_4a.py — Phase 7.4a Assets, Programs, Secrets list pages.

Tests cover:
  - GET /assets returns 200 with table content
  - GET /assets?program_id=X filters correctly
  - GET /assets/{nonexistent} returns 404
  - GET /assets/{real_id} returns 200 with detail content
  - GET /programs returns 200 with '+ New Program' button
  - GET /programs/{real_id} returns 200 with scope/detail content
  - GET /programs/{nonexistent} returns 404
  - GET /secrets returns 200 with secret-related content
  - GET /secrets?status=invalid filters
  - All three list pages return partial on HX-Request
  - Empty DB on each page → empty state rendered
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from bounty.db import apply_migrations, get_conn, init_db
from bounty.ulid import make_ulid


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _seed_program(
    db: Path,
    *,
    prog_id: str | None = None,
    platform: str = "h1",
    handle: str = "testprog",
    name: str = "Test Program",
    active: int = 1,
) -> str:
    pid = prog_id or make_ulid()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO programs (id, platform, handle, name, url, policy_url, active, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (pid, platform, handle, name, "", "", active, _now(), _now()),
        )
        await conn.commit()
    return pid


async def _seed_asset(
    db: Path,
    *,
    asset_id: str | None = None,
    program_id: str | None = None,
    host: str = "example.com",
    port: int | None = 443,
    http_status: int | None = 200,
    title: str = "Test Title",
    server: str = "nginx",
    cdn: str = "",
) -> str:
    aid = asset_id or make_ulid()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO assets
               (id, program_id, host, port, scheme, url, ip, status, http_status, title, server, cdn,
                waf, seen_protocols, tags, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                aid, program_id, host, port, "https",
                f"https://{host}", "1.2.3.4", "active",
                http_status, title, server, cdn, "",
                json.dumps(["https"]), json.dumps([]),
                _now(), _now(),
            ),
        )
        await conn.commit()
    return aid


async def _seed_secret(
    db: Path,
    *,
    secret_id: str | None = None,
    provider: str = "aws",
    secret_preview: str = "AKIA***REDACTED***",
    status: str = "live",
    finding_id: str | None = None,
) -> str:
    sid = secret_id or make_ulid()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO secrets_validations
               (id, asset_id, finding_id, provider, secret_preview, secret_pattern,
                secret_hash, status, scope, identity, last_checked, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sid, None, finding_id, provider, secret_preview, "aws_access_key",
                "hash-" + sid, status, None, None, _now(), _now(), _now(),
            ),
        )
        await conn.commit()
    return sid


async def _seed_target(db: Path, program_id: str, value: str = "*.example.com") -> None:
    async with get_conn(db) as conn:
        await conn.execute(
            "INSERT INTO targets (program_id, scope_type, asset_type, value) VALUES (?, ?, ?, ?)",
            (program_id, "in_scope", "wildcard", value),
        )
        await conn.commit()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def test_db(tmp_path: Path) -> Path:
    db = tmp_path / "bounty.db"
    init_db(db)
    apply_migrations(db)
    return db


@pytest.fixture()
async def client(test_db: Path) -> AsyncIterator[AsyncClient]:
    from bounty.config import get_settings
    get_settings.cache_clear()
    os.environ["DATA_DIR"] = str(test_db.parent)

    from bounty.ui.app import app
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    get_settings.cache_clear()
    os.environ.pop("DATA_DIR", None)


@pytest.fixture()
async def seeded_client(test_db: Path) -> AsyncIterator[AsyncClient]:
    """Client with pre-seeded programs, assets, and secrets."""
    pid1 = await _seed_program(test_db, handle="prog-alpha", name="Alpha Program", platform="h1")
    pid2 = await _seed_program(test_db, handle="prog-beta", name="Beta Corp", platform="bugcrowd", active=0)

    await _seed_target(test_db, pid1, "*.alpha.com")
    await _seed_target(test_db, pid1, "api.alpha.com")

    aid1 = await _seed_asset(test_db, program_id=pid1, host="api.alpha.com", http_status=200, title="Alpha API")
    await _seed_asset(test_db, program_id=pid2, host="beta.example.com", http_status=404, title="Beta Main")

    await _seed_secret(test_db, provider="aws", status="live", secret_preview="AKIA***LIVE")
    await _seed_secret(test_db, provider="github", status="invalid", secret_preview="ghp_***INVALID")
    await _seed_secret(test_db, provider="stripe", status="pending", secret_preview="sk_test_***")

    from bounty.config import get_settings
    get_settings.cache_clear()
    os.environ["DATA_DIR"] = str(test_db.parent)
    # Store IDs in env for tests to access - we use a hack via closure
    os.environ["_TEST_PID1"] = pid1
    os.environ["_TEST_AID1"] = aid1

    from bounty.ui.app import app
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    get_settings.cache_clear()
    os.environ.pop("DATA_DIR", None)
    os.environ.pop("_TEST_PID1", None)
    os.environ.pop("_TEST_AID1", None)


# ===========================================================================
# A. Assets list page
# ===========================================================================

async def test_assets_page_returns_200(client: AsyncClient) -> None:
    r = await client.get("/assets")
    assert r.status_code == 200


async def test_assets_page_has_heading(client: AsyncClient) -> None:
    r = await client.get("/assets")
    assert "Assets" in r.text


async def test_assets_page_has_filter_bar(client: AsyncClient) -> None:
    r = await client.get("/assets")
    assert "program" in r.text.lower()
    assert "search" in r.text.lower() or "filter" in r.text.lower()


async def test_assets_page_empty_state(client: AsyncClient) -> None:
    r = await client.get("/assets")
    assert "No assets" in r.text or "🖥️" in r.text


async def test_assets_page_shows_seeded_data(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/assets")
    assert r.status_code == 200
    assert "api.alpha.com" in r.text


async def test_assets_page_program_filter(seeded_client: AsyncClient) -> None:
    pid1 = os.environ.get("_TEST_PID1", "")
    r = await seeded_client.get(f"/assets?program_id={pid1}")
    assert r.status_code == 200
    assert "api.alpha.com" in r.text
    assert "beta.example.com" not in r.text


async def test_assets_page_search_filter(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/assets?search=api.alpha")
    assert r.status_code == 200
    assert "api.alpha.com" in r.text
    assert "beta.example.com" not in r.text


async def test_assets_htmx_partial(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/assets", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<!DOCTYPE html>" not in r.text
    assert "<nav" not in r.text


async def test_assets_htmx_contains_rows(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/assets", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "api.alpha.com" in r.text


# ===========================================================================
# B. Asset detail page
# ===========================================================================

async def test_asset_detail_404_nonexistent(client: AsyncClient) -> None:
    r = await client.get("/assets/NONEXISTENT_ID_XYZ")
    assert r.status_code == 404


async def test_asset_detail_returns_200(seeded_client: AsyncClient) -> None:
    aid = os.environ.get("_TEST_AID1", "")
    r = await seeded_client.get(f"/assets/{aid}")
    assert r.status_code == 200


async def test_asset_detail_shows_host(seeded_client: AsyncClient) -> None:
    aid = os.environ.get("_TEST_AID1", "")
    r = await seeded_client.get(f"/assets/{aid}")
    assert "api.alpha.com" in r.text


async def test_asset_detail_shows_metadata(seeded_client: AsyncClient) -> None:
    aid = os.environ.get("_TEST_AID1", "")
    r = await seeded_client.get(f"/assets/{aid}")
    assert "nginx" in r.text or "Server" in r.text


async def test_asset_detail_has_back_link(seeded_client: AsyncClient) -> None:
    aid = os.environ.get("_TEST_AID1", "")
    r = await seeded_client.get(f"/assets/{aid}")
    assert "/assets" in r.text


async def test_asset_detail_shows_fingerprints_section(seeded_client: AsyncClient) -> None:
    aid = os.environ.get("_TEST_AID1", "")
    r = await seeded_client.get(f"/assets/{aid}")
    assert "Fingerprint" in r.text


# ===========================================================================
# C. Programs list page
# ===========================================================================

async def test_programs_page_returns_200(client: AsyncClient) -> None:
    r = await client.get("/programs")
    assert r.status_code == 200


async def test_programs_page_has_new_program_button(client: AsyncClient) -> None:
    r = await client.get("/programs")
    assert "New Program" in r.text


async def test_programs_page_has_filter_bar(client: AsyncClient) -> None:
    r = await client.get("/programs")
    assert "platform" in r.text.lower() or "Platform" in r.text


async def test_programs_page_empty_state(client: AsyncClient) -> None:
    r = await client.get("/programs")
    assert "No programs" in r.text or "🎯" in r.text


async def test_programs_page_shows_seeded_data(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/programs")
    assert "Alpha Program" in r.text
    assert "Beta Corp" in r.text


async def test_programs_page_platform_filter(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/programs?platform=h1")
    assert r.status_code == 200
    assert "Alpha Program" in r.text
    assert "Beta Corp" not in r.text


async def test_programs_page_active_only_filter(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/programs?active_only=true")
    assert r.status_code == 200
    assert "Alpha Program" in r.text
    assert "Beta Corp" not in r.text


async def test_programs_htmx_partial(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/programs", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<!DOCTYPE html>" not in r.text
    assert "<nav" not in r.text


async def test_programs_htmx_has_rows(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/programs", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "Alpha Program" in r.text


# ===========================================================================
# D. Program detail page
# ===========================================================================

async def test_program_detail_returns_200(seeded_client: AsyncClient) -> None:
    pid = os.environ.get("_TEST_PID1", "")
    r = await seeded_client.get(f"/programs/{pid}")
    assert r.status_code == 200


async def test_program_detail_404_nonexistent(client: AsyncClient) -> None:
    r = await client.get("/programs/NONEXISTENT_XYZ")
    assert r.status_code == 404


async def test_program_detail_shows_name(seeded_client: AsyncClient) -> None:
    pid = os.environ.get("_TEST_PID1", "")
    r = await seeded_client.get(f"/programs/{pid}")
    assert "Alpha Program" in r.text


async def test_program_detail_shows_scope_rules(seeded_client: AsyncClient) -> None:
    pid = os.environ.get("_TEST_PID1", "")
    r = await seeded_client.get(f"/programs/{pid}")
    assert "*.alpha.com" in r.text or "Scope" in r.text


async def test_program_detail_has_back_link(seeded_client: AsyncClient) -> None:
    pid = os.environ.get("_TEST_PID1", "")
    r = await seeded_client.get(f"/programs/{pid}")
    assert "/programs" in r.text


# ===========================================================================
# E. Secrets list page
# ===========================================================================

async def test_secrets_page_returns_200(client: AsyncClient) -> None:
    r = await client.get("/secrets")
    assert r.status_code == 200


async def test_secrets_page_has_heading(client: AsyncClient) -> None:
    r = await client.get("/secrets")
    assert "Secret" in r.text


async def test_secrets_page_has_filter_bar(client: AsyncClient) -> None:
    r = await client.get("/secrets")
    assert "status" in r.text.lower() or "provider" in r.text.lower()


async def test_secrets_page_empty_state(client: AsyncClient) -> None:
    r = await client.get("/secrets")
    assert "No validated secrets" in r.text or "🔑" in r.text


async def test_secrets_page_shows_seeded_data(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/secrets")
    assert r.status_code == 200
    assert "AKIA***LIVE" in r.text or "aws" in r.text


async def test_secrets_page_status_filter_live(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/secrets?status=live")
    assert r.status_code == 200
    assert "AKIA***LIVE" in r.text
    assert "ghp_***INVALID" not in r.text


async def test_secrets_page_status_filter_invalid(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/secrets?status=invalid")
    assert r.status_code == 200
    assert "ghp_***INVALID" in r.text
    assert "AKIA***LIVE" not in r.text


async def test_secrets_page_provider_filter(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/secrets?provider=github")
    assert r.status_code == 200
    assert "ghp_***INVALID" in r.text
    assert "AKIA***LIVE" not in r.text


async def test_secrets_page_search_filter(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/secrets?search=AKIA")
    assert r.status_code == 200
    assert "AKIA***LIVE" in r.text
    assert "ghp_***INVALID" not in r.text


async def test_secrets_htmx_partial(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/secrets", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<!DOCTYPE html>" not in r.text
    assert "<nav" not in r.text


async def test_secrets_htmx_has_rows(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/secrets", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "AKIA***LIVE" in r.text or "aws" in r.text


async def test_secrets_page_shows_provider_dropdown(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/secrets")
    # Providers are pulled from DB and shown in dropdown
    assert "aws" in r.text
    assert "github" in r.text


async def test_secrets_page_shows_revalidate_button(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/secrets")
    assert "Revalidate" in r.text

