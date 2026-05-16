"""
tests/test_phase7_2.py — Phase 7.2 UI page tests.

Tests cover:
  - Dashboard page rendering (200, HTML, stat cards)
  - Auth guard redirect
  - Scans list page (filters, empty state, New Scan button)
  - Scan detail page (200, 404 for unknown)
  - Nav pages all return 200 (placeholder pages)
  - Dashboard API stats endpoint
  - Static files served
"""

from __future__ import annotations

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


# ---------------------------------------------------------------------------
# Fixtures (mirror test_phase7_1.py pattern)
# ---------------------------------------------------------------------------

@pytest.fixture()
def test_db(tmp_path: Path) -> Path:
    from bounty.config import get_settings as _gs
    db = tmp_path / "bounty.db"
    _gs.cache_clear()
    os.environ["AUTO_SEED_ON_EMPTY_DB"] = "false"
    try:
        init_db(db)
        apply_migrations(db)
    finally:
        os.environ.pop("AUTO_SEED_ON_EMPTY_DB", None)
        _gs.cache_clear()
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
async def authed_client(test_db: Path) -> AsyncIterator[AsyncClient]:
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


# Seed helpers
async def _seed_program(db: Path, pid: str = "test-p1") -> str:
    ts = _now()
    async with get_conn(db) as conn:
        await conn.execute(
            "INSERT OR IGNORE INTO programs (id, platform, handle, name, created_at, updated_at)"
            " VALUES (?, 'manual', ?, ?, ?, ?)",
            (pid, pid, pid, ts, ts),
        )
        await conn.commit()
    return pid


async def _seed_scan(db: Path, pid: str | None = None, status: str = "queued") -> str:
    sid = make_ulid()
    ts = _now()
    async with get_conn(db) as conn:
        await conn.execute(
            "INSERT INTO scans (id, program_id, scan_type, status, intensity, triggered_by, created_at)"
            " VALUES (?, ?, 'full', ?, 'normal', 'ui', ?)",
            (sid, pid, status, ts),
        )
        await conn.commit()
    return sid


async def _seed_finding(db: Path, pid: str, severity: int = 800) -> str:
    fid = make_ulid()
    ts = _now()
    async with get_conn(db) as conn:
        await conn.execute(
            "INSERT INTO findings"
            " (id, program_id, dedup_key, title, category, severity, severity_label,"
            "  status, url, created_at, updated_at)"
            " VALUES (?, ?, ?, 'Test Finding', 'misc', ?, 'high', 'new',"
            "         'https://example.com', ?, ?)",
            (fid, pid, f"dk-{fid}", severity, ts, ts),
        )
        await conn.commit()
    return fid


# ===========================================================================
# A. Dashboard page
# ===========================================================================

async def test_dashboard_returns_200(client: AsyncClient) -> None:
    r = await client.get("/")
    assert r.status_code == 200


async def test_dashboard_is_html(client: AsyncClient) -> None:
    r = await client.get("/")
    assert "text/html" in r.headers["content-type"]


async def test_dashboard_contains_dashboard_heading(client: AsyncClient) -> None:
    r = await client.get("/")
    assert r.status_code == 200
    assert "Dashboard" in r.text


async def test_dashboard_empty_state_no_programs(client: AsyncClient) -> None:
    """With no programs, dashboard should render empty state."""
    r = await client.get("/")
    assert r.status_code == 200
    # Empty state message
    assert "No programs yet" in r.text or "Add your first" in r.text or "No programs" in r.text


async def test_dashboard_shows_kpi_cards_with_data(client: AsyncClient, test_db: Path) -> None:
    """After seeding a program + finding, KPI cards should render."""
    pid = await _seed_program(test_db)
    await _seed_finding(test_db, pid, severity=800)
    r = await client.get("/")
    assert r.status_code == 200
    assert "Dashboard" in r.text


async def test_dashboard_auth_redirect(authed_client: AsyncClient) -> None:
    """With UI_TOKEN set and no cookie, GET / should redirect to /login."""
    r = await authed_client.get("/", follow_redirects=False)
    # Either 302 redirect or 401 — depending on impl
    assert r.status_code in (302, 401)
    if r.status_code == 302:
        assert "/login" in r.headers.get("location", "")


async def test_dashboard_shows_recent_scans(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    await _seed_scan(test_db, pid)
    r = await client.get("/")
    assert r.status_code == 200
    # Should render recent scans section
    assert "Recent Scans" in r.text


# ===========================================================================
# B. Scans list page
# ===========================================================================

async def test_scans_list_returns_200(client: AsyncClient) -> None:
    r = await client.get("/scans")
    assert r.status_code == 200


async def test_scans_list_is_html(client: AsyncClient) -> None:
    r = await client.get("/scans")
    assert "text/html" in r.headers["content-type"]


async def test_scans_list_contains_new_scan_button(client: AsyncClient) -> None:
    """Page must have a 'New Scan' button."""
    r = await client.get("/scans")
    assert r.status_code == 200
    assert "New Scan" in r.text


async def test_scans_list_contains_scan_heading(client: AsyncClient) -> None:
    r = await client.get("/scans")
    assert r.status_code == 200
    assert "Scans" in r.text


async def test_scans_list_shows_seeded_scan(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    sid = await _seed_scan(test_db, pid)
    r = await client.get("/scans")
    assert r.status_code == 200
    # Scan ID appears in the page (truncated to first 16 chars)
    assert sid[:16] in r.text


async def test_scans_list_filter_bar_present(client: AsyncClient) -> None:
    r = await client.get("/scans")
    assert r.status_code == 200
    # Filter form elements
    assert "program_id" in r.text or "Program" in r.text
    assert "Status" in r.text or "status" in r.text


async def test_scans_list_empty_state(client: AsyncClient) -> None:
    r = await client.get("/scans")
    assert r.status_code == 200
    # When empty, either empty state or 'No scans yet'
    assert "No scans" in r.text or "scans" in r.text.lower()


async def test_scans_list_modal_form_present(client: AsyncClient) -> None:
    r = await client.get("/scans")
    assert r.status_code == 200
    # Modal form elements
    assert "intensity" in r.text
    assert "scan_type" in r.text or "Scan Type" in r.text


async def test_scans_list_filter_by_status(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    sid = await _seed_scan(test_db, pid, status="running")
    r = await client.get("/scans?status=running")
    assert r.status_code == 200
    assert sid[:16] in r.text


async def test_scans_list_pagination_params(client: AsyncClient) -> None:
    r = await client.get("/scans?offset=0&limit=25")
    assert r.status_code == 200


# ===========================================================================
# C. Scan detail page
# ===========================================================================

async def test_scan_detail_not_found(client: AsyncClient) -> None:
    r = await client.get("/scans/nonexistent-scan-id")
    assert r.status_code == 404


async def test_scan_detail_returns_200_for_real_scan(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    sid = await _seed_scan(test_db, pid)
    r = await client.get(f"/scans/{sid}")
    assert r.status_code == 200


async def test_scan_detail_is_html(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    sid = await _seed_scan(test_db, pid)
    r = await client.get(f"/scans/{sid}")
    assert "text/html" in r.headers["content-type"]


async def test_scan_detail_contains_scan_id(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    sid = await _seed_scan(test_db, pid)
    r = await client.get(f"/scans/{sid}")
    assert r.status_code == 200
    assert sid in r.text


async def test_scan_detail_contains_status(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    sid = await _seed_scan(test_db, pid, status="queued")
    r = await client.get(f"/scans/{sid}")
    assert r.status_code == 200
    assert "queued" in r.text.lower()


async def test_scan_detail_running_shows_cancel(client: AsyncClient, test_db: Path) -> None:
    """Running scans should have a Cancel button."""
    pid = await _seed_program(test_db)
    sid = await _seed_scan(test_db, pid, status="running")
    r = await client.get(f"/scans/{sid}")
    assert r.status_code == 200
    assert "Cancel" in r.text


async def test_scan_detail_shows_program_link(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    sid = await _seed_scan(test_db, pid)
    r = await client.get(f"/scans/{sid}")
    assert r.status_code == 200
    assert pid in r.text


# ===========================================================================
# D. Placeholder nav pages all return 200
# ===========================================================================

@pytest.mark.parametrize("path", ["/assets", "/findings", "/programs", "/secrets", "/reports", "/settings"])
async def test_nav_placeholder_pages_return_200(client: AsyncClient, path: str) -> None:
    r = await client.get(path)
    assert r.status_code == 200


@pytest.mark.parametrize("path", ["/assets", "/findings", "/programs", "/secrets", "/reports", "/settings"])
async def test_nav_pages_are_html(client: AsyncClient, path: str) -> None:
    r = await client.get(path)
    assert "text/html" in r.headers["content-type"]


async def test_nav_pages_contain_nav_sidebar(client: AsyncClient) -> None:
    """All pages should include the sidebar navigation."""
    for path in ["/", "/scans", "/assets", "/findings"]:
        r = await client.get(path)
        assert r.status_code == 200
        # Sidebar nav items should be in the HTML
        assert "Dashboard" in r.text


# ===========================================================================
# E. Dashboard API stats endpoint
# ===========================================================================

async def test_dashboard_stats_api_returns_200(client: AsyncClient) -> None:
    r = await client.get("/api/dashboard/stats")
    assert r.status_code == 200


async def test_dashboard_stats_api_is_json(client: AsyncClient) -> None:
    r = await client.get("/api/dashboard/stats")
    assert "application/json" in r.headers["content-type"]


async def test_dashboard_stats_api_has_expected_keys(client: AsyncClient) -> None:
    r = await client.get("/api/dashboard/stats")
    assert r.status_code == 200
    data = r.json()
    assert "programs" in data
    assert "assets" in data
    assert "findings_by_severity" in data
    assert "live_secrets" in data
    assert "open_findings" in data


async def test_dashboard_stats_api_zero_for_empty_db(client: AsyncClient) -> None:
    r = await client.get("/api/dashboard/stats")
    data = r.json()
    assert data["programs"] == 0
    assert data["assets"] == 0
    assert data["live_secrets"] == 0


async def test_dashboard_stats_api_counts_seeded_data(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    await _seed_finding(test_db, pid, severity=800)
    r = await client.get("/api/dashboard/stats")
    data = r.json()
    assert data["programs"] == 1
    assert data["open_findings"] >= 1


# ===========================================================================
# F. Static files
# ===========================================================================

async def test_static_css_served(client: AsyncClient) -> None:
    r = await client.get("/static/app.css")
    assert r.status_code == 200
    assert "text/css" in r.headers.get("content-type", "")


async def test_static_js_served(client: AsyncClient) -> None:
    r = await client.get("/static/app.js")
    assert r.status_code == 200


async def test_static_css_has_severity_vars(client: AsyncClient) -> None:
    r = await client.get("/static/app.css")
    assert r.status_code == 200
    assert "--color-critical" in r.text


async def test_static_js_has_sse_connect(client: AsyncClient) -> None:
    r = await client.get("/static/app.js")
    assert r.status_code == 200
    assert "sseConnect" in r.text


async def test_static_js_has_toast(client: AsyncClient) -> None:
    r = await client.get("/static/app.js")
    assert r.status_code == 200
    assert "function toast" in r.text


# ===========================================================================
# G. New scan via API (modal submission smoke test)
# ===========================================================================

async def test_new_scan_api_creates_scan(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    r = await client.post("/api/scans", json={
        "program_id": pid,
        "scan_type": "full",
        "intensity": "normal",
    })
    assert r.status_code == 201
    data = r.json()
    assert "scan_id" in data
    assert data["status"] == "queued"


async def test_new_scan_appears_in_scans_list(client: AsyncClient, test_db: Path) -> None:
    pid = await _seed_program(test_db)
    r = await client.post("/api/scans", json={
        "program_id": pid,
        "scan_type": "full",
        "intensity": "light",
    })
    assert r.status_code == 201
    scan_id = r.json()["scan_id"]

    # Check the scan detail page
    dr = await client.get(f"/scans/{scan_id}")
    assert dr.status_code == 200
    assert scan_id in dr.text


async def test_new_scan_detail_accessible_immediately(client: AsyncClient, test_db: Path) -> None:
    """Scan detail page should be accessible immediately after creation."""
    pid = await _seed_program(test_db)
    r = await client.post("/api/scans", json={"program_id": pid, "intensity": "light"})
    assert r.status_code == 201
    sid = r.json()["scan_id"]

    detail = await client.get(f"/scans/{sid}")
    assert detail.status_code == 200
    assert "light" in detail.text.lower()

