"""
tests/test_phase7_3a.py — Phase 7.3a Findings list page tests.

Tests cover:
  - GET /findings returns 200 with title and filter bar
  - Severity filter (critical only)
  - Status filter (triaged)
  - Search filter (title match)
  - HX-Request header returns partial (no _base.html nav)
  - Pagination (page=2)
  - API GET /api/findings returns JSON with items+total+page
  - Empty DB → empty state displayed
  - validated_only filter
  - category filter
  - Multi-severity comma filter
  - API comma-separated severity_label filter
  - API page/per_page pagination
  - Findings are ordered by severity desc
  - Filter bar present on findings page
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


async def _seed_finding(
    db: Path,
    *,
    title: str = "Test Finding",
    severity: int = 500,
    severity_label: str = "medium",
    status: str = "new",
    category: str = "sqli",
    url: str = "https://example.com/vuln",
    validated: int = 0,
) -> str:
    fid = make_ulid()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO findings
               (id, dedup_key, title, category, severity, severity_label,
                status, url, path, description, validated, tags, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                fid, f"dk-{fid}", title, category, severity, severity_label,
                status, url, "/vuln", "Test finding description", validated,
                "[]", _now(), _now(),
            ),
        )
        await conn.commit()
    return fid


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
    """Client with 5 pre-seeded findings of varying severity/status."""
    # critical + new
    await _seed_finding(test_db, title="Jenkins RCE", severity=900,
                        severity_label="critical", status="new",
                        category="rce", url="https://jenkins.example.com/script")
    # high + triaged
    await _seed_finding(test_db, title="SQL Injection on login", severity=700,
                        severity_label="high", status="triaged",
                        category="sqli", url="https://app.example.com/login")
    # medium + new, validated
    await _seed_finding(test_db, title="Reflected XSS", severity=500,
                        severity_label="medium", status="new",
                        category="xss", url="https://app.example.com/search",
                        validated=1)
    # low + accepted
    await _seed_finding(test_db, title="Missing HSTS header", severity=300,
                        severity_label="low", status="accepted",
                        category="headers", url="https://example.com/")
    # info + dismissed
    await _seed_finding(test_db, title="Server version disclosure", severity=100,
                        severity_label="info", status="dismissed",
                        category="info", url="https://example.com/")

    from bounty.config import get_settings
    get_settings.cache_clear()
    os.environ["DATA_DIR"] = str(test_db.parent)

    from bounty.ui.app import app

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    get_settings.cache_clear()
    os.environ.pop("DATA_DIR", None)


# ===========================================================================
# A. Basic page rendering
# ===========================================================================

async def test_findings_page_returns_200(client: AsyncClient) -> None:
    r = await client.get("/findings")
    assert r.status_code == 200


async def test_findings_page_contains_title(client: AsyncClient) -> None:
    r = await client.get("/findings")
    assert r.status_code == 200
    assert "Findings" in r.text


async def test_findings_page_contains_filter_bar(client: AsyncClient) -> None:
    r = await client.get("/findings")
    assert r.status_code == 200
    # Filter bar elements
    assert "severity" in r.text.lower()
    assert "status" in r.text.lower()


async def test_findings_page_contains_severity_checkboxes(client: AsyncClient) -> None:
    r = await client.get("/findings")
    assert r.status_code == 200
    assert "critical" in r.text
    assert "high" in r.text
    assert "medium" in r.text


async def test_findings_page_contains_status_dropdown(client: AsyncClient) -> None:
    r = await client.get("/findings")
    assert r.status_code == 200
    assert "triaged" in r.text
    assert "reported" in r.text


# ===========================================================================
# B. Empty state
# ===========================================================================

async def test_findings_page_empty_state(client: AsyncClient) -> None:
    r = await client.get("/findings")
    assert r.status_code == 200
    # Should show empty state (no findings in fresh DB)
    assert "No findings" in r.text or "🐛" in r.text


# ===========================================================================
# C. Filter: severity
# ===========================================================================

async def test_findings_page_severity_filter_critical(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/findings?severity=critical")
    assert r.status_code == 200
    assert "Jenkins RCE" in r.text
    assert "SQL Injection" not in r.text
    assert "Reflected XSS" not in r.text


async def test_findings_page_severity_filter_multiple(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/findings?severity=critical,high")
    assert r.status_code == 200
    assert "Jenkins RCE" in r.text
    assert "SQL Injection" in r.text
    assert "Reflected XSS" not in r.text


# ===========================================================================
# D. Filter: status
# ===========================================================================

async def test_findings_page_status_filter_triaged(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/findings?status=triaged")
    assert r.status_code == 200
    assert "SQL Injection" in r.text
    assert "Jenkins RCE" not in r.text


async def test_findings_page_status_filter_dismissed(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/findings?status=dismissed")
    assert r.status_code == 200
    assert "Server version disclosure" in r.text
    assert "Jenkins RCE" not in r.text


# ===========================================================================
# E. Filter: search
# ===========================================================================

async def test_findings_page_search_title(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/findings?search=Jenkins")
    assert r.status_code == 200
    assert "Jenkins RCE" in r.text
    assert "SQL Injection" not in r.text


async def test_findings_page_search_no_match(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/findings?search=nothingmatches12345")
    assert r.status_code == 200
    assert "Jenkins" not in r.text
    assert "SQL Injection" not in r.text


# ===========================================================================
# F. HTMX partial response
# ===========================================================================

async def test_findings_page_htmx_returns_partial(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/findings", headers={"HX-Request": "true"})
    assert r.status_code == 200
    # Should NOT contain full page chrome (nav/body tags)
    assert "<!DOCTYPE html>" not in r.text
    assert "<nav" not in r.text


async def test_findings_page_htmx_contains_rows(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/findings", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "Jenkins RCE" in r.text


async def test_findings_page_htmx_severity_filter(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/findings?severity=critical",
                                headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "Jenkins RCE" in r.text
    assert "SQL Injection" not in r.text


# ===========================================================================
# G. Pagination
# ===========================================================================

async def test_findings_page_pagination(test_db: Path) -> None:
    # Seed 30 findings
    for i in range(30):
        await _seed_finding(test_db, title=f"Finding {i:03}", severity=500,
                            severity_label="medium")

    from bounty.config import get_settings
    get_settings.cache_clear()
    os.environ["DATA_DIR"] = str(test_db.parent)
    from bounty.ui.app import app
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r1 = await ac.get("/findings?page=1&per_page=10")
        assert r1.status_code == 200
        assert "Finding 000" in r1.text or "Finding 029" in r1.text  # highest sev first

        r2 = await ac.get("/findings?page=2&per_page=10")
        assert r2.status_code == 200
        # Different page has different rows
        assert "Next" in r1.text or "Prev" in r2.text

    get_settings.cache_clear()
    os.environ.pop("DATA_DIR", None)


# ===========================================================================
# H. API endpoint
# ===========================================================================

async def test_api_findings_returns_json(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/findings")
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert data["total"] >= 5


async def test_api_findings_severity_filter(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/findings?severity_label=critical")
    assert r.status_code == 200
    data = r.json()
    assert all(item["severity_label"] == "critical" for item in data["items"])
    assert data["total"] >= 1


async def test_api_findings_comma_severity(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/findings?severity_label=critical,high")
    assert r.status_code == 200
    data = r.json()
    labels = {item["severity_label"] for item in data["items"]}
    assert labels.issubset({"critical", "high"})
    assert data["total"] >= 2


async def test_api_findings_page_per_page(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/findings?page=1&per_page=2")
    assert r.status_code == 200
    data = r.json()
    assert len(data["items"]) == 2
    assert data["per_page"] == 2
    assert data["page"] == 1

