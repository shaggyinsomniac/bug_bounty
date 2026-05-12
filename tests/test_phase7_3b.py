"""
tests/test_phase7_3b.py — Phase 7.3b: Finding detail, kanban view, PATCH /status.

Tests cover:
  - GET /findings/{nonexistent} → 404
  - GET /findings/{real_id} → 200 with title
  - GET /findings/{real_id} with HX-Request → partial (no <html>)
  - GET /findings/{real_id}/drawer → partial (no <html>)
  - Finding detail contains evidence section
  - Finding detail with curl_cmd evidence shows curl_cmd
  - PATCH /api/findings/{id}/status → 200, DB updated
  - PATCH /api/findings/{id}/status with invalid status → 422
  - PATCH /api/findings/{id}/status for unknown ID → 404
  - GET /findings?view=kanban → 200, contains kanban columns
  - GET /findings?view=kanban with HX-Request → partial (no <html>)
  - Seeded finding appears in correct kanban column
  - POST /api/secrets/{id}/revalidate → 200 (mocked)
  - After PATCH /status, reload shows finding in correct kanban column
  - GET /api/findings/{id} returns evidence + secrets arrays
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from bounty.db import apply_migrations, get_conn, init_db
from bounty.models import ValidationResult
from bounty.validate._base import REGISTRY as _REGISTRY
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
                status, url, path, description, remediation, validated, tags, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                fid, f"dk-{fid}", title, category, severity, severity_label,
                status, url, "/vuln", "## Description\nTest finding body",
                "## Remediation\nFix it.", validated,
                "[]", _now(), _now(),
            ),
        )
        await conn.commit()
    return fid


async def _seed_evidence(
    db: Path,
    finding_id: str,
    *,
    curl_cmd: str = "curl -X GET https://example.com/vuln",
    response_status: int = 200,
    request_raw: str = "GET /vuln HTTP/1.1\nHost: example.com",
    response_raw: str = "HTTP/1.1 200 OK\n\n<html>test</html>",
) -> str:
    eid = make_ulid()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO evidence_packages
               (id, finding_id, kind, curl_cmd, request_raw, response_raw,
                response_status, captured_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (eid, finding_id, "http", curl_cmd, request_raw, response_raw,
             response_status, _now()),
        )
        await conn.commit()
    return eid


async def _seed_secret(
    db: Path,
    *,
    finding_id: str | None = None,
    provider: str = "github_token",
    status: str = "pending",
) -> str:
    sid = make_ulid()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO secrets_validations
               (id, finding_id, provider, secret_hash, secret_preview, secret_pattern, status)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (sid, finding_id, provider,
             f"hash_{make_ulid()}", "ghp_****", provider, status),
        )
        await conn.commit()
    return sid


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


# ===========================================================================
# A. Finding detail page
# ===========================================================================

async def test_finding_detail_404(client: AsyncClient) -> None:
    r = await client.get("/findings/nonexistent-id-abc")
    assert r.status_code == 404


async def test_finding_detail_200(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Jenkins RCE", severity=900,
                              severity_label="critical")
    r = await client.get(f"/findings/{fid}")
    assert r.status_code == 200


async def test_finding_detail_contains_title(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Jenkins RCE")
    r = await client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "Jenkins RCE" in r.text


async def test_finding_detail_contains_evidence_section(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="XSS Finding")
    r = await client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "Evidence" in r.text
    assert "evidence-section" in r.text


async def test_finding_detail_htmx_partial(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Partial Test")
    r = await client.get(f"/findings/{fid}", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<html" not in r.text.lower()
    assert "Partial Test" in r.text


async def test_finding_drawer_partial(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Drawer Test")
    r = await client.get(f"/findings/{fid}/drawer")
    assert r.status_code == 200
    assert "<html" not in r.text.lower()
    assert "Drawer Test" in r.text


async def test_finding_detail_curl_cmd(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Evidence Finding")
    await _seed_evidence(test_db, fid, curl_cmd="curl -X GET https://target.com/api")
    r = await client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "curl" in r.text.lower()
    assert "curl-cmd" in r.text or "curl_cmd" in r.text or "target.com" in r.text


async def test_finding_detail_contains_back_link(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Back Link Test")
    r = await client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "/findings" in r.text


async def test_finding_detail_contains_status_dropdown(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Status Dropdown")
    r = await client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "status-select" in r.text


# ===========================================================================
# B. PATCH /api/findings/{id}/status
# ===========================================================================

async def test_patch_status_updates_db(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Patch Me", status="new")
    r = await client.patch(
        f"/api/findings/{fid}/status",
        json={"status": "triaged"},
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "triaged"

    # verify persisted
    async with get_conn(test_db) as conn:
        cur = await conn.execute("SELECT status FROM findings WHERE id = ?", (fid,))
        row = await cur.fetchone()
    assert row is not None
    assert row[0] == "triaged"


async def test_patch_status_invalid_returns_422(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Bad Status")
    r = await client.patch(
        f"/api/findings/{fid}/status",
        json={"status": "absolutely_invalid_xyz"},
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 422


async def test_patch_status_unknown_id_returns_404(client: AsyncClient) -> None:
    r = await client.patch(
        "/api/findings/nonexistent-zzz/status",
        json={"status": "triaged"},
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 404


async def test_patch_status_all_valid_values(client: AsyncClient, test_db: Path) -> None:
    """All kanban status values should be accepted."""
    valid = ["new", "triaged", "reported", "accepted", "dismissed", "duplicate"]
    fid = await _seed_finding(test_db, title="Multi Status")
    for s in valid:
        r = await client.patch(
            f"/api/findings/{fid}/status",
            json={"status": s},
        )
        assert r.status_code == 200, f"Expected 200 for status={s!r}, got {r.status_code}"


# ===========================================================================
# C. Kanban view
# ===========================================================================

async def test_kanban_view_200(client: AsyncClient) -> None:
    r = await client.get("/findings?view=kanban")
    assert r.status_code == 200


async def test_kanban_view_contains_columns(client: AsyncClient) -> None:
    r = await client.get("/findings?view=kanban")
    assert r.status_code == 200
    assert "kanban-column" in r.text
    assert "New" in r.text or "new" in r.text.lower()
    assert "Triaged" in r.text or "triaged" in r.text.lower()


async def test_kanban_htmx_partial(client: AsyncClient) -> None:
    r = await client.get("/findings?view=kanban", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<html" not in r.text.lower()
    assert "kanban-column" in r.text


async def test_kanban_seeded_finding_appears(client: AsyncClient, test_db: Path) -> None:
    await _seed_finding(test_db, title="Kanban Critical", status="new",
                        severity=900, severity_label="critical")
    r = await client.get("/findings?view=kanban")
    assert r.status_code == 200
    assert "Kanban Critical" in r.text


async def test_kanban_finding_in_correct_column(client: AsyncClient, test_db: Path) -> None:
    fid = await _seed_finding(test_db, title="Triaged Finding", status="triaged")
    r = await client.get("/findings?view=kanban")
    assert r.status_code == 200
    html = r.text
    # The triaged column should contain this finding
    triaged_idx = html.find('data-status="triaged"')
    new_idx = html.find('data-status="new"')
    finding_idx = html.find("Triaged Finding")
    assert triaged_idx != -1
    assert finding_idx > triaged_idx  # finding appears after triaged column header


# ===========================================================================
# D. POST /api/secrets/{id}/revalidate
# ===========================================================================

async def test_revalidate_secret_mocked(client: AsyncClient, test_db: Path) -> None:
    """Revalidate a secret using a mocked validator."""
    fid = await _seed_finding(test_db, title="Secret Finding")
    sv_id = await _seed_secret(test_db, finding_id=fid, provider="github_token")

    # Build a minimal ValidationResult with all required fields
    mock_result = ValidationResult(
        provider="github_token",
        secret_preview="ghp_****",
        secret_hash="mockhash123",
        secret_pattern="github_token",
        status="live",
        identity="testuser@github.com",
    )
    mock_validator = AsyncMock()
    mock_validator.validate = AsyncMock(return_value=mock_result)
    mock_validator.provider = "github_token"

    with patch.dict(_REGISTRY._validators, {"github_token": mock_validator}):
        r = await client.post(f"/api/secrets/{sv_id}/revalidate")

    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "live"
    assert data["identity"] == "testuser@github.com"


async def test_revalidate_secret_unknown(client: AsyncClient) -> None:
    r = await client.post("/api/secrets/nonexistent-secret-id/revalidate")
    assert r.status_code == 404


# ===========================================================================
# E. GET /api/findings/{id} — evidence + secrets join
# ===========================================================================

async def test_api_finding_detail_includes_evidence(
    client: AsyncClient, test_db: Path
) -> None:
    fid = await _seed_finding(test_db, title="API Evidence Test")
    await _seed_evidence(test_db, fid, curl_cmd="curl https://example.com")
    r = await client.get(f"/api/findings/{fid}")
    assert r.status_code == 200
    data = r.json()
    assert "evidence" in data
    assert len(data["evidence"]) == 1
    assert data["evidence"][0]["curl_cmd"] == "curl https://example.com"


async def test_api_finding_detail_includes_secrets(
    client: AsyncClient, test_db: Path
) -> None:
    fid = await _seed_finding(test_db, title="API Secrets Test")
    await _seed_secret(test_db, finding_id=fid, provider="stripe", status="live")
    r = await client.get(f"/api/findings/{fid}")
    assert r.status_code == 200
    data = r.json()
    assert "secrets" in data
    assert len(data["secrets"]) == 1
    assert data["secrets"][0]["provider"] == "stripe"


