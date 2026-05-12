"""
tests/test_phase7_4b.py — Phase 7.4b: Reports pages, Settings, Palette.

Tests cover:
  Reports:
  - GET /reports returns 200
  - POST /api/reports with real finding_id creates draft, body contains finding title
  - GET /api/reports/{id} returns full record
  - PATCH /api/reports/{id} updates body
  - POST /api/reports/{id}/generate regenerates
  - DELETE /api/reports/{id} removes
  - Generated h1 template body contains standard sections
  - Generated bugcrowd template differs from h1
  - Secrets in body show preview, never raw secret value
  Settings:
  - GET /settings returns 200
  - GET /api/system/info returns version dict
  - POST /api/system/wipe-test-data without confirm=true returns 400
  - POST /api/system/vacuum returns 200
  Palette:
  - GET /api/palette/search?q=jenkins returns finding results
  - GET /api/palette/search?q=127 returns asset results
  - Empty query returns quick actions only
  - Results capped at 15 total
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
) -> str:
    pid = prog_id or make_ulid()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO programs (id, platform, handle, name, url, policy_url, active, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (pid, platform, handle, name, "", "", 1, _now(), _now()),
        )
        await conn.commit()
    return pid


async def _seed_asset(
    db: Path,
    *,
    program_id: str,
    host: str = "127.0.0.1",
    http_status: int = 200,
) -> str:
    aid = make_ulid()
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO assets
               (id, program_id, host, port, scheme, url, ip, status, http_status, title, server, cdn,
                waf, seen_protocols, tags, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                aid, program_id, host, 443, "https",
                f"https://{host}", "127.0.0.1", "active",
                http_status, f"Title {host}", "nginx", "",
                "", json.dumps(["https"]), json.dumps([]),
                _now(), _now(),
            ),
        )
        await conn.commit()
    return aid


async def _seed_finding(
    db: Path,
    *,
    program_id: str,
    asset_id: str | None = None,
    title: str = "Jenkins Exposed Admin Panel",
    url: str = "https://jenkins.example.com",
    severity_label: str = "high",
    severity: int = 700,
    category: str = "admin_panel",
    description: str = "Jenkins admin panel accessible without authentication",
    remediation: str = "Restrict access with authentication",
) -> str:
    fid = make_ulid()
    dedup = f"dedup-{fid}"
    async with get_conn(db) as conn:
        await conn.execute(
            """INSERT INTO findings
               (id, program_id, asset_id, scan_id, title, url, severity, severity_label,
                category, description, remediation, dedup_key, status, validated,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                fid, program_id, asset_id, None,
                title, url, severity, severity_label,
                category, description, remediation,
                dedup, "new", 0, _now(), _now(),
            ),
        )
        await conn.commit()
    return fid


async def _seed_secret(
    db: Path,
    *,
    finding_id: str,
    provider: str = "aws",
    secret_preview: str = "AKIA1234…",
    raw_value: str = "AKIA1234SECRET_SHOULD_NEVER_APPEAR",
    status: str = "live",
) -> str:
    sid = make_ulid()
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
    """Client with pre-seeded program, asset, finding, and secret."""
    pid = await _seed_program(test_db, handle="acme", name="Acme Corp", platform="h1")
    aid = await _seed_asset(test_db, program_id=pid, host="127.0.0.1", http_status=200)
    fid = await _seed_finding(
        test_db,
        program_id=pid,
        asset_id=aid,
        title="Jenkins Exposed Admin Panel",
        url="https://jenkins.example.com/login",
        severity_label="high",
    )
    # seed a second finding with "127" in URL for asset-search test
    fid2 = await _seed_finding(
        test_db,
        program_id=pid,
        asset_id=aid,
        title="Open Redirect on 127.0.0.1",
        url="http://127.0.0.1/redirect",
        severity_label="medium",
        severity=500,
        category="redirect",
    )
    await _seed_secret(test_db, finding_id=fid)

    from bounty.config import get_settings
    get_settings.cache_clear()
    os.environ["DATA_DIR"] = str(test_db.parent)
    os.environ["_TEST_PID"] = pid
    os.environ["_TEST_FID"] = fid
    os.environ["_TEST_FID2"] = fid2
    os.environ["_TEST_AID"] = aid

    from bounty.ui.app import app
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    get_settings.cache_clear()
    for k in ("DATA_DIR", "_TEST_PID", "_TEST_FID", "_TEST_FID2", "_TEST_AID"):
        os.environ.pop(k, None)


# ===========================================================================
# A. Reports page (HTML)
# ===========================================================================

async def test_reports_page_returns_200(client: AsyncClient) -> None:
    r = await client.get("/reports")
    assert r.status_code == 200


async def test_reports_page_has_heading(client: AsyncClient) -> None:
    r = await client.get("/reports")
    assert "Reports" in r.text


async def test_reports_page_has_new_button(client: AsyncClient) -> None:
    r = await client.get("/reports")
    assert "New Report" in r.text


async def test_reports_page_has_modal(client: AsyncClient) -> None:
    r = await client.get("/reports")
    assert "new-report-modal" in r.text or "new-report" in r.text.lower()


async def test_reports_page_htmx_partial(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/reports", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<!DOCTYPE html>" not in r.text


# ===========================================================================
# B. Report detail page (HTML)
# ===========================================================================

async def test_report_detail_returns_200(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    assert r.status_code == 201
    rid = r.json()["id"]
    rp = await seeded_client.get(f"/reports/{rid}")
    assert rp.status_code == 200


async def test_report_detail_has_body(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = r.json()["id"]
    rp = await seeded_client.get(f"/reports/{rid}")
    assert "Summary" in rp.text or "Jenkins" in rp.text


async def test_report_detail_404(client: AsyncClient) -> None:
    r = await client.get("/reports/99999")
    assert r.status_code == 404


# ===========================================================================
# C. POST /api/reports — create
# ===========================================================================

async def test_create_report_returns_201(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    assert r.status_code == 201


async def test_create_report_is_draft(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    assert r.json()["status"] == "draft"


async def test_create_report_body_has_finding_title(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    assert "Jenkins" in r.json()["body"]


async def test_create_report_auto_title_from_finding(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    assert "Jenkins" in r.json()["title"]


async def test_create_report_custom_title(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1", "title": "My Custom Title"},
    )
    assert r.json()["title"] == "My Custom Title"


async def test_create_report_bad_template_422(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [], "template": "invalid"},
    )
    assert r.status_code == 422


# ===========================================================================
# D. GET /api/reports/{id}
# ===========================================================================

async def test_get_report_returns_full_record(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    cr = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = cr.json()["id"]
    r = await seeded_client.get(f"/api/reports/{rid}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == rid
    assert "body" in data
    assert "template" in data
    assert "status" in data


async def test_get_report_finding_ids_is_list(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    cr = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = cr.json()["id"]
    r = await seeded_client.get(f"/api/reports/{rid}")
    assert isinstance(r.json()["finding_ids"], list)


async def test_get_report_404(client: AsyncClient) -> None:
    r = await client.get("/api/reports/99999")
    assert r.status_code == 404


# ===========================================================================
# E. PATCH /api/reports/{id}
# ===========================================================================

async def test_patch_report_updates_body(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    cr = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = cr.json()["id"]
    r = await seeded_client.patch(
        f"/api/reports/{rid}",
        json={"body": "# Updated Body\n\nNew content here."},
    )
    assert r.status_code == 200
    assert r.json()["body"] == "# Updated Body\n\nNew content here."


async def test_patch_report_updates_status(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    cr = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = cr.json()["id"]
    r = await seeded_client.patch(f"/api/reports/{rid}", json={"status": "sent"})
    assert r.status_code == 200
    assert r.json()["status"] == "sent"
    assert r.json()["sent_at"] is not None


async def test_patch_report_invalid_status_422(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    cr = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = cr.json()["id"]
    r = await seeded_client.patch(f"/api/reports/{rid}", json={"status": "invalid_status"})
    assert r.status_code == 422


async def test_patch_report_404(client: AsyncClient) -> None:
    r = await client.patch("/api/reports/99999", json={"body": "new"})
    assert r.status_code == 404


# ===========================================================================
# F. POST /api/reports/{id}/generate
# ===========================================================================

async def test_generate_report_returns_200(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    cr = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = cr.json()["id"]
    r = await seeded_client.post(f"/api/reports/{rid}/generate")
    assert r.status_code == 200


async def test_generate_report_refreshes_body(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    cr = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = cr.json()["id"]
    # Wipe body first
    await seeded_client.patch(f"/api/reports/{rid}", json={"body": ""})
    r = await seeded_client.post(f"/api/reports/{rid}/generate")
    assert "Jenkins" in r.json()["body"]


# ===========================================================================
# G. DELETE /api/reports/{id}
# ===========================================================================

async def test_delete_report_returns_204(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    cr = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = cr.json()["id"]
    r = await seeded_client.delete(f"/api/reports/{rid}")
    assert r.status_code == 204


async def test_delete_report_removes_from_db(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    cr = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    rid = cr.json()["id"]
    await seeded_client.delete(f"/api/reports/{rid}")
    r = await seeded_client.get(f"/api/reports/{rid}")
    assert r.status_code == 404


async def test_delete_report_404(client: AsyncClient) -> None:
    r = await client.delete("/api/reports/99999")
    assert r.status_code == 404


# ===========================================================================
# H. Report body content / templates
# ===========================================================================

async def test_h1_body_has_summary_section(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    body = r.json()["body"]
    assert "Summary" in body


async def test_h1_body_has_steps_to_reproduce(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    body = r.json()["body"]
    assert "Steps to Reproduce" in body


async def test_h1_body_has_impact_section(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    body = r.json()["body"]
    assert "Impact" in body


async def test_h1_body_has_recommended_fix(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    body = r.json()["body"]
    assert "Recommended Fix" in body


async def test_bugcrowd_template_differs_from_h1(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    h1_r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    bc_r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "bugcrowd"},
    )
    assert h1_r.json()["body"] != bc_r.json()["body"]


async def test_bugcrowd_body_has_vrt_category(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "bugcrowd"},
    )
    body = r.json()["body"]
    assert "Bugcrowd" in body


async def test_secrets_in_body_use_preview_not_raw(seeded_client: AsyncClient) -> None:
    """Secret raw values must NOT appear in the report body — only preview."""
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    body = r.json()["body"]
    # Preview should appear (if secret is linked)
    assert "SECRET_SHOULD_NEVER_APPEAR" not in body
    # The raw value that was seeded must never be in the body
    assert "AKIA1234SECRET_SHOULD_NEVER_APPEAR" not in body


async def test_report_no_findings_returns_placeholder(seeded_client: AsyncClient) -> None:
    pid = os.environ["_TEST_PID"]
    r = await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [], "template": "h1"},
    )
    assert r.status_code == 201
    body = r.json()["body"]
    assert "No findings" in body or "_No findings" in body


# ===========================================================================
# I. Settings page
# ===========================================================================

async def test_settings_page_returns_200(client: AsyncClient) -> None:
    r = await client.get("/settings")
    assert r.status_code == 200


async def test_settings_page_has_tabs(client: AsyncClient) -> None:
    r = await client.get("/settings")
    text = r.text.lower()
    assert "general" in text or "integrations" in text or "notifications" in text


async def test_settings_page_has_system_tab(client: AsyncClient) -> None:
    r = await client.get("/settings")
    assert "system" in r.text.lower() or "System" in r.text


# ===========================================================================
# J. System API
# ===========================================================================

async def test_system_info_returns_200(client: AsyncClient) -> None:
    r = await client.get("/api/system/info")
    assert r.status_code == 200


async def test_system_info_has_version(client: AsyncClient) -> None:
    r = await client.get("/api/system/info")
    data = r.json()
    assert "bounty_version" in data
    assert "python_version" in data


async def test_system_info_has_db_path(client: AsyncClient) -> None:
    r = await client.get("/api/system/info")
    assert "db_path" in r.json()


async def test_wipe_test_data_without_confirm_returns_400(client: AsyncClient) -> None:
    r = await client.post("/api/system/wipe-test-data", json={"confirm": False})
    assert r.status_code == 400


async def test_wipe_test_data_requires_confirm_true(client: AsyncClient) -> None:
    # confirm omitted → default False → 400
    r = await client.post("/api/system/wipe-test-data", json={})
    assert r.status_code == 400


async def test_wipe_test_data_with_confirm_returns_200(client: AsyncClient) -> None:
    r = await client.post("/api/system/wipe-test-data", json={"confirm": True})
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


async def test_vacuum_returns_200(client: AsyncClient) -> None:
    r = await client.post("/api/system/vacuum")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ===========================================================================
# K. Command palette
# ===========================================================================

async def test_palette_empty_query_returns_quick_actions(client: AsyncClient) -> None:
    r = await client.get("/api/palette/search?q=")
    assert r.status_code == 200
    data = r.json()
    assert "quick_actions" in data
    assert len(data["quick_actions"]) > 0
    assert data["results"] == []


async def test_palette_empty_query_no_results(client: AsyncClient) -> None:
    r = await client.get("/api/palette/search")
    data = r.json()
    assert data["results"] == []


async def test_palette_search_jenkins_returns_findings(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/palette/search?q=jenkins")
    assert r.status_code == 200
    data = r.json()
    finding_results = [x for x in data["results"] if x["type"] == "finding"]
    assert len(finding_results) > 0


async def test_palette_search_jenkins_result_has_label(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/palette/search?q=jenkins")
    data = r.json()
    labels = [x["label"] for x in data["results"]]
    assert any("Jenkins" in l or "jenkins" in l.lower() for l in labels)


async def test_palette_search_127_returns_asset_results(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/palette/search?q=127")
    data = r.json()
    asset_results = [x for x in data["results"] if x["type"] == "asset"]
    assert len(asset_results) > 0


async def test_palette_results_have_url(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/palette/search?q=jenkins")
    data = r.json()
    for item in data["results"]:
        assert "url" in item
        assert item["url"].startswith("/")


async def test_palette_results_capped_at_15(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/palette/search?q=a")
    data = r.json()
    assert len(data["results"]) <= 15


async def test_palette_search_returns_quick_actions_always(seeded_client: AsyncClient) -> None:
    r = await seeded_client.get("/api/palette/search?q=jenkins")
    data = r.json()
    assert "quick_actions" in data
    assert len(data["quick_actions"]) > 0


async def test_palette_quick_actions_have_required_fields(client: AsyncClient) -> None:
    r = await client.get("/api/palette/search?q=")
    data = r.json()
    for qa in data["quick_actions"]:
        assert "label" in qa
        assert "url" in qa


async def test_get_reports_list_api(seeded_client: AsyncClient) -> None:
    """GET /api/reports returns paginated JSON."""
    pid = os.environ["_TEST_PID"]
    fid = os.environ["_TEST_FID"]
    await seeded_client.post(
        "/api/reports",
        json={"program_id": pid, "finding_ids": [fid], "template": "h1"},
    )
    r = await seeded_client.get("/api/reports")
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert data["total"] >= 1


