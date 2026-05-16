"""
tests/test_program_create_form.py — Backend tests for POST /api/programs.

Covers:
  1. Program is created with a server-generated ULID id (id != name)
  2. Targets are persisted when scope list is supplied
  3. Program is created with empty targets when scope is omitted
  4. Invalid scope_type returns 422
  5. Invalid asset_type returns 422
  6. Client-supplied id field is ignored (model has no id field)
  7. Round trip: create with 3 targets → GET returns program + 3 targets
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from bounty.db import apply_migrations, init_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path: Path) -> TestClient:  # type: ignore[misc]
    """Return a FastAPI test client backed by a fresh in-memory DB."""
    from bounty.ui.app import app
    from bounty.config import Settings
    import bounty.ui.deps as _deps

    db_path = tmp_path / "test.db"

    # Initialise DB with seeding disabled
    with patch("bounty.config.get_settings") as mock_gs:
        s = Settings(
            data_dir=tmp_path,
            auto_seed_on_empty_db=False,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s
        init_db(db_path)
        apply_migrations(db_path)

    with patch("bounty.config.get_settings") as mock_gs:
        s = Settings(
            data_dir=tmp_path,
            auto_seed_on_empty_db=False,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s
        with patch.object(_deps, "get_settings_dep", return_value=s):
            with TestClient(app, raise_server_exceptions=True) as c:
                yield c


def _raw_conn(tmp_path: Path) -> sqlite3.Connection:
    """Open a raw sqlite3 connection to the app db (bounty.db) for assertions."""
    # Settings.db_path = data_dir / "bounty.db"; data_dir=tmp_path in tests.
    return sqlite3.connect(str(tmp_path / "bounty.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_BODY = {
    "platform": "manual",
    "handle": "test-handle",
    "name": "Test Program",
    "url": "",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestProgramCreateULID:
    """Bug A: The program id must be a server-generated ULID, never the name."""

    def test_id_is_ulid_not_name(self, client: TestClient) -> None:
        """Returned id must be a 26-char ULID, not equal to the program name."""
        r = client.post("/api/programs", json=_VALID_BODY)
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["id"] != data["name"], "id must not equal name"
        assert len(data["id"]) == 26, f"ULID must be 26 chars, got {data['id']!r}"
        # Crockford Base32: only digits + A-HJ-NP-TV-Z (no I, L, O, U)
        assert data["id"] == data["id"].upper(), "ULID must be uppercase"

    def test_two_programs_get_distinct_ids(self, client: TestClient) -> None:
        """Each program must receive a unique id."""
        r1 = client.post("/api/programs", json={**_VALID_BODY, "handle": "h1"})
        r2 = client.post("/api/programs", json={**_VALID_BODY, "handle": "h2", "name": "Other"})
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["id"] != r2.json()["id"]

    def test_client_supplied_id_is_ignored(self, client: TestClient) -> None:
        """Extra 'id' field in request body must be silently ignored."""
        body = {**_VALID_BODY, "handle": "h3", "id": "should-be-ignored"}
        r = client.post("/api/programs", json=body)
        assert r.status_code == 201, r.text
        data = r.json()
        # The returned id must be a ULID, not the string we sent
        assert data["id"] != "should-be-ignored"
        assert len(data["id"]) == 26


class TestProgramCreateTargets:
    """Bug B: Targets supplied in the request must be persisted."""

    def test_targets_persisted(self, client: TestClient, tmp_path: Path) -> None:
        """Scope list targets must appear in the targets table after creation."""
        body = {
            **_VALID_BODY,
            "handle": "t1",
            "scope": [
                {"scope_type": "in_scope", "asset_type": "domain", "value": "example.com"},
            ],
        }
        r = client.post("/api/programs", json=body)
        assert r.status_code == 201, r.text
        program_id = r.json()["id"]

        conn = _raw_conn(tmp_path)
        rows = conn.execute(
            "SELECT scope_type, asset_type, value FROM targets WHERE program_id = ?",
            (program_id,),
        ).fetchall()
        conn.close()

        assert len(rows) == 1
        assert rows[0] == ("in_scope", "domain", "example.com")

    def test_no_targets_allowed(self, client: TestClient, tmp_path: Path) -> None:
        """Creating a program without targets is allowed — empty targets list."""
        body = {**_VALID_BODY, "handle": "t2"}
        r = client.post("/api/programs", json=body)
        assert r.status_code == 201, r.text
        program_id = r.json()["id"]

        conn = _raw_conn(tmp_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM targets WHERE program_id = ?", (program_id,)
        ).fetchone()[0]
        conn.close()
        assert count == 0

    def test_multiple_targets_persisted(self, client: TestClient, tmp_path: Path) -> None:
        """All targets in the scope list must be stored."""
        body = {
            **_VALID_BODY,
            "handle": "t3",
            "scope": [
                {"scope_type": "in_scope", "asset_type": "domain", "value": "a.example.com"},
                {"scope_type": "in_scope", "asset_type": "wildcard", "value": "*.example.com"},
                {"scope_type": "out_of_scope", "asset_type": "url", "value": "https://example.com/admin"},
            ],
        }
        r = client.post("/api/programs", json=body)
        assert r.status_code == 201, r.text
        program_id = r.json()["id"]

        conn = _raw_conn(tmp_path)
        rows = conn.execute(
            "SELECT value FROM targets WHERE program_id = ? ORDER BY value",
            (program_id,),
        ).fetchall()
        conn.close()
        values = {row[0] for row in rows}
        assert values == {"a.example.com", "*.example.com", "https://example.com/admin"}


class TestProgramCreateValidation:
    """Enum validation for scope_type and asset_type."""

    def test_invalid_scope_type_rejected(self, client: TestClient) -> None:
        """Invalid scope_type must return HTTP 422."""
        body = {
            **_VALID_BODY,
            "handle": "v1",
            "scope": [{"scope_type": "INVALID", "asset_type": "domain", "value": "x.com"}],
        }
        r = client.post("/api/programs", json=body)
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"

    def test_invalid_asset_type_rejected(self, client: TestClient) -> None:
        """Invalid asset_type must return HTTP 422."""
        body = {
            **_VALID_BODY,
            "handle": "v2",
            "scope": [{"scope_type": "in_scope", "asset_type": "banana", "value": "x.com"}],
        }
        r = client.post("/api/programs", json=body)
        assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"


class TestProgramRoundTrip:
    """Round-trip: create program + GET /api/programs/{id} returns full data."""

    def test_round_trip_with_targets(self, client: TestClient) -> None:
        """Create program with 3 targets; GET returns program with all 3 targets."""
        body = {
            **_VALID_BODY,
            "handle": "rt1",
            "name": "Round-Trip Test",
            "scope": [
                {"scope_type": "in_scope", "asset_type": "domain", "value": "rt.example.com"},
                {"scope_type": "in_scope", "asset_type": "ip", "value": "10.0.0.1"},
                {"scope_type": "out_of_scope", "asset_type": "url", "value": "https://rt.example.com/internal"},
            ],
        }
        create_r = client.post("/api/programs", json=body)
        assert create_r.status_code == 201, create_r.text
        program_id = create_r.json()["id"]

        get_r = client.get(f"/api/programs/{program_id}")
        assert get_r.status_code == 200, get_r.text
        data = get_r.json()

        assert data["id"] == program_id
        assert data["name"] == "Round-Trip Test"
        assert len(data["id"]) == 26, "id should be a 26-char ULID"

        target_values = {t["value"] for t in data["targets"]}
        assert target_values == {
            "rt.example.com",
            "10.0.0.1",
            "https://rt.example.com/internal",
        }


