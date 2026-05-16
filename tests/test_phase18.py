"""
tests/test_phase18.py — Phase 18: Seed data + first-run experience.

Tests cover:
  1.  seed_database on empty DB inserts all 3 programs + their targets
  2.  seed_database idempotent (running twice never duplicates)
  3.  --force re-seeds (delete existing + insert)
  4.  --list mode of CLI prints output and inserts nothing
  5.  seed_sync helper returns expected structure
  6.  init_db auto-seeds when programs table is empty
  7.  init_db skips auto-seed when programs already exist
  8.  init_db skips auto-seed when auto_seed_on_empty_db=False
  9.  POST /api/seed endpoint returns {inserted, skipped}
  10. GET /api/programs after seed returns 3 programs
  11. SEED_PROGRAMS list has exactly 3 entries
  12. Each seed program has required fields populated
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from bounty.db import apply_migrations, init_db
from bounty.seed import SEED_PROGRAMS, seed_database, seed_sync


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    """Return a path to a freshly initialised (but not yet seeded) DB."""
    db_path = tmp_path / "test.db"
    # Initialise with auto-seed disabled so we control seeding manually.
    with patch("bounty.config.get_settings") as mock_gs:
        from bounty.config import Settings
        s = Settings(
            data_dir=tmp_path,
            auto_seed_on_empty_db=False,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s
        init_db(db_path)
        apply_migrations(db_path)
    return db_path


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    """Return a FastAPI test client with a fresh DB."""
    from bounty.ui.app import app
    from bounty.config import get_settings

    db_path = tmp_path / "test.db"

    with patch("bounty.config.get_settings") as mock_gs:
        from bounty.config import Settings
        s = Settings(
            data_dir=tmp_path,
            auto_seed_on_empty_db=False,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s
        init_db(db_path)
        apply_migrations(db_path)

    # Patch settings for the test client duration
    with patch("bounty.config.get_settings") as mock_gs:
        from bounty.config import Settings
        s = Settings(
            data_dir=tmp_path,
            auto_seed_on_empty_db=False,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s
        # Patch the deps module too
        import bounty.ui.deps as _deps
        with patch.object(_deps, "get_settings_dep", return_value=s):
            with TestClient(app, raise_server_exceptions=True) as c:
                yield c


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _count_programs(db_path: Path) -> int:
    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT COUNT(*) FROM programs").fetchone()
    conn.close()
    return row[0] if row else 0


def _count_targets(db_path: Path) -> int:
    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT COUNT(*) FROM targets").fetchone()
    conn.close()
    return row[0] if row else 0


def _get_program_ids(db_path: Path) -> list[str]:
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute("SELECT id FROM programs ORDER BY id").fetchall()
    conn.close()
    return [r[0] for r in rows]


# ---------------------------------------------------------------------------
# Test 11 — SEED_PROGRAMS has exactly 3 entries
# ---------------------------------------------------------------------------

def test_seed_programs_count() -> None:
    assert len(SEED_PROGRAMS) == 3


# ---------------------------------------------------------------------------
# Test 12 — Each seed program has required fields
# ---------------------------------------------------------------------------

def test_seed_programs_required_fields() -> None:
    required = {"id", "name", "platform", "handle", "description", "targets"}
    for prog in SEED_PROGRAMS:
        missing = required - set(prog.keys())
        assert not missing, f"Program {prog.get('id')!r} missing fields: {missing}"
        assert prog["id"].startswith("seed:")
        assert prog["platform"] == "manual"
        assert isinstance(prog["targets"], list)
        assert len(prog["targets"]) >= 1
        for t in prog["targets"]:
            assert "scope_type" in t
            assert "asset_type" in t
            assert "value" in t


# ---------------------------------------------------------------------------
# Test 1 — seed_database on empty DB inserts all programs + targets
# ---------------------------------------------------------------------------

def test_seed_database_inserts_all(tmp_db: Path) -> None:
    assert _count_programs(tmp_db) == 0

    result = asyncio.run(seed_database(tmp_db))

    assert result["inserted"] == len(SEED_PROGRAMS)
    assert result["skipped"] == 0
    assert len(result["programs"]) == len(SEED_PROGRAMS)
    assert _count_programs(tmp_db) == len(SEED_PROGRAMS)

    # All seed IDs present
    ids = _get_program_ids(tmp_db)
    for prog in SEED_PROGRAMS:
        assert prog["id"] in ids

    # Targets inserted
    assert _count_targets(tmp_db) >= len(SEED_PROGRAMS)


# ---------------------------------------------------------------------------
# Test 2 — seed_database is idempotent (running twice doesn't duplicate)
# ---------------------------------------------------------------------------

def test_seed_database_idempotent(tmp_db: Path) -> None:
    result1 = asyncio.run(seed_database(tmp_db))
    result2 = asyncio.run(seed_database(tmp_db))

    assert result1["inserted"] == len(SEED_PROGRAMS)
    assert result2["inserted"] == 0
    assert result2["skipped"] == len(SEED_PROGRAMS)

    # Counts unchanged after second call
    assert _count_programs(tmp_db) == len(SEED_PROGRAMS)

    conn = sqlite3.connect(str(tmp_db))
    tcount = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    conn.close()
    expected_targets = sum(len(p["targets"]) for p in SEED_PROGRAMS)
    assert tcount == expected_targets


# ---------------------------------------------------------------------------
# Test 3 — --force re-seeds (delete + insert)
# ---------------------------------------------------------------------------

def test_seed_database_force(tmp_db: Path) -> None:
    asyncio.run(seed_database(tmp_db))

    # Modify a program name to confirm it gets reset
    conn = sqlite3.connect(str(tmp_db))
    conn.execute("UPDATE programs SET name='MODIFIED' WHERE id='seed:hackerone'")
    conn.commit()
    conn.close()

    result = asyncio.run(seed_database(tmp_db, force=True))

    assert result["inserted"] == len(SEED_PROGRAMS)
    assert result["skipped"] == 0

    # Verify name was restored
    conn = sqlite3.connect(str(tmp_db))
    row = conn.execute("SELECT name FROM programs WHERE id='seed:hackerone'").fetchone()
    conn.close()
    assert row is not None
    assert row[0] != "MODIFIED"
    assert "HackerOne" in row[0]


# ---------------------------------------------------------------------------
# Test 4 — --list mode (CLI) doesn't insert
# ---------------------------------------------------------------------------

def test_seed_list_mode_no_insert(tmp_db: Path) -> None:
    from typer.testing import CliRunner
    from bounty.cli import app as cli_app

    runner = CliRunner()

    with patch("bounty.config.get_settings") as mock_gs:
        from bounty.config import Settings
        s = Settings(
            data_dir=tmp_db.parent,
            auto_seed_on_empty_db=False,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s
        result = runner.invoke(cli_app, ["seed", "--list"])

    assert result.exit_code == 0, result.output
    assert "seed:hackerone" in result.output or "HackerOne" in result.output
    # Nothing inserted
    assert _count_programs(tmp_db) == 0


# ---------------------------------------------------------------------------
# Test 5 — seed_sync helper returns expected structure
# ---------------------------------------------------------------------------

def test_seed_sync_structure(tmp_db: Path) -> None:
    result = seed_sync(tmp_db)

    assert isinstance(result, dict)
    assert "inserted" in result
    assert "skipped" in result
    assert "programs" in result
    assert result["inserted"] == len(SEED_PROGRAMS)
    assert isinstance(result["programs"], list)


# ---------------------------------------------------------------------------
# Test 6 — init_db auto-seeds when programs table empty
# ---------------------------------------------------------------------------

def test_init_db_auto_seeds_empty(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.db"

    with patch("bounty.config.get_settings") as mock_gs:
        from bounty.config import Settings
        s = Settings(
            data_dir=tmp_path,
            auto_seed_on_empty_db=True,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s
        init_db(db_path)

    assert _count_programs(db_path) == len(SEED_PROGRAMS)


# ---------------------------------------------------------------------------
# Test 7 — init_db skips auto-seed when programs already exist
# ---------------------------------------------------------------------------

def test_init_db_skips_auto_seed_when_programs_exist(tmp_path: Path) -> None:
    db_path = tmp_path / "existing.db"

    # Create DB and manually insert a program first
    with patch("bounty.config.get_settings") as mock_gs:
        from bounty.config import Settings
        s = Settings(
            data_dir=tmp_path,
            auto_seed_on_empty_db=False,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s
        init_db(db_path)

    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO programs (id, platform, handle, name) VALUES ('test:existing', 'manual', 'existing', 'Existing')"
    )
    conn.commit()
    conn.close()

    # Now call init_db with auto_seed=True — should NOT seed since programs exist
    with patch("bounty.config.get_settings") as mock_gs:
        from bounty.config import Settings
        s2 = Settings(
            data_dir=tmp_path,
            auto_seed_on_empty_db=True,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s2
        init_db(db_path)

    # Only the manually inserted program should be present
    assert _count_programs(db_path) == 1
    assert _get_program_ids(db_path) == ["test:existing"]


# ---------------------------------------------------------------------------
# Test 8 — init_db skips auto-seed when auto_seed_on_empty_db=False
# ---------------------------------------------------------------------------

def test_init_db_skips_auto_seed_when_disabled(tmp_path: Path) -> None:
    db_path = tmp_path / "noseed.db"

    with patch("bounty.config.get_settings") as mock_gs:
        from bounty.config import Settings
        s = Settings(
            data_dir=tmp_path,
            auto_seed_on_empty_db=False,
            scheduler_test_mode=True,
        )
        mock_gs.return_value = s
        init_db(db_path)

    assert _count_programs(db_path) == 0


# ---------------------------------------------------------------------------
# Test 9 — POST /api/seed endpoint works
# ---------------------------------------------------------------------------

def test_post_api_seed(tmp_path: Path) -> None:
    """POST /api/seed on an empty DB returns inserted=3 and inserts programs."""
    from fastapi.testclient import TestClient
    from bounty.ui.app import app as ui_app
    from bounty.config import Settings
    import bounty.ui.deps as _deps

    s = Settings(
        data_dir=tmp_path,
        auto_seed_on_empty_db=False,
        scheduler_test_mode=True,
    )
    db_path = s.db_path  # tmp_path / "bounty.db"

    with patch("bounty.config.get_settings", return_value=s):
        init_db(db_path)
        apply_migrations(db_path)

    with patch("bounty.config.get_settings", return_value=s):
        with patch.object(_deps, "get_settings_dep", return_value=s):
            with TestClient(ui_app, raise_server_exceptions=True) as c:
                resp = c.post("/api/seed")

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["inserted"] == len(SEED_PROGRAMS)
    assert data["skipped"] == 0
    assert _count_programs(db_path) == len(SEED_PROGRAMS)


# ---------------------------------------------------------------------------
# Test 10 — GET /api/programs after seed returns 3 programs
# ---------------------------------------------------------------------------

def test_get_programs_after_seed(tmp_path: Path) -> None:
    """GET /api/programs after seeding must return all 3 seed programs."""
    from fastapi.testclient import TestClient
    from bounty.ui.app import app as ui_app
    from bounty.config import Settings
    import bounty.ui.deps as _deps

    s = Settings(
        data_dir=tmp_path,
        auto_seed_on_empty_db=False,
        scheduler_test_mode=True,
    )
    db_path = s.db_path  # tmp_path / "bounty.db"

    with patch("bounty.config.get_settings", return_value=s):
        init_db(db_path)
        apply_migrations(db_path)

    # Seed directly via sync helper
    seed_sync(db_path)

    with patch("bounty.config.get_settings", return_value=s):
        with patch.object(_deps, "get_settings_dep", return_value=s):
            with TestClient(ui_app, raise_server_exceptions=True) as c:
                resp = c.get("/api/programs")

    assert resp.status_code == 200, resp.text
    data = resp.json()
    items = data.get("items", [])
    assert len(items) == len(SEED_PROGRAMS)

    ids = {item["id"] for item in items}
    for prog in SEED_PROGRAMS:
        assert prog["id"] in ids, f"Seed program {prog['id']} not in /api/programs response"


