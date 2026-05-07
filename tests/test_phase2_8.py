"""
tests/test_phase2_8.py — Phase 2.8 regression tests.

Covers the four bugs fixed in Phase 2.8:
  BUG 1 — Asset deduplication: http/https variants of same host → single row
  BUG 3 — CLI summary asset count matches pipeline return value
  BUG 4 — Pipeline skips enumerate/resolve phases for IP-only targets
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from bounty.db import apply_migrations, get_conn, init_db
from bounty.models import Target
from bounty.recon import recon_pipeline
from bounty.ulid import make_ulid


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _setup_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "test.db"
    init_db(db_path)
    apply_migrations(db_path)
    async with get_conn(db_path) as conn:
        await conn.execute(
            "INSERT INTO programs (id, platform, handle, name) VALUES (?,?,?,?)",
            ("test:p28", "manual", "p28", "Phase 2.8 Test"),
        )
        await conn.commit()
    return db_path


# ---------------------------------------------------------------------------
# BUG 1 — Asset deduplication: http + https → single row
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_asset_upsert_collapses_http_https(tmp_path: Path) -> None:
    """Probing http://X then https://X must produce ONE asset row.

    seen_protocols should contain both schemes, primary_scheme should be 'https'.
    The pipeline may return the same asset_id twice (once per scheme probe), but
    the DB must have exactly one row.
    """
    from bounty.recon import recon_pipeline
    from bounty.models import ProbeResult, TLSInfo

    db_path = await _setup_db(tmp_path)

    probe_call_count = 0

    async def _fake_probe(url: str, **kwargs: object) -> ProbeResult:
        nonlocal probe_call_count
        probe_call_count += 1
        return ProbeResult(
            url=url,
            final_url=url,
            status_code=200,
            headers={"server": "nginx"},
            body=b"<html><title>test</title></html>",
            body_text="<html><title>test</title></html>",
            ip="1.2.3.4",
            elapsed_ms=50.0,
        )

    # Use a fake resolve result that marks testhost.local as alive
    from bounty.recon.resolve import ResolveResult
    fake_resolve: dict[str, ResolveResult] = {
        "testhost.local": ResolveResult(
            hostname="testhost.local",
            a_records=["1.2.3.4"],
            alive=True,
        )
    }

    targets = [
        Target(
            program_id="test:p28",
            scope_type="in_scope",
            asset_type="url",
            value="testhost.local",
        )
    ]

    with (
        patch("bounty.recon.probe", side_effect=_fake_probe),
        patch("bounty.recon.resolve_batch", return_value=fake_resolve),
        patch("bounty.recon.enumerate_subdomains", return_value=AsyncMockIter([])),
    ):
        result = await recon_pipeline(
            "test:p28",
            targets,
            intensity="gentle",
            db_path=db_path,
            scan_id=make_ulid(),
        )

    # Regardless of how many asset_ids the pipeline returned (could be 1 per probe),
    # the DB must contain exactly ONE row for this host.
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "SELECT id, host, seen_protocols, primary_scheme, url FROM assets WHERE program_id='test:p28'"
        )
        rows = list(await cur.fetchall())

    assert len(rows) == 1, (
        f"Expected 1 asset row after http+https probes, got {len(rows)}: "
        f"{[dict(r) for r in rows]}"
    )
    row = rows[0]
    protocols: list[str] = json.loads(row["seen_protocols"])
    assert "https" in protocols, f"Expected 'https' in seen_protocols, got {protocols}"
    assert row["primary_scheme"] == "https", f"Expected primary_scheme='https', got {row['primary_scheme']}"
    assert row["url"].startswith("https://"), f"Expected https:// URL, got {row['url']}"


# ---------------------------------------------------------------------------
# BUG 4 — IP-only targets: enumerate and resolve phases must be skipped
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pipeline_skips_resolve_for_ip_only_targets(tmp_path: Path) -> None:
    """Feed the pipeline IP targets only; assert no 'recon' or 'resolve' phase rows."""
    from bounty.models import ProbeResult

    db_path = await _setup_db(tmp_path)

    async def _fast_fail_probe(url: str, **kwargs: object) -> ProbeResult:
        return ProbeResult(
            url=url,
            final_url=url,
            status_code=0,
            headers={},
            body=b"",
            body_text="",
            error="connection refused",
            elapsed_ms=10.0,
        )

    targets = [
        Target(
            program_id="test:p28",
            scope_type="in_scope",
            asset_type="ip",
            value="203.0.113.1",  # TEST-NET-3 — won't actually respond
        )
    ]

    scan_id = make_ulid()

    with patch("bounty.recon.probe", side_effect=_fast_fail_probe):
        await recon_pipeline(
            "test:p28",
            targets,
            intensity="gentle",
            db_path=db_path,
            scan_id=scan_id,
        )

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "SELECT phase FROM scan_phases WHERE scan_id=?",
            (scan_id,),
        )
        phases = {row["phase"] for row in await cur.fetchall()}

    assert "recon" not in phases, (
        f"'recon' phase should NOT be created for IP-only scan, got phases={phases}"
    )
    assert "resolve" not in phases, (
        f"'resolve' phase should NOT be created for IP-only scan, got phases={phases}"
    )


# ---------------------------------------------------------------------------
# BUG 3 — CLI summary count matches pipeline asset_ids
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cli_summary_matches_pipeline_count(tmp_path: Path) -> None:
    """scan-ips must report 'assets discovered: N' where N == len(pipeline.assets).

    We test the underlying async helper directly (rather than through the CLI
    entrypoint) to avoid subprocess overhead.
    """
    from bounty.models import ProbeResult
    from bounty.cli import _scan_ips_async

    db_path = await _setup_db(tmp_path)

    probe_responses: dict[str, int] = {
        "https://203.0.113.5": 200,
        "http://203.0.113.5": 200,
    }

    async def _selective_probe(url: str, **kwargs: object) -> ProbeResult:
        status = probe_responses.get(url, 0)
        if status > 0:
            return ProbeResult(
                url=url, final_url=url, status_code=status,
                headers={}, body=b"<title>ok</title>", body_text="<title>ok</title>",
                ip="203.0.113.5", elapsed_ms=50.0,
            )
        return ProbeResult(
            url=url, final_url=url, status_code=0, headers={},
            body=b"", body_text="", error="no route", elapsed_ms=5.0,
        )

    targets = [
        Target(
            program_id="test:p28",
            scope_type="in_scope",
            asset_type="ip",
            value="203.0.113.5",
        )
    ]

    scan_id = make_ulid()

    with patch("bounty.recon.probe", side_effect=_selective_probe):
        pipeline_result, _scan_row, asset_rows, _phases = await _scan_ips_async(
            db_path, "test:p28", targets, scan_id, "gentle"
        )

    pipeline_count = len(pipeline_result.get("assets", []))
    cli_displayed_count = len(asset_rows)

    assert pipeline_count == cli_displayed_count, (
        f"CLI displayed {cli_displayed_count} assets but pipeline returned {pipeline_count}. "
        "Asset count mismatch (BUG 3)."
    )

    # And the DB should match too (deduplicated)
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "SELECT COUNT(*) FROM assets WHERE program_id='test:p28'"
        )
        db_count = (await cur.fetchone())[0]

    # db_count may be less if http/https were collapsed
    assert db_count <= pipeline_count, (
        f"DB has {db_count} rows but pipeline returned {pipeline_count} IDs — "
        "IDs from updated rows can appear multiple times in pipeline result."
    )


# ---------------------------------------------------------------------------
# Migration V3 — verify deduplication of existing http/https rows
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_migration_v3_deduplicates_existing_rows(tmp_path: Path) -> None:
    """Running migration V3 on a DB that already has duplicate http+https rows
    should leave exactly one row per (program_id, host, port) group."""
    import sqlite3 as stdlib_sqlite3

    db_path = tmp_path / "migrate_test.db"

    # Manually create a V2-era DB (with UNIQUE(program_id, url)) and insert duplicates.
    conn = stdlib_sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript("""
        CREATE TABLE programs (
            id TEXT PRIMARY KEY, platform TEXT NOT NULL DEFAULT 'manual',
            handle TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '',
            url TEXT NOT NULL DEFAULT '', policy_url TEXT NOT NULL DEFAULT '',
            bounty_table TEXT, active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
            scope_type TEXT NOT NULL, asset_type TEXT NOT NULL,
            value TEXT NOT NULL, max_severity TEXT, notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE assets (
            id TEXT PRIMARY KEY,
            program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
            host TEXT NOT NULL, port INTEGER, scheme TEXT NOT NULL DEFAULT 'https',
            url TEXT NOT NULL, ip TEXT, status TEXT NOT NULL DEFAULT 'discovered',
            http_status INTEGER, title TEXT, server TEXT,
            cdn TEXT, waf TEXT, tls_issuer TEXT, tls_expiry TEXT,
            tags TEXT NOT NULL DEFAULT '[]',
            last_seen TEXT,
            first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            UNIQUE(program_id, url)
        );
        CREATE TABLE asset_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL,
            field TEXT NOT NULL, old_value TEXT, new_value TEXT,
            changed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL,
            tech TEXT NOT NULL, version TEXT, category TEXT NOT NULL DEFAULT 'other',
            evidence TEXT NOT NULL DEFAULT '', confidence INTEGER NOT NULL DEFAULT 50,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE scans (
            id TEXT PRIMARY KEY, program_id TEXT,
            asset_id TEXT, scan_type TEXT NOT NULL DEFAULT 'full',
            status TEXT NOT NULL DEFAULT 'queued', intensity TEXT NOT NULL DEFAULT 'normal',
            triggered_by TEXT NOT NULL DEFAULT 'scheduler', started_at TEXT,
            finished_at TEXT, finding_count INTEGER NOT NULL DEFAULT 0, error TEXT,
            meta TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE scan_phases (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            phase TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            started_at TEXT, finished_at TEXT, detail TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, program_id TEXT, asset_id TEXT,
            scan_id TEXT, dedup_key TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
            category TEXT NOT NULL, severity INTEGER NOT NULL DEFAULT 500,
            severity_label TEXT NOT NULL DEFAULT 'medium', status TEXT NOT NULL DEFAULT 'new',
            url TEXT NOT NULL, path TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
            remediation TEXT NOT NULL DEFAULT '', cvss_score REAL, cve TEXT, cwe TEXT,
            validated INTEGER NOT NULL DEFAULT 0, validated_at TEXT,
            tags TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE evidence_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER,
            secret_val_id INTEGER, kind TEXT NOT NULL DEFAULT 'http',
            request_raw TEXT, response_raw TEXT, response_status INTEGER,
            response_body_path TEXT, screenshot_path TEXT, curl_cmd TEXT,
            notes TEXT NOT NULL DEFAULT '',
            captured_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE secrets_validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT, finding_id INTEGER,
            provider TEXT NOT NULL, secret_hash TEXT NOT NULL, secret_preview TEXT NOT NULL,
            secret_pattern TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            scope TEXT, identity TEXT, last_checked TEXT, next_check TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            UNIQUE(secret_hash, provider)
        );
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL,
            platform TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft',
            title TEXT NOT NULL, body TEXT NOT NULL, submitted_at TEXT,
            platform_id TEXT, bounty_usd REAL, notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL,
            entity_type TEXT, entity_id TEXT, detail TEXT NOT NULL DEFAULT '{}',
            ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE TABLE leads (
            id TEXT PRIMARY KEY, source TEXT NOT NULL DEFAULT 'shodan',
            source_query TEXT, ip TEXT NOT NULL, port INTEGER,
            hostnames TEXT NOT NULL DEFAULT '[]', org TEXT, asn TEXT, product TEXT,
            title TEXT, raw_data TEXT NOT NULL DEFAULT '{}',
            program_id TEXT, status TEXT NOT NULL DEFAULT 'new',
            discovered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            UNIQUE(source, ip, port)
        );

        INSERT INTO programs (id, platform, handle, name) VALUES ('prog1', 'manual', 'prog1', 'Test');

        -- Two duplicate rows: http and https for same host, same "null" port
        INSERT INTO assets (id, program_id, host, port, scheme, url, http_status)
            VALUES ('id-http', 'prog1', 'myhost.io', NULL, 'http', 'http://myhost.io', 404);
        INSERT INTO assets (id, program_id, host, port, scheme, url, http_status)
            VALUES ('id-https', 'prog1', 'myhost.io', NULL, 'https', 'https://myhost.io', 200);

        PRAGMA user_version = 2;
    """)
    conn.close()

    # Now run V3 migration only
    from bounty.db import _MIGRATION_V3, _recreate_indexes
    conn2 = stdlib_sqlite3.connect(str(db_path))
    conn2.execute("PRAGMA foreign_keys = OFF")
    conn2.commit()
    conn2.executescript(_MIGRATION_V3)
    conn2.execute("PRAGMA foreign_keys = ON")
    _recreate_indexes(conn2)
    conn2.execute("PRAGMA user_version = 3")
    conn2.commit()
    conn2.close()

    # Verify: one row remains, with https preference
    async with get_conn(db_path) as conn3:
        cur = await conn3.execute(
            "SELECT id, host, seen_protocols, primary_scheme, url, http_status FROM assets WHERE program_id='prog1'"
        )
        rows = list(await cur.fetchall())

    assert len(rows) == 1, f"Expected 1 row after V3 dedup, got {len(rows)}"
    row = rows[0]
    protocols = json.loads(row["seen_protocols"])
    assert sorted(protocols) == ["http", "https"], f"Expected both protocols, got {protocols}"
    assert row["primary_scheme"] == "https"
    assert row["url"] == "https://myhost.io"
    # Winner is the https row (scheme DESC wins ties, or higher http_status: 200 > 404)
    assert row["id"] == "id-https", f"Expected https row to win, got id={row['id']}"
    assert row["http_status"] == 200


# ---------------------------------------------------------------------------
# Helper: async iterable mock
# ---------------------------------------------------------------------------

class AsyncMockIter:
    """Async iterator that yields from a list (for patching async generators)."""

    def __init__(self, items: list[str]) -> None:
        self._items = items

    def __aiter__(self) -> "AsyncMockIter":
        self._iter = iter(self._items)
        return self

    async def __anext__(self) -> str:
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


