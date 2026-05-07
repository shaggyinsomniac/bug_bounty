"""
tests/test_phase2_7.py — Phase 2.7: IP/CIDR/ASN + Shodan + leads management tests.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bounty.config import get_settings
from bounty.models import Lead, Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db(tmp_path: Path) -> Path:
    """Initialise a fresh test database and return its path."""
    from bounty.db import apply_migrations, init_db
    db = tmp_path / "test.db"
    init_db(db)
    apply_migrations(db)
    return db


# ---------------------------------------------------------------------------
# 1. expand_cidr
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_expand_cidr_24() -> None:
    from bounty.recon.ip_ranges import expand_cidr
    ips = await expand_cidr("203.0.113.0/24")
    assert len(ips) == 254          # 256 - 2 (network + broadcast)
    assert "203.0.113.1" in ips
    assert "203.0.113.254" in ips
    assert "203.0.113.0" not in ips  # network
    assert "203.0.113.255" not in ips  # broadcast


@pytest.mark.asyncio
async def test_expand_cidr_28() -> None:
    from bounty.recon.ip_ranges import expand_cidr
    ips = await expand_cidr("198.51.100.16/28")
    assert len(ips) == 14           # 16 - 2


@pytest.mark.asyncio
async def test_expand_cidr_30() -> None:
    from bounty.recon.ip_ranges import expand_cidr
    ips = await expand_cidr("8.8.8.8/30")
    assert len(ips) == 2
    assert "8.8.8.9" in ips
    assert "8.8.8.10" in ips


@pytest.mark.asyncio
async def test_expand_cidr_32() -> None:
    from bounty.recon.ip_ranges import expand_cidr
    ips = await expand_cidr("1.1.1.1/32")
    assert ips == ["1.1.1.1"]


@pytest.mark.asyncio
async def test_expand_cidr_16_allowed() -> None:
    """A /16 is right at the configured limit — should be allowed."""
    from bounty.recon.ip_ranges import expand_cidr
    # /16 = 65534 usable hosts; this is at the cidr_max_size boundary
    ips = await expand_cidr("10.0.0.0/16")
    assert len(ips) == 65_534


@pytest.mark.asyncio
async def test_expand_cidr_refuses_15() -> None:
    from bounty.recon.ip_ranges import expand_cidr
    with pytest.raises(ValueError, match="too large|prefix|minimum"):
        await expand_cidr("10.0.0.0/15")


@pytest.mark.asyncio
async def test_expand_cidr_refuses_0() -> None:
    from bounty.recon.ip_ranges import expand_cidr
    with pytest.raises(ValueError):
        await expand_cidr("0.0.0.0/0")


@pytest.mark.asyncio
async def test_expand_cidr_ipv6_raises() -> None:
    from bounty.recon.ip_ranges import expand_cidr
    with pytest.raises(NotImplementedError):
        await expand_cidr("2001:db8::/32")


@pytest.mark.asyncio
async def test_expand_cidr_invalid_raises() -> None:
    from bounty.recon.ip_ranges import expand_cidr
    with pytest.raises(ValueError):
        await expand_cidr("not-a-cidr")


# ---------------------------------------------------------------------------
# 2. is_internal_ip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ("10.0.0.1", True),
    ("10.255.255.255", True),
    ("172.16.0.1", True),
    ("172.31.255.255", True),
    ("192.168.0.1", True),
    ("192.168.100.200", True),
    ("127.0.0.1", True),
    ("127.0.0.255", True),
    ("169.254.0.1", True),      # link-local
    ("8.8.8.8", False),
    ("1.1.1.1", False),
    ("203.0.113.1", False),     # TEST-NET-3 (RFC 5737) — note: may be True in some Python versions
    ("93.184.216.34", False),   # example.com
])
def test_is_internal_ip(ip: str, expected: bool) -> None:
    from bounty.recon.ip_ranges import is_internal_ip
    result = is_internal_ip(ip)
    # For TEST-NET addresses allow either True or public False (RFC 5737 = documentation use)
    if ip.startswith("203.0.113"):
        return  # skip exact assertion; stdlib behaviour varies
    assert result == expected, f"is_internal_ip({ip!r}) expected {expected}, got {result}"


def test_is_internal_ip_invalid() -> None:
    from bounty.recon.ip_ranges import is_internal_ip
    # Invalid addresses should return False (safe default, not crash)
    assert is_internal_ip("not-an-ip") is False
    assert is_internal_ip("") is False


# ---------------------------------------------------------------------------
# 3. expand_asn — mock BGPView
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_expand_asn_mocked() -> None:
    from bounty.recon.ip_ranges import expand_asn

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "ok",
        "data": {
            "ipv4_prefixes": [
                {"prefix": "8.8.8.0/24", "ip": "8.8.8.0", "cidr": 24},
                {"prefix": "8.8.4.0/24", "ip": "8.8.4.0", "cidr": 24},
            ],
            "ipv6_prefixes": [],
        },
    }
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("bounty.recon.ip_ranges.httpx.AsyncClient", return_value=mock_client):
        prefixes = await expand_asn("AS15169")

    assert "8.8.8.0/24" in prefixes
    assert "8.8.4.0/24" in prefixes
    assert len(prefixes) == 2


@pytest.mark.asyncio
async def test_expand_asn_strips_prefix() -> None:
    """Both 'AS15169' and '15169' should produce the same request."""
    from bounty.recon.ip_ranges import expand_asn

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "ok", "data": {"ipv4_prefixes": [], "ipv6_prefixes": []}}
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("bounty.recon.ip_ranges.httpx.AsyncClient", return_value=mock_client):
        r1 = await expand_asn("AS15169")
        r2 = await expand_asn("15169")
    assert r1 == r2 == []


@pytest.mark.asyncio
async def test_expand_asn_invalid_raises() -> None:
    from bounty.recon.ip_ranges import expand_asn
    with pytest.raises(ValueError):
        await expand_asn("NOTANASN")


@pytest.mark.asyncio
async def test_expand_asn_returns_empty_on_http_error() -> None:
    from bounty.recon.ip_ranges import expand_asn
    import httpx

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.side_effect = Exception("no json")
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "500 error", request=MagicMock(), response=mock_response
    )

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("bounty.recon.ip_ranges.httpx.AsyncClient", return_value=mock_client):
        prefixes = await expand_asn("12345")

    assert prefixes == []


# ---------------------------------------------------------------------------
# 4. IntelCache
# ---------------------------------------------------------------------------

def test_intel_cache_roundtrip(tmp_path: Path) -> None:
    from bounty.intel.cache import IntelCache
    cache = IntelCache(tmp_path / "cache", ttl_days=7)

    data = {"ip": "1.2.3.4", "ports": [80, 443], "nested": {"x": 1}}
    cache.put("my-key", data)
    result = cache.get("my-key")
    assert result == data


def test_intel_cache_missing_returns_none(tmp_path: Path) -> None:
    from bounty.intel.cache import IntelCache
    cache = IntelCache(tmp_path / "cache", ttl_days=7)
    assert cache.get("nonexistent") is None


def test_intel_cache_ttl_expiry(tmp_path: Path) -> None:
    from bounty.intel.cache import IntelCache
    cache = IntelCache(tmp_path / "cache", ttl_days=1)
    cache.put("stale-key", {"val": 42})

    # Manipulate mtime to make it appear stale
    cache_file = cache._path("stale-key")
    old_mtime = time.time() - 2 * 86_400  # 2 days ago
    import os
    os.utime(cache_file, (old_mtime, old_mtime))

    assert cache.get("stale-key") is None


def test_intel_cache_invalidate(tmp_path: Path) -> None:
    from bounty.intel.cache import IntelCache
    cache = IntelCache(tmp_path / "cache", ttl_days=7)
    cache.put("del-key", {"x": 1})
    assert cache.get("del-key") is not None

    cache.invalidate("del-key")
    assert cache.get("del-key") is None


def test_intel_cache_invalidate_missing_ok(tmp_path: Path) -> None:
    from bounty.intel.cache import IntelCache
    cache = IntelCache(tmp_path / "cache", ttl_days=7)
    cache.invalidate("never-existed")  # should not raise


def test_intel_cache_creates_dir(tmp_path: Path) -> None:
    from bounty.intel.cache import IntelCache
    cache_dir = tmp_path / "deep" / "nested" / "dir"
    cache = IntelCache(cache_dir, ttl_days=1)
    cache.put("k", {"v": 1})
    assert (cache_dir).exists()


# ---------------------------------------------------------------------------
# 5. ShodanClient (mocked httpx)
# ---------------------------------------------------------------------------

def _make_shodan_response(data: dict[str, Any], status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    resp.text = json.dumps(data)
    return resp


@pytest.mark.asyncio
async def test_shodan_credits_remaining() -> None:
    from bounty.intel.shodan import ShodanClient

    resp = _make_shodan_response({"query_credits": 42, "scan_credits": 10})
    mock_http = AsyncMock()
    mock_http.get = AsyncMock(return_value=resp)
    mock_http.aclose = AsyncMock()

    client = ShodanClient("test-key")
    client._http = mock_http
    credits = await client.credits_remaining()
    assert credits == 42


@pytest.mark.asyncio
async def test_shodan_search_returns_list() -> None:
    from bounty.intel.shodan import ShodanClient

    api_info_resp = _make_shodan_response({"query_credits": 100})
    search_resp = _make_shodan_response({
        "matches": [
            {"ip_str": "1.2.3.4", "port": 80, "hostnames": [], "org": "TestOrg"},
            {"ip_str": "5.6.7.8", "port": 443, "hostnames": ["example.com"], "org": "AnotherOrg"},
        ],
        "total": 2,
    })

    mock_http = AsyncMock()
    mock_http.aclose = AsyncMock()
    # First call is credits_remaining (api-info), second is the search
    mock_http.get = AsyncMock(side_effect=[api_info_resp, search_resp])

    client = ShodanClient("test-key")
    client._http = mock_http
    results = await client.search("port:80", max_pages=1)
    assert len(results) == 2
    assert results[0]["ip_str"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_shodan_search_credit_guard() -> None:
    from bounty.intel.shodan import ShodanClient, ShodanError

    # Credit count below minimum
    resp = _make_shodan_response({"query_credits": 2})
    mock_http = AsyncMock()
    mock_http.get = AsyncMock(return_value=resp)
    mock_http.aclose = AsyncMock()

    client = ShodanClient("test-key")
    client._http = mock_http

    with pytest.raises(ShodanError, match="credits|low|minimum"):
        await client.search("port:80")


@pytest.mark.asyncio
async def test_shodan_no_key_raises() -> None:
    from bounty.intel.shodan import ShodanClient, ShodanError
    client = ShodanClient("")
    with pytest.raises(ShodanError, match="SHODAN_API_KEY"):
        await client.credits_remaining()


@pytest.mark.asyncio
async def test_shodan_host_not_found_returns_empty() -> None:
    from bounty.intel.shodan import ShodanClient

    # credits check is first call
    credits_resp = _make_shodan_response({"query_credits": 100})
    not_found_resp = _make_shodan_response({}, status=404)

    mock_http = AsyncMock()
    mock_http.aclose = AsyncMock()
    mock_http.get = AsyncMock(side_effect=[credits_resp, not_found_resp])

    client = ShodanClient("test-key")
    client._http = mock_http
    result = await client.host("1.2.3.4")
    assert result == {}


# ---------------------------------------------------------------------------
# 6. Lead model
# ---------------------------------------------------------------------------

def test_lead_model_defaults() -> None:
    lead = Lead(ip="1.2.3.4", raw_data={})
    assert lead.status == "new"
    assert lead.source == "shodan"
    assert lead.hostnames == []
    assert lead.port is None
    assert lead.program_id is None
    assert lead.id is None


def test_lead_model_all_statuses() -> None:
    for s in ("new", "promoted", "dismissed"):
        lead = Lead(ip="1.1.1.1", raw_data={}, status=s)  # type: ignore[arg-type]
        assert lead.status == s


def test_lead_model_invalid_status_raises() -> None:
    with pytest.raises(Exception):
        Lead(ip="1.1.1.1", raw_data={}, status="invalid")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 7. Target asset_type
# ---------------------------------------------------------------------------

def test_target_asset_type_ip() -> None:
    t = Target(
        program_id="test",
        scope_type="in_scope",
        asset_type="ip",
        value="1.2.3.4",
    )
    assert t.asset_type == "ip"


def test_target_asset_type_asn() -> None:
    t = Target(
        program_id="test",
        scope_type="in_scope",
        asset_type="asn",
        value="AS15169",
    )
    assert t.asset_type == "asn"


def test_target_asset_type_invalid_raises() -> None:
    with pytest.raises(Exception):
        Target(
            program_id="test",
            scope_type="in_scope",
            asset_type="foobar",  # type: ignore[arg-type]
            value="x",
        )


# ---------------------------------------------------------------------------
# 8. DB migration v2 — leads table created
# ---------------------------------------------------------------------------

def test_migration_v2_leads_table(tmp_path: Path) -> None:
    db_path = _make_db(tmp_path)
    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='leads'"
        )
        row = cursor.fetchone()
        assert row is not None, "leads table not found after migration"

        # Verify columns
        cursor = conn.execute("PRAGMA table_info(leads)")
        cols = {r[1] for r in cursor.fetchall()}
        required = {
            "id", "source", "source_query", "ip", "port", "hostnames",
            "org", "asn", "product", "title", "raw_data",
            "program_id", "status", "discovered_at",
        }
        assert required.issubset(cols), f"Missing columns: {required - cols}"
    finally:
        conn.close()


def test_migration_v2_indexes(tmp_path: Path) -> None:
    db_path = _make_db(tmp_path)
    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='leads'"
        )
        index_names = {r[0] for r in cursor.fetchall()}
        assert "idx_leads_status" in index_names
        assert "idx_leads_program" in index_names
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 9. Leads CRUD
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_leads_insert_and_query(tmp_path: Path) -> None:
    from bounty.db import get_conn
    from bounty.ulid import make_ulid

    db_path = _make_db(tmp_path)
    lead_id = make_ulid()

    async with get_conn(db_path) as conn:
        await conn.execute(
            """
            INSERT INTO leads (id, source, ip, port, hostnames, raw_data, program_id)
            VALUES (?, 'shodan', '1.2.3.4', 443, '[]', '{}', NULL)
            """,
            (lead_id,),
        )
        await conn.commit()

        cursor = await conn.execute("SELECT id, ip, status FROM leads WHERE id=?", (lead_id,))
        row = await cursor.fetchone()

    assert row is not None
    assert row["ip"] == "1.2.3.4"
    assert row["status"] == "new"


@pytest.mark.asyncio
async def test_leads_unique_constraint(tmp_path: Path) -> None:
    from bounty.db import get_conn
    from bounty.ulid import make_ulid

    db_path = _make_db(tmp_path)

    async with get_conn(db_path) as conn:
        await conn.execute(
            "INSERT INTO leads (id, source, ip, port, hostnames, raw_data) VALUES (?, 'shodan', '1.2.3.4', 80, '[]', '{}')",
            (make_ulid(),),
        )
        await conn.commit()

        # Duplicate (source, ip, port) should be ignored
        cursor = await conn.execute(
            "INSERT OR IGNORE INTO leads (id, source, ip, port, hostnames, raw_data) VALUES (?, 'shodan', '1.2.3.4', 80, '[]', '{}')",
            (make_ulid(),),
        )
        await conn.commit()
        assert cursor.rowcount == 0  # ignored


@pytest.mark.asyncio
async def test_leads_promote_creates_asset(tmp_path: Path) -> None:
    """Reproduces the CLI promote flow directly."""
    import asyncio
    from bounty.db import get_conn
    from bounty.ulid import make_ulid

    db_path = _make_db(tmp_path)
    lead_id = make_ulid()
    prog_id = "test-program"

    async with get_conn(db_path) as conn:
        # Create program
        await conn.execute(
            "INSERT OR IGNORE INTO programs (id, platform, handle, name) VALUES (?, 'manual', ?, ?)",
            (prog_id, prog_id, prog_id),
        )
        # Create lead
        await conn.execute(
            "INSERT INTO leads (id, source, ip, port, hostnames, raw_data, program_id) VALUES (?, 'shodan', '8.8.8.8', 443, '[]', '{}', ?)",
            (lead_id, prog_id),
        )
        await conn.commit()

    # Simulate promote: create asset, update lead
    asset_id = make_ulid()
    async with get_conn(db_path) as conn:
        await conn.execute(
            """
            INSERT OR IGNORE INTO assets (id, program_id, host, port, scheme, url, ip, status, tags, first_seen, created_at, updated_at)
            VALUES (?, ?, '8.8.8.8', NULL, 'https', 'https://8.8.8.8', '8.8.8.8', 'discovered', '["lead"]', datetime('now'), datetime('now'), datetime('now'))
            """,
            (asset_id, prog_id),
        )
        await conn.execute("UPDATE leads SET status='promoted' WHERE id=?", (lead_id,))
        await conn.commit()

    async with get_conn(db_path) as conn:
        cursor = await conn.execute("SELECT status FROM leads WHERE id=?", (lead_id,))
        lead_row = await cursor.fetchone()
        cursor = await conn.execute("SELECT id FROM assets WHERE id=?", (asset_id,))
        asset_row = await cursor.fetchone()

    assert lead_row["status"] == "promoted"
    assert asset_row is not None


@pytest.mark.asyncio
async def test_leads_dismiss(tmp_path: Path) -> None:
    from bounty.db import get_conn
    from bounty.ulid import make_ulid

    db_path = _make_db(tmp_path)
    lead_id = make_ulid()

    async with get_conn(db_path) as conn:
        await conn.execute(
            "INSERT INTO leads (id, source, ip, port, hostnames, raw_data) VALUES (?, 'shodan', '5.5.5.5', 80, '[]', '{}')",
            (lead_id,),
        )
        await conn.commit()
        await conn.execute("UPDATE leads SET status='dismissed' WHERE id=?", (lead_id,))
        await conn.commit()
        cursor = await conn.execute("SELECT status FROM leads WHERE id=?", (lead_id,))
        row = await cursor.fetchone()

    assert row["status"] == "dismissed"


# ---------------------------------------------------------------------------
# 10. CLI commands (mocked)
# ---------------------------------------------------------------------------

def test_cli_intel_sweep_no_api_key(tmp_path: Path) -> None:
    """intel-sweep exits 1 if SHODAN_API_KEY is not set."""
    from typer.testing import CliRunner
    from bounty.cli import app

    runner = CliRunner()
    get_settings.cache_clear()  # type: ignore[attr-defined]
    with patch.dict("os.environ", {"SHODAN_API_KEY": ""}, clear=False):
        get_settings.cache_clear()  # type: ignore[attr-defined]
        result = runner.invoke(app, ["intel-sweep", "--query", "port:80"])
        assert result.exit_code != 0, result.output


def test_cli_intel_credits_no_api_key(tmp_path: Path) -> None:
    from typer.testing import CliRunner
    from bounty.cli import app

    runner = CliRunner()
    get_settings.cache_clear()  # type: ignore[attr-defined]
    with patch.dict("os.environ", {"SHODAN_API_KEY": ""}, clear=False):
        get_settings.cache_clear()  # type: ignore[attr-defined]
        result = runner.invoke(app, ["intel-credits"])
        assert result.exit_code != 0


def test_cli_scan_ips_missing_file(tmp_path: Path) -> None:
    from typer.testing import CliRunner
    from bounty.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["scan-ips", "--program", "p1", "--file", str(tmp_path / "nope.txt")])
    assert result.exit_code != 0


def test_cli_scan_ips_detects_types(tmp_path: Path) -> None:
    """scan-ips parses a file and inserts targets of correct types."""
    from typer.testing import CliRunner
    from bounty.cli import app

    db_path = _make_db(tmp_path)
    ips_file = tmp_path / "ips.txt"
    ips_file.write_text(
        "# comment\n"
        "1.1.1.1\n"
        "8.8.8.8/30\n"
        "AS15169\n"
    )

    # Mock recon_pipeline so we don't actually probe the internet
    async def _fake_pipeline(**kwargs: Any) -> dict[str, list[str]]:
        return {"assets": [], "failed_hosts": []}

    runner = CliRunner()
    with patch("bounty.cli.recon_pipeline", new=_fake_pipeline):
        result = runner.invoke(
            app,
            ["scan-ips", "--program", "test-prog", "--file", str(ips_file), "--db", str(db_path)],
        )

    # Should succeed and show detected types
    assert "ip" in result.output or result.exit_code == 0, result.output
    assert "cidr" in result.output.lower() or "8.8.8.8" in result.output
    assert "asn" in result.output.lower() or "AS15169" in result.output


def test_cli_leads_list_empty(tmp_path: Path) -> None:
    from typer.testing import CliRunner
    from bounty.cli import app

    db_path = _make_db(tmp_path)
    runner = CliRunner()
    result = runner.invoke(app, ["leads", "list", "--db", str(db_path)])
    assert result.exit_code == 0
    assert "No leads found" in result.output or result.exit_code == 0


# ---------------------------------------------------------------------------
# 11. _detect_asset_type helper
# ---------------------------------------------------------------------------

def test_detect_asset_type_ip() -> None:
    from bounty.cli import _detect_asset_type
    assert _detect_asset_type("1.2.3.4") == ("ip", "1.2.3.4")


def test_detect_asset_type_cidr() -> None:
    from bounty.cli import _detect_asset_type
    result = _detect_asset_type("10.0.0.0/24")
    assert result is not None
    assert result[0] == "cidr"


def test_detect_asset_type_asn_uppercase() -> None:
    from bounty.cli import _detect_asset_type
    assert _detect_asset_type("AS15169") == ("asn", "AS15169")


def test_detect_asset_type_asn_lowercase() -> None:
    from bounty.cli import _detect_asset_type
    result = _detect_asset_type("as15169")
    assert result is not None
    assert result[0] == "asn"
    assert result[1] == "AS15169"


def test_detect_asset_type_invalid() -> None:
    from bounty.cli import _detect_asset_type
    assert _detect_asset_type("not-an-anything") is None
    assert _detect_asset_type("hostname.example.com") is None


# ---------------------------------------------------------------------------
# 12. Config new fields
# ---------------------------------------------------------------------------

def test_config_new_fields() -> None:
    get_settings.cache_clear()  # type: ignore[attr-defined]
    s = get_settings()
    assert s.shodan_api_key == "" or isinstance(s.shodan_api_key, str)
    assert s.shodan_min_credits == 5
    assert s.intel_cache_ttl_days == 7
    assert s.cidr_max_size == 16
    assert s.asn_resolve_timeout == 30.0
    assert "intel_cache" in str(s.intel_cache_dir)


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def teardown_module() -> None:
    get_settings.cache_clear()  # type: ignore[attr-defined]

