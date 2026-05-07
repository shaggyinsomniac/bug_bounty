"""
tests/test_phase2.py — Phase 2 test suite.

Test categories:
1. ScopeRules / load_scope  — unit tests, no network
2. Target parsers (h1, bugcrowd, intigriti) — mock-based, no network
3. resolve.py  — real DNS against known, stable domains
4. subdomains.py — real test if subfinder installed, skip otherwise
5. recon_pipeline — real mini-pipeline against a small known domain
   (configure TEST_DOMAIN env var; default: httpbin.org)
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bounty.targets.manual import ScopeRules, _pattern_matches, load_scope
from bounty.recon.resolve import ResolveResult, _is_public_ip, resolve_batch
from bounty.recon.subdomains import _parse_line
from bounty.recon.port_scan import _parse_naabu_line, _port_set_to_naabu_arg
from bounty.exceptions import PlatformError, ScopeParseError, ToolMissingError

# ============================================================================
# 1. ScopeRules / load_scope
# ============================================================================

class TestScopeRules:
    """Unit tests for ScopeRules matching logic."""

    def test_exact_match(self) -> None:
        scope = ScopeRules(in_scope=["example.com"], out_of_scope=[])
        assert scope.matches("example.com")
        assert not scope.matches("other.com")
        assert not scope.matches("sub.example.com")

    def test_wildcard_immediate_subdomain(self) -> None:
        scope = ScopeRules(in_scope=["*.example.com"], out_of_scope=[])
        assert scope.matches("sub.example.com")
        assert scope.matches("another.example.com")

    def test_wildcard_deep_subdomain(self) -> None:
        scope = ScopeRules(in_scope=["*.example.com"], out_of_scope=[])
        assert scope.matches("deep.sub.example.com")

    def test_wildcard_does_not_match_root(self) -> None:
        """*.example.com should NOT match bare example.com."""
        scope = ScopeRules(in_scope=["*.example.com"], out_of_scope=[])
        # Per the spec: "*.example.com" matches any subdomain (one or more levels)
        # The root domain itself is NOT matched by the wildcard.
        assert not scope.matches("example.com")

    def test_out_of_scope_takes_precedence(self) -> None:
        scope = ScopeRules(
            in_scope=["*.example.com"],
            out_of_scope=["staging.example.com"],
        )
        assert scope.matches("prod.example.com")
        assert not scope.matches("staging.example.com")

    def test_cidr_match_ipv4(self) -> None:
        scope = ScopeRules(in_scope=["203.0.113.0/24"], out_of_scope=[])
        assert scope.matches("203.0.113.42")
        assert not scope.matches("203.0.114.1")

    def test_cidr_out_of_scope(self) -> None:
        scope = ScopeRules(
            in_scope=["10.0.0.0/8"],
            out_of_scope=["10.1.0.0/16"],
        )
        assert scope.matches("10.0.0.1")
        assert not scope.matches("10.1.5.5")

    def test_case_insensitive(self) -> None:
        scope = ScopeRules(in_scope=["*.Example.COM"], out_of_scope=[])
        assert scope.matches("SUB.EXAMPLE.COM")
        assert scope.matches("sub.example.com")

    def test_url_strip(self) -> None:
        scope = ScopeRules(in_scope=["example.com"], out_of_scope=[])
        assert scope.matches("https://example.com/path?q=1")
        assert scope.matches("http://example.com:8080")

    def test_all_domains(self) -> None:
        scope = ScopeRules(
            in_scope=["*.example.com", "other.org", "10.0.0.0/8"],
            out_of_scope=[],
        )
        domains = scope.all_domains()
        assert "example.com" in domains
        assert "other.org" in domains
        assert "10.0.0.0/8" not in domains  # CIDR excluded

    def test_is_out_of_scope(self) -> None:
        scope = ScopeRules(
            in_scope=["*.example.com"],
            out_of_scope=["admin.example.com"],
        )
        assert scope.is_out_of_scope("admin.example.com")
        assert not scope.is_out_of_scope("app.example.com")


class TestPatternMatches:
    """Unit tests for the _pattern_matches helper."""

    def test_wildcard_matches_multi_level(self) -> None:
        assert _pattern_matches("*.example.com", "a.b.example.com")

    def test_wildcard_no_match_root(self) -> None:
        assert not _pattern_matches("*.example.com", "example.com")

    def test_cidr_ipv4(self) -> None:
        assert _pattern_matches("192.168.0.0/16", "192.168.1.1")
        assert not _pattern_matches("192.168.0.0/16", "10.0.0.1")

    def test_cidr_invalid_host_is_false(self) -> None:
        assert not _pattern_matches("192.168.0.0/16", "notanip")

    def test_exact(self) -> None:
        assert _pattern_matches("foo.com", "foo.com")
        assert not _pattern_matches("foo.com", "bar.com")


class TestLoadScope:
    """Tests for the YAML/JSON scope file loader."""

    def test_load_yaml(self, tmp_path: Path) -> None:
        content = """
in_scope:
  - "*.example.com"
  - "203.0.113.0/24"
out_of_scope:
  - "staging.example.com"
wildcards_resolve: true
"""
        f = tmp_path / "scope.yaml"
        f.write_text(content)
        scope = load_scope(f)
        assert scope.wildcards_resolve is True
        assert "*.example.com" in scope.in_scope
        assert scope.matches("app.example.com")
        assert not scope.matches("staging.example.com")

    def test_load_json(self, tmp_path: Path) -> None:
        data = {
            "in_scope": ["*.test.io"],
            "out_of_scope": [],
        }
        f = tmp_path / "scope.json"
        f.write_text(json.dumps(data))
        scope = load_scope(f)
        assert scope.matches("api.test.io")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text("not: a: valid: yaml: file: [")
        with pytest.raises(ScopeParseError):
            load_scope(f)

    def test_non_dict_top_level(self, tmp_path: Path) -> None:
        f = tmp_path / "list.yaml"
        f.write_text("- item1\n- item2\n")
        with pytest.raises(ScopeParseError):
            load_scope(f)

    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_scope(tmp_path / "nonexistent.yaml")


# ============================================================================
# 2. Platform target parsers — mock-based
# ============================================================================

class TestH1TargetParser:
    """Mock-based tests for h1.fetch_program_scope."""

    @pytest.mark.asyncio
    async def test_fetch_success(self) -> None:
        from bounty.targets.h1 import _parse_response

        fake_data: dict[str, Any] = {
            "in_scope": [
                {"asset_identifier": "*.shopify.com", "asset_type": "WILDCARD"},
                {"asset_identifier": "shopify.com", "asset_type": "URL"},
                {"asset_identifier": "com.shopify.android", "asset_type": "ANDROID_PLAY_STORE_APP_ID"},
            ],
            "out_of_scope": [
                {"asset_identifier": "partners.shopify.com", "asset_type": "URL"},
            ],
        }
        program, targets = _parse_response("shopify", fake_data)
        assert program.id == "h1:shopify"
        assert program.platform == "h1"
        in_scope = [t for t in targets if t.scope_type == "in_scope"]
        out_scope = [t for t in targets if t.scope_type == "out_of_scope"]
        assert len(in_scope) == 3
        assert len(out_scope) == 1
        wildcard_target = next(t for t in in_scope if t.value == "*.shopify.com")
        assert wildcard_target.asset_type == "wildcard"
        android_target = next(t for t in in_scope if "android" in t.value)
        assert android_target.asset_type == "android"

    @pytest.mark.asyncio
    async def test_fetch_404_raises_platform_error(self) -> None:
        from bounty.targets.h1 import fetch_program_scope
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            with pytest.raises(PlatformError) as exc_info:
                await fetch_program_scope("nonexistent-program-xyz")
            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_fetch_success_full_mock(self) -> None:
        from bounty.targets.h1 import fetch_program_scope

        fake_json = {
            "in_scope": [
                {"asset_identifier": "*.example.com", "asset_type": "WILDCARD"},
            ],
            "out_of_scope": [],
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(return_value=fake_json)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_client

            program, targets = await fetch_program_scope("example")
        assert program.platform == "h1"
        assert len(targets) == 1
        assert targets[0].asset_type == "wildcard"


class TestBugcrowdTargetParser:
    """Mock-based tests for bugcrowd.fetch_program_scope."""

    @pytest.mark.asyncio
    async def test_parse_target_groups(self) -> None:
        from bounty.targets.bugcrowd import _parse_target_groups

        groups = [
            {
                "out_of_scope": False,
                "targets": [
                    {"target": "*.tesla.com", "type": "wildcard"},
                    {"target": "https://api.tesla.com", "type": "url"},
                ],
            },
            {
                "out_of_scope": True,
                "targets": [
                    {"target": "dev.tesla.com", "type": "website"},
                ],
            },
        ]
        targets = _parse_target_groups(groups, "bugcrowd:tesla")
        assert len(targets) == 3
        in_scope = [t for t in targets if t.scope_type == "in_scope"]
        out_scope = [t for t in targets if t.scope_type == "out_of_scope"]
        assert len(in_scope) == 2
        assert len(out_scope) == 1


class TestIntigritiTargetParser:
    """Mock-based tests for intigriti target parsing."""

    @pytest.mark.asyncio
    async def test_parse_response(self) -> None:
        from bounty.targets.intigriti import _parse_response

        fake_data: dict[str, Any] = {
            "name": "Test Program",
            "handle": "testprogram",
            "companyHandle": "testco",
            "programHandle": "testprogram",
            "domains": [
                {"endpoint": "*.testco.com", "type": "wildcard"},
                {"endpoint": "api.testco.com", "type": "url"},
            ],
            "outOfScope": [
                {"endpoint": "legacy.testco.com", "type": "url"},
            ],
        }
        program, targets = _parse_response("testco/testprogram", "intigriti:testco:testprogram", fake_data)
        assert program.platform == "intigriti"
        assert program.name == "Test Program"
        in_scope = [t for t in targets if t.scope_type == "in_scope"]
        out_scope = [t for t in targets if t.scope_type == "out_of_scope"]
        assert len(in_scope) == 2
        assert len(out_scope) == 1


# ============================================================================
# 3. targets dispatcher
# ============================================================================

@pytest.mark.asyncio
async def test_fetch_for_platform_unknown_raises() -> None:
    from bounty.targets import fetch_for_platform
    with pytest.raises(ValueError, match="Unknown platform"):
        await fetch_for_platform("unknown_platform", "handle")


# ============================================================================
# 4. DNS resolve
# ============================================================================

class TestResolveHelpers:
    """Unit tests for resolve.py helper functions."""

    def test_is_public_ip_private(self) -> None:
        assert not _is_public_ip("10.0.0.1")
        assert not _is_public_ip("192.168.1.1")
        assert not _is_public_ip("172.16.0.1")
        assert not _is_public_ip("127.0.0.1")
        assert not _is_public_ip("169.254.0.1")

    def test_is_public_ip_public(self) -> None:
        assert _is_public_ip("8.8.8.8")
        assert _is_public_ip("1.1.1.1")
        assert _is_public_ip("104.21.0.0")

    def test_is_public_ip_invalid(self) -> None:
        assert not _is_public_ip("not-an-ip")
        assert not _is_public_ip("")


@pytest.mark.asyncio
async def test_resolve_batch_known_domain() -> None:
    """resolve_batch should return alive=True for one.one.one.one."""
    results = await resolve_batch(["one.one.one.one"], concurrency=5)
    assert "one.one.one.one" in results
    res = results["one.one.one.one"]
    assert res.alive is True
    assert "1.1.1.1" in res.a_records or len(res.a_records) > 0


@pytest.mark.asyncio
async def test_resolve_batch_nonexistent() -> None:
    """resolve_batch returns NXDOMAIN error for non-existent domains."""
    results = await resolve_batch(
        ["this-absolutely-does-not-exist-bounty-test-xyz.invalid"],
        concurrency=5,
    )
    hostname = "this-absolutely-does-not-exist-bounty-test-xyz.invalid"
    assert hostname in results
    res = results[hostname]
    assert res.alive is False
    assert res.error is not None


@pytest.mark.asyncio
async def test_resolve_batch_empty() -> None:
    """resolve_batch with empty input returns empty dict."""
    results = await resolve_batch([], concurrency=5)
    assert results == {}


# ============================================================================
# 5. Subdomain enumeration helpers (no live network)
# ============================================================================

class TestSubfinderLineParser:
    """Unit tests for the subfinder JSONL line parser."""

    def test_parse_json_line(self) -> None:
        line = '{"host": "sub.example.com", "input": "example.com", "source": "crtsh"}'
        result = _parse_line(line)
        assert result == "sub.example.com"

    def test_parse_bare_hostname(self) -> None:
        result = _parse_line("api.example.com")
        assert result == "api.example.com"

    def test_parse_strips_trailing_dot(self) -> None:
        result = _parse_line("api.example.com.")
        assert result == "api.example.com"

    def test_parse_empty_line(self) -> None:
        assert _parse_line("") is None
        assert _parse_line("   ") is None

    def test_parse_invalid_json_falls_back(self) -> None:
        result = _parse_line("{broken json")
        # Should fall back to treating as bare text — but "{broken" has no dot
        assert result is None

    def test_parse_lowercase(self) -> None:
        result = _parse_line("API.Example.COM")
        assert result == "api.example.com"


@pytest.mark.asyncio
async def test_subfinder_not_installed_raises_tool_missing() -> None:
    """enumerate() must raise ToolMissingError if subfinder is not on PATH."""
    import shutil
    # Temporarily hide subfinder from PATH by patching shutil.which
    with patch("bounty.recon.subdomains.shutil.which", return_value=None):
        with patch("bounty.recon.subdomains.get_settings") as mock_settings:
            mock_cfg = MagicMock()
            mock_cfg.tools_dir = Path("/nonexistent/tools")
            mock_settings.return_value = mock_cfg

            from bounty.recon.subdomains import enumerate as sub_enum
            with pytest.raises(ToolMissingError):
                async for _ in sub_enum("example.com"):
                    pass


@pytest.mark.asyncio
async def test_subfinder_live() -> None:
    """Real subfinder run — skipped if subfinder is not installed."""
    import shutil
    if not shutil.which("subfinder"):
        pytest.skip("subfinder not installed")

    # Run a gentle passive scan against a well-known domain; expect at least
    # one result within the tool's timeout.
    domain = os.environ.get("TEST_DOMAIN", "cloudflare.com")
    found: list[str] = []
    from bounty.recon.subdomains import enumerate as sub_enum
    from bounty.exceptions import ToolFailedError
    try:
        async for hostname in sub_enum(domain, intensity="gentle"):
            found.append(hostname)
            if len(found) >= 3:
                break  # Don't wait for completion, just verify it works
    except ToolFailedError as exc:
        # Exit code 2 = no API keys configured; skip rather than fail.
        if exc.returncode == 2:
            pytest.skip("subfinder passive mode requires API keys (exit 2)")
        raise

    if not found:
        pytest.skip(
            "subfinder returned no results in passive mode "
            "(API keys may be required for this domain)"
        )
    assert len(found) >= 1, f"Expected >=1 subdomains for {domain}, got 0"


# ============================================================================
# 6. Port scan helpers (no live network)
# ============================================================================

class TestNaabuLineParser:
    """Unit tests for the naabu JSONL line parser."""

    def test_parse_json_line(self) -> None:
        line = '{"ip": "1.2.3.4", "port": 443, "protocol": "tcp"}'
        result = _parse_naabu_line(line, "1.2.3.4")
        assert result is not None
        assert result.port == 443
        assert result.service_guess == "https"

    def test_parse_colon_format(self) -> None:
        result = _parse_naabu_line("1.2.3.4:80", "1.2.3.4")
        assert result is not None
        assert result.port == 80

    def test_parse_empty(self) -> None:
        assert _parse_naabu_line("", "1.2.3.4") is None

    def test_port_set_args(self) -> None:
        assert _port_set_to_naabu_arg("top100") == "top-100"
        assert _port_set_to_naabu_arg("top1000") == "top-1000"
        assert "80" in _port_set_to_naabu_arg("web")
        assert "6379" in _port_set_to_naabu_arg("admin")
        # Custom pass-through
        assert _port_set_to_naabu_arg("22,80,443") == "22,80,443"


# ============================================================================
# 7. Mini recon pipeline (real network, small domain)
# ============================================================================

@pytest.mark.asyncio
async def test_recon_pipeline_mini() -> None:
    """Run the recon pipeline against a single known domain and verify DB state.

    Uses TEST_DOMAIN env var (default: httpbin.org).
    Skips subfinder/naabu steps gracefully if tools are missing.

    This test is the guard against the silent-persistence bug: it queries the
    DB directly after the pipeline completes and asserts that actual rows were
    written — not just that the in-memory return value looks non-empty.
    """
    from bounty.db import init_db, apply_migrations
    from bounty.models import Target
    from bounty.recon import recon_pipeline
    from bounty.ulid import make_ulid

    test_domain = os.environ.get("TEST_DOMAIN", "httpbin.org")

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        init_db(db_path)
        apply_migrations(db_path)

        # Insert a placeholder program
        from bounty.db import get_conn
        async with get_conn(db_path) as conn:
            await conn.execute(
                "INSERT INTO programs (id, platform, handle, name) VALUES (?,?,?,?)",
                ("test:pipeline", "manual", "pipeline", "Pipeline Test"),
            )
            await conn.commit()

        scan_id = make_ulid()

        targets = [
            Target(
                program_id="test:pipeline",
                scope_type="in_scope",
                asset_type="url",
                value=test_domain,
            )
        ]

        result = await recon_pipeline(
            "test:pipeline",
            targets,
            intensity="gentle",
            db_path=db_path,
            scan_id=scan_id,
        )

        # ── Assert return value ───────────────────────────────────────────────
        assert isinstance(result["assets"], list), "assets key must be a list"
        assert len(result["assets"]) >= 1, (
            f"Expected >=1 assets in return value for {test_domain}, got 0"
        )

        # ── Assert DB state (this is the critical check) ──────────────────────
        from bounty.db import get_conn
        async with get_conn(db_path) as conn:
            # 1. Assets table must have rows
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM assets WHERE program_id='test:pipeline'"
            )
            asset_count = (await cursor.fetchone())[0]
            assert asset_count >= 1, (
                f"Expected >=1 assets in DB for test:pipeline, got {asset_count}. "
                "Silent persistence bug detected — check asset_upsert_failed logs."
            )

            # 2. Scan row must exist with status='completed'
            cursor = await conn.execute(
                "SELECT status, finished_at FROM scans WHERE id=?",
                (scan_id,),
            )
            scan_row = await cursor.fetchone()
            assert scan_row is not None, (
                f"Scan row not found in DB for id={scan_id}. "
                "Pipeline must create the scan row before writing phases."
            )
            assert scan_row["status"] == "completed", (
                f"Expected scan status='completed', got '{scan_row['status']}'. "
                f"Check pipeline error handling."
            )
            assert scan_row["finished_at"] is not None, (
                "scan.finished_at must be set when pipeline completes"
            )

            # 3. scan_phases rows must exist with status='completed'
            cursor = await conn.execute(
                "SELECT phase, status FROM scan_phases WHERE scan_id=?",
                (scan_id,),
            )
            phase_rows = await cursor.fetchall()
            assert len(phase_rows) >= 1, (
                f"Expected >=1 scan_phases rows for scan_id={scan_id}, got 0. "
                "FK violation likely — scan row must be created before phase writes."
            )
            phases_map = {row["phase"]: row["status"] for row in phase_rows}
            # At minimum http_probe phase should be completed
            assert "http_probe" in phases_map, (
                f"http_probe phase not found; got phases: {list(phases_map.keys())}"
            )
            assert phases_map["http_probe"] == "completed", (
                f"http_probe phase status={phases_map['http_probe']}, expected 'completed'"
            )

            # 4. Asset IDs in return value must match what's in the DB
            cursor = await conn.execute(
                "SELECT id FROM assets WHERE program_id='test:pipeline'"
            )
            db_id_rows = await cursor.fetchall()
            db_ids = {row["id"] for row in db_id_rows}
            for aid in result["assets"]:
                assert aid in db_ids, (
                    f"Asset ID {aid!r} from pipeline return value not found in DB. "
                    "Upsert must commit before returning."
                )


