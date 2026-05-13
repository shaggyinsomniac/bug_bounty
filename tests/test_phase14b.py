"""
tests/test_phase14b.py — Phase 14b: Nuclei vulnerability scanner integration tests.

Tests cover:
- applicable_to gating logic (bare IP with no fingerprint → False, hostname → True)
- _build_tags_from_fingerprints (known tech → tags, unknown → fallback)
- _parse_nuclei_line (valid JSON, missing fields, empty, invalid JSON)
- NucleiRunner subprocess args built correctly
- NucleiRunner.scan — binary not found → empty list + warning
- NucleiRunner.scan — subprocess mock returns JSON → parsed findings
- Blocked-tag filtering (dos templates excluded)
- Severity mapping (info→200, critical→950, etc.)
- NucleiCveCheck.run — yields FindingDraft with source='nuclei'
- NucleiCveCheck.run — nuclei_enabled=False → yields nothing
- CVE/CWE extraction from classification block
- Finding.source defaults to 'native'
- FindingDraft.source='nuclei' propagated to DB
- DB migration v10 adds source column to findings
- NucleiCveCheck.id and .category constants
- Timeout: subprocess timeout → returns empty list
- Fingerprint prefix matching (wordpress-5.8 → wordpress tag)
- Config defaults: nuclei_enabled, nuclei_severities, etc.
- nuclei_install_hint() returns useful string
- get_nuclei_path() resolution order
- CLI tools commands registered correctly
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    """Create a fresh fully-migrated DB in a temp directory."""
    from bounty.db import apply_migrations, init_db

    db_path = tmp_path / "test.db"
    init_db(db_path)
    apply_migrations(db_path)
    return db_path


@pytest.fixture()
def mock_asset_hostname() -> MagicMock:
    """Fake Asset object with a hostname."""
    a = MagicMock()
    a.id = "ASSET01"
    a.program_id = "prog:test"
    a.host = "example.com"
    a.port = 443
    a.primary_scheme = "https"
    a.url = "https://example.com"
    return a


@pytest.fixture()
def mock_asset_bare_ip() -> MagicMock:
    """Fake Asset object that is a bare IPv4 address."""
    a = MagicMock()
    a.id = "ASSET02"
    a.program_id = "prog:test"
    a.host = "192.168.1.1"
    a.port = 80
    a.primary_scheme = "http"
    a.url = "http://192.168.1.1"
    return a


@pytest.fixture()
def fp_wordpress() -> MagicMock:
    """WordPress fingerprint with version."""
    fp = MagicMock()
    fp.tech = "WordPress"
    fp.version = "5.8"
    fp.category = "cms"
    return fp


@pytest.fixture()
def fp_no_version() -> MagicMock:
    """Generic CMS fingerprint without a version."""
    fp = MagicMock()
    fp.tech = "Django"
    fp.version = None
    fp.category = "framework"
    return fp


@pytest.fixture()
def fp_unknown_tech() -> MagicMock:
    """Fingerprint for a tech not in the tag map."""
    fp = MagicMock()
    fp.tech = "UnknownFramework9000"
    fp.version = "1.0"
    fp.category = "other"
    return fp


@pytest.fixture()
def nuclei_json_wordpress() -> str:
    """Minimal Nuclei JSON line for a WordPress detection."""
    return json.dumps({
        "template-id": "wordpress-version",
        "info": {
            "name": "WordPress Version Detection",
            "severity": "info",
            "tags": "wordpress,cms",
            "description": "WordPress version detected via meta generator tag.",
            "remediation": "",
            "classification": {},
        },
        "matched-at": "https://example.com",
        "extracted-results": ["5.8"],
        "curl-command": "curl -s https://example.com",
    })


@pytest.fixture()
def nuclei_json_cve() -> str:
    """Nuclei JSON line for a critical CVE."""
    return json.dumps({
        "template-id": "CVE-2021-44228",
        "info": {
            "name": "Log4Shell RCE",
            "severity": "critical",
            "tags": "log4j,cve,rce",
            "description": "Remote code execution via Log4j.",
            "remediation": "Upgrade to Log4j 2.15.0+.",
            "classification": {
                "cve-id": "CVE-2021-44228",
                "cwe-id": "CWE-502",
            },
        },
        "matched-at": "https://example.com/login",
        "extracted-results": [],
        "curl-command": "",
    })


@pytest.fixture()
def nuclei_json_dos() -> str:
    """Nuclei JSON line for a DoS template (should be filtered)."""
    return json.dumps({
        "template-id": "some-dos-template",
        "info": {
            "name": "Some DoS Check",
            "severity": "medium",
            "tags": "dos,network",
            "description": "",
        },
        "matched-at": "https://example.com",
    })


@pytest.fixture()
def mock_detection_ctx(mock_asset_hostname: MagicMock) -> MagicMock:
    """Minimal DetectionContext mock."""
    ctx = MagicMock()
    ctx.scan_id = "SCAN001"
    ctx.fingerprints = []
    ctx.log = MagicMock()
    ctx.log.warning = MagicMock()
    return ctx


# ---------------------------------------------------------------------------
# 1. applicable_to — bare IP with no fingerprints → False
# ---------------------------------------------------------------------------


def test_applicable_to_bare_ip_no_fingerprints(mock_asset_bare_ip: MagicMock) -> None:
    from bounty.detect.nuclei_detection import NucleiCveCheck

    check = NucleiCveCheck()
    assert check.applicable_to(mock_asset_bare_ip, []) is False


# ---------------------------------------------------------------------------
# 2. applicable_to — hostname with no fingerprints → True
# ---------------------------------------------------------------------------


def test_applicable_to_hostname_no_fingerprints(mock_asset_hostname: MagicMock) -> None:
    from bounty.detect.nuclei_detection import NucleiCveCheck

    check = NucleiCveCheck()
    assert check.applicable_to(mock_asset_hostname, []) is True


# ---------------------------------------------------------------------------
# 3. applicable_to — asset with version-bearing fingerprint → True (even for IP)
# ---------------------------------------------------------------------------


def test_applicable_to_ip_with_fingerprint(
    mock_asset_bare_ip: MagicMock,
    fp_wordpress: MagicMock,
) -> None:
    from bounty.detect.nuclei_detection import NucleiCveCheck

    check = NucleiCveCheck()
    assert check.applicable_to(mock_asset_bare_ip, [fp_wordpress]) is True


# ---------------------------------------------------------------------------
# 4. applicable_to — asset with category fingerprint → True
# ---------------------------------------------------------------------------


def test_applicable_to_with_category_fingerprint(
    mock_asset_hostname: MagicMock,
    fp_no_version: MagicMock,
) -> None:
    from bounty.detect.nuclei_detection import NucleiCveCheck

    check = NucleiCveCheck()
    assert check.applicable_to(mock_asset_hostname, [fp_no_version]) is True


# ---------------------------------------------------------------------------
# 5. _build_tags_from_fingerprints — wordpress → ["wordpress"]
# ---------------------------------------------------------------------------


def test_build_tags_wordpress(fp_wordpress: MagicMock) -> None:
    from bounty.detect.nuclei_runner import _build_tags_from_fingerprints

    tags = _build_tags_from_fingerprints([fp_wordpress])
    assert "wordpress" in tags


# ---------------------------------------------------------------------------
# 6. _build_tags_from_fingerprints — unknown tech → fallback tags
# ---------------------------------------------------------------------------


def test_build_tags_unknown_falls_back(fp_unknown_tech: MagicMock) -> None:
    from bounty.detect.nuclei_runner import _build_tags_from_fingerprints, _FALLBACK_TAGS

    tags = _build_tags_from_fingerprints([fp_unknown_tech])
    assert tags == sorted(_FALLBACK_TAGS)


# ---------------------------------------------------------------------------
# 7. _build_tags_from_fingerprints — empty list → fallback
# ---------------------------------------------------------------------------


def test_build_tags_empty_fingerprints() -> None:
    from bounty.detect.nuclei_runner import _build_tags_from_fingerprints, _FALLBACK_TAGS

    tags = _build_tags_from_fingerprints([])
    assert tags == sorted(_FALLBACK_TAGS)


# ---------------------------------------------------------------------------
# 8. _build_tags — prefix match (wordpress-5.8 → wordpress)
# ---------------------------------------------------------------------------


def test_build_tags_prefix_match() -> None:
    from bounty.detect.nuclei_runner import _build_tags_from_fingerprints

    fp = MagicMock()
    fp.tech = "wordpress-5.8"
    fp.version = "5.8"
    tags = _build_tags_from_fingerprints([fp])
    assert "wordpress" in tags


# ---------------------------------------------------------------------------
# 9. _parse_nuclei_line — valid JSON → NucleiFinding
# ---------------------------------------------------------------------------


def test_parse_nuclei_line_valid(nuclei_json_wordpress: str) -> None:
    from bounty.detect.nuclei_runner import _parse_nuclei_line

    result = _parse_nuclei_line(nuclei_json_wordpress)
    assert result is not None
    assert result.template_id == "wordpress-version"
    assert result.name == "WordPress Version Detection"
    assert result.severity == "info"
    assert result.matched_at == "https://example.com"
    assert "5.8" in result.extracted_results
    assert "wordpress" in result.tags
    assert "cms" in result.tags


# ---------------------------------------------------------------------------
# 10. _parse_nuclei_line — invalid JSON → None
# ---------------------------------------------------------------------------


def test_parse_nuclei_line_invalid_json() -> None:
    from bounty.detect.nuclei_runner import _parse_nuclei_line

    assert _parse_nuclei_line("not valid json {{{") is None


# ---------------------------------------------------------------------------
# 11. _parse_nuclei_line — empty string → None
# ---------------------------------------------------------------------------


def test_parse_nuclei_line_empty() -> None:
    from bounty.detect.nuclei_runner import _parse_nuclei_line

    assert _parse_nuclei_line("") is None
    assert _parse_nuclei_line("   ") is None


# ---------------------------------------------------------------------------
# 12. _parse_nuclei_line — missing template-id → None
# ---------------------------------------------------------------------------


def test_parse_nuclei_line_no_template_id() -> None:
    from bounty.detect.nuclei_runner import _parse_nuclei_line

    line = json.dumps({"info": {"name": "Test"}, "matched-at": "https://example.com"})
    assert _parse_nuclei_line(line) is None


# ---------------------------------------------------------------------------
# 13. Severity mapping
# ---------------------------------------------------------------------------


def test_severity_map_values() -> None:
    from bounty.detect.nuclei_detection import _SEVERITY_MAP

    assert _SEVERITY_MAP["info"] == 200
    assert _SEVERITY_MAP["low"] == 400
    assert _SEVERITY_MAP["medium"] == 600
    assert _SEVERITY_MAP["high"] == 800
    assert _SEVERITY_MAP["critical"] == 950


# ---------------------------------------------------------------------------
# 14. Blocked tag filtering — dos template excluded
# ---------------------------------------------------------------------------


def test_blocked_tag_dos_filtered(
    nuclei_json_dos: str,
    mock_asset_hostname: MagicMock,
) -> None:
    from bounty.detect.nuclei_runner import _parse_nuclei_line, _BLOCKED_TAGS

    finding = _parse_nuclei_line(nuclei_json_dos)
    assert finding is not None
    blocked = _BLOCKED_TAGS.intersection(finding.tags)
    assert "dos" in blocked


# ---------------------------------------------------------------------------
# 15. NucleiRunner.scan — binary not found → returns [], logs warning
# ---------------------------------------------------------------------------


def test_nuclei_runner_binary_not_found(
    mock_asset_hostname: MagicMock,
) -> None:
    from bounty.detect.nuclei_runner import NucleiRunner

    runner = NucleiRunner(binary_path=Path("/nonexistent/nuclei"))

    async def _run() -> list[Any]:
        return await runner.scan(mock_asset_hostname, [])

    results = asyncio.run(_run())
    assert results == []


# ---------------------------------------------------------------------------
# 16. NucleiRunner.scan — subprocess mock returns JSON → parsed
# ---------------------------------------------------------------------------


def test_nuclei_runner_scan_parses_json(
    mock_asset_hostname: MagicMock,
    nuclei_json_wordpress: str,
    tmp_path: Path,
) -> None:
    from bounty.detect.nuclei_runner import NucleiRunner

    # Create a real (but empty) file so Path.exists() returns True
    fake_binary = tmp_path / "nuclei"
    fake_binary.write_bytes(b"")

    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(
        return_value=(nuclei_json_wordpress.encode(), b"")
    )

    async def _run() -> list[Any]:
        runner = NucleiRunner(binary_path=fake_binary)
        with patch("bounty.detect.nuclei_runner.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            return await runner.scan(mock_asset_hostname, [])

    results = asyncio.run(_run())
    assert len(results) == 1
    assert results[0].template_id == "wordpress-version"


# ---------------------------------------------------------------------------
# 17. NucleiRunner._build_command — correct args
# ---------------------------------------------------------------------------


def test_nuclei_runner_build_command() -> None:
    from bounty.detect.nuclei_runner import NucleiRunner

    runner = NucleiRunner(rate_limit=25)
    cmd = runner._build_command(
        Path("/usr/bin/nuclei"),
        "https://example.com",
        ["wordpress"],
        ["medium", "high"],
    )
    assert cmd[0] == "/usr/bin/nuclei"
    assert "-target" in cmd
    assert "https://example.com" in cmd
    assert "-json" in cmd
    assert "-silent" in cmd
    assert "-severity" in cmd
    assert "medium,high" in cmd
    assert "-tags" in cmd
    assert "wordpress" in cmd
    assert "-rate-limit" in cmd
    assert "25" in cmd
    assert "-no-update-check" in cmd


# ---------------------------------------------------------------------------
# 18. NucleiCveCheck.run — nuclei_enabled=False → yields nothing
# ---------------------------------------------------------------------------


def test_nuclei_check_disabled(
    mock_asset_hostname: MagicMock,
    mock_detection_ctx: MagicMock,
) -> None:
    from bounty.detect.nuclei_detection import NucleiCveCheck
    from bounty.config import get_settings

    check = NucleiCveCheck()

    async def _run() -> list[Any]:
        drafts = []
        with patch("bounty.detect.nuclei_detection.get_settings") as mock_settings:
            s = MagicMock()
            s.nuclei_enabled = False
            mock_settings.return_value = s
            async for draft in check.run(mock_asset_hostname, mock_detection_ctx):
                drafts.append(draft)
        return drafts

    results = asyncio.run(_run())
    assert results == []


# ---------------------------------------------------------------------------
# 19. NucleiCveCheck.run — mock runner returns finding → yields FindingDraft
# ---------------------------------------------------------------------------


def test_nuclei_check_run_yields_draft(
    mock_asset_hostname: MagicMock,
    mock_detection_ctx: MagicMock,
    nuclei_json_wordpress: str,
) -> None:
    from bounty.detect.nuclei_detection import NucleiCveCheck
    from bounty.detect.nuclei_runner import _parse_nuclei_line

    check = NucleiCveCheck()
    nf = _parse_nuclei_line(nuclei_json_wordpress)
    assert nf is not None

    async def _run() -> list[Any]:
        drafts = []
        with patch("bounty.detect.nuclei_detection.get_settings") as mock_gs:
            s = MagicMock()
            s.nuclei_enabled = True
            s.nuclei_timeout_seconds = 30
            s.nuclei_rate_limit = 50
            s.nuclei_severities = ["medium", "high", "critical"]
            mock_gs.return_value = s
            with patch("bounty.detect.nuclei_detection.NucleiRunner") as MockRunner:
                inst = MagicMock()
                inst.scan = AsyncMock(return_value=[nf])
                MockRunner.return_value = inst
                async for draft in check.run(mock_asset_hostname, mock_detection_ctx):
                    drafts.append(draft)
        return drafts

    results = asyncio.run(_run())
    assert len(results) == 1
    draft = results[0]
    assert draft.source == "nuclei"
    assert "[Nuclei]" in draft.title
    assert "nuclei" in draft.tags
    assert "nuclei-template:wordpress-version" in draft.tags


# ---------------------------------------------------------------------------
# 20. FindingDraft source='nuclei' field
# ---------------------------------------------------------------------------


def test_finding_draft_source_nuclei() -> None:
    from bounty.models import FindingDraft

    draft = FindingDraft(
        dedup_key="nuclei.cve-123:ASSET01:https://example.com",
        title="[Nuclei] Test",
        category="nuclei.CVE-2021-123",
        severity=800,
        url="https://example.com",
        source="nuclei",
    )
    assert draft.source == "nuclei"


# ---------------------------------------------------------------------------
# 21. Finding.source defaults to 'native'
# ---------------------------------------------------------------------------


def test_finding_source_default_native() -> None:
    from bounty.models import Finding

    f = Finding(
        dedup_key="test:dedup",
        title="Test",
        category="test",
        url="http://example.com",
    )
    assert f.source == "native"


# ---------------------------------------------------------------------------
# 22. DB migration v10 adds source column to findings
# ---------------------------------------------------------------------------


def test_migration_v10_source_column(tmp_db: Path) -> None:
    conn = sqlite3.connect(str(tmp_db))
    try:
        cur = conn.execute("PRAGMA table_info(findings)")
        columns = {row[1] for row in cur.fetchall()}
        assert "source" in columns, "source column should exist after migration v10"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 23. NucleiCveCheck.id constant
# ---------------------------------------------------------------------------


def test_nuclei_check_id() -> None:
    from bounty.detect.nuclei_detection import NucleiCveCheck

    assert NucleiCveCheck.id == "nuclei.cve_check"


# ---------------------------------------------------------------------------
# 24. NucleiCveCheck.category constant
# ---------------------------------------------------------------------------


def test_nuclei_check_category() -> None:
    from bounty.detect.nuclei_detection import NucleiCveCheck

    assert NucleiCveCheck.category == "nuclei_cve"


# ---------------------------------------------------------------------------
# 25. Timeout: subprocess timeout → returns empty list
# ---------------------------------------------------------------------------


def test_nuclei_runner_timeout(mock_asset_hostname: MagicMock, tmp_path: Path) -> None:
    from bounty.detect.nuclei_runner import NucleiRunner

    fake_binary = tmp_path / "nuclei"
    fake_binary.write_bytes(b"")
    runner = NucleiRunner(binary_path=fake_binary, timeout=1)

    async def _fake_communicate() -> tuple[bytes, bytes]:
        await asyncio.sleep(10)
        return b"", b""

    mock_proc = AsyncMock()
    mock_proc.communicate = _fake_communicate
    mock_proc.kill = MagicMock()

    async def _run() -> list[Any]:
        with patch("bounty.detect.nuclei_runner.asyncio.create_subprocess_exec",
                   return_value=mock_proc):
            return await runner.scan(mock_asset_hostname, [], severities=("critical",))

    results = asyncio.run(_run())
    assert results == []


# ---------------------------------------------------------------------------
# 26. CVE extraction from classification block
# ---------------------------------------------------------------------------


def test_cve_extraction_from_json(nuclei_json_cve: str) -> None:
    from bounty.detect.nuclei_runner import _parse_nuclei_line

    nf = _parse_nuclei_line(nuclei_json_cve)
    assert nf is not None
    classification = nf.info_dict.get("classification") or {}
    assert classification.get("cve-id") == "CVE-2021-44228"
    assert classification.get("cwe-id") == "CWE-502"


# ---------------------------------------------------------------------------
# 27. CVE/CWE propagated to FindingDraft
# ---------------------------------------------------------------------------


def test_nuclei_check_cve_propagated(
    mock_asset_hostname: MagicMock,
    mock_detection_ctx: MagicMock,
    nuclei_json_cve: str,
) -> None:
    from bounty.detect.nuclei_detection import NucleiCveCheck
    from bounty.detect.nuclei_runner import _parse_nuclei_line

    check = NucleiCveCheck()
    nf = _parse_nuclei_line(nuclei_json_cve)
    assert nf is not None

    async def _run() -> list[Any]:
        drafts = []
        with patch("bounty.detect.nuclei_detection.get_settings") as mock_gs:
            s = MagicMock()
            s.nuclei_enabled = True
            s.nuclei_timeout_seconds = 30
            s.nuclei_rate_limit = 50
            s.nuclei_severities = ["medium", "high", "critical"]
            mock_gs.return_value = s
            with patch("bounty.detect.nuclei_detection.NucleiRunner") as MockRunner:
                inst = MagicMock()
                inst.scan = AsyncMock(return_value=[nf])
                MockRunner.return_value = inst
                async for draft in check.run(mock_asset_hostname, mock_detection_ctx):
                    drafts.append(draft)
        return drafts

    results = asyncio.run(_run())
    assert len(results) == 1
    draft = results[0]
    assert draft.cve == "CVE-2021-44228"
    assert draft.cwe == "CWE-502"
    assert draft.severity == 950  # critical
    assert "nuclei.CVE-2021-44228" in draft.category


# ---------------------------------------------------------------------------
# 28. Config defaults
# ---------------------------------------------------------------------------


def test_config_defaults() -> None:
    from bounty.config import Settings

    s = Settings()
    assert s.nuclei_enabled is True
    assert "medium" in s.nuclei_severities
    assert "high" in s.nuclei_severities
    assert "critical" in s.nuclei_severities
    assert s.nuclei_timeout_seconds == 300
    assert s.nuclei_rate_limit == 50
    assert s.nuclei_total_time_budget == 1800


# ---------------------------------------------------------------------------
# 29. nuclei_install_hint returns useful string
# ---------------------------------------------------------------------------


def test_nuclei_install_hint() -> None:
    from bounty.tools import nuclei_install_hint

    hint = nuclei_install_hint()
    assert "nuclei" in hint.lower()
    assert "install" in hint.lower()


# ---------------------------------------------------------------------------
# 30. get_nuclei_path() with missing binary returns None
# ---------------------------------------------------------------------------


def test_get_nuclei_path_missing() -> None:
    from bounty.tools import get_nuclei_path
    import bounty.tools as _bt

    with patch("shutil.which", return_value=None), \
         patch.object(_bt, "_DEFAULT_NUCLEI_PATH", Path("/nonexistent/default_nuclei")):
        result = get_nuclei_path(Path("/nonexistent/nuclei"))
    assert result is None


# ---------------------------------------------------------------------------
# 31. CLI commands registered
# ---------------------------------------------------------------------------


def test_cli_install_nuclei_registered() -> None:
    from bounty.cli import tools_app

    command_names = [cmd.name for cmd in tools_app.registered_commands]
    assert "install-nuclei" in command_names


def test_cli_update_nuclei_templates_registered() -> None:
    from bounty.cli import tools_app

    command_names = [cmd.name for cmd in tools_app.registered_commands]
    assert "update-nuclei-templates" in command_names


def test_cli_nuclei_status_registered() -> None:
    from bounty.cli import nuclei_app

    command_names = [cmd.name for cmd in nuclei_app.registered_commands]
    assert "status" in command_names


# ---------------------------------------------------------------------------
# 32. NucleiCveCheck is in REGISTERED_DETECTIONS
# ---------------------------------------------------------------------------


def test_nuclei_check_in_registry() -> None:
    from bounty.detect import REGISTERED_DETECTIONS
    from bounty.detect.nuclei_detection import NucleiCveCheck

    types = [type(d) for d in REGISTERED_DETECTIONS]
    assert NucleiCveCheck in types


# ---------------------------------------------------------------------------
# 33. FindingDraft with source='nuclei' stored in DB via _persist_finding
# ---------------------------------------------------------------------------


def test_persist_finding_source_nuclei(tmp_db: Path) -> None:
    from bounty.detect.runner import _persist_finding
    from bounty.models import FindingDraft

    draft = FindingDraft(
        program_id=None,
        asset_id=None,
        scan_id=None,
        dedup_key="nuclei.test:ASSET01:https://example.com",
        title="[Nuclei] Test CVE",
        category="nuclei.CVE-2021-123",
        severity=800,
        url="https://example.com",
        source="nuclei",
    )

    async def _run() -> str:
        from bounty.db import get_conn
        async with get_conn(tmp_db) as conn:
            finding = await _persist_finding(draft, conn)
            return finding.source

    source = asyncio.run(_run())
    assert source == "nuclei"


# ---------------------------------------------------------------------------
# 34. _build_target_url fallback: no url attr, uses host/port/scheme
# ---------------------------------------------------------------------------


def test_nuclei_runner_build_target_url_from_parts() -> None:
    from bounty.detect.nuclei_runner import NucleiRunner

    runner = NucleiRunner()
    asset = MagicMock()
    asset.url = None
    asset.host = "example.com"
    asset.port = 8080
    asset.primary_scheme = "https"

    url = runner._build_target_url(asset)
    assert url == "https://example.com:8080"


# ---------------------------------------------------------------------------
# 35. _build_target_url: default port omitted
# ---------------------------------------------------------------------------


def test_nuclei_runner_build_target_url_default_port() -> None:
    from bounty.detect.nuclei_runner import NucleiRunner

    runner = NucleiRunner()
    asset = MagicMock()
    asset.url = None
    asset.host = "example.com"
    asset.port = 443
    asset.primary_scheme = "https"

    url = runner._build_target_url(asset)
    assert url == "https://example.com"












