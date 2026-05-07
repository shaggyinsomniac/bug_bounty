"""
tests/test_phase4.py — Phase 4 (Detection Engine) test suite.

Test sections:
1.  is_real_file_response — 10 cases
2.  soft_404_check — 3 cases
3.  ExposedGitDirectory — 3 cases (positive, negative, confirm-only)
4.  ExposedGitCredentials — 2 cases
5.  ExposedSvnDirectory — 2 cases
6.  ExposedEnvFile — 4 cases (severity scaling)
7.  ExposedWpConfigBackup — 3 cases (applicable_to gating + positive + negative)
8.  ExposedTerraformState — 2 cases
9.  ExposedPrivateKey — 2 cases
10. ExposedDatabaseDump — 2 cases
11. ExposedSourceMap — 2 cases
12. ExposedDsStore — 2 cases
13. runner — dedup test + evidence linking + pipeline integration
14. Migration V6 — findings/evidence TEXT id
15. severity_label derivation
16. DetectionContext — soft_404 + drain_evidence
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from bounty.db import apply_migrations, init_db
from bounty.detect.base import Detection, DetectionContext
from bounty.detect.exposed_files._common import is_real_file_response, soft_404_check
from bounty.detect.exposed_files.source_control import (
    ExposedGitDirectory,
    ExposedGitCredentials,
    ExposedSvnDirectory,
)
from bounty.detect.exposed_files.env_config import (
    ExposedEnvFile,
    ExposedWpConfigBackup,
    ExposedTerraformState,
    ExposedPrivateKey,
    ExposedDsStore,
)
from bounty.detect.exposed_files.backups import (
    ExposedDatabaseDump,
    ExposedSourceMap,
)
from bounty.detect.runner import run_detections
from bounty.models import Asset, EvidencePackage, Finding, FindingDraft, FingerprintResult, ProbeResult, severity_label

# ============================================================================
# Helpers
# ============================================================================

def _make_probe_result(
    *,
    status_code: int = 200,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    url: str = "https://example.com/test",
) -> ProbeResult:
    return ProbeResult(
        url=url,
        final_url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        body_text=body.decode("utf-8", errors="replace"),
    )


def _make_asset(
    host: str = "example.com",
    asset_id: str = "01TEST000000000000000000001",
) -> Asset:
    return Asset(
        id=asset_id,
        program_id="prog_test",
        host=host,
        url=f"https://{host}",
        scheme="https",
        primary_scheme="https",
    )


async def _noop_capture(url: str, pr: ProbeResult, scan_id: str) -> EvidencePackage:
    """Mock capture function — returns an EvidencePackage without touching the DB."""
    return EvidencePackage(
        id="EV" + url[-6:].replace("/", "_"),
        kind="http",
        response_status=pr.status_code,
    )


def _make_ctx(
    probe_responses: dict[str, ProbeResult],
    *,
    log: Any = None,
) -> DetectionContext:
    """Build a DetectionContext with a URL-keyed probe mock."""
    import structlog
    from bounty.config import get_settings

    async def _probe(url: str) -> ProbeResult:
        # Exact match first, then suffix match
        if url in probe_responses:
            return probe_responses[url]
        for pattern, resp in probe_responses.items():
            if url.endswith(pattern):
                return resp
        return _make_probe_result(status_code=404, body=b"Not Found")

    return DetectionContext(
        probe_fn=_probe,
        capture_fn=_noop_capture,
        scan_id="test-scan-01",
        settings=get_settings(),
        log=log or structlog.get_logger(),
    )


# ============================================================================
# 1. is_real_file_response
# ============================================================================

class TestIsRealFileResponse:
    def test_valid_git_head(self) -> None:
        pr = _make_probe_result(body=b"ref: refs/heads/main\n")
        assert is_real_file_response(pr, [b"ref: refs/heads/"])

    def test_spa_html_fallback_rejected(self) -> None:
        pr = _make_probe_result(body=b"<!DOCTYPE html><html><head></head></html>")
        assert not is_real_file_response(pr, [b"ref: refs/heads/"])

    def test_empty_200_rejected(self) -> None:
        pr = _make_probe_result(body=b"ok")  # < 10 bytes
        assert not is_real_file_response(pr, [b"ok"])

    def test_non_200_rejected(self) -> None:
        pr = _make_probe_result(status_code=403, body=b"ref: refs/heads/main")
        assert not is_real_file_response(pr, [b"ref: refs/heads/"])

    def test_404_rejected(self) -> None:
        pr = _make_probe_result(status_code=404, body=b"Not Found page here")
        assert not is_real_file_response(pr, [b"Not Found"])

    def test_signature_not_in_body_rejected(self) -> None:
        pr = _make_probe_result(body=b"some random content that is long enough")
        assert not is_real_file_response(pr, [b"ref: refs/heads/"])

    def test_two_signatures_one_match(self) -> None:
        pr = _make_probe_result(body=b"[core]\nrepositoryformatversion = 0\n\tfilemode = true")
        assert is_real_file_response(pr, [b"[core]", b"repositoryformatversion"])

    def test_allow_html_flag(self) -> None:
        pr = _make_probe_result(
            body=b"<!DOCTYPE html><html>stages: [build, deploy]</html>"
        )
        assert is_real_file_response(pr, [b"stages:"], allow_html=True)
        assert not is_real_file_response(pr, [b"stages:"], allow_html=False)

    def test_binary_magic_bytes_valid(self) -> None:
        pr = _make_probe_result(body=b"\x00\x00\x00\x01Bud1\x00" + b"\x00" * 30)
        assert is_real_file_response(pr, [b"\x00\x00\x00\x01Bud1"])

    def test_html_doctype_lowercase_rejected(self) -> None:
        pr = _make_probe_result(body=b"<!doctype html><html lang='en'>some content</html>")
        assert not is_real_file_response(pr, [b"some content"])


# ============================================================================
# 2. soft_404_check
# ============================================================================

class TestSoft404Check:
    @pytest.mark.asyncio
    async def test_real_404_not_soft(self) -> None:
        """Real 404 → not a soft-404 site."""
        async def probe(url: str) -> ProbeResult:
            return _make_probe_result(status_code=404, body=b"Not Found")

        asset = _make_asset()
        result = await soft_404_check(asset, probe)
        assert result is False

    @pytest.mark.asyncio
    async def test_catchall_200_is_soft_404(self) -> None:
        """Catch-all 200 with substantial body → soft-404 site."""
        async def probe(url: str) -> ProbeResult:
            return _make_probe_result(status_code=200, body=b"<!DOCTYPE html>" + b"x" * 500)

        asset = _make_asset()
        result = await soft_404_check(asset, probe)
        assert result is True

    @pytest.mark.asyncio
    async def test_200_with_tiny_body_not_soft(self) -> None:
        """200 with body < 200 bytes → not considered soft-404."""
        async def probe(url: str) -> ProbeResult:
            return _make_probe_result(status_code=200, body=b"ok")

        asset = _make_asset()
        result = await soft_404_check(asset, probe)
        assert result is False


# ============================================================================
# 3. ExposedGitDirectory
# ============================================================================

class TestExposedGitDirectory:
    @pytest.mark.asyncio
    async def test_positive_git_directory(self) -> None:
        """Valid .git/HEAD + .git/config → yields one finding."""
        ctx = _make_ctx({
            "/.git/HEAD": _make_probe_result(body=b"ref: refs/heads/main\n"),
            "/.git/config": _make_probe_result(
                body=b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
            ),
        })
        asset = _make_asset()
        ctx.set_soft_404(asset, False)

        det = ExposedGitDirectory()
        drafts = []
        async for d in det.run(asset, ctx):
            drafts.append(d)

        assert len(drafts) == 1
        assert "git" in drafts[0].dedup_key
        assert drafts[0].severity == 700
        assert drafts[0].cwe == "CWE-540"

    @pytest.mark.asyncio
    async def test_negative_no_git(self) -> None:
        """404 for .git/HEAD → no findings."""
        ctx = _make_ctx({})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)

        det = ExposedGitDirectory()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []

    @pytest.mark.asyncio
    async def test_soft_404_skipped(self) -> None:
        """Soft-404 site → skip entirely, no probe made."""
        probes_made: list[str] = []

        async def probe(url: str) -> ProbeResult:
            probes_made.append(url)
            return _make_probe_result(body=b"ref: refs/heads/main\n")

        import structlog
        from bounty.config import get_settings
        ctx = DetectionContext(
            probe_fn=probe,
            capture_fn=_noop_capture,
            scan_id="t1",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        asset = _make_asset()
        ctx.set_soft_404(asset, True)  # Mark as soft-404

        det = ExposedGitDirectory()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []
        assert probes_made == []  # No probes made at all


# ============================================================================
# 4. ExposedGitCredentials
# ============================================================================

class TestExposedGitCredentials:
    @pytest.mark.asyncio
    async def test_positive_credentials(self) -> None:
        ctx = _make_ctx({
            "/.git-credentials": _make_probe_result(
                body=b"https://user:ghp_abc123@github.com\n"
            ),
        })
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedGitCredentials()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1
        assert drafts[0].severity == 900

    @pytest.mark.asyncio
    async def test_negative_no_credentials(self) -> None:
        ctx = _make_ctx({})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedGitCredentials()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []


# ============================================================================
# 5. ExposedSvnDirectory
# ============================================================================

class TestExposedSvnDirectory:
    @pytest.mark.asyncio
    async def test_positive_svn_entries(self) -> None:
        ctx = _make_ctx({
            "/.svn/entries": _make_probe_result(body=b"10\n\ndir\nhttps://svn.example.com/repo\n"),
        })
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedSvnDirectory()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1

    @pytest.mark.asyncio
    async def test_negative(self) -> None:
        ctx = _make_ctx({})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedSvnDirectory()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []


# ============================================================================
# 6. ExposedEnvFile — severity scaling
# ============================================================================

class TestExposedEnvFile:
    @pytest.mark.asyncio
    async def test_env_with_no_high_value_keys(self) -> None:
        ctx = _make_ctx({
            "/.env": _make_probe_result(body=b"APP_NAME=myapp\nDEBUG=true\n"),
        })
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedEnvFile()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1
        assert drafts[0].severity == 400

    @pytest.mark.asyncio
    async def test_env_with_db_creds(self) -> None:
        ctx = _make_ctx({
            "/.env": _make_probe_result(
                body=b"DB_HOST=localhost\nDB_USER=root\nDB_PASSWORD=secret123\n"
            ),
        })
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedEnvFile()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1
        assert drafts[0].severity >= 800

    @pytest.mark.asyncio
    async def test_env_negative_no_key_value(self) -> None:
        ctx = _make_ctx({
            "/.env": _make_probe_result(body=b"just some random text here"),
        })
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedEnvFile()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []

    @pytest.mark.asyncio
    async def test_env_html_fallback_rejected(self) -> None:
        ctx = _make_ctx({
            "/.env": _make_probe_result(
                body=b"<!DOCTYPE html><html>APP_NAME=test</html>"
            ),
        })
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedEnvFile()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []


# ============================================================================
# 7. ExposedWpConfigBackup — applicable_to gating
# ============================================================================

class TestExposedWpConfigBackup:
    def _wp_fp(self) -> FingerprintResult:
        return FingerprintResult(tech="wordpress", category="cms", confidence="strong")

    @pytest.mark.asyncio
    async def test_applicable_to_requires_wp_fingerprint(self) -> None:
        """Should only apply when WordPress fingerprint is present."""
        det = ExposedWpConfigBackup()
        asset = _make_asset()
        assert det.applicable_to(asset, []) is False
        assert det.applicable_to(asset, [self._wp_fp()]) is True
        # HINT confidence should NOT gate the detection
        hint_fp = FingerprintResult(tech="wordpress", category="cms", confidence="hint")
        assert det.applicable_to(asset, [hint_fp]) is False

    @pytest.mark.asyncio
    async def test_positive_wp_config_backup(self) -> None:
        ctx = _make_ctx({
            "/wp-config.php.bak": _make_probe_result(
                body=b"<?php\n// DB settings\ndefine('DB_PASSWORD', 's3cr3t');\ndefine('AUTH_KEY', 'xxxxx');\n"
            ),
        })
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedWpConfigBackup()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1
        assert drafts[0].severity == 800

    @pytest.mark.asyncio
    async def test_negative_no_php_content(self) -> None:
        ctx = _make_ctx({})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedWpConfigBackup()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []


# ============================================================================
# 8. ExposedTerraformState
# ============================================================================

class TestExposedTerraformState:
    @pytest.mark.asyncio
    async def test_positive(self) -> None:
        body = json.dumps({
            "format_version": "0.1",
            "terraform_version": "1.5.0",
            "resources": [{"type": "aws_instance"}],
        }).encode()
        ctx = _make_ctx({"/terraform.tfstate": _make_probe_result(body=body)})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedTerraformState()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1
        assert drafts[0].severity == 950

    @pytest.mark.asyncio
    async def test_negative(self) -> None:
        ctx = _make_ctx({})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedTerraformState()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []


# ============================================================================
# 9. ExposedPrivateKey
# ============================================================================

class TestExposedPrivateKey:
    @pytest.mark.asyncio
    async def test_positive_pem_key(self) -> None:
        body = (
            b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4ET4xL/\n"
            b"-----END RSA PRIVATE KEY-----\n"
        )
        ctx = _make_ctx({"/id_rsa": _make_probe_result(body=body)})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedPrivateKey()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1
        assert drafts[0].severity == 950

    @pytest.mark.asyncio
    async def test_negative(self) -> None:
        ctx = _make_ctx({})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedPrivateKey()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []


# ============================================================================
# 10. ExposedDatabaseDump
# ============================================================================

class TestExposedDatabaseDump:
    @pytest.mark.asyncio
    async def test_positive_sql_dump(self) -> None:
        body = b"-- MySQL dump 10.13\nCREATE TABLE users (\n  id INT,\n  email VARCHAR(255)\n);\nINSERT INTO users VALUES (1,'a@b.com');\n"
        ctx = _make_ctx({"/backup.sql": _make_probe_result(body=body)})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedDatabaseDump()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1
        assert drafts[0].severity == 900

    @pytest.mark.asyncio
    async def test_negative(self) -> None:
        ctx = _make_ctx({})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedDatabaseDump()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []


# ============================================================================
# 11. ExposedSourceMap
# ============================================================================

class TestExposedSourceMap:
    @pytest.mark.asyncio
    async def test_positive_source_map(self) -> None:
        body = json.dumps({
            "version": 3,
            "sources": ["../src/app.ts"],
            "sourcesContent": ["export function main() {}"],
            "mappings": "AAAA",
        }).encode()
        ctx = _make_ctx({"/static/js/main.js.map": _make_probe_result(body=body)})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedSourceMap()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1

    @pytest.mark.asyncio
    async def test_negative(self) -> None:
        ctx = _make_ctx({})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedSourceMap()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []


# ============================================================================
# 12. ExposedDsStore
# ============================================================================

class TestExposedDsStore:
    @pytest.mark.asyncio
    async def test_positive_magic_bytes(self) -> None:
        body = b"\x00\x00\x00\x01Bud1" + b"\x00" * 100
        ctx = _make_ctx({"/.DS_Store": _make_probe_result(body=body)})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedDsStore()
        drafts = [d async for d in det.run(asset, ctx)]
        assert len(drafts) == 1
        assert drafts[0].severity == 200

    @pytest.mark.asyncio
    async def test_negative(self) -> None:
        ctx = _make_ctx({})
        asset = _make_asset()
        ctx.set_soft_404(asset, False)
        det = ExposedDsStore()
        drafts = [d async for d in det.run(asset, ctx)]
        assert drafts == []


# ============================================================================
# 13. Runner — persistence + dedup + evidence linking
# ============================================================================

@pytest.mark.asyncio
async def test_runner_persists_finding_to_db() -> None:
    """run_detections should persist a finding row and yield a Finding."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        init_db(db_path)
        apply_migrations(db_path)

        from bounty.db import get_conn as _gc
        async with _gc(db_path) as conn:
            await conn.execute(
                "INSERT INTO programs (id, platform, handle, name) VALUES ('p1','manual','p1','Test')"
            )
            await conn.execute(
                """INSERT INTO assets (id, program_id, host, port, scheme, url, status,
                   seen_protocols, primary_scheme, tags, last_seen, first_seen, created_at, updated_at)
                   VALUES ('A1','p1','testgit.com',NULL,'https','https://testgit.com','alive',
                   '["https"]','https','[]','2024-01-01T00:00:00Z','2024-01-01T00:00:00Z',
                   '2024-01-01T00:00:00Z','2024-01-01T00:00:00Z')"""
            )
            await conn.commit()

        git_head = _make_probe_result(body=b"ref: refs/heads/main\n")
        git_cfg = _make_probe_result(body=b"[core]\nrepositoryformatversion = 0\n")

        async def probe(url: str) -> ProbeResult:
            if url.endswith("/.git/HEAD"):
                return git_head
            if url.endswith("/.git/config"):
                return git_cfg
            return _make_probe_result(status_code=404)

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=probe,
            capture_fn=_noop_capture,
            scan_id="scan-runner-01",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        asset = _make_asset("testgit.com", "A1")
        ctx.set_soft_404(asset, False)

        det = ExposedGitDirectory()
        findings = []
        async for f in run_detections(asset, [], ctx, db_path, detections=[det]):
            findings.append(f)

        assert len(findings) == 1
        assert isinstance(findings[0], Finding)
        assert findings[0].id is not None

        # Verify DB
        async with _gc(db_path) as conn:
            cur = await conn.execute("SELECT id, dedup_key, severity FROM findings")
            rows = await cur.fetchall()
        assert len(rows) == 1
        assert "git" in rows[0]["dedup_key"]
        # id should be a TEXT ULID, not an integer
        assert isinstance(rows[0]["id"], str)
        assert len(rows[0]["id"]) == 26


@pytest.mark.asyncio
async def test_runner_dedup_no_duplicate_row() -> None:
    """Running the same detection twice → still only one findings row."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        init_db(db_path)
        apply_migrations(db_path)

        from bounty.db import get_conn as _gc
        async with _gc(db_path) as conn:
            await conn.execute(
                "INSERT INTO programs (id, platform, handle, name) VALUES ('p1','manual','p1','T')"
            )
            await conn.execute(
                """INSERT INTO assets (id, program_id, host, port, scheme, url, status,
                   seen_protocols, primary_scheme, tags, last_seen, first_seen, created_at, updated_at)
                   VALUES ('A2','p1','dedup.example.com',NULL,'https','https://dedup.example.com',
                   'alive','["https"]','https','[]','2024-01-01T00:00:00Z','2024-01-01T00:00:00Z',
                   '2024-01-01T00:00:00Z','2024-01-01T00:00:00Z')"""
            )
            await conn.commit()

        async def probe(url: str) -> ProbeResult:
            if url.endswith("/.git/HEAD"):
                return _make_probe_result(body=b"ref: refs/heads/main\n")
            if url.endswith("/.git/config"):
                return _make_probe_result(body=b"[core]\nrepositoryformatversion = 0\n")
            return _make_probe_result(status_code=404)

        import structlog
        from bounty.config import get_settings

        asset = _make_asset("dedup.example.com", "A2")
        det = ExposedGitDirectory()

        for run_num in range(2):
            ctx = DetectionContext(
                probe_fn=probe,
                capture_fn=_noop_capture,
                scan_id=f"scan-dedup-{run_num:02d}",
                settings=get_settings(),
                log=structlog.get_logger(),
            )
            ctx.set_soft_404(asset, False)
            async for _ in run_detections(asset, [], ctx, db_path, detections=[det]):
                pass

        from bounty.db import get_conn as _gc
        async with _gc(db_path) as conn:
            cur = await conn.execute("SELECT COUNT(*) as cnt FROM findings")
            row = await cur.fetchone()
        assert row["cnt"] == 1, "Dedup failed: expected 1 row, got more"


@pytest.mark.asyncio
async def test_runner_pipeline_integration() -> None:
    """Integration: feed asset with .git signals → finding + evidence persisted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        data_dir = Path(tmpdir) / "data"
        data_dir.mkdir()
        init_db(db_path)
        apply_migrations(db_path)

        from bounty.db import get_conn as _gc
        async with _gc(db_path) as conn:
            await conn.execute(
                "INSERT INTO programs (id, platform, handle, name) VALUES ('p1','manual','p1','T')"
            )
            await conn.execute(
                """INSERT INTO assets (id, program_id, host, port, scheme, url, status,
                   seen_protocols, primary_scheme, tags, last_seen, first_seen, created_at, updated_at)
                   VALUES ('A3','p1','integration.test',NULL,'https','https://integration.test',
                   'alive','["https"]','https','[]','2024-01-01T00:00:00Z','2024-01-01T00:00:00Z',
                   '2024-01-01T00:00:00Z','2024-01-01T00:00:00Z')"""
            )
            await conn.commit()

        async def probe(url: str) -> ProbeResult:
            if url.endswith("/.git/HEAD"):
                return _make_probe_result(
                    url=url, body=b"ref: refs/heads/main\n",
                    headers={"content-type": "text/plain"},
                )
            if url.endswith("/.git/config"):
                return _make_probe_result(
                    url=url, body=b"[core]\nrepositoryformatversion = 0\n",
                    headers={"content-type": "text/plain"},
                )
            return _make_probe_result(status_code=404)

        import structlog
        from bounty.config import get_settings
        from bounty.evidence.capture import capture_http_evidence

        async def capture_fn(url: str, pr: ProbeResult, scan_id: str) -> EvidencePackage:
            return await capture_http_evidence(
                url, pr, scan_id, db_path=db_path, data_dir=data_dir
            )

        ctx = DetectionContext(
            probe_fn=probe,
            capture_fn=capture_fn,
            scan_id="scan-int-01",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        asset = _make_asset("integration.test", "A3")
        ctx.set_soft_404(asset, False)

        det = ExposedGitDirectory()
        findings = [f async for f in run_detections(asset, [], ctx, db_path, detections=[det])]

        assert len(findings) == 1
        assert findings[0].dedup_key == "exposed.source_control.git:A3:/.git/"

        # Verify evidence was captured in DB
        async with _gc(db_path) as conn:
            cur = await conn.execute("SELECT COUNT(*) as cnt FROM evidence_packages")
            row = await cur.fetchone()
        assert row["cnt"] >= 1


# ============================================================================
# 14. Migration V6 — findings / evidence TEXT id
# ============================================================================

@pytest.mark.asyncio
async def test_migration_v6_findings_text_id() -> None:
    """Fresh DB should have TEXT id for findings; inserting gives str results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        init_db(db_path)
        apply_migrations(db_path)

        from bounty.db import get_conn as _gc
        from bounty.ulid import make_ulid

        async with _gc(db_path) as conn:
            await conn.execute(
                "INSERT INTO programs (id, platform, handle, name) VALUES ('p1','manual','p1','T')"
            )
            finding_id = make_ulid()
            await conn.execute(
                """INSERT INTO findings (id, dedup_key, title, category, url)
                   VALUES (?, 'test:key', 'Test', 'test_cat', 'https://example.com')""",
                (finding_id,),
            )
            await conn.commit()

            cur = await conn.execute("SELECT id FROM findings WHERE id=?", (finding_id,))
            row = await cur.fetchone()

        assert row is not None
        assert isinstance(row["id"], str)
        assert row["id"] == finding_id
        assert len(row["id"]) == 26


# ============================================================================
# 15. Severity label derivation
# ============================================================================

class TestSeverityLabel:
    def test_critical(self) -> None:
        assert severity_label(950) == "critical"
        assert severity_label(800) == "critical"

    def test_high(self) -> None:
        assert severity_label(700) == "high"
        assert severity_label(600) == "high"

    def test_medium(self) -> None:
        assert severity_label(500) == "medium"
        assert severity_label(400) == "medium"

    def test_low(self) -> None:
        assert severity_label(300) == "low"
        assert severity_label(200) == "low"

    def test_info(self) -> None:
        assert severity_label(100) == "info"
        assert severity_label(0) == "info"


# ============================================================================
# 16. DetectionContext helpers
# ============================================================================

class TestDetectionContext:
    @pytest.mark.asyncio
    async def test_drain_evidence_empties_list(self) -> None:
        import structlog
        from bounty.config import get_settings

        captured: list[EvidencePackage] = []

        async def capture(url: str, pr: ProbeResult, sid: str) -> EvidencePackage:
            pkg = EvidencePackage(id=make_ulid_str(), kind="http")
            captured.append(pkg)
            return pkg

        def make_ulid_str() -> str:
            from bounty.ulid import make_ulid
            return make_ulid()

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_make_probe_result()),
            capture_fn=capture,
            scan_id="t1",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        pr = _make_probe_result()
        await ctx.capture_evidence("https://x.com/test", pr)
        await ctx.capture_evidence("https://x.com/test2", pr)

        ev = ctx.drain_evidence()
        assert len(ev) == 2
        # Second drain should be empty
        ev2 = ctx.drain_evidence()
        assert ev2 == []

    def test_soft_404_cache(self) -> None:
        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(),
            capture_fn=AsyncMock(),
            scan_id="t1",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        asset = _make_asset()
        assert ctx.is_soft_404_site(asset) is False
        ctx.set_soft_404(asset, True)
        assert ctx.is_soft_404_site(asset) is True
        ctx.set_soft_404(asset, False)
        assert ctx.is_soft_404_site(asset) is False

