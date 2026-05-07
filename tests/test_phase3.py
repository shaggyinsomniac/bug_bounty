"""
tests/test_phase3.py — Phase 3 (Fingerprinting Engine) test suite.

Test sections:
1. parse_headers — 12 cases
2. parse_cookies — 15 cases
3. parse_body    — 12 cases
4. parse_tls     — 5 cases
5. favicon_hash  — stability test
6. _dedupe       — confidence boost logic
7. fingerprint_asset integration — WordPress signals fixture
8. SAN hostname scoping
9. Pipeline fingerprint phase (mock probe)
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bounty.fingerprint.body import parse_body
from bounty.fingerprint.cookies import parse_cookies
from bounty.fingerprint.favicon import favicon_hash, lookup_favicon_db
from bounty.fingerprint.headers import parse_headers
from bounty.fingerprint.tls import parse_tls
from bounty.fingerprint import _dedupe, fingerprint_asset
from bounty.models import Asset, FingerprintResult, ProbeResult, TLSInfo

# ============================================================================
# Helpers
# ============================================================================

def _make_probe(
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    body_text: str = "",
    url: str = "https://example.com",
    status_code: int = 200,
    tls: TLSInfo | None = None,
) -> ProbeResult:
    """Build a minimal ProbeResult for testing."""
    return ProbeResult(
        url=url,
        final_url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        body_text=body_text or body.decode("utf-8", errors="replace"),
        tls=tls,
    )


def _make_asset(
    host: str = "example.com",
    asset_id: str = "01TESTASSET000000000000001",
    program_id: str = "prog_1",
) -> Asset:
    return Asset(
        id=asset_id,
        program_id=program_id,
        host=host,
        url=f"https://{host}",
        scheme="https",
        primary_scheme="https",
    )


def _tech_set(results: list[FingerprintResult]) -> set[str]:
    return {r.tech for r in results}


# ============================================================================
# 1. parse_headers
# ============================================================================

class TestParseHeaders:
    def test_nginx_with_version(self) -> None:
        rs = parse_headers({"Server": "nginx/1.23.4"})
        assert any(r.tech == "nginx" and r.version == "1.23.4" and r.confidence == 90 for r in rs)

    def test_apache_with_version(self) -> None:
        rs = parse_headers({"Server": "Apache/2.4.57 (Ubuntu)"})
        assert any(r.tech == "apache" and r.version == "2.4.57" for r in rs)

    def test_iis_server(self) -> None:
        rs = parse_headers({"Server": "Microsoft-IIS/10.0"})
        assert any(r.tech == "iis" and r.version == "10.0" for r in rs)

    def test_cloudflare_server(self) -> None:
        rs = parse_headers({"Server": "cloudflare"})
        assert any(r.tech == "cloudflare" and r.category == "cdn" for r in rs)

    def test_cf_ray_cdn(self) -> None:
        rs = parse_headers({"CF-Ray": "8abc123-LHR"})
        assert any(r.tech == "cloudflare" and r.category == "cdn" for r in rs)

    def test_x_powered_by_php(self) -> None:
        rs = parse_headers({"X-Powered-By": "PHP/8.2.0"})
        assert any(r.tech == "php" and r.version == "8.2.0" and r.category == "language" for r in rs)

    def test_x_powered_by_aspnet(self) -> None:
        rs = parse_headers({"X-Powered-By": "ASP.NET"})
        assert any(r.tech == "asp.net" for r in rs)

    def test_x_aspnet_version(self) -> None:
        rs = parse_headers({"X-AspNet-Version": "4.0.30319"})
        assert any(r.tech == "asp.net" and r.version == "4.0.30319" for r in rs)

    def test_x_generator_drupal(self) -> None:
        rs = parse_headers({"X-Generator": "Drupal 9 (https://www.drupal.org)"})
        assert any(r.tech == "drupal" and r.version == "9" for r in rs)

    def test_x_amz_cf_id_cloudfront(self) -> None:
        rs = parse_headers({"X-Amz-Cf-Id": "12345abcde"})
        assert any(r.tech == "cloudfront" and r.category == "cdn" for r in rs)

    def test_via_fastly(self) -> None:
        rs = parse_headers({"Via": "1.1 varnish (Fastly)"})
        assert any(r.tech == "fastly" for r in rs)

    def test_werkzeug_flask_hint(self) -> None:
        rs = parse_headers({"Server": "Werkzeug/3.0.1 Python/3.11.0"})
        assert any(r.tech == "werkzeug" and r.category == "framework" for r in rs)

    def test_header_case_insensitive_keys(self) -> None:
        """Header dict keys are case-normalised inside parse_headers."""
        rs = parse_headers({"server": "nginx/1.24.0"})
        assert any(r.tech == "nginx" for r in rs)

    def test_empty_headers(self) -> None:
        assert parse_headers({}) == []


# ============================================================================
# 2. parse_cookies
# ============================================================================

class TestParseCookies:
    def test_phpsessid(self) -> None:
        rs = parse_cookies(["PHPSESSID=abc123; Path=/; HttpOnly"])
        assert any(r.tech == "php" and r.confidence == 70 for r in rs)

    def test_jsessionid(self) -> None:
        rs = parse_cookies(["JSESSIONID=ABCDEF; Path=/"])
        assert any(r.tech == "java" and r.confidence == 60 for r in rs)

    def test_aspnet_session(self) -> None:
        rs = parse_cookies(["ASP.NET_SessionId=xyz; HttpOnly"])
        assert any(r.tech == "asp.net" and r.confidence == 80 for r in rs)

    def test_laravel_session(self) -> None:
        rs = parse_cookies(["laravel_session=abc; Path=/; HttpOnly; SameSite=Lax"])
        assert any(r.tech == "laravel" and r.confidence == 90 for r in rs)

    def test_symfony(self) -> None:
        rs = parse_cookies(["sf_redirect=%7B%22_route%22%3A%22home%22%7D"])
        assert any(r.tech == "symfony" for r in rs)

    def test_connect_sid_express(self) -> None:
        rs = parse_cookies(["connect.sid=s%3Aabc.XYZ; Path=/; HttpOnly"])
        assert any(r.tech == "express" for r in rs)

    def test_wordpress_logged_in(self) -> None:
        rs = parse_cookies(["wordpress_logged_in_abcdef=user; Path=/"])
        assert any(r.tech == "wordpress" and r.confidence == 90 for r in rs)

    def test_drupal_sess(self) -> None:
        # 32 hex chars after SESS
        rs = parse_cookies(["SESS" + "a" * 32 + "=xyz"])
        assert any(r.tech == "drupal" for r in rs)

    def test_shopify_token(self) -> None:
        rs = parse_cookies(["SHOP_SESSION_TOKEN=xyz; Path=/; Secure"])
        assert any(r.tech == "shopify" and r.confidence == 90 for r in rs)

    def test_cloudflare_bm(self) -> None:
        rs = parse_cookies(["__cf_bm=abc.0.def; Path=/; Secure; HttpOnly"])
        assert any(r.tech == "cloudflare" and r.category == "cdn" for r in rs)

    def test_imperva(self) -> None:
        rs = parse_cookies(["incap_ses_123_456=abc; Path=/"])
        assert any(r.tech == "imperva" and r.category == "waf" for r in rs)

    def test_django_requires_both(self) -> None:
        # Only csrftoken — no django detection
        rs = parse_cookies(["csrftoken=abc"])
        assert not any(r.tech == "django" for r in rs)

    def test_django_both_cookies(self) -> None:
        rs = parse_cookies(["csrftoken=abc", "sessionid=xyz"])
        assert any(r.tech == "django" and r.confidence == 85 for r in rs)

    def test_xsrf_token_ambiguous(self) -> None:
        rs = parse_cookies(["XSRF-TOKEN=abc123"])
        assert any(r.tech == "laravel-or-angular" and r.confidence == 50 for r in rs)

    def test_aws_elb(self) -> None:
        rs = parse_cookies(["AWSALB=xyz; Expires=Thu, 14 Dec 2023 06:37:46 GMT"])
        assert any(r.tech == "aws-elb" for r in rs)

    def test_empty_cookies(self) -> None:
        assert parse_cookies([]) == []


# ============================================================================
# 3. parse_body
# ============================================================================

class TestParseBody:
    def test_skips_non_html(self) -> None:
        assert parse_body(b'{"key":"val"}', "application/json", "https://example.com") == []

    def test_skips_image(self) -> None:
        assert parse_body(b"\x89PNG", "image/png", "https://example.com") == []

    def test_meta_generator_wordpress(self) -> None:
        html = b'<meta name="generator" content="WordPress 6.4.2" />'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "wordpress" and r.version == "6.4.2" and r.confidence == 95 for r in rs)

    def test_meta_generator_drupal(self) -> None:
        html = b'<html><head><meta name="generator" content="Drupal 9"></head></html>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "drupal" and r.confidence == 95 for r in rs)

    def test_wp_content_path(self) -> None:
        html = b'<script src="/wp-content/themes/main.js"></script>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "wordpress" for r in rs)

    def test_next_static_path(self) -> None:
        html = b'<script src="/_next/static/chunks/main.js"></script>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "nextjs" and r.confidence == 90 for r in rs)

    def test_next_data_script(self) -> None:
        html = b'<script id="__NEXT_DATA__" type="application/json">{"page":"/"}</script>'
        rs = parse_body(html, "text/html; charset=utf-8", "https://example.com")
        assert any(r.tech == "nextjs" and r.confidence == 95 for r in rs)

    def test_shopify_comment(self) -> None:
        html = b"<!-- Powered by Shopify -->"
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "shopify" and r.confidence == 80 for r in rs)

    def test_title_phpinfo(self) -> None:
        html = b"<html><head><title>phpinfo()</title></head></html>"
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "phpinfo-exposed" and r.confidence == 100 for r in rs)

    def test_title_dir_listing(self) -> None:
        html = b"<html><head><title>Index of /secret</title></head><body></body></html>"
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "directory-listing" and r.confidence == 95 for r in rs)

    def test_title_jenkins(self) -> None:
        html = b"<html><head><title>Dashboard [Jenkins]</title></head></html>"
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "jenkins" and r.confidence >= 90 for r in rs)

    def test_angular_ng_app(self) -> None:
        html = b'<div ng-app="myApp"><div ng-controller="ctrl"></div></div>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "angularjs" for r in rs)

    def test_empty_body(self) -> None:
        assert parse_body(b"", "text/html", "https://example.com") == []


# ============================================================================
# 4. parse_tls
# ============================================================================

class TestParseTls:
    def _asset(self) -> Asset:
        return _make_asset("example.com")

    def test_self_signed(self) -> None:
        tls = TLSInfo(issuer="CN=example.com", subject="CN=example.com")
        probe = _make_probe(tls=tls)
        rs, hosts = parse_tls(probe, self._asset())
        assert any(r.tech == "self-signed-cert" and r.confidence == 90 for r in rs)

    def test_lets_encrypt(self) -> None:
        tls = TLSInfo(issuer="C=US, O=Let's Encrypt, CN=R3", subject="CN=example.com")
        probe = _make_probe(tls=tls)
        rs, _ = parse_tls(probe, self._asset())
        assert any(r.tech == "lets-encrypt" for r in rs)

    def test_cert_expired(self) -> None:
        expired = (datetime.now(tz=timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        tls = TLSInfo(issuer="CN=CA", subject="CN=example.com", not_after=expired)
        probe = _make_probe(tls=tls)
        rs, _ = parse_tls(probe, self._asset())
        assert any(r.tech == "cert-expired" and r.confidence == 100 for r in rs)

    def test_cert_expiring_soon(self) -> None:
        soon = (datetime.now(tz=timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        tls = TLSInfo(issuer="CN=CA", subject="CN=example.com", not_after=soon)
        probe = _make_probe(tls=tls)
        rs, _ = parse_tls(probe, self._asset())
        assert any(r.tech == "cert-expiring-soon" and r.confidence >= 90 for r in rs)

    def test_valid_commercial_cert(self) -> None:
        future = (datetime.now(tz=timezone.utc) + timedelta(days=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
        tls = TLSInfo(issuer="CN=DigiCert", subject="CN=example.com", not_after=future)
        probe = _make_probe(tls=tls)
        rs, _ = parse_tls(probe, self._asset())
        # No cert-expired or cert-expiring-soon
        assert not any(r.tech in ("cert-expired", "cert-expiring-soon") for r in rs)

    def test_no_tls(self) -> None:
        probe = _make_probe()
        rs, hosts = parse_tls(probe, self._asset())
        assert rs == []
        assert hosts == []


# ============================================================================
# 5. Favicon hash stability
# ============================================================================

class TestFaviconHash:
    def test_hash_stable(self) -> None:
        body = b"\x89PNG\r\n\x1a\nfakefavicondata"
        h1 = favicon_hash(body)
        h2 = favicon_hash(body)
        assert h1 == h2

    def test_hash_is_int(self) -> None:
        assert isinstance(favicon_hash(b"\x00" * 100), int)

    def test_lookup_unknown_hash(self) -> None:
        assert lookup_favicon_db(999999999) is None


# ============================================================================
# 6. Deduplication + confidence boost
# ============================================================================

class TestDedupeBoost:
    def test_single_signal_no_boost(self) -> None:
        results = [FingerprintResult(tech="nginx", category="web-server", confidence=90)]
        merged = _dedupe(results)
        assert len(merged) == 1
        assert merged[0].confidence == 90

    def test_two_signals_boost_10(self) -> None:
        results = [
            FingerprintResult(tech="nginx", category="web-server", confidence=70, evidence="server header"),
            FingerprintResult(tech="nginx", category="web-server", confidence=60, evidence="via header"),
        ]
        merged = _dedupe(results)
        assert len(merged) == 1
        assert merged[0].confidence == 80  # max(70,60) + 10
        assert "server header" in merged[0].evidence
        assert "via header" in merged[0].evidence

    def test_three_signals_boost_20(self) -> None:
        results = [
            FingerprintResult(tech="wordpress", category="cms", confidence=80, evidence="path"),
            FingerprintResult(tech="wordpress", category="cms", confidence=70, evidence="cookie"),
            FingerprintResult(tech="wordpress", category="cms", confidence=60, evidence="meta"),
        ]
        merged = _dedupe(results)
        assert len(merged) == 1
        assert merged[0].confidence == 100  # min(100, 80+20)

    def test_cap_at_100(self) -> None:
        results = [
            FingerprintResult(tech="drupal", category="cms", confidence=95),
            FingerprintResult(tech="drupal", category="cms", confidence=90),
        ]
        merged = _dedupe(results)
        assert merged[0].confidence == 100

    def test_different_techs_kept_separate(self) -> None:
        results = [
            FingerprintResult(tech="nginx", category="web-server", confidence=90),
            FingerprintResult(tech="php", category="language", confidence=90),
        ]
        merged = _dedupe(results)
        assert len(merged) == 2
        assert _tech_set(merged) == {"nginx", "php"}


# ============================================================================
# 7. fingerprint_asset integration
# ============================================================================

@pytest.mark.asyncio
async def test_fingerprint_asset_integration() -> None:
    """WordPress + PHP + nginx signals → persists rows, updates asset.server."""
    import aiosqlite
    from bounty.db import init_db, apply_migrations

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "fp_test.db"
        init_db(db_path)
        apply_migrations(db_path)

        # Insert program + asset rows
        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA foreign_keys = ON")
            await conn.execute(
                "INSERT INTO programs (id, platform, handle, name) VALUES ('p1', 'manual', 'p1', 'Test')"
            )
            await conn.execute(
                """
                INSERT INTO assets
                    (id, program_id, host, port, scheme, url, status,
                     seen_protocols, primary_scheme, tags, last_seen, first_seen, created_at, updated_at)
                VALUES ('A1', 'p1', 'example.com', NULL, 'https', 'https://example.com', 'alive',
                        '["https"]', 'https', '[]', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z',
                        '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')
                """
            )
            await conn.commit()

        # Build a probe result with WordPress + PHP + nginx signals
        html = (
            b'<html><head>'
            b'<meta name="generator" content="WordPress 6.4" />'
            b'</head><body>'
            b'<script src="/wp-content/themes/twenty/js/main.js"></script>'
            b'</body></html>'
        )
        probe = _make_probe(
            headers={
                "Server": "nginx/1.24.0",
                "X-Powered-By": "PHP/8.2.0",
                "Content-Type": "text/html; charset=utf-8",
            },
            body=html,
            body_text=html.decode(),
        )

        asset = _make_asset("example.com", "A1", "p1")

        # Mock probe_fn (favicon fetch will fail → gracefully skipped)
        async def mock_probe(url: str) -> ProbeResult:
            return ProbeResult(
                url=url, final_url=url, status_code=404,
                headers={}, body=b"", body_text="", error="not found",
            )

        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA foreign_keys = ON")
            results = await fingerprint_asset(asset, probe, mock_probe, conn)

        tech_names = {r.tech for r in results}
        assert "wordpress" in tech_names, f"Expected wordpress in {tech_names}"
        assert "php" in tech_names, f"Expected php in {tech_names}"
        assert "nginx" in tech_names, f"Expected nginx in {tech_names}"

        # Check DB rows were persisted
        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cur = await conn.execute("SELECT tech FROM fingerprints WHERE asset_id='A1'")
            db_techs = {r["tech"] for r in await cur.fetchall()}
        assert "wordpress" in db_techs
        assert "nginx" in db_techs

        # Asset.server should be updated to nginx
        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cur = await conn.execute("SELECT server FROM assets WHERE id='A1'")
            row = await cur.fetchone()
        assert row is not None
        assert row["server"] == "nginx"


# ============================================================================
# 8. SAN hostname scoping
# ============================================================================

class TestSanHostnames:
    def _asset(self, host: str = "example.com") -> Asset:
        return _make_asset(host)

    def test_san_same_domain_extracted(self) -> None:
        """SANs with same root domain are returned."""
        tls = TLSInfo(
            issuer="CN=CA",
            subject="DNS:example.com, DNS:www.example.com, DNS:api.example.com",
        )
        probe = _make_probe(tls=tls)
        _, hosts = parse_tls(probe, self._asset("example.com"))
        assert "api.example.com" in hosts or "www.example.com" in hosts

    def test_san_cross_domain_filtered(self) -> None:
        """SANs from a different root domain are not returned."""
        tls = TLSInfo(
            issuer="CN=CA",
            subject="DNS:other.org, DNS:api.other.org",
        )
        probe = _make_probe(tls=tls)
        _, hosts = parse_tls(probe, self._asset("example.com"))
        assert not any("other.org" in h for h in hosts)

    def test_no_tls_no_hostnames(self) -> None:
        probe = _make_probe()
        _, hosts = parse_tls(probe, self._asset())
        assert hosts == []


# ============================================================================
# 9. Pipeline fingerprint phase (mock probe)
# ============================================================================

@pytest.mark.asyncio
async def test_pipeline_fingerprint_phase() -> None:
    """Full pipeline with mocked probe produces fingerprint rows."""
    import aiosqlite
    from bounty.db import init_db, apply_migrations
    from bounty.models import Target

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "pipeline_test.db"
        init_db(db_path)
        apply_migrations(db_path)

        html = (
            b'<html><head><title>My Site</title>'
            b'<meta name="generator" content="WordPress 6.5"></head>'
            b'<body><script src="/wp-content/themes/t.js"></script></body></html>'
        )

        fake_probe_result = ProbeResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            headers={"Server": "nginx/1.25.0", "Content-Type": "text/html"},
            body=html,
            body_text=html.decode(),
        )
        error_result = ProbeResult(
            url="https://example.com/favicon.ico",
            final_url="https://example.com/favicon.ico",
            status_code=404,
            headers={},
            body=b"",
            body_text="",
            error="not found",
        )

        async def _mock_probe(url: str, **kw: Any) -> ProbeResult:
            if "favicon" in url:
                return error_result
            return fake_probe_result

        targets = [
            Target(value="example.com", asset_type="url", scope_type="in_scope", program_id="prog_test"),
        ]

        with (
            patch("bounty.recon.probe", side_effect=_mock_probe),
            patch("bounty.recon.resolve_batch", return_value={"example.com": MagicMock(
                alive=True, primary_ip="1.2.3.4", wildcard_zone=False
            )}),
            patch("bounty.recon.enumerate_subdomains", return_value=_aiter([])),
        ):
            from bounty.recon import recon_pipeline
            result = await recon_pipeline(
                "prog_test",
                targets,
                intensity="gentle",
                db_path=db_path,
            )

        assert result["assets"], "Expected at least one asset"

        # Verify fingerprint rows exist
        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cur = await conn.execute("SELECT COUNT(*) as cnt FROM fingerprints")
            row = await cur.fetchone()
            assert row is not None
            count = row["cnt"]
        assert count > 0, "Expected fingerprint rows after pipeline"


async def _aiter(items: list[str]) -> Any:
    """Async generator wrapper for test patching."""
    for item in items:
        yield item




