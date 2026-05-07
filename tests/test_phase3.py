"""
tests/test_phase3.py — Phase 3 (Fingerprinting Engine) test suite.

Test sections:
1.  parse_headers — 14 cases
2.  parse_cookies — 16 cases
3.  parse_body    — 18 cases (12 original + 3 Phase-3.1 + 3 Phase-3.2 regression)
4.  parse_tls     — 6 cases
5.  favicon_hash  — stability test
6.  _dedupe       — corroboration + P1 drop logic
7.  fingerprint_asset integration — WordPress signals fixture
8.  SAN hostname scoping
9.  Pipeline fingerprint phase (mock probe)
10. Principle tests — 8 new tests for P1–P5
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
from bounty.fingerprint import (
    _apply_category_exclusion,
    _apply_vendor_overrides,
    _dedupe,
    fingerprint_asset,
)
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
        assert any(r.tech == "nginx" and r.version == "1.23.4" and r.confidence == "definitive" for r in rs)

    def test_nginx_without_version_is_strong(self) -> None:
        rs = parse_headers({"Server": "nginx"})
        assert any(r.tech == "nginx" and r.version is None and r.confidence == "strong" for r in rs)

    def test_apache_with_version(self) -> None:
        rs = parse_headers({"Server": "Apache/2.4.57 (Ubuntu)"})
        assert any(r.tech == "apache" and r.version == "2.4.57" and r.confidence == "definitive" for r in rs)

    def test_iis_server(self) -> None:
        rs = parse_headers({"Server": "Microsoft-IIS/10.0"})
        assert any(r.tech == "iis" and r.version == "10.0" and r.confidence == "definitive" for r in rs)

    def test_cloudflare_server(self) -> None:
        rs = parse_headers({"Server": "cloudflare"})
        assert any(r.tech == "cloudflare" and r.category == "cdn" and r.confidence == "strong" for r in rs)

    def test_cf_ray_cdn_is_definitive(self) -> None:
        rs = parse_headers({"CF-Ray": "8abc123-LHR"})
        assert any(r.tech == "cloudflare" and r.category == "cdn" and r.confidence == "definitive" for r in rs)

    def test_x_powered_by_php_with_version(self) -> None:
        rs = parse_headers({"X-Powered-By": "PHP/8.2.0"})
        assert any(r.tech == "php" and r.version == "8.2.0" and r.confidence == "definitive" for r in rs)

    def test_x_powered_by_aspnet(self) -> None:
        rs = parse_headers({"X-Powered-By": "ASP.NET"})
        assert any(r.tech == "asp.net" and r.confidence == "strong" for r in rs)

    def test_x_aspnet_version(self) -> None:
        rs = parse_headers({"X-AspNet-Version": "4.0.30319"})
        assert any(r.tech == "asp.net" and r.version == "4.0.30319" and r.confidence == "definitive" for r in rs)

    def test_x_generator_drupal(self) -> None:
        rs = parse_headers({"X-Generator": "Drupal 9 (https://www.drupal.org)"})
        assert any(r.tech == "drupal" and r.version == "9" and r.confidence == "definitive" for r in rs)

    def test_x_amz_cf_id_cloudfront(self) -> None:
        rs = parse_headers({"X-Amz-Cf-Id": "12345abcde"})
        assert any(r.tech == "cloudfront" and r.category == "cdn" and r.confidence == "definitive" for r in rs)

    def test_via_fastly(self) -> None:
        rs = parse_headers({"Via": "1.1 varnish (Fastly)"})
        assert any(r.tech == "fastly" and r.confidence == "strong" for r in rs)

    def test_werkzeug_flask_hint(self) -> None:
        rs = parse_headers({"Server": "Werkzeug/3.0.1 Python/3.11.0"})
        assert any(r.tech == "werkzeug" and r.category == "framework" and r.confidence == "definitive" for r in rs)

    def test_header_case_insensitive_keys(self) -> None:
        rs = parse_headers({"server": "nginx/1.24.0"})
        assert any(r.tech == "nginx" and r.confidence == "definitive" for r in rs)

    def test_empty_headers(self) -> None:
        assert parse_headers({}) == []

    def test_evidence_format_is_header_prefix(self) -> None:
        """Evidence must start with 'header:' per Principle 5."""
        rs = parse_headers({"Server": "nginx/1.23.4"})
        nginx_r = next((r for r in rs if r.tech == "nginx"), None)
        assert nginx_r is not None
        assert nginx_r.evidence.startswith("header:")
        assert "=" in nginx_r.evidence


# ============================================================================
# 2. parse_cookies
# ============================================================================

class TestParseCookies:
    def test_phpsessid_is_weak(self) -> None:
        rs = parse_cookies(["PHPSESSID=abc123; Path=/; HttpOnly"])
        assert any(r.tech == "php" and r.confidence == "weak" for r in rs)

    def test_jsessionid_is_weak(self) -> None:
        rs = parse_cookies(["JSESSIONID=ABCDEF; Path=/"])
        assert any(r.tech == "java" and r.confidence == "weak" for r in rs)

    def test_aspnet_session_is_strong(self) -> None:
        rs = parse_cookies(["ASP.NET_SessionId=xyz; HttpOnly"])
        assert any(r.tech == "asp.net" and r.confidence == "strong" for r in rs)

    def test_laravel_session_is_definitive(self) -> None:
        rs = parse_cookies(["laravel_session=abc; Path=/; HttpOnly; SameSite=Lax"])
        assert any(r.tech == "laravel" and r.confidence == "definitive" for r in rs)

    def test_symfony(self) -> None:
        rs = parse_cookies(["sf_redirect=%7B%22_route%22%3A%22home%22%7D"])
        assert any(r.tech == "symfony" and r.confidence == "strong" for r in rs)

    def test_connect_sid_express(self) -> None:
        rs = parse_cookies(["connect.sid=s%3Aabc.XYZ; Path=/; HttpOnly"])
        assert any(r.tech == "express" and r.confidence == "strong" for r in rs)

    def test_wordpress_logged_in_is_definitive(self) -> None:
        rs = parse_cookies(["wordpress_logged_in_abcdef=user; Path=/"])
        assert any(r.tech == "wordpress" and r.confidence == "definitive" for r in rs)

    def test_drupal_sess(self) -> None:
        rs = parse_cookies(["SESS" + "a" * 32 + "=xyz"])
        assert any(r.tech == "drupal" and r.confidence == "strong" for r in rs)

    def test_shopify_token_is_definitive(self) -> None:
        rs = parse_cookies(["SHOP_SESSION_TOKEN=xyz; Path=/; Secure"])
        assert any(r.tech == "shopify" and r.confidence == "definitive" for r in rs)

    def test_cloudflare_bm_is_definitive(self) -> None:
        rs = parse_cookies(["__cf_bm=abc.0.def; Path=/; Secure; HttpOnly"])
        assert any(r.tech == "cloudflare" and r.category == "cdn" and r.confidence == "definitive" for r in rs)

    def test_imperva_is_definitive(self) -> None:
        rs = parse_cookies(["incap_ses_123_456=abc; Path=/"])
        assert any(r.tech == "imperva" and r.category == "waf" and r.confidence == "definitive" for r in rs)

    def test_django_requires_both(self) -> None:
        rs = parse_cookies(["csrftoken=abc"])
        assert not any(r.tech == "django" for r in rs)

    def test_django_both_cookies_is_strong(self) -> None:
        rs = parse_cookies(["csrftoken=abc", "sessionid=xyz"])
        assert any(r.tech == "django" and r.confidence == "strong" for r in rs)

    def test_xsrf_token_is_hint(self) -> None:
        rs = parse_cookies(["XSRF-TOKEN=abc123"])
        assert any(r.tech == "laravel-or-angular" and r.confidence == "hint" for r in rs)

    def test_aws_elb_is_strong(self) -> None:
        rs = parse_cookies(["AWSALB=xyz; Expires=Thu, 14 Dec 2023 06:37:46 GMT"])
        assert any(r.tech == "aws-elb" and r.confidence == "strong" for r in rs)

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

    def test_meta_generator_wordpress_is_definitive(self) -> None:
        html = b'<meta name="generator" content="WordPress 6.4.2" />'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "wordpress" and r.version == "6.4.2" and r.confidence == "definitive" for r in rs)
        assert any("meta:generator=" in r.evidence for r in rs if r.tech == "wordpress")

    def test_meta_generator_drupal_is_definitive(self) -> None:
        html = b'<html><head><meta name="generator" content="Drupal 9"></head></html>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "drupal" and r.confidence == "definitive" for r in rs)

    def test_wp_content_path_is_strong(self) -> None:
        html = b'<script src="/wp-content/themes/main.js"></script>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "wordpress" and r.confidence == "strong" for r in rs)

    def test_next_static_path_is_definitive(self) -> None:
        html = b'<script src="/_next/static/chunks/main.js"></script>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "nextjs" and r.confidence == "definitive" for r in rs)

    def test_next_data_script_is_definitive(self) -> None:
        html = b'<script id="__NEXT_DATA__" type="application/json">{"page":"/"}</script>'
        rs = parse_body(html, "text/html; charset=utf-8", "https://example.com")
        assert any(r.tech == "nextjs" and r.confidence == "definitive" for r in rs)

    def test_shopify_comment_is_strong(self) -> None:
        html = b"<!-- Powered by Shopify -->"
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "shopify" and r.confidence == "strong" for r in rs)

    def test_title_phpinfo_is_definitive(self) -> None:
        html = b"<html><head><title>phpinfo()</title></head></html>"
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "phpinfo-exposed" and r.confidence == "definitive" for r in rs)

    def test_title_dir_listing_is_definitive(self) -> None:
        html = b"<html><head><title>Index of /secret</title></head><body></body></html>"
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "directory-listing" and r.confidence == "definitive" for r in rs)

    def test_title_jenkins_is_strong(self) -> None:
        html = b"<html><head><title>Dashboard [Jenkins]</title></head></html>"
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "jenkins" and r.confidence == "strong" for r in rs)

    def test_angular_ng_app(self) -> None:
        html = b'<div ng-app="myApp"><div ng-controller="ctrl"></div></div>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "angularjs" and r.confidence == "strong" for r in rs)

    def test_empty_body(self) -> None:
        assert parse_body(b"", "text/html", "https://example.com") == []

    # ── Phase-3.1 regressions ──────────────────────────────────────────────

    def test_magento_fp_drupal_body_classes_no_detect(self) -> None:
        """Drupal body classes ('page-node', 'cms-front') must NOT trigger Magento."""
        html = b'<html><body class="page-node cms-front layout-no-sidebars"><p>Drupal</p></body></html>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert not any(r.tech == "magento" for r in rs)

    def test_magento_tp_catalog_product_class(self) -> None:
        """A real Magento body class ('catalog-product-view') MUST trigger Magento at WEAK."""
        html = b'<html><body class="catalog-product-view category-bag"><p>Magento</p></body></html>'
        rs = parse_body(html, "text/html", "https://example.com")
        assert any(r.tech == "magento" and r.confidence == "weak" for r in rs)

    def test_zendesk_detection_suppresses_rails_hotwire(self) -> None:
        """When Zendesk is detected (zendesk.com script src), rails-hotwire must NOT be emitted."""
        html = (
            b'<html><head>'
            b'<script src="https://static.zdassets.com/zendesk.com/assets/main.js"></script>'
            b'</head><body data-turbo="true"><p>Help Center</p></body></html>'
        )
        rs = parse_body(html, "text/html", "https://docs.example.com")
        techs = {r.tech for r in rs}
        assert "zendesk" in techs
        assert "rails-hotwire" not in techs


# ============================================================================
# 4. parse_tls
# ============================================================================

class TestParseTls:
    def _asset(self) -> Asset:
        return _make_asset("example.com")

    def test_self_signed_is_definitive(self) -> None:
        tls = TLSInfo(issuer="CN=example.com", subject="CN=example.com")
        probe = _make_probe(tls=tls)
        rs, hosts = parse_tls(probe, self._asset())
        assert any(r.tech == "self-signed-cert" and r.confidence == "definitive" for r in rs)
        assert any(r.evidence.startswith("tls:") for r in rs if r.tech == "self-signed-cert")

    def test_lets_encrypt_is_strong(self) -> None:
        tls = TLSInfo(issuer="C=US, O=Let's Encrypt, CN=R3", subject="CN=example.com")
        probe = _make_probe(tls=tls)
        rs, _ = parse_tls(probe, self._asset())
        assert any(r.tech == "lets-encrypt" and r.confidence == "strong" for r in rs)

    def test_cert_expired_is_definitive(self) -> None:
        expired = (datetime.now(tz=timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        tls = TLSInfo(issuer="CN=CA", subject="CN=example.com", not_after=expired)
        probe = _make_probe(tls=tls)
        rs, _ = parse_tls(probe, self._asset())
        assert any(r.tech == "cert-expired" and r.confidence == "definitive" for r in rs)

    def test_cert_expiring_soon_is_strong(self) -> None:
        soon = (datetime.now(tz=timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        tls = TLSInfo(issuer="CN=CA", subject="CN=example.com", not_after=soon)
        probe = _make_probe(tls=tls)
        rs, _ = parse_tls(probe, self._asset())
        assert any(r.tech == "cert-expiring-soon" and r.confidence == "strong" for r in rs)

    def test_valid_commercial_cert(self) -> None:
        future = (datetime.now(tz=timezone.utc) + timedelta(days=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
        tls = TLSInfo(issuer="CN=DigiCert", subject="CN=example.com", not_after=future)
        probe = _make_probe(tls=tls)
        rs, _ = parse_tls(probe, self._asset())
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
# 6. Deduplication — Principle 1 + Principle 4
# ============================================================================

class TestDedupeBoost:
    def test_single_strong_signal_no_change(self) -> None:
        results = [FingerprintResult(tech="nginx", category="web-server", confidence="strong")]
        merged = _dedupe(results)
        assert len(merged) == 1
        assert merged[0].confidence == "strong"

    def test_two_weak_signals_upgrade_to_strong(self) -> None:
        """P4: two WEAK at same tier → upgrade ONE step to STRONG."""
        results = [
            FingerprintResult(tech="nginx", category="web-server", confidence="weak",
                              evidence="header:server=nginx"),
            FingerprintResult(tech="nginx", category="web-server", confidence="weak",
                              evidence="body:script=nginx-marker"),
        ]
        merged = _dedupe(results)
        assert len(merged) == 1
        assert merged[0].confidence == "strong"
        assert "header:server=nginx" in merged[0].evidence
        assert "body:script=nginx-marker" in merged[0].evidence

    def test_three_weak_signals_still_only_strong(self) -> None:
        """P4: three WEAK → STRONG (one-tier upgrade, no double-jump)."""
        results = [
            FingerprintResult(tech="wordpress", category="cms", confidence="weak",
                              evidence="body:path=/wp-content/"),
            FingerprintResult(tech="wordpress", category="cms", confidence="weak",
                              evidence="cookie:wp-settings-"),
            FingerprintResult(tech="wordpress", category="cms", confidence="weak",
                              evidence="meta:generator=WordPress"),
        ]
        merged = _dedupe(results)
        assert len(merged) == 1
        assert merged[0].confidence == "strong"  # NOT definitive — no double-jump per P4

    def test_two_strong_signals_upgrade_to_definitive(self) -> None:
        """P4: two STRONG at same tier → upgrade to DEFINITIVE."""
        results = [
            FingerprintResult(tech="drupal", category="cms", confidence="strong",
                              evidence="header:x-drupal-cache=HIT"),
            FingerprintResult(tech="drupal", category="cms", confidence="strong",
                              evidence="body:path=/sites/default/"),
        ]
        merged = _dedupe(results)
        assert len(merged) == 1
        assert merged[0].confidence == "definitive"

    def test_definitive_absorbs_weaker(self) -> None:
        """P4: DEFINITIVE + WEAK → stays DEFINITIVE (absorbs weaker)."""
        results = [
            FingerprintResult(tech="drupal", category="cms", confidence="definitive"),
            FingerprintResult(tech="drupal", category="cms", confidence="weak"),
        ]
        merged = _dedupe(results)
        assert merged[0].confidence == "definitive"

    def test_different_techs_kept_separate(self) -> None:
        results = [
            FingerprintResult(tech="nginx", category="web-server", confidence="strong"),
            FingerprintResult(tech="php", category="language", confidence="strong"),
        ]
        merged = _dedupe(results)
        assert len(merged) == 2
        assert _tech_set(merged) == {"nginx", "php"}

    def test_single_hint_is_dropped(self) -> None:
        """P1: a single HINT signal is always dropped."""
        results = [FingerprintResult(tech="rails", category="framework", confidence="hint")]
        merged = _dedupe(results)
        assert merged == []

    def test_single_weak_is_dropped(self) -> None:
        """P1: an uncorroborated WEAK signal is always dropped."""
        results = [FingerprintResult(tech="magento", category="cms", confidence="weak",
                                     evidence="body:class=catalog-product-view")]
        merged = _dedupe(results)
        assert merged == []

    def test_weak_corroborated_by_hint_survives(self) -> None:
        """P1: WEAK + HINT (same tech) → WEAK survives (corroborated by 2nd signal)."""
        results = [
            FingerprintResult(tech="rails", category="framework", confidence="weak",
                              evidence="cookie:_session_id"),
            FingerprintResult(tech="rails", category="framework", confidence="hint",
                              evidence="header:x-runtime=0.045"),
        ]
        merged = _dedupe(results)
        # WEAK is best tier; only 1 signal at WEAK tier → no boost; len=2 → corroborated
        assert len(merged) == 1
        assert merged[0].confidence == "weak"
        assert merged[0].tech == "rails"


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

        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cur = await conn.execute("SELECT tech, confidence FROM fingerprints WHERE asset_id='A1'")
            rows = await cur.fetchall()
        db_techs = {r["tech"] for r in rows}
        assert "wordpress" in db_techs
        assert "nginx" in db_techs
        # Confidence values should be tier strings now
        conf_vals = {r["confidence"] for r in rows}
        assert conf_vals <= {"definitive", "strong", "weak", "hint"}, \
            f"Unexpected confidence values in DB: {conf_vals}"

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
        tls = TLSInfo(
            issuer="CN=CA",
            subject="DNS:example.com, DNS:www.example.com, DNS:api.example.com",
        )
        probe = _make_probe(tls=tls)
        _, hosts = parse_tls(probe, self._asset("example.com"))
        assert "api.example.com" in hosts or "www.example.com" in hosts

    def test_san_cross_domain_filtered(self) -> None:
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
    """Full pipeline with mocked probe produces fingerprint rows with tier confidence."""
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

        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cur = await conn.execute("SELECT tech, confidence FROM fingerprints")
            rows = await cur.fetchall()
        assert len(rows) > 0, "Expected fingerprint rows after pipeline"
        # All fingerprints must use tier strings
        for row in rows:
            assert row["confidence"] in ("definitive", "strong", "weak", "hint"), \
                f"Invalid confidence tier: {row['confidence']}"


async def _aiter(items: list[str]) -> Any:
    """Async generator wrapper for test patching."""
    for item in items:
        yield item


# ============================================================================
# 10. Principle tests (8 required by Phase 3.2 spec)
# ============================================================================

class TestPrinciples:

    def test_weak_signal_alone_is_dropped(self) -> None:
        """P1: a single WEAK signal with no corroboration is dropped from dedup output."""
        results = [
            FingerprintResult(tech="magento", category="cms", confidence="weak",
                              evidence="body:class=catalog-product-view")
        ]
        merged = _dedupe(results)
        assert merged == [], "Uncorroborated WEAK must be dropped (Principle 1)"

    def test_weak_signal_with_corroboration_survives(self) -> None:
        """P1: WEAK + HINT (same tech) → WEAK survives because it's corroborated."""
        results = [
            FingerprintResult(tech="rails", category="framework", confidence="weak",
                              evidence="cookie:_session_id"),
            FingerprintResult(tech="rails", category="framework", confidence="hint",
                              evidence="header:x-runtime=0.050"),
        ]
        merged = _dedupe(results)
        assert len(merged) == 1
        assert merged[0].tech == "rails"
        assert merged[0].confidence == "weak"  # no boost since only 1 WEAK; but corroborated so survives

    def test_same_category_definitive_collision_demotes_loser(self) -> None:
        """P2: two DEFINITIVE CMS detections → first keeps DEFINITIVE, second demoted to STRONG."""
        drupal = FingerprintResult(tech="drupal", category="cms", confidence="definitive",
                                   evidence="header:x-generator=Drupal 9")
        wordpress = FingerprintResult(tech="wordpress", category="cms", confidence="definitive",
                                      evidence="meta:generator=WordPress")
        out = _apply_category_exclusion([drupal, wordpress])
        techs_by_conf = {r.tech: r.confidence for r in out}
        assert "drupal" in techs_by_conf
        assert "wordpress" in techs_by_conf
        assert techs_by_conf["drupal"] == "definitive"
        assert techs_by_conf["wordpress"] == "strong"  # demoted

    def test_drupal_definitive_suppresses_magento_weak(self) -> None:
        """P2: Drupal DEFINITIVE in cms category suppresses Magento WEAK in same category."""
        drupal = FingerprintResult(tech="drupal", category="cms", confidence="definitive",
                                   evidence="header:x-generator=Drupal 9")
        magento = FingerprintResult(tech="magento", category="cms", confidence="weak",
                                    evidence="body:class=catalog-product-view")
        out = _apply_category_exclusion([drupal, magento])
        techs = {r.tech for r in out}
        assert "drupal" in techs
        assert "magento" not in techs, "WEAK Magento must be suppressed by DEFINITIVE Drupal (P2)"

    def test_zendesk_vendor_override_suppresses_rails(self) -> None:
        """P3: Zendesk at STRONG+ suppresses rails-hotwire via vendor override table."""
        zendesk = FingerprintResult(tech="zendesk", category="other", confidence="strong",
                                    evidence="body:zendesk-src")
        rails = FingerprintResult(tech="rails-hotwire", category="framework", confidence="hint",
                                  evidence="body:script=data-turbo")
        php = FingerprintResult(tech="php", category="language", confidence="strong",
                                evidence="header:x-powered-by=PHP/8.1")
        out = _apply_vendor_overrides([zendesk, rails, php])
        techs = {r.tech for r in out}
        assert "zendesk" in techs
        assert "rails-hotwire" not in techs, "rails-hotwire must be suppressed by zendesk vendor override"
        assert "php" in techs  # unrelated tech unaffected

    def test_github_pages_suppresses_cms_detections(self) -> None:
        """P3: GitHub detection suppresses CMS category detections (hosted static content)."""
        github = FingerprintResult(tech="github", category="other", confidence="strong",
                                   evidence="header:x-github-request-id=abc123")
        wordpress = FingerprintResult(tech="wordpress", category="cms", confidence="strong",
                                      evidence="body:path=/wp-content/")
        drupal = FingerprintResult(tech="drupal", category="cms", confidence="weak",
                                   evidence="body:class=drupal")
        out = _apply_vendor_overrides([github, wordpress, drupal])
        techs = {r.tech for r in out}
        assert "github" in techs
        assert "wordpress" not in techs, "CMS detections must be suppressed on GitHub-served assets"
        assert "drupal" not in techs

    def test_corroboration_upgrades_one_tier_not_two(self) -> None:
        """P4: three same-tier WEAK signals → STRONG (one tier up), NOT DEFINITIVE (no double-jump)."""
        results = [
            FingerprintResult(tech="nginx", category="web-server", confidence="weak",
                              evidence="header:server=nginx"),
            FingerprintResult(tech="nginx", category="web-server", confidence="weak",
                              evidence="body:path=/nginx_status"),
            FingerprintResult(tech="nginx", category="web-server", confidence="weak",
                              evidence="body:title=welcome to nginx"),
        ]
        merged = _dedupe(results)
        assert len(merged) == 1
        assert merged[0].confidence == "strong", (
            "Three WEAK signals → STRONG (one-tier upgrade), not DEFINITIVE"
        )

    def test_evidence_format_is_structured_per_source(self) -> None:
        """P5: evidence strings must use the 'source:key=value' structured format."""
        # Headers
        rs = parse_headers({"Server": "nginx/1.23.4"})
        nginx_r = next((r for r in rs if r.tech == "nginx"), None)
        assert nginx_r is not None
        assert nginx_r.evidence.startswith("header:")
        assert "=" in nginx_r.evidence

        # Cookies
        rs = parse_cookies(["laravel_session=abc"])
        laravel_r = next((r for r in rs if r.tech == "laravel"), None)
        assert laravel_r is not None
        assert laravel_r.evidence.startswith("cookie:")

        # Body — meta generator
        html = b'<meta name="generator" content="WordPress 6.4" />'
        rs = parse_body(html, "text/html", "https://example.com")
        wp_r = next((r for r in rs if r.tech == "wordpress" and "generator" in r.evidence), None)
        assert wp_r is not None
        assert wp_r.evidence.startswith("meta:"), f"Expected meta:, got: {wp_r.evidence}"

        # TLS
        tls = TLSInfo(issuer="CN=example.com", subject="CN=example.com")
        probe = _make_probe(tls=tls)
        rs, _ = parse_tls(probe, _make_asset())
        tls_r = next((r for r in rs if r.tech == "self-signed-cert"), None)
        assert tls_r is not None
        assert tls_r.evidence.startswith("tls:")
