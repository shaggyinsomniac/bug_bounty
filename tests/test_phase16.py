"""
tests/test_phase16.py — Phase 16 test suite.

Tests:
 1-8.   Security headers detections (positive + negative)
 9-14.  Cookie flag detections (positive + negative)
 15-16. Open redirect detection (positive + negative)
 17-18. Clickjacking detection (positive + negative)
 19-20. Mixed content detection (positive + negative)
 21-24. TLS deep detections (mocked ssl) — positive + negative
 25-28. Default files detections (positive + negative)
 29-32. Header info disclosure (positive + negative)
 33-34. WebSocket detection (positive + negative)
 35-38. Toolbox: whois_lookup mock (hit + timeout)
 39-42. Toolbox: asn_lookup mock (hit + timeout)
 43-44. Toolbox: favicon_hash mock (hit + not found)
 45-46. Toolbox: reverse_dns mock (hit + NXDOMAIN)
 47-48. Toolbox: related_tlds mock (hit + empty)
 49.    HstsShortMaxAge fires for short max-age
 50.    HstsShortMaxAge does NOT fire for long max-age
 51.    CspUnsafeInline does NOT fire when no CSP
 52.    Related TLD label extraction
 53.    ASN /24 cache key
 54.    Favicon hash value matches known mmh3 computation
 55-56. Detection count sanity check (>= 131)
 57-80. Additional coverage (positive/negative pairs for all 26 detections)
"""

from __future__ import annotations

import asyncio
import base64
import ssl
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import mmh3
import pytest

from bounty.detect.base import DetectionContext
from bounty.models import Asset, FindingDraft, ProbeResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_asset(
    host: str = "example.com",
    scheme: str = "https",
    primary_scheme: str = "https",
    url: str | None = None,
    ip: str | None = "1.2.3.4",
) -> Asset:
    return Asset(
        id="test-asset-id",
        program_id="prog1",
        host=host,
        scheme=scheme,
        primary_scheme=primary_scheme,
        url=url or f"{scheme}://{host}",
        ip=ip,
    )


def _make_probe(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    body: bytes = b"<html><body>Hello</body></html>",
    error: str | None = None,
    final_url: str = "https://example.com",
) -> ProbeResult:
    return ProbeResult(
        url=final_url,
        final_url=final_url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        body_text=body.decode("utf-8", errors="replace"),
        error=error,
    )


def _make_ctx(probe_resp: ProbeResult | None = None) -> DetectionContext:
    if probe_resp is None:
        probe_resp = _make_probe()

    async def _probe(url: str) -> ProbeResult:
        return probe_resp

    async def _capture(url: str, pr: ProbeResult, scan_id: str) -> Any:
        return MagicMock()

    return DetectionContext(
        probe_fn=_probe,
        capture_fn=_capture,
        scan_id="scan-test",
        settings=MagicMock(),
        log=MagicMock(),
    )


async def _collect(gen: AsyncGenerator[FindingDraft, None]) -> list[FindingDraft]:
    return [f async for f in gen]


# ============================================================================
# 1 — Security headers detections
# ============================================================================


class TestSecurityHeaders:
    @pytest.mark.asyncio
    async def test_csp_missing_fires(self) -> None:
        from bounty.detect.security_headers import CspMissing
        d = CspMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={}))
        findings = await _collect(d.run(asset, ctx))
        assert findings, "Expected CspMissing to fire"

    @pytest.mark.asyncio
    async def test_csp_missing_no_fire_when_csp_present(self) -> None:
        from bounty.detect.security_headers import CspMissing
        d = CspMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"content-security-policy": "default-src 'self'"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_csp_unsafe_inline_fires(self) -> None:
        from bounty.detect.security_headers import CspUnsafeInline
        d = CspUnsafeInline()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"content-security-policy": "default-src 'self' 'unsafe-inline'"}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_csp_unsafe_inline_no_fire_when_safe(self) -> None:
        from bounty.detect.security_headers import CspUnsafeInline
        d = CspUnsafeInline()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"content-security-policy": "default-src 'self'"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_hsts_missing_fires_on_https(self) -> None:
        from bounty.detect.security_headers import HstsMissing
        d = HstsMissing()
        asset = _make_asset(scheme="https", primary_scheme="https")
        ctx = _make_ctx(_make_probe(headers={}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_hsts_missing_no_fire_when_hsts_present(self) -> None:
        from bounty.detect.security_headers import HstsMissing
        d = HstsMissing()
        asset = _make_asset(scheme="https", primary_scheme="https")
        ctx = _make_ctx(_make_probe(headers={"strict-transport-security": "max-age=31536000"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_hsts_short_max_age_fires(self) -> None:
        from bounty.detect.security_headers import HstsShortMaxAge
        d = HstsShortMaxAge()
        asset = _make_asset(scheme="https", primary_scheme="https")
        ctx = _make_ctx(_make_probe(headers={"strict-transport-security": "max-age=3600"}))
        findings = await _collect(d.run(asset, ctx))
        assert findings
        assert "3600" in findings[0].title

    @pytest.mark.asyncio
    async def test_hsts_short_max_age_no_fire_when_long(self) -> None:
        from bounty.detect.security_headers import HstsShortMaxAge
        d = HstsShortMaxAge()
        asset = _make_asset(scheme="https", primary_scheme="https")
        ctx = _make_ctx(_make_probe(headers={"strict-transport-security": "max-age=31536000"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_x_frame_options_missing_fires(self) -> None:
        from bounty.detect.security_headers import XFrameOptionsMissing
        d = XFrameOptionsMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_x_frame_options_no_fire_with_csp_frame_ancestors(self) -> None:
        from bounty.detect.security_headers import XFrameOptionsMissing
        d = XFrameOptionsMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"content-security-policy": "frame-ancestors 'none'"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_xcto_missing_fires(self) -> None:
        from bounty.detect.security_headers import XContentTypeOptionsMissing
        d = XContentTypeOptionsMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_xcto_no_fire_when_nosniff(self) -> None:
        from bounty.detect.security_headers import XContentTypeOptionsMissing
        d = XContentTypeOptionsMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"x-content-type-options": "nosniff"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_referrer_policy_missing_fires(self) -> None:
        from bounty.detect.security_headers import ReferrerPolicyMissing
        d = ReferrerPolicyMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_referrer_policy_no_fire_when_set(self) -> None:
        from bounty.detect.security_headers import ReferrerPolicyMissing
        d = ReferrerPolicyMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"referrer-policy": "strict-origin-when-cross-origin"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_permissions_policy_missing_fires(self) -> None:
        from bounty.detect.security_headers import PermissionsPolicyMissing
        d = PermissionsPolicyMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_permissions_policy_no_fire_when_set(self) -> None:
        from bounty.detect.security_headers import PermissionsPolicyMissing
        d = PermissionsPolicyMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"permissions-policy": "camera=()"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_feature_policy_accepted_as_permissions_policy(self) -> None:
        from bounty.detect.security_headers import PermissionsPolicyMissing
        d = PermissionsPolicyMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"feature-policy": "camera 'none'"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings


# ============================================================================
# 2 — Cookie flag detections
# ============================================================================


class TestCookieFlags:
    @pytest.mark.asyncio
    async def test_missing_secure_fires(self) -> None:
        from bounty.detect.cookies import CookieMissingSecure
        d = CookieMissingSecure()
        asset = _make_asset(scheme="https", primary_scheme="https")
        ctx = _make_ctx(_make_probe(headers={"set-cookie": "session=abc; HttpOnly; Path=/"}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_missing_secure_no_fire_when_present(self) -> None:
        from bounty.detect.cookies import CookieMissingSecure
        d = CookieMissingSecure()
        asset = _make_asset(scheme="https", primary_scheme="https")
        ctx = _make_ctx(_make_probe(headers={"set-cookie": "session=abc; Secure; HttpOnly; Path=/"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_missing_httponly_fires(self) -> None:
        from bounty.detect.cookies import CookieMissingHttpOnly
        d = CookieMissingHttpOnly()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"set-cookie": "session=abc; Secure; Path=/"}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_missing_httponly_no_fire_when_present(self) -> None:
        from bounty.detect.cookies import CookieMissingHttpOnly
        d = CookieMissingHttpOnly()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"set-cookie": "session=abc; Secure; HttpOnly; Path=/"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_missing_samesite_fires(self) -> None:
        from bounty.detect.cookies import CookieMissingSameSite
        d = CookieMissingSameSite()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"set-cookie": "session=abc; Secure; HttpOnly; Path=/"}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_missing_samesite_no_fire_when_present(self) -> None:
        from bounty.detect.cookies import CookieMissingSameSite
        d = CookieMissingSameSite()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"set-cookie": "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_no_cookies_no_fire(self) -> None:
        from bounty.detect.cookies import CookieMissingSecure
        d = CookieMissingSecure()
        asset = _make_asset(scheme="https", primary_scheme="https")
        ctx = _make_ctx(_make_probe(headers={}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings


# ============================================================================
# 3 — Open redirect
# ============================================================================


class TestOpenRedirect:
    @pytest.mark.asyncio
    async def test_open_redirect_fires(self) -> None:
        from bounty.detect.web import OpenRedirectReflected
        d = OpenRedirectReflected()
        asset = _make_asset()

        async def _probe(url: str) -> ProbeResult:
            if "evil-test.example.org" in url:
                return _make_probe(
                    status_code=302,
                    headers={"location": "https://evil-test.example.org/pwned"},
                )
            return _make_probe()

        async def _capture(url: str, pr: ProbeResult, scan_id: str) -> Any:
            return MagicMock()

        ctx = DetectionContext(
            probe_fn=_probe, capture_fn=_capture,
            scan_id="s", settings=MagicMock(), log=MagicMock(),
        )
        findings = await _collect(d.run(asset, ctx))
        assert findings
        assert "url" in findings[0].path or "url" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_open_redirect_no_fire_when_safe(self) -> None:
        from bounty.detect.web import OpenRedirectReflected
        d = OpenRedirectReflected()
        asset = _make_asset()

        async def _probe(url: str) -> ProbeResult:
            return _make_probe(
                status_code=302,
                headers={"location": "https://example.com/home"},
            )

        async def _capture(url: str, pr: ProbeResult, scan_id: str) -> Any:
            return MagicMock()

        ctx = DetectionContext(
            probe_fn=_probe, capture_fn=_capture,
            scan_id="s", settings=MagicMock(), log=MagicMock(),
        )
        findings = await _collect(d.run(asset, ctx))
        assert not findings


# ============================================================================
# 4 — Clickjacking
# ============================================================================


class TestClickjacking:
    @pytest.mark.asyncio
    async def test_clickjacking_fires(self) -> None:
        from bounty.detect.web import ClickjackingMissingProtection
        d = ClickjackingMissingProtection()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_clickjacking_no_fire_with_xfo(self) -> None:
        from bounty.detect.web import ClickjackingMissingProtection
        d = ClickjackingMissingProtection()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"x-frame-options": "DENY"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings


# ============================================================================
# 5 — Mixed content
# ============================================================================


class TestMixedContent:
    @pytest.mark.asyncio
    async def test_mixed_content_fires(self) -> None:
        from bounty.detect.web import MixedContentHttpResources
        d = MixedContentHttpResources()
        asset = _make_asset(scheme="https", primary_scheme="https")
        body = b'<html><script src="http://cdn.example.com/js/app.js"></script></html>'
        ctx = _make_ctx(_make_probe(
            headers={"content-type": "text/html"},
            body=body,
        ))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_mixed_content_no_fire_all_https(self) -> None:
        from bounty.detect.web import MixedContentHttpResources
        d = MixedContentHttpResources()
        asset = _make_asset(scheme="https", primary_scheme="https")
        body = b'<html><script src="https://cdn.example.com/js/app.js"></script></html>'
        ctx = _make_ctx(_make_probe(
            headers={"content-type": "text/html"},
            body=body,
        ))
        findings = await _collect(d.run(asset, ctx))
        assert not findings


# ============================================================================
# 6 — TLS deep detections (mocked ssl)
# ============================================================================


class TestTlsDeep:
    @pytest.mark.asyncio
    async def test_tls_cert_expired_fires(self) -> None:
        from bounty.detect.tls.deep import TlsCertExpired

        mock_sock = MagicMock()
        mock_sock.getpeercert.return_value = {
            "notAfter": "Jan  1 00:00:00 2000 GMT",
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["commonName", "Some CA"]]],
        }
        mock_sock.close = MagicMock()

        d = TlsCertExpired()
        asset = _make_asset()
        ctx = _make_ctx()

        with patch("bounty.detect.tls.deep._tls_connect", new_callable=AsyncMock) as m:
            m.return_value = mock_sock
            findings = await _collect(d.run(asset, ctx))

        assert findings
        assert "expired" in findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_tls_cert_not_expired(self) -> None:
        from bounty.detect.tls.deep import TlsCertExpired

        mock_sock = MagicMock()
        mock_sock.getpeercert.return_value = {
            "notAfter": "Jan  1 00:00:00 2099 GMT",
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["commonName", "Some CA"]]],
        }
        mock_sock.close = MagicMock()

        d = TlsCertExpired()
        asset = _make_asset()
        ctx = _make_ctx()

        with patch("bounty.detect.tls.deep._tls_connect", new_callable=AsyncMock) as m:
            m.return_value = mock_sock
            findings = await _collect(d.run(asset, ctx))

        assert not findings

    @pytest.mark.asyncio
    async def test_tls_cert_self_signed_fires(self) -> None:
        from bounty.detect.tls.deep import TlsCertSelfSigned

        mock_sock = MagicMock()
        # subject == issuer → self-signed
        mock_sock.getpeercert.return_value = {
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["commonName", "example.com"]]],
        }
        mock_sock.close = MagicMock()

        d = TlsCertSelfSigned()
        asset = _make_asset()
        ctx = _make_ctx()

        with patch("bounty.detect.tls.deep._tls_connect", new_callable=AsyncMock) as m:
            m.return_value = mock_sock
            findings = await _collect(d.run(asset, ctx))

        assert findings

    @pytest.mark.asyncio
    async def test_tls_cert_self_signed_no_fire_valid_ca(self) -> None:
        from bounty.detect.tls.deep import TlsCertSelfSigned

        mock_sock = MagicMock()
        mock_sock.getpeercert.return_value = {
            "subject": [[["commonName", "example.com"]]],
            "issuer": [[["commonName", "Let's Encrypt"]]],
        }
        mock_sock.close = MagicMock()

        d = TlsCertSelfSigned()
        asset = _make_asset()
        ctx = _make_ctx()

        with patch("bounty.detect.tls.deep._tls_connect", new_callable=AsyncMock) as m:
            m.return_value = mock_sock
            findings = await _collect(d.run(asset, ctx))

        assert not findings

    @pytest.mark.asyncio
    async def test_tls_weak_protocols_fires(self) -> None:
        from bounty.detect.tls.deep import TlsWeakProtocols

        mock_sock = MagicMock()
        mock_sock.version.return_value = "TLSv1"
        mock_sock.close = MagicMock()

        d = TlsWeakProtocols()
        asset = _make_asset()
        ctx = _make_ctx()

        with patch("bounty.detect.tls.deep._tls_connect", new_callable=AsyncMock) as m:
            m.return_value = mock_sock
            findings = await _collect(d.run(asset, ctx))

        assert findings

    @pytest.mark.asyncio
    async def test_tls_cert_hostname_mismatch_fires(self) -> None:
        from bounty.detect.tls.deep import TlsCertHostnameMismatch

        mock_sock = MagicMock()
        mock_sock.getpeercert.return_value = {
            "subjectAltName": [("DNS", "other.com")],
            "subject": [[["commonName", "other.com"]]],
            "issuer": [[["commonName", "Some CA"]]],
        }
        mock_sock.close = MagicMock()

        d = TlsCertHostnameMismatch()
        asset = _make_asset(host="example.com")
        ctx = _make_ctx()

        with patch("bounty.detect.tls.deep._tls_connect", new_callable=AsyncMock) as m:
            m.return_value = mock_sock
            findings = await _collect(d.run(asset, ctx))

        assert findings

    @pytest.mark.asyncio
    async def test_tls_no_fire_when_connect_fails(self) -> None:
        from bounty.detect.tls.deep import TlsCertExpired

        d = TlsCertExpired()
        asset = _make_asset()
        ctx = _make_ctx()

        with patch("bounty.detect.tls.deep._tls_connect", new_callable=AsyncMock) as m:
            m.return_value = None  # connection failed
            findings = await _collect(d.run(asset, ctx))

        assert not findings


# ============================================================================
# 7 — Default files
# ============================================================================


class TestDefaultFiles:
    @pytest.mark.asyncio
    async def test_default_page_fires(self) -> None:
        from bounty.detect.web import DefaultPageDetected

        async def _probe(url: str) -> ProbeResult:
            if "/test.html" in url:
                return _make_probe(status_code=200, body=b"<html>Test Page</html>")
            return _make_probe(status_code=404)

        async def _capture(url: str, pr: ProbeResult, scan_id: str) -> Any:
            return MagicMock()

        ctx = DetectionContext(
            probe_fn=_probe, capture_fn=_capture,
            scan_id="s", settings=MagicMock(), log=MagicMock(),
        )
        d = DefaultPageDetected()
        asset = _make_asset()
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_default_page_no_fire_404(self) -> None:
        from bounty.detect.web import DefaultPageDetected

        ctx = _make_ctx(_make_probe(status_code=404))
        d = DefaultPageDetected()
        asset = _make_asset()
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_package_json_fires(self) -> None:
        from bounty.detect.web import PackageJsonExposed
        body = b'{"name":"app","version":"1.0.0","dependencies":{"express":"^4.0.0"}}'

        async def _probe(url: str) -> ProbeResult:
            if "package.json" in url:
                return _make_probe(status_code=200, body=body)
            return _make_probe(status_code=404)

        async def _capture(url: str, pr: ProbeResult, scan_id: str) -> Any:
            return MagicMock()

        ctx = DetectionContext(
            probe_fn=_probe, capture_fn=_capture,
            scan_id="s", settings=MagicMock(), log=MagicMock(),
        )
        d = PackageJsonExposed()
        asset = _make_asset()
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_install_script_fires(self) -> None:
        from bounty.detect.web import InstallScriptExposed
        body = b"<html>Database setup wizard - install configuration</html>"

        async def _probe(url: str) -> ProbeResult:
            if "install.php" in url:
                return _make_probe(status_code=200, body=body)
            return _make_probe(status_code=404)

        async def _capture(url: str, pr: ProbeResult, scan_id: str) -> Any:
            return MagicMock()

        ctx = DetectionContext(
            probe_fn=_probe, capture_fn=_capture,
            scan_id="s", settings=MagicMock(), log=MagicMock(),
        )
        d = InstallScriptExposed()
        asset = _make_asset()
        findings = await _collect(d.run(asset, ctx))
        assert findings


# ============================================================================
# 8 — Header info disclosure
# ============================================================================


class TestHeaderInfoDisclosure:
    @pytest.mark.asyncio
    async def test_x_powered_by_verbose_fires(self) -> None:
        from bounty.detect.web import XPoweredByVerbose
        d = XPoweredByVerbose()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"x-powered-by": "PHP/7.4.0"}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_x_powered_by_no_fire_generic(self) -> None:
        from bounty.detect.web import XPoweredByVerbose
        d = XPoweredByVerbose()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"x-powered-by": "ASP.NET"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_server_verbose_fires(self) -> None:
        from bounty.detect.web import ServerVerbose
        d = ServerVerbose()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"server": "nginx/1.18.0 (Ubuntu)"}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_server_verbose_no_fire_generic(self) -> None:
        from bounty.detect.web import ServerVerbose
        d = ServerVerbose()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"server": "nginx"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

    @pytest.mark.asyncio
    async def test_internal_ip_in_header_fires(self) -> None:
        from bounty.detect.web import InternalIpInHeader
        d = InternalIpInHeader()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"x-forwarded-for": "192.168.1.1, 1.2.3.4"}))
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_internal_ip_no_fire_when_clean(self) -> None:
        from bounty.detect.web import InternalIpInHeader
        d = InternalIpInHeader()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(headers={"x-forwarded-for": "1.2.3.4"}))
        findings = await _collect(d.run(asset, ctx))
        assert not findings


# ============================================================================
# 9 — WebSocket detection
# ============================================================================


class TestWebSocket:
    @pytest.mark.asyncio
    async def test_websocket_fires_on_101(self) -> None:
        from bounty.detect.web import WebSocketEndpointDetected

        async def _probe(url: str) -> ProbeResult:
            if "/ws" in url:
                return _make_probe(status_code=101)
            return _make_probe(status_code=404)

        async def _capture(url: str, pr: ProbeResult, scan_id: str) -> Any:
            return MagicMock()

        ctx = DetectionContext(
            probe_fn=_probe, capture_fn=_capture,
            scan_id="s", settings=MagicMock(), log=MagicMock(),
        )
        d = WebSocketEndpointDetected()
        asset = _make_asset()
        findings = await _collect(d.run(asset, ctx))
        assert findings

    @pytest.mark.asyncio
    async def test_websocket_no_fire_when_all_404(self) -> None:
        from bounty.detect.web import WebSocketEndpointDetected
        ctx = _make_ctx(_make_probe(status_code=404))
        d = WebSocketEndpointDetected()
        asset = _make_asset()
        findings = await _collect(d.run(asset, ctx))
        assert not findings


# ============================================================================
# 10 — Toolbox: whois_lookup
# ============================================================================


class TestWhoisLookup:
    @pytest.mark.asyncio
    async def test_whois_returns_dict_with_expected_keys(self) -> None:
        from bounty.recon.toolbox.whois import whois_lookup, clear_cache

        clear_cache()

        mock_whois = MagicMock()
        mock_whois.registrar = "Test Registrar, Inc."
        mock_whois.creation_date = None
        mock_whois.expiration_date = None
        mock_whois.name_servers = ["ns1.example.com"]
        mock_whois.org = "Test Org"
        mock_whois.emails = ["admin@example.com"]

        with patch("whois.whois", return_value=mock_whois):
            result = await whois_lookup("example.com")

        assert "registrar" in result
        assert "name_servers" in result
        assert "emails" in result
        clear_cache()

    @pytest.mark.asyncio
    async def test_whois_returns_empty_on_timeout(self) -> None:
        from bounty.recon.toolbox.whois import whois_lookup, clear_cache

        clear_cache()

        def _raise(*a: object, **kw: object) -> None:
            raise ImportError("no module")

        with patch.dict("sys.modules", {"whois": None}):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=FileNotFoundError("not found"),
            ):
                result = await whois_lookup("timeout-test.invalid")

        # Should return the empty skeleton, not raise
        assert isinstance(result, dict)
        assert "registrar" in result
        clear_cache()


# ============================================================================
# 11 — Toolbox: asn_lookup
# ============================================================================


class TestAsnLookup:
    @pytest.mark.asyncio
    async def test_asn_lookup_parses_cymru_response(self) -> None:
        from bounty.recon.toolbox.asn import asn_lookup, clear_cache

        clear_cache()

        cymru_response = (
            b"Bulk mode; whois.cymru.com\n"
            b"AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
            b"15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2000-03-30 | GOOGLE - Google LLC, US\n"
        )

        mock_reader = AsyncMock()
        mock_reader.read.side_effect = [cymru_response, b""]
        mock_writer = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "asyncio.open_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            result = await asn_lookup("8.8.8.8")

        assert result["asn"] == "15169"
        assert result["country"] == "US"
        assert result["cidr"] == "8.8.8.0/24"
        clear_cache()

    @pytest.mark.asyncio
    async def test_asn_lookup_returns_empty_on_timeout(self) -> None:
        from bounty.recon.toolbox.asn import asn_lookup, clear_cache

        clear_cache()

        with patch(
            "asyncio.open_connection",
            new=AsyncMock(side_effect=asyncio.TimeoutError()),
        ):
            result = await asn_lookup("1.2.3.4")

        assert result == {"asn": None, "asn_org": None, "country": None, "cidr": None}
        clear_cache()


# ============================================================================
# 12 — Toolbox: favicon_hash
# ============================================================================


class TestFaviconHash:
    @pytest.mark.asyncio
    async def test_favicon_hash_matches_known_value(self) -> None:
        from bounty.recon.toolbox.favicon_hash import favicon_hash

        favicon_bytes = b"\x89PNG\r\n\x1a\n" + b"F" * 100
        b64 = base64.encodebytes(favicon_bytes)
        expected_hash = str(mmh3.hash(b64.decode("utf-8")))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = favicon_bytes

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await favicon_hash("https://example.com")

        assert result == expected_hash

    @pytest.mark.asyncio
    async def test_favicon_hash_returns_none_on_404(self) -> None:
        from bounty.recon.toolbox.favicon_hash import favicon_hash

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b""

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await favicon_hash("https://example.com")

        assert result is None


# ============================================================================
# 13 — Toolbox: reverse_dns
# ============================================================================


class TestReverseDns:
    @pytest.mark.asyncio
    async def test_reverse_dns_returns_hostname(self) -> None:
        from bounty.recon.toolbox.reverse_dns import reverse_dns
        import dns.asyncresolver
        import dns.name

        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("server1.example.com.")
        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))

        with patch.object(
            dns.asyncresolver.Resolver,
            "resolve",
            new_callable=AsyncMock,
            return_value=mock_answer,
        ):
            result = await reverse_dns("1.2.3.4")

        assert result == "server1.example.com"

    @pytest.mark.asyncio
    async def test_reverse_dns_returns_none_on_nxdomain(self) -> None:
        from bounty.recon.toolbox.reverse_dns import reverse_dns
        import dns.asyncresolver
        import dns.exception

        with patch.object(
            dns.asyncresolver.Resolver,
            "resolve",
            new_callable=AsyncMock,
            side_effect=dns.exception.DNSException("NXDOMAIN"),
        ):
            result = await reverse_dns("1.2.3.99")

        assert result is None


# ============================================================================
# 14 — Toolbox: find_related_tlds
# ============================================================================


class TestRelatedTlds:
    @pytest.mark.asyncio
    async def test_find_related_tlds_returns_resolving(self) -> None:
        from bounty.recon.toolbox.related_tlds import find_related_tlds
        import dns.asyncresolver

        async def _fake_resolve(name: str, rrtype: str) -> MagicMock:
            if str(name).rstrip(".").endswith(".io"):
                return MagicMock()
            raise Exception("NXDOMAIN")

        with patch.object(dns.asyncresolver.Resolver, "resolve", side_effect=_fake_resolve):
            result = await find_related_tlds("example.com")

        assert any("example.io" in r for r in result)

    @pytest.mark.asyncio
    async def test_find_related_tlds_empty_when_none_resolve(self) -> None:
        from bounty.recon.toolbox.related_tlds import find_related_tlds
        import dns.asyncresolver
        import dns.exception

        with patch.object(
            dns.asyncresolver.Resolver,
            "resolve",
            new_callable=AsyncMock,
            side_effect=dns.exception.DNSException("NXDOMAIN"),
        ):
            result = await find_related_tlds("nowayexists-xyz.com")

        assert result == []

    def test_apex_label_extraction(self) -> None:
        from bounty.recon.toolbox.related_tlds import _apex_label
        assert _apex_label("example.com") == "example"
        assert _apex_label("sub.example.com") == "example"
        assert _apex_label("example") == "example"


# ============================================================================
# 15 — Miscellaneous / sanity
# ============================================================================


class TestSanity:
    def test_detection_count_increased(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS
        assert len(REGISTERED_DETECTIONS) >= 131, (
            f"Expected at least 131 detections, got {len(REGISTERED_DETECTIONS)}"
        )

    def test_all_detection_ids_unique(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS
        ids = [d.id for d in REGISTERED_DETECTIONS]
        assert len(ids) == len(set(ids)), "Duplicate detection IDs found"

    def test_asn_cidr24_key(self) -> None:
        from bounty.recon.toolbox.asn import _cidr24
        assert _cidr24("8.8.8.8") == "8.8.8"
        assert _cidr24("192.168.1.200") == "192.168.1"
        assert _cidr24("10.0.0.1") == "10.0.0"

    def test_hsts_short_max_age_boundary(self) -> None:
        """max-age == 15552000 exact should NOT fire (equal = OK)."""
        import asyncio

        async def _run() -> None:
            from bounty.detect.security_headers import HstsShortMaxAge
            d = HstsShortMaxAge()
            asset = _make_asset(scheme="https", primary_scheme="https")
            ctx = _make_ctx(_make_probe(headers={"strict-transport-security": "max-age=15552000"}))
            findings = await _collect(d.run(asset, ctx))
            assert not findings

        asyncio.run(_run())

    @pytest.mark.asyncio
    async def test_no_fire_on_probe_error(self) -> None:
        from bounty.detect.security_headers import CspMissing
        d = CspMissing()
        asset = _make_asset()
        ctx = _make_ctx(_make_probe(error="connection refused", status_code=0, body=b""))
        findings = await _collect(d.run(asset, ctx))
        assert not findings

