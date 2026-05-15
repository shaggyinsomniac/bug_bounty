"""
tests/test_phase13.py — Phase 13: Subdomain takeover, CORS, mail, DNS, Discovery detections.

Test sections:
 1. SubdomainTakeover   — CNAME mocking (10 tests)
 2. CorsWildcardWithCredentials (8 tests)
 3. CorsNullOrigin (6 tests)
 4. CorsPreflightWildcard (6 tests)
 5. SpfMissing (6 tests)
 6. SpfWeak (6 tests)
 7. DmarcMissing (6 tests)
 8. DmarcWeak (6 tests)
 9. DkimNotFound (6 tests)
10. ZoneTransferAllowed (8 tests)
11. RobotsSensitivePaths (8 tests)
12. SitemapExposed (8 tests)
13. Registry integration (6 tests)
14. DetectionContext.claim_apex dedup logic (4 tests)

Total: ~94 tests
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bounty.detect.base import DetectionContext
from bounty.models import (
    Asset,
    ConfidenceTier,
    EvidencePackage,
    FindingDraft,
    FingerprintResult,
    ProbeResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pr(
    *,
    status_code: int = 200,
    body: bytes = b"",
    ct: str = "text/html",
    url: str = "https://example.com/",
    headers: dict[str, str] | None = None,
    final_url: str | None = None,
) -> ProbeResult:
    h: dict[str, str] = dict(headers or {})
    if ct:
        h.setdefault("content-type", ct)
    return ProbeResult(
        url=url,
        final_url=final_url or url,
        status_code=status_code,
        headers=h,
        body=body,
        body_text=body.decode("utf-8", errors="replace"),
    )


def _html_pr(html: str, *, status_code: int = 200) -> ProbeResult:
    return _pr(status_code=status_code, body=html.encode(), ct="text/html")


async def _noop_capture(url: str, pr: ProbeResult, scan_id: str) -> EvidencePackage:
    return EvidencePackage(kind="http", response_status=pr.status_code)


def _ctx(
    responses: dict[str, ProbeResult] | None = None,
    headers_responses: dict[str, dict[str, ProbeResult]] | None = None,
) -> DetectionContext:
    import structlog
    from bounty.config import get_settings

    resp_map = responses or {}

    async def _probe(url: str) -> ProbeResult:
        if url in resp_map:
            return resp_map[url]
        for pattern, resp in resp_map.items():
            if pattern in url or url.endswith(pattern):
                return resp
        return _pr(status_code=404, body=b"Not Found")

    async def _probe_headers(url: str, hdrs: dict[str, str]) -> ProbeResult:
        h_map = headers_responses or {}
        origin = hdrs.get("Origin", "")
        inner = h_map.get(url, h_map.get(origin, {}))
        if isinstance(inner, ProbeResult):
            return inner
        if isinstance(inner, dict):
            # inner is { origin_value: ProbeResult }
            if origin in inner:
                return inner[origin]
        # fallback to regular probe
        return await _probe(url)

    return DetectionContext(
        probe_fn=_probe,
        capture_fn=_noop_capture,
        probe_fn_with_headers=_probe_headers,
        scan_id="scan-phase13-test",
        settings=get_settings(),
        log=structlog.get_logger(),
    )


def _asset(
    host: str = "example.com",
    port: int | None = None,
    http_status: int | None = 200,
) -> Asset:
    scheme = "https"
    url = f"{scheme}://{host}" + (f":{port}" if port else "")
    return Asset(
        id="01TEST000000000000000PHASE13",
        program_id="prog_test",
        host=host,
        port=port,
        url=url,
        scheme=scheme,
        primary_scheme=scheme,
        http_status=http_status,
    )


async def _collect(det: Any, asset: Asset, ctx: DetectionContext) -> list[FindingDraft]:
    return [f async for f in det.run(asset, ctx)]


# ===========================================================================
# 1. SubdomainTakeover
# ===========================================================================

from bounty.detect.takeover import SubdomainTakeover


class TestSubdomainTakeover:
    det = SubdomainTakeover()

    def test_applicable_to_hostname(self) -> None:
        assert self.det.applicable_to(_asset("sub.example.com"), [])

    def test_not_applicable_to_ip(self) -> None:
        asset = _asset("192.168.1.1")
        assert not self.det.applicable_to(asset, [])

    @pytest.mark.asyncio
    async def test_github_pages_takeover(self) -> None:
        """CNAME → github.io + body with unclaimed fingerprint → finding."""
        body = b"There isn't a GitHub Pages site here."
        pr_404 = _pr(status_code=404, body=body)
        ctx = _ctx({"https://sub.example.com": pr_404})

        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(return_value=["username.github.io"]),
        ):
            findings = await _collect(self.det, _asset("sub.example.com"), ctx)

        assert len(findings) == 1
        assert findings[0].severity == 800
        assert "GitHub Pages" in findings[0].title
        assert "takeover" in findings[0].category

    @pytest.mark.asyncio
    async def test_heroku_takeover(self) -> None:
        body = b"No such app"
        pr_404 = _pr(status_code=404, body=body)
        ctx = _ctx({"https://app.example.com": pr_404})

        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(return_value=["myapp.herokudns.com"]),
        ):
            findings = await _collect(self.det, _asset("app.example.com"), ctx)

        assert len(findings) == 1
        assert "Heroku" in findings[0].title

    @pytest.mark.asyncio
    async def test_s3_bucket_takeover(self) -> None:
        body = b"<Code>NoSuchBucket</Code>"
        pr_404 = _pr(status_code=404, body=body)
        ctx = _ctx({"https://assets.example.com": pr_404})

        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(return_value=["mybucket.s3.amazonaws.com"]),
        ):
            findings = await _collect(self.det, _asset("assets.example.com"), ctx)

        assert len(findings) == 1
        assert "S3" in findings[0].title

    @pytest.mark.asyncio
    async def test_no_cname_no_finding(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(return_value=[]),
        ):
            findings = await _collect(self.det, _asset("sub.example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_cname_matches_but_body_does_not(self) -> None:
        """CNAME points to Heroku but site appears to be claimed."""
        body = b"<html><h1>Welcome to our app!</h1></html>"
        pr_ok = _pr(status_code=200, body=body)
        ctx = _ctx({"https://sub.example.com": pr_ok})

        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(return_value=["myapp.herokudns.com"]),
        ):
            findings = await _collect(self.det, _asset("sub.example.com"), ctx)

        assert findings == []

    @pytest.mark.asyncio
    async def test_cname_no_known_service(self) -> None:
        """CNAME is to an unknown service — no finding."""
        ctx = _ctx()
        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(return_value=["other.unknowncdn.com"]),
        ):
            findings = await _collect(self.det, _asset("sub.example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_netlify_takeover(self) -> None:
        body = b"Not Found - Request ID"
        pr = _pr(status_code=404, body=body)
        ctx = _ctx({"https://docs.example.com": pr})

        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(return_value=["mysite.netlify.com"]),
        ):
            findings = await _collect(self.det, _asset("docs.example.com"), ctx)

        assert len(findings) == 1
        assert "Netlify" in findings[0].title

    @pytest.mark.asyncio
    async def test_dns_error_graceful(self) -> None:
        """DNS resolution error → no finding, no exception raised."""
        import dns.exception

        ctx = _ctx()
        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(side_effect=dns.exception.DNSException("timeout")),
        ):
            findings = await _collect(self.det, _asset("sub.example.com"), ctx)

        assert findings == []

    @pytest.mark.asyncio
    async def test_vercel_takeover(self) -> None:
        body = b"The deployment you are looking for does not exist"
        pr = _pr(status_code=404, body=body)
        ctx = _ctx({"https://preview.example.com": pr})

        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(return_value=["mysite.vercel.app"]),
        ):
            findings = await _collect(self.det, _asset("preview.example.com"), ctx)

        assert len(findings) == 1
        assert findings[0].severity == 800

    @pytest.mark.asyncio
    async def test_dedup_key_includes_service(self) -> None:
        body = b"There isn't a GitHub Pages site here."
        pr = _pr(status_code=404, body=body)
        ctx = _ctx({"https://sub.example.com": pr})

        with patch(
            "bounty.detect.takeover.subdomain_takeover._resolve_cname_chain",
            AsyncMock(return_value=["user.github.io"]),
        ):
            findings = await _collect(self.det, _asset("sub.example.com"), ctx)

        assert len(findings) == 1
        assert "GitHub Pages" in findings[0].dedup_key


# ===========================================================================
# 2. CorsWildcardWithCredentials
# ===========================================================================

from bounty.detect.cors import CorsWildcardWithCredentials, CorsNullOrigin, CorsPreflightWildcard


class TestCorsWildcardWithCredentials:
    det = CorsWildcardWithCredentials()

    def test_applicable_to_normal_asset(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    def test_not_applicable_to_500_asset(self) -> None:
        assert not self.det.applicable_to(_asset(http_status=500), [])

    @pytest.mark.asyncio
    async def test_fires_on_reflected_origin_with_credentials(self) -> None:
        h = {
            "access-control-allow-origin": "https://evil.example.com",
            "access-control-allow-credentials": "true",
        }
        pr = _pr(headers=h)

        async def _fake_probe_headers(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr(status_code=404)),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake_probe_headers,
            scan_id="scan-cors-test",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 700

    @pytest.mark.asyncio
    async def test_no_finding_without_credentials_header(self) -> None:
        h = {"access-control-allow-origin": "https://evil.example.com"}
        pr = _pr(headers=h)

        async def _fake(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr()),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake,
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_when_acao_not_reflected(self) -> None:
        h = {
            "access-control-allow-origin": "https://trusted.com",
            "access-control-allow-credentials": "true",
        }
        pr = _pr(headers=h)

        async def _fake(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr()),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake,
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_probe_error(self) -> None:
        pr = _pr()
        pr = ProbeResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=0,
            headers={},
            body=b"",
            body_text="",
            error="connection refused",
        )

        async def _fake(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr()),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake,
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_wildcard_acao_with_credentials_not_fired(self) -> None:
        """* ACAO with credentials — ACAO is *, not the reflected evil.example.com."""
        h = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        pr = _pr(headers=h)

        async def _fake(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr()),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake,
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        # Wildcard + credentials trick doesn't work in browsers, but reflected
        # origin class should NOT fire here since ACAO is * not our evil origin
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_dedup_key_per_asset(self) -> None:
        h = {
            "access-control-allow-origin": "https://evil.example.com",
            "access-control-allow-credentials": "true",
        }
        pr = _pr(headers=h)

        async def _fake(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr()),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake,
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "01TEST000000000000000PHASE13" in findings[0].dedup_key


# ===========================================================================
# 3. CorsNullOrigin
# ===========================================================================

class TestCorsNullOrigin:
    det = CorsNullOrigin()

    @pytest.mark.asyncio
    async def test_fires_on_null_acao(self) -> None:
        h = {"access-control-allow-origin": "null"}
        pr = _pr(headers=h)

        async def _fake(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr()),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake,
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 500

    @pytest.mark.asyncio
    async def test_no_finding_when_acao_not_null(self) -> None:
        h = {"access-control-allow-origin": "https://example.com"}
        pr = _pr(headers=h)

        async def _fake(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr()),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake,
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_no_acao_header(self) -> None:
        pr = _pr()

        async def _fake(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr()),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake,
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        assert await _collect(self.det, _asset(), ctx) == []

    def test_applicable_to_normal_status(self) -> None:
        assert self.det.applicable_to(_asset(http_status=200), [])

    def test_not_applicable_to_500(self) -> None:
        assert not self.det.applicable_to(_asset(http_status=500), [])

    @pytest.mark.asyncio
    async def test_cwe_set(self) -> None:
        h = {"access-control-allow-origin": "null"}
        pr = _pr(headers=h)

        async def _fake(url: str, hdrs: dict[str, str]) -> ProbeResult:
            return pr

        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(return_value=_pr()),
            capture_fn=_noop_capture,
            probe_fn_with_headers=_fake,
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-942"


# ===========================================================================
# 4. CorsPreflightWildcard
# ===========================================================================

class TestCorsPreflightWildcard:
    det = CorsPreflightWildcard()

    @pytest.mark.asyncio
    async def test_fires_on_wildcard_acao(self) -> None:
        h = {"access-control-allow-origin": "*"}
        ctx = _ctx({"https://example.com": _pr(headers=h)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 300

    @pytest.mark.asyncio
    async def test_no_finding_without_wildcard(self) -> None:
        h = {"access-control-allow-origin": "https://trusted.com"}
        ctx = _ctx({"https://example.com": _pr(headers=h)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_when_no_cors_header(self) -> None:
        ctx = _ctx({"https://example.com": _pr()})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_error(self) -> None:
        pr = ProbeResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=0,
            headers={},
            body=b"",
            body_text="",
            error="timeout",
        )
        ctx = _ctx({"https://example.com": pr})
        assert await _collect(self.det, _asset(), ctx) == []

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_category(self) -> None:
        h = {"access-control-allow-origin": "*"}
        ctx = _ctx({"https://example.com": _pr(headers=h)})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings[0].category == "cors_misconfiguration"


# ===========================================================================
# 5. SpfMissing
# ===========================================================================

from bounty.detect.mail import SpfMissing, SpfWeak, DmarcMissing, DmarcWeak, DkimNotFound


class TestSpfMissing:
    det = SpfMissing()

    def test_applicable_to_apex(self) -> None:
        assert self.det.applicable_to(_asset("example.com"), [])

    def test_applicable_to_www(self) -> None:
        assert self.det.applicable_to(_asset("www.example.com"), [])

    def test_not_applicable_to_subdomain(self) -> None:
        assert not self.det.applicable_to(_asset("api.example.com"), [])

    @pytest.mark.asyncio
    async def test_fires_when_no_spf(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._spf_record",
            AsyncMock(return_value=None),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 300

    @pytest.mark.asyncio
    async def test_no_finding_when_spf_exists(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._spf_record",
            AsyncMock(return_value="v=spf1 include:_spf.google.com -all"),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_dedup_per_apex(self) -> None:
        """Second run on same apex (different scan-id makes no difference)
        but same context → dedup via claim_apex."""
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._spf_record",
            AsyncMock(return_value=None),
        ):
            f1 = await _collect(self.det, _asset("example.com"), ctx)
            # Second call with same context — apex already claimed → no finding
            f2 = await _collect(self.det, _asset("example.com"), ctx)
        assert len(f1) == 1
        assert f2 == []


# ===========================================================================
# 6. SpfWeak
# ===========================================================================

class TestSpfWeak:
    det = SpfWeak()

    @pytest.mark.asyncio
    async def test_fires_on_plus_all(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._spf_record",
            AsyncMock(return_value="v=spf1 +all"),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 500

    @pytest.mark.asyncio
    async def test_fires_on_question_all(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._spf_record",
            AsyncMock(return_value="v=spf1 ?all"),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_tilde_all(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._spf_record",
            AsyncMock(return_value="v=spf1 include:_spf.google.com ~all"),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_on_minus_all(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._spf_record",
            AsyncMock(return_value="v=spf1 include:_spf.google.com -all"),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_when_no_spf(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._spf_record",
            AsyncMock(return_value=None),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_dedup_per_apex(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._spf_record",
            AsyncMock(return_value="v=spf1 +all"),
        ):
            f1 = await _collect(self.det, _asset("example.com"), ctx)
            f2 = await _collect(self.det, _asset("example.com"), ctx)
        assert len(f1) == 1
        assert f2 == []


# ===========================================================================
# 7. DmarcMissing
# ===========================================================================

class TestDmarcMissing:
    det = DmarcMissing()

    def test_applicable_to_apex(self) -> None:
        assert self.det.applicable_to(_asset("example.com"), [])

    @pytest.mark.asyncio
    async def test_fires_when_no_dmarc(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value=None),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 400

    @pytest.mark.asyncio
    async def test_no_finding_when_dmarc_exists(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value="v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_dedup_per_apex(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value=None),
        ):
            f1 = await _collect(self.det, _asset("example.com"), ctx)
            f2 = await _collect(self.det, _asset("example.com"), ctx)
        assert len(f1) == 1
        assert f2 == []

    @pytest.mark.asyncio
    async def test_category(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value=None),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings[0].category == "mail_misconfiguration"

    def test_not_applicable_to_deep_subdomain(self) -> None:
        assert not self.det.applicable_to(_asset("deep.sub.example.com"), [])

    @pytest.mark.asyncio
    async def test_dedup_key_uses_apex(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value=None),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert "example.com" in findings[0].dedup_key


# ===========================================================================
# 8. DmarcWeak
# ===========================================================================

class TestDmarcWeak:
    det = DmarcWeak()

    @pytest.mark.asyncio
    async def test_fires_on_p_none(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value="v=DMARC1; p=none; rua=mailto:dmarc@example.com"),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 300

    @pytest.mark.asyncio
    async def test_no_finding_on_p_quarantine(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value="v=DMARC1; p=quarantine"),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_on_p_reject(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value="v=DMARC1; p=reject"),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_when_no_dmarc(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value=None),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_dedup_per_apex(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._dmarc_record",
            AsyncMock(return_value="v=DMARC1; p=none"),
        ):
            f1 = await _collect(self.det, _asset("example.com"), ctx)
            f2 = await _collect(self.det, _asset("example.com"), ctx)
        assert len(f1) == 1
        assert f2 == []

    def test_applicable_to_www(self) -> None:
        assert self.det.applicable_to(_asset("www.example.com"), [])


# ===========================================================================
# 9. DkimNotFound
# ===========================================================================

class TestDkimNotFound:
    det = DkimNotFound()

    @pytest.mark.asyncio
    async def test_fires_when_no_dkim(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._any_dkim_found",
            AsyncMock(return_value=False),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 200

    @pytest.mark.asyncio
    async def test_no_finding_when_dkim_found(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._any_dkim_found",
            AsyncMock(return_value=True),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_dedup_per_apex(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._any_dkim_found",
            AsyncMock(return_value=False),
        ):
            f1 = await _collect(self.det, _asset("example.com"), ctx)
            f2 = await _collect(self.det, _asset("example.com"), ctx)
        assert len(f1) == 1
        assert f2 == []

    def test_applicable_to_apex(self) -> None:
        assert self.det.applicable_to(_asset("example.com"), [])

    def test_not_applicable_to_subdomain(self) -> None:
        assert not self.det.applicable_to(_asset("mail.example.com"), [])

    @pytest.mark.asyncio
    async def test_selectors_in_description(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.mail.mail_config._any_dkim_found",
            AsyncMock(return_value=False),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert "default" in findings[0].description or "selector1" in findings[0].description


# ===========================================================================
# 10. ZoneTransferAllowed
# ===========================================================================

from bounty.detect.dns import ZoneTransferAllowed


class TestZoneTransferAllowed:
    det = ZoneTransferAllowed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_when_axfr_succeeds(self) -> None:
        ctx = _ctx()
        with (
            patch(
                "bounty.detect.dns.zone_transfer._get_nameservers",
                AsyncMock(return_value=["ns1.example.com", "ns2.example.com"]),
            ),
            patch(
                "bounty.detect.dns.zone_transfer._check_axfr",
                AsyncMock(return_value=True),
            ),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 700

    @pytest.mark.asyncio
    async def test_no_finding_when_axfr_fails(self) -> None:
        ctx = _ctx()
        with (
            patch(
                "bounty.detect.dns.zone_transfer._get_nameservers",
                AsyncMock(return_value=["ns1.example.com"]),
            ),
            patch(
                "bounty.detect.dns.zone_transfer._check_axfr",
                AsyncMock(return_value=False),
            ),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_when_no_nameservers(self) -> None:
        ctx = _ctx()
        with patch(
            "bounty.detect.dns.zone_transfer._get_nameservers",
            AsyncMock(return_value=[]),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_dedup_per_apex(self) -> None:
        ctx = _ctx()
        with (
            patch(
                "bounty.detect.dns.zone_transfer._get_nameservers",
                AsyncMock(return_value=["ns1.example.com"]),
            ),
            patch(
                "bounty.detect.dns.zone_transfer._check_axfr",
                AsyncMock(return_value=True),
            ),
        ):
            f1 = await _collect(self.det, _asset("example.com"), ctx)
            f2 = await _collect(self.det, _asset("example.com"), ctx)
        assert len(f1) == 1
        assert f2 == []

    @pytest.mark.asyncio
    async def test_only_lists_vulnerable_ns(self) -> None:
        """ns1 fails, ns2 succeeds — only ns2 listed in finding."""

        async def _mock_axfr(ns: str, domain: str) -> bool:
            return ns == "ns2.example.com"

        ctx = _ctx()
        with (
            patch(
                "bounty.detect.dns.zone_transfer._get_nameservers",
                AsyncMock(return_value=["ns1.example.com", "ns2.example.com"]),
            ),
            patch(
                "bounty.detect.dns.zone_transfer._check_axfr",
                _mock_axfr,
            ),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert len(findings) == 1
        assert "ns2.example.com" in findings[0].description
        assert "ns1.example.com" not in findings[0].description

    @pytest.mark.asyncio
    async def test_category(self) -> None:
        ctx = _ctx()
        with (
            patch(
                "bounty.detect.dns.zone_transfer._get_nameservers",
                AsyncMock(return_value=["ns1.example.com"]),
            ),
            patch(
                "bounty.detect.dns.zone_transfer._check_axfr",
                AsyncMock(return_value=True),
            ),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings[0].category == "dns_misconfiguration"

    @pytest.mark.asyncio
    async def test_axfr_exception_skipped(self) -> None:
        """Exception during AXFR attempt is swallowed — no finding."""
        ctx = _ctx()
        with (
            patch(
                "bounty.detect.dns.zone_transfer._get_nameservers",
                AsyncMock(return_value=["ns1.example.com"]),
            ),
            patch(
                "bounty.detect.dns.zone_transfer._check_axfr",
                AsyncMock(side_effect=Exception("network error")),
            ),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert findings == []

    @pytest.mark.asyncio
    async def test_dedup_key_uses_apex(self) -> None:
        ctx = _ctx()
        with (
            patch(
                "bounty.detect.dns.zone_transfer._get_nameservers",
                AsyncMock(return_value=["ns1.example.com"]),
            ),
            patch(
                "bounty.detect.dns.zone_transfer._check_axfr",
                AsyncMock(return_value=True),
            ),
        ):
            findings = await _collect(self.det, _asset("example.com"), ctx)
        assert "example.com" in findings[0].dedup_key


# ===========================================================================
# 11. RobotsSensitivePaths
# ===========================================================================

from bounty.detect.discovery import RobotsSensitivePaths, SitemapExposed


class TestRobotsSensitivePaths:
    det = RobotsSensitivePaths()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_admin_disallow(self) -> None:
        robots = b"User-agent: *\nDisallow: /admin/\nDisallow: /public/"
        ctx = _ctx({"/robots.txt": _pr(body=robots, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 300
        assert "/admin/" in findings[0].description

    @pytest.mark.asyncio
    async def test_fires_on_multiple_sensitive_paths(self) -> None:
        robots = b"User-agent: *\nDisallow: /backup/\nDisallow: /config/\nDisallow: /api/internal"
        ctx = _ctx({"/robots.txt": _pr(body=robots, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        desc = findings[0].description
        assert "/backup/" in desc or "/config/" in desc

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/robots.txt": _pr(status_code=404, body=b"Not Found")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_when_only_harmless_disallows(self) -> None:
        robots = b"User-agent: *\nDisallow: /images/\nDisallow: /css/"
        ctx = _ctx({"/robots.txt": _pr(body=robots, ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_html_soft_404(self) -> None:
        body = b"<html><body>Page not found</body></html>"
        ctx = _ctx({"/robots.txt": _pr(body=body, ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_fires_on_git_disallow(self) -> None:
        robots = b"User-agent: *\nDisallow: /.git/"
        ctx = _ctx({"/robots.txt": _pr(body=robots, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_fires_on_staging_path(self) -> None:
        robots = b"User-agent: *\nDisallow: /staging/\nDisallow: /dev/"
        ctx = _ctx({"/robots.txt": _pr(body=robots, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_path_set_correctly(self) -> None:
        robots = b"User-agent: *\nDisallow: /admin/"
        ctx = _ctx({"/robots.txt": _pr(body=robots, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings[0].path == "/robots.txt"


# ===========================================================================
# 12. SitemapExposed
# ===========================================================================

class TestSitemapExposed:
    det = SitemapExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_valid_sitemap(self) -> None:
        sitemap = (
            b'<?xml version="1.0"?>'
            b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            b"  <url><loc>https://example.com/page1</loc></url>"
            b"  <url><loc>https://example.com/page2</loc></url>"
            b"</urlset>"
        )
        ctx = _ctx({"/sitemap.xml": _pr(body=sitemap, ct="application/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 200

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/sitemap.xml": _pr(status_code=404, body=b"Not Found")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_when_body_not_sitemap_xml(self) -> None:
        ctx = _ctx({"/sitemap.xml": _pr(body=b"<html><body>Error</body></html>", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_url_count_in_title(self) -> None:
        locs = "".join(
            f"<url><loc>https://example.com/p{i}</loc></url>" for i in range(10)
        )
        sitemap = f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{locs}</urlset>'
        ctx = _ctx({"/sitemap.xml": _pr(body=sitemap.encode(), ct="application/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "10" in findings[0].title

    @pytest.mark.asyncio
    async def test_falls_back_to_sitemap_index(self) -> None:
        idx = (
            b'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            b"<sitemap><loc>https://example.com/sitemap1.xml</loc></sitemap>"
            b"</sitemapindex>"
        )
        ctx = _ctx(
            {
                "/sitemap.xml": _pr(status_code=404, body=b"Not Found"),
                "/sitemap_index.xml": _pr(body=idx, ct="application/xml"),
            }
        )
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_category(self) -> None:
        sitemap = b'<urlset><url><loc>https://example.com/x</loc></url></urlset>'
        ctx = _ctx({"/sitemap.xml": _pr(body=sitemap, ct="application/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings[0].category == "information_disclosure"

    @pytest.mark.asyncio
    async def test_path_set_correctly(self) -> None:
        sitemap = b'<urlset><url><loc>https://example.com/x</loc></url></urlset>'
        ctx = _ctx({"/sitemap.xml": _pr(body=sitemap, ct="application/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings[0].path == "/sitemap.xml"

    @pytest.mark.asyncio
    async def test_no_finding_when_no_loc_urls(self) -> None:
        sitemap = b"<urlset></urlset>"
        ctx = _ctx({"/sitemap.xml": _pr(body=sitemap, ct="application/xml")})
        assert await _collect(self.det, _asset(), ctx) == []


# ===========================================================================
# 13. Registry integration
# ===========================================================================

class TestRegistryIntegration:
    def test_all_new_detections_registered(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS

        ids = {d.id for d in REGISTERED_DETECTIONS}
        assert "takeover.subdomain" in ids
        assert "cors.reflected_origin_with_credentials" in ids
        assert "cors.null_origin_reflected" in ids
        assert "cors.preflight_wildcard" in ids
        assert "mail.spf_missing" in ids
        assert "mail.spf_weak" in ids
        assert "mail.dmarc_missing" in ids
        assert "mail.dmarc_weak" in ids
        assert "mail.dkim_not_found" in ids
        assert "dns.zone_transfer_allowed" in ids
        assert "discovery.robots_sensitive_paths" in ids
        assert "discovery.sitemap_exposed" in ids

    def test_registry_total_count_grew(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS

        # Phase 12 had 93 + Nuclei (94 total). Phase 13 adds 12 more → 106+
        assert len(REGISTERED_DETECTIONS) >= 106

    def test_all_detections_have_required_attrs(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS

        for det in REGISTERED_DETECTIONS:
            assert hasattr(det, "id"), f"{det} missing id"
            assert hasattr(det, "name"), f"{det} missing name"
            assert hasattr(det, "category"), f"{det} missing category"
            assert hasattr(det, "severity_default"), f"{det} missing severity_default"

    def test_new_detection_ids_unique(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS

        ids = [d.id for d in REGISTERED_DETECTIONS]
        assert len(ids) == len(set(ids)), "Duplicate detection IDs found"

    def test_takeover_fingerprints_json_loads(self) -> None:
        import json
        from pathlib import Path

        fp_path = Path(__file__).parent.parent / "bounty/detect/takeover/fingerprints.json"
        with fp_path.open() as fh:
            data = json.load(fh)
        assert isinstance(data, list)
        assert len(data) >= 20
        for entry in data:
            assert "service" in entry
            assert "cname_patterns" in entry
            assert "body_fingerprints" in entry
            assert "vulnerable_status" in entry

    def test_cors_detection_severities(self) -> None:
        from bounty.detect.cors import (
            CorsNullOrigin,
            CorsPreflightWildcard,
            CorsWildcardWithCredentials,
        )

        assert CorsWildcardWithCredentials.severity_default == 700
        assert CorsNullOrigin.severity_default == 500
        assert CorsPreflightWildcard.severity_default == 300


# ===========================================================================
# 14. DetectionContext.claim_apex dedup logic
# ===========================================================================

class TestClaimApex:
    def test_first_claim_returns_true(self) -> None:
        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(),
            capture_fn=AsyncMock(),
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        assert ctx.claim_apex("mail", "example.com") is True

    def test_second_claim_same_apex_returns_false(self) -> None:
        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(),
            capture_fn=AsyncMock(),
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        ctx.claim_apex("mail", "example.com")
        assert ctx.claim_apex("mail", "example.com") is False

    def test_different_apex_can_be_claimed(self) -> None:
        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(),
            capture_fn=AsyncMock(),
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        ctx.claim_apex("mail", "example.com")
        assert ctx.claim_apex("mail", "other.com") is True

    def test_different_category_same_apex_both_allowed(self) -> None:
        import structlog
        from bounty.config import get_settings

        ctx = DetectionContext(
            probe_fn=AsyncMock(),
            capture_fn=AsyncMock(),
            scan_id="s",
            settings=get_settings(),
            log=structlog.get_logger(),
        )
        assert ctx.claim_apex("mail", "example.com") is True
        assert ctx.claim_apex("dns", "example.com") is True


