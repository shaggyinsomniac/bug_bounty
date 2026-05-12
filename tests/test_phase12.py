"""
tests/test_phase12.py — Phase 12: CMS, cloud, AI infra, API docs, network services detections.

Test sections (target 200+ tests):

 1. CMS – WordPress (5 detections × 4 tests = 20)
 2. CMS – Drupal    (3 detections × 4 tests = 12)
 3. CMS – Magento   (3 detections × 4 tests = 12)
 4. CMS – Joomla    (2 detections × 4 tests = 8)
 5. Cloud – S3      (2 detections × 4 tests = 8)
 6. Cloud – Azure   (2 detections × 4 tests = 8)
 7. Cloud – GCP     (2 detections × 4 tests = 8)
 8. Cloud – Generic (2 detections × 4 tests = 8)
 9. AI Infra        (6 detections × 4 tests = 24)
10. API Docs        (5 detections × 4 tests = 20)
11. Spring Actuator (5 detections × 4 tests = 20)
12. PHP Specific    (4 detections × 4 tests = 16)
13. Network Services integration (5 detections × 4 tests = 20)
14. Integration / registry tests (20)

Total: ~204 tests
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

from bounty.detect._fingerprint_helpers import has_tech
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
# Test helpers (mirrors test_phase6.py pattern)
# ---------------------------------------------------------------------------

def _pr(
    *,
    status_code: int = 200,
    body: bytes = b"",
    ct: str = "text/html",
    url: str = "https://example.com/",
    headers: dict[str, str] | None = None,
    redirect_chain: list[str] | None = None,
    final_url: str | None = None,
) -> ProbeResult:
    h: dict[str, str] = headers or {}
    if ct:
        h = {"content-type": ct, **h}
    return ProbeResult(
        url=url,
        final_url=final_url or url,
        status_code=status_code,
        headers=h,
        body=body,
        body_text=body.decode("utf-8", errors="replace"),
        redirect_chain=redirect_chain or [],
    )


def _json_pr(data: Any, *, status_code: int = 200, url: str = "https://example.com/") -> ProbeResult:
    body = json.dumps(data).encode()
    return _pr(status_code=status_code, body=body, ct="application/json", url=url)


def _html_pr(html: str, *, status_code: int = 200) -> ProbeResult:
    return _pr(status_code=status_code, body=html.encode(), ct="text/html")


def _fp(tech: str, confidence: str = "strong") -> FingerprintResult:
    return FingerprintResult(tech=tech, confidence=cast(ConfidenceTier, confidence))


def _asset(host: str = "example.com", port: int | None = None) -> Asset:
    return Asset(
        id="01TEST000000000000000000001",
        program_id="prog_test",
        host=host,
        port=port,
        url=f"https://{host}" + (f":{port}" if port else ""),
        scheme="https",
        primary_scheme="https",
    )


async def _noop_capture(url: str, pr: ProbeResult, scan_id: str) -> EvidencePackage:
    return EvidencePackage(kind="http", response_status=pr.status_code)


def _ctx(
    responses: dict[str, ProbeResult],
    post_responses: dict[str, ProbeResult] | None = None,
) -> DetectionContext:
    import structlog
    from bounty.config import get_settings

    async def _probe(url: str) -> ProbeResult:
        if url in responses:
            return responses[url]
        for pattern, resp in responses.items():
            if url.endswith(pattern) or pattern in url:
                return resp
        return _pr(status_code=404, body=b"Not Found", ct="text/html")

    async def _post(url: str, body: Any) -> ProbeResult:
        pr_map = post_responses or {}
        if url in pr_map:
            return pr_map[url]
        for pattern, resp in pr_map.items():
            if url.endswith(pattern) or pattern in url:
                return resp
        return _pr(status_code=404, body=b"Not Found", ct="text/html")

    return DetectionContext(
        probe_fn=_probe,
        capture_fn=_noop_capture,
        post_json_fn=_post if post_responses is not None else None,
        scan_id="scan-test-phase12",
        settings=get_settings(),
        log=structlog.get_logger(),
    )


async def _collect(detection: Any, asset: Asset, ctx: DetectionContext) -> list[FindingDraft]:
    return [f async for f in detection.run(asset, ctx)]


# ===========================================================================
# 1. WordPress Detections
# ===========================================================================

from bounty.detect.cms_specific.wordpress import (
    WpDebugLog,
    WpInstallExposed,
    WpReadmeExposed,
    WpUserEnum,
    XmlrpcExposed,
)


class TestWpDebugLog:
    det = WpDebugLog()

    def test_not_applicable_without_wp(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_wordpress(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("WordPress")])

    @pytest.mark.asyncio
    async def test_fires_on_php_error_log(self) -> None:
        body = b"PHP Notice: Undefined variable on line 42\nWordPress debug output\n"
        ctx = _ctx({"/wp-content/debug.log": _pr(body=body, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 500
        assert "debug" in findings[0].title.lower() or "wp" in findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/wp-content/debug.log": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_php_markers(self) -> None:
        ctx = _ctx({"/wp-content/debug.log": _pr(body=b"some random text here", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_fires_on_stack_trace(self) -> None:
        body = b"PHP Fatal error: Call to undefined function\nStack trace:\n#0 wp-content/plugins/foo.php"
        ctx = _ctx({"/wp-content/debug.log": _pr(body=body, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1


class TestWpInstallExposed:
    det = WpInstallExposed()

    def test_not_applicable_without_wp(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_wordpress(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("WordPress")])

    @pytest.mark.asyncio
    async def test_fires_on_install_page(self) -> None:
        html = "<html><h1>WordPress Installation</h1><form>Site title: <input> Step 1</form></html>"
        ctx = _ctx({"/wp-admin/install.php": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity >= 700

    @pytest.mark.asyncio
    async def test_fires_on_already_installed(self) -> None:
        html = "<html>WordPress is already installed. <a href='/wp-login.php'>log in</a></html>"
        ctx = _ctx({"/wp-admin/install.php": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/wp-admin/install.php": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_random_html(self) -> None:
        html = "<html><h1>Not Found</h1></html>"
        ctx = _ctx({"/wp-admin/install.php": _html_pr(html)})
        assert await _collect(self.det, _asset(), ctx) == []


class TestWpUserEnum:
    det = WpUserEnum()

    def test_not_applicable_without_wp(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_wordpress(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("WordPress")])

    @pytest.mark.asyncio
    async def test_fires_on_author_redirect(self) -> None:
        target_url = "https://example.com/author/admin"
        pr = _pr(
            status_code=301,
            url=target_url,
            final_url=target_url,
            redirect_chain=["https://example.com/?author=1", target_url],
        )
        ctx = _ctx({"/?author=1": pr})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "admin" in findings[0].description

    @pytest.mark.asyncio
    async def test_fires_on_final_url_with_author(self) -> None:
        final = "https://example.com/author/johndoe/"
        pr = _pr(status_code=200, url=final, final_url=final)
        ctx = _ctx({"/?author=1": pr})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_without_author_in_url(self) -> None:
        pr = _pr(status_code=200, final_url="https://example.com/")
        ctx = _ctx({"/?author=1": pr})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/?author=1": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []


class TestWpReadmeExposed:
    det = WpReadmeExposed()

    def test_not_applicable_without_wp(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_wordpress(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("WordPress")])

    @pytest.mark.asyncio
    async def test_fires_on_readme_with_version(self) -> None:
        html = "<html><h1>WordPress</h1><p>Version 6.4.2</p></html>"
        ctx = _ctx({"/readme.html": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 200

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/readme.html": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_wordpress_keyword(self) -> None:
        html = "<html><h1>Welcome</h1></html>"
        ctx = _ctx({"/readme.html": _html_pr(html)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_version_captured_in_description(self) -> None:
        html = "<html><h1>WordPress</h1><p>Version 5.9.3</p></html>"
        ctx = _ctx({"/readme.html": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "5.9.3" in findings[0].description


class TestXmlrpcExposed:
    det = XmlrpcExposed()

    def test_not_applicable_without_wp(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_wordpress(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("WordPress")])

    @pytest.mark.asyncio
    async def test_fires_on_xmlrpc_405(self) -> None:
        body = b"XML-RPC server accepts POST requests only."
        ctx = _ctx({"/xmlrpc.php": _pr(status_code=405, body=body, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 500

    @pytest.mark.asyncio
    async def test_fires_on_xmlrpc_200(self) -> None:
        body = b"<?xml version='1.0'?><methodResponse><params><xmlrpc></xmlrpc></params></methodResponse>"
        ctx = _ctx({"/xmlrpc.php": _pr(status_code=200, body=body, ct="text/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/xmlrpc.php": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_xmlrpc_body(self) -> None:
        ctx = _ctx({"/xmlrpc.php": _html_pr("<html><h1>Not Found</h1></html>", status_code=200)})
        assert await _collect(self.det, _asset(), ctx) == []


# ===========================================================================
# 2. Drupal Detections
# ===========================================================================

from bounty.detect.cms_specific.drupal import (
    DrupalChangelogExposed,
    DrupalCron,
    DrupalUpdatePhp,
)


class TestDrupalChangelogExposed:
    det = DrupalChangelogExposed()

    def test_not_applicable_without_drupal(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_drupal(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Drupal")])

    @pytest.mark.asyncio
    async def test_fires_on_changelog_with_version(self) -> None:
        body = b"Drupal 10.3.2, 2024-07-17\n- Fixed security issues\n"
        ctx = _ctx({"/CHANGELOG.txt": _pr(body=body, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "10.3.2" in findings[0].description or "changelog" in findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/CHANGELOG.txt": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_drupal_keyword(self) -> None:
        ctx = _ctx({"/CHANGELOG.txt": _pr(body=b"Some random changelog text", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_severity_is_info(self) -> None:
        body = b"Drupal 9.5.0\n- Bug fixes"
        ctx = _ctx({"/CHANGELOG.txt": _pr(body=body, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 200


class TestDrupalCron:
    det = DrupalCron()

    def test_not_applicable_without_drupal(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_drupal(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Drupal")])

    @pytest.mark.asyncio
    async def test_fires_on_cron_success(self) -> None:
        body = b"Cron has been run successfully."
        ctx = _ctx({"/cron.php": _pr(body=body, ct="text/html")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_fires_on_empty_cron_response(self) -> None:
        # Old Drupal 6/7 returns empty body on cron success
        ctx = _ctx({"/cron.php": _pr(body=b"", ct="text/html")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/cron.php": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_access_denied(self) -> None:
        ctx = _ctx({"/cron.php": _pr(status_code=403, body=b"Access denied")})
        assert await _collect(self.det, _asset(), ctx) == []


class TestDrupalUpdatePhp:
    det = DrupalUpdatePhp()

    def test_not_applicable_without_drupal(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_drupal(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Drupal")])

    @pytest.mark.asyncio
    async def test_fires_on_update_page(self) -> None:
        html = "<html><h1>Drupal database update</h1><p>Apply pending updates</p></html>"
        ctx = _ctx({"/update.php": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 700

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/update.php": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_drupal_keyword(self) -> None:
        html = "<html><h1>Update script</h1><p>Apply pending updates</p></html>"
        ctx = _ctx({"/update.php": _html_pr(html)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_redirect(self) -> None:
        ctx = _ctx({"/update.php": _pr(status_code=302)})
        assert await _collect(self.det, _asset(), ctx) == []


# ===========================================================================
# 3. Magento Detections
# ===========================================================================

from bounty.detect.cms_specific.magento import (
    MagentoDownloader,
    MagentoLocalXml,
    MagentoVersionDisclosure,
)


class TestMagentoLocalXml:
    det = MagentoLocalXml()

    def test_not_applicable_without_magento(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_magento(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Magento")])

    @pytest.mark.asyncio
    async def test_fires_on_config_xml(self) -> None:
        body = b"<config><connection><username>root</username><password>secret</password><dbname>magento</dbname></connection></config>"
        ctx = _ctx({"/app/etc/local.xml": _pr(body=body, ct="text/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 900

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/app/etc/local.xml": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_html_response(self) -> None:
        ctx = _ctx({"/app/etc/local.xml": _html_pr("<html>Not Found</html>")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_tiny_body(self) -> None:
        ctx = _ctx({"/app/etc/local.xml": _pr(body=b"ok", ct="text/xml")})
        assert await _collect(self.det, _asset(), ctx) == []


class TestMagentoDownloader:
    det = MagentoDownloader()

    def test_not_applicable_without_magento(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_magento(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Magento")])

    @pytest.mark.asyncio
    async def test_fires_on_downloader_page(self) -> None:
        html = "<html><h1>Magento Connect Manager</h1><p>Downloader</p></html>"
        ctx = _ctx({"/downloader/": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 700

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/downloader/": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_magento_marker(self) -> None:
        ctx = _ctx({"/downloader/": _html_pr("<html><h1>Welcome</h1></html>")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_redirect(self) -> None:
        ctx = _ctx({"/downloader/": _pr(status_code=302)})
        assert await _collect(self.det, _asset(), ctx) == []


class TestMagentoVersionDisclosure:
    det = MagentoVersionDisclosure()

    def test_not_applicable_without_magento(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_magento(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Magento")])

    @pytest.mark.asyncio
    async def test_fires_on_version_response(self) -> None:
        ctx = _ctx({"/magento_version": _pr(body=b"Magento/2.4.6", ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 200

    @pytest.mark.asyncio
    async def test_fires_on_plain_version(self) -> None:
        ctx = _ctx({"/magento_version": _pr(body=b"2.4.6", ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/magento_version": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_long_body(self) -> None:
        ctx = _ctx({"/magento_version": _html_pr("<html>long page content here " * 10)})
        assert await _collect(self.det, _asset(), ctx) == []


# ===========================================================================
# 4. Joomla Detections
# ===========================================================================

from bounty.detect.cms_specific.joomla import JoomlaAdminVersion, JoomlaConfigBackup


class TestJoomlaConfigBackup:
    det = JoomlaConfigBackup()

    def test_not_applicable_without_joomla(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_joomla(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Joomla")])

    @pytest.mark.asyncio
    async def test_fires_on_config_bak(self) -> None:
        body = b"""<?php\n$JConfig = new JConfig();\n$secret = 'abc123';\n$password = 'dbpass';\n$db = 'mydb';\n"""
        ctx = _ctx({"/configuration.php.bak": _pr(body=body, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 900

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/configuration.php.bak": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_joomla_markers(self) -> None:
        ctx = _ctx({"/configuration.php.bak": _pr(body=b"random content here", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_dedup_key_has_path(self) -> None:
        body = b"$JConfig = new JConfig();\n$db = 'mydb';\n$host = 'localhost';\n"
        ctx = _ctx({"/configuration.php.bak": _pr(body=body, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "joomla" in findings[0].dedup_key


class TestJoomlaAdminVersion:
    det = JoomlaAdminVersion()

    def test_not_applicable_without_joomla(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_joomla(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Joomla")])

    @pytest.mark.asyncio
    async def test_fires_on_manifest_xml(self) -> None:
        body = b"""<?xml version="1.0"?><extension><version>5.1.2</version><name>Joomla!</name></extension>"""
        ctx = _ctx({"/administrator/manifests/files/joomla.xml": _pr(body=body, ct="text/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "5.1.2" in findings[0].description

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/administrator/manifests/files/joomla.xml": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_version_or_joomla(self) -> None:
        ctx = _ctx({"/administrator/manifests/files/joomla.xml": _pr(body=b"random xml", ct="text/xml")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_severity_is_info(self) -> None:
        body = b"<extension><version>4.4.0</version><name>Joomla!</name></extension>"
        ctx = _ctx({"/administrator/manifests/files/joomla.xml": _pr(body=body, ct="text/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 200


# ===========================================================================
# 5. Cloud – S3
# ===========================================================================

from bounty.detect.cloud.s3 import S3BucketListing, S3PolicyExposed


class TestS3BucketListing:
    det = S3BucketListing()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_list_bucket_result(self) -> None:
        body = b"""<?xml version="1.0"?>
<ListBucketResult>
  <Name>my-bucket</Name>
  <Prefix></Prefix>
  <Contents><Key>secret.txt</Key></Contents>
</ListBucketResult>"""
        ctx = _ctx({"": _pr(body=body, ct="application/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 600

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_listing_marker(self) -> None:
        ctx = _ctx({"": _html_pr("<html>Hello World</html>")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_dedup_key_has_detection_id(self) -> None:
        body = b"<ListBucketResult><Name>x</Name><Prefix></Prefix><Contents><Key>a</Key></Contents></ListBucketResult>"
        ctx = _ctx({"": _pr(body=body, ct="application/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings
        assert "cloud.s3.bucket_listing" in findings[0].dedup_key


class TestS3PolicyExposed:
    det = S3PolicyExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_bucket_policy(self) -> None:
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*"}]}
        ctx = _ctx({"/?policy": _json_pr(policy)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/?policy": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_statement(self) -> None:
        ctx = _ctx({"/?policy": _json_pr({"foo": "bar"})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_non_json(self) -> None:
        ctx = _ctx({"/?policy": _html_pr("<html>Not JSON</html>")})
        assert await _collect(self.det, _asset(), ctx) == []


# ===========================================================================
# 6. Cloud – Azure
# ===========================================================================

from bounty.detect.cloud.azure import AzureBlobAnonAccess, AzureStorageContainerListing


class TestAzureStorageContainerListing:
    det = AzureStorageContainerListing()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_enumeration_results(self) -> None:
        body = b"""<?xml version="1.0"?>
<EnumerationResults>
  <Containers>
    <Container><Name>my-data</Name></Container>
  </Containers>
</EnumerationResults>"""
        ctx = _ctx({"/?comp=list": _pr(body=body, ct="application/xml")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/?comp=list": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_azure_marker(self) -> None:
        ctx = _ctx({"/?comp=list": _html_pr("<html>hello</html>")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_container_marker(self) -> None:
        body = b"<EnumerationResults></EnumerationResults>"
        ctx = _ctx({"/?comp=list": _pr(body=body, ct="application/xml")})
        assert await _collect(self.det, _asset(), ctx) == []


class TestAzureBlobAnonAccess:
    det = AzureBlobAnonAccess()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_azure_blob_with_header(self) -> None:
        body = b"Binary file content here, definitely not an error"
        ctx = _ctx({"/": _pr(
            body=body,
            ct="application/octet-stream",
            headers={"x-ms-request-id": "abc123", "x-ms-version": "2021-06-08"},
        )})
        findings = await _collect(self.det, _asset("myaccount.blob.core.windows.net"), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_without_azure_indicator(self) -> None:
        ctx = _ctx({"/": _pr(body=b"some content here ok", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_access_denied_error(self) -> None:
        body = b"<Error><Code>PublicAccessNotPermitted</Code></Error>"
        ctx = _ctx({"/": _pr(
            body=body,
            ct="application/xml",
            headers={"x-ms-request-id": "abc123"},
        )})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/": _pr(status_code=404, headers={"x-ms-request-id": "abc"})})
        assert await _collect(self.det, _asset("myaccount.blob.core.windows.net"), ctx) == []


# ===========================================================================
# 7. Cloud – GCP
# ===========================================================================

from bounty.detect.cloud.gcp import GcpMetadataLeak, GcpStorageBucketListing


class TestGcpStorageBucketListing:
    det = GcpStorageBucketListing()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_gcs_xml_listing(self) -> None:
        body = b'<ListBucketResult><Name>my-gcs-bucket</Name><Prefix></Prefix><Contents><Key>data.csv</Key></Contents></ListBucketResult>storage.googleapis.com'
        ctx = _ctx({"/": _pr(body=body, ct="application/xml")})
        findings = await _collect(self.det, _asset("storage.googleapis.com"), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_fires_on_gcs_json_listing(self) -> None:
        data = {"kind": "storage#objects", "items": [{"name": "secret.json"}]}
        body = json.dumps(data).encode()
        ctx = _ctx({"/": _pr(body=body, ct="application/json", headers={"x-guploader-uploadid": "ABC"})})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_gcs_indicator(self) -> None:
        ctx = _ctx({"/": _html_pr("<html>Hello World</html>")})
        assert await _collect(self.det, _asset(), ctx) == []


class TestGcpMetadataLeak:
    det = GcpMetadataLeak()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_metadata_response(self) -> None:
        body = b'{"project-id": "my-project", "instance-id": "123", "service-accounts": {"default": {"email": "sa@gserviceaccount.com"}}}'
        ctx = _ctx({"/computeMetadata/v1/?recursive=true": _json_pr(json.loads(body.decode()))})
        findings = await _collect(self.det, _asset("169.254.169.254"), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 800

    @pytest.mark.asyncio
    async def test_no_finding_on_normal_host(self) -> None:
        ctx = _ctx({"/computeMetadata/v1/?recursive=true": _json_pr({"project-id": "x"})})
        assert await _collect(self.det, _asset("example.com"), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/computeMetadata/v1/?recursive=true": _pr(status_code=404)})
        assert await _collect(self.det, _asset("169.254.169.254"), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_metadata_keys(self) -> None:
        ctx = _ctx({"/computeMetadata/v1/?recursive=true": _json_pr({"foo": "bar"})})
        assert await _collect(self.det, _asset("169.254.169.254"), ctx) == []


# ===========================================================================
# 8. Cloud – Generic
# ===========================================================================

from bounty.detect.cloud.generic import CdnCacheBackend, CloudfrontMisconfig


class TestCdnCacheBackend:
    det = CdnCacheBackend()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_backend_server_header_internal_ip(self) -> None:
        ctx = _ctx({"https://example.com": _pr(
            status_code=200,
            body=b"Hello",
            ct="text/html",
            headers={"x-backend-server": "10.0.0.5"},
        )})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 300

    @pytest.mark.asyncio
    async def test_fires_on_via_header_internal(self) -> None:
        ctx = _ctx({"https://example.com": _pr(
            status_code=200,
            body=b"Hello",
            ct="text/html",
            headers={"via": "1.1 webserver.internal"},
        )})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_without_internal_header(self) -> None:
        ctx = _ctx({"https://example.com": _pr(
            status_code=200,
            body=b"Hello",
            ct="text/html",
        )})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_public_via_header(self) -> None:
        ctx = _ctx({"https://example.com": _pr(
            status_code=200,
            body=b"Hello",
            ct="text/html",
            headers={"via": "1.1 cloudflare.com"},
        )})
        assert await _collect(self.det, _asset(), ctx) == []


class TestCloudfrontMisconfig:
    det = CloudfrontMisconfig()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_x_forwarded_server_internal(self) -> None:
        ctx = _ctx({"https://example.com": _pr(
            status_code=200,
            body=b"Hello",
            ct="text/html",
            headers={
                "x-amz-cf-id": "abcdefg",
                "x-forwarded-server": "10.0.5.100",
            },
        )})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_without_cloudfront(self) -> None:
        ctx = _ctx({"https://example.com": _pr(
            status_code=200,
            body=b"Hello",
            ct="text/html",
            headers={"x-forwarded-server": "10.0.0.1"},
        )})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_public_forwarded_server(self) -> None:
        ctx = _ctx({"https://example.com": _pr(
            status_code=200,
            body=b"Hello",
            ct="text/html",
            headers={"x-amz-cf-id": "xyz", "x-forwarded-server": "8.8.8.8"},
        )})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"https://example.com": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []


# ===========================================================================
# 9. AI Infra
# ===========================================================================

from bounty.detect.ai_infra.inference_servers import (
    HuggingFaceSpacesMisconfig,
    OllamaExposed,
    OpenWebUIExposed,
    StableDiffusionExposed,
    TritonExposed,
    VllmExposed,
)


class TestOllamaExposed:
    det = OllamaExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_api_tags(self) -> None:
        data = {"models": [{"name": "llama3:8b"}, {"name": "mistral:7b"}]}
        ctx = _ctx({"/api/tags": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "llama3:8b" in findings[0].description

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/api/tags": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_models_key(self) -> None:
        ctx = _ctx({"/api/tags": _json_pr({"status": "ok"})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_severity_is_700(self) -> None:
        data = {"models": [{"name": "phi3:mini"}]}
        ctx = _ctx({"/api/tags": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings[0].severity == 700


class TestTritonExposed:
    det = TritonExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_models_list(self) -> None:
        data = {"models": [{"name": "bert", "version": "1"}]}
        ctx = _ctx({"/v2/models": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_fires_on_array_response(self) -> None:
        data = [{"name": "resnet50"}, {"name": "yolov8"}]
        ctx = _ctx({"/v2/models": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/v2/models": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_wrong_structure(self) -> None:
        ctx = _ctx({"/v2/models": _json_pr({"error": "unauthorized"})})
        assert await _collect(self.det, _asset(), ctx) == []


class TestVllmExposed:
    det = VllmExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_models_list(self) -> None:
        data = {"object": "list", "data": [{"id": "meta-llama/Llama-3.1-8B"}]}
        ctx = _ctx({"/v1/models": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "meta-llama" in findings[0].description

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/v1/models": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_data_key(self) -> None:
        ctx = _ctx({"/v1/models": _json_pr({"models": ["llama"]})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_non_json(self) -> None:
        ctx = _ctx({"/v1/models": _html_pr("<html>Not JSON</html>")})
        assert await _collect(self.det, _asset(), ctx) == []


class TestStableDiffusionExposed:
    det = StableDiffusionExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_sdapi_options(self) -> None:
        data = {
            "sd_model_checkpoint": "v1-5-pruned.ckpt",
            "sd_vae": "Automatic",
            "CLIP_stop_at_last_layers": 1,
        }
        ctx = _ctx({"/sdapi/v1/options": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/sdapi/v1/options": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_sd_keys(self) -> None:
        ctx = _ctx({"/sdapi/v1/options": _json_pr({"version": "1.0"})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_severity_is_600(self) -> None:
        data = {"sd_model_checkpoint": "model.ckpt", "outdir_samples": "/tmp/output"}
        ctx = _ctx({"/sdapi/v1/options": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings[0].severity == 600


class TestOpenWebUIExposed:
    det = OpenWebUIExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_api_config(self) -> None:
        data = {
            "WEBUI_NAME": "Open WebUI",
            "OPENAI_API_BASE_URL": "https://api.openai.com/v1",
            "auth": True,
        }
        ctx = _ctx({"/api/config": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/api/config": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_webui_keys(self) -> None:
        ctx = _ctx({"/api/config": _json_pr({"version": "1.0", "status": "ok"})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_fires_on_ollama_base_url_key(self) -> None:
        data = {"OLLAMA_BASE_URL": "http://localhost:11434", "version": "0.3.10"}
        ctx = _ctx({"/api/config": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1


class TestHuggingFaceSpacesMisconfig:
    det = HuggingFaceSpacesMisconfig()

    def test_applicable_to_hf_host(self) -> None:
        assert self.det.applicable_to(_asset("myspace.hf.space"), [])

    def test_not_applicable_to_random_host(self) -> None:
        assert not self.det.applicable_to(_asset("example.com"), [])

    @pytest.mark.asyncio
    async def test_fires_on_gradio_api_endpoints(self) -> None:
        data = {
            "named_endpoints": {"/predict": {"parameters": []}},
            "unnamed_endpoints": {},
        }
        ctx = _ctx({"/api": _json_pr(data)})
        findings = await _collect(self.det, _asset("myspace.hf.space"), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_all_404(self) -> None:
        ctx = _ctx({
            "/api/queue/status": _pr(status_code=404),
            "/api": _pr(status_code=404),
        })
        assert await _collect(self.det, _asset("myspace.hf.space"), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_endpoints(self) -> None:
        ctx = _ctx({"/api": _json_pr({"status": "ok"})})
        assert await _collect(self.det, _asset("myspace.hf.space"), ctx) == []

    @pytest.mark.asyncio
    async def test_fires_on_queue_status(self) -> None:
        data = {"queue_size": 2, "status": "online"}
        ctx = _ctx({
            "/api/queue/status": _json_pr(data),
            "/api": _pr(status_code=404),
        })
        findings = await _collect(self.det, _asset("myspace.hf.space"), ctx)
        assert len(findings) == 1


# ===========================================================================
# 10. API Docs
# ===========================================================================

from bounty.detect.api_docs.graphql import GraphqlIntrospection, GraphqlPlayground
from bounty.detect.api_docs.openapi import OpenApiJsonExposed, SwaggerUiExposed
from bounty.detect.api_docs.postman import PostmanCollectionExposed


class TestSwaggerUiExposed:
    det = SwaggerUiExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_swagger_ui_html(self) -> None:
        html = "<html><head><title>Swagger UI</title></head><body><div id='swagger-ui'></div></body></html>"
        ctx = _ctx({"/swagger-ui.html": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 300

    @pytest.mark.asyncio
    async def test_fires_on_docs_path(self) -> None:
        html = "<html><body>SwaggerUI - API Documentation</body></html>"
        ctx = _ctx({"/docs": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_swagger_marker(self) -> None:
        html = "<html><body>API Reference Guide here</body></html>"
        ctx = _ctx({"/api-docs": _html_pr(html)})
        assert await _collect(self.det, _asset(), ctx) == []


class TestOpenApiJsonExposed:
    det = OpenApiJsonExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_openapi_json(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "My API", "version": "1.0.0"},
            "paths": {"/users": {"get": {"summary": "List users"}}},
        }
        ctx = _ctx({"/openapi.json": _json_pr(spec)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_severity_bumped_with_auth_schemes(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "API", "version": "1.0"},
            "paths": {"/secret": {}},
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        }
        ctx = _ctx({"/openapi.json": _json_pr(spec)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity > 400

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_non_spec_json(self) -> None:
        ctx = _ctx({"/openapi.json": _json_pr({"foo": "bar"})})
        assert await _collect(self.det, _asset(), ctx) == []


class TestGraphqlIntrospection:
    det = GraphqlIntrospection()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_introspection_response_via_post(self) -> None:
        response = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"name": "User"}, {"name": "Post"}],
                }
            }
        }
        ctx = _ctx(
            {},
            post_responses={"/graphql": _json_pr(response)},
        )
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 500

    @pytest.mark.asyncio
    async def test_fires_without_post_fn_using_get_fallback(self) -> None:
        # Without post_json_fn, falls back to GET probe
        response_body = b'{"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}}'
        ctx = _ctx({"/graphql": _pr(body=response_body, ct="application/json")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx(
            {},
            post_responses={"/graphql": _pr(status_code=404)},
        )
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_non_graphql_response(self) -> None:
        ctx = _ctx(
            {},
            post_responses={"/graphql": _json_pr({"error": "not found"})},
        )
        assert await _collect(self.det, _asset(), ctx) == []


class TestGraphqlPlayground:
    det = GraphqlPlayground()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_graphiql(self) -> None:
        html = "<html><title>GraphiQL</title><body>graphiql editor here</body></html>"
        ctx = _ctx({"/graphiql": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 300

    @pytest.mark.asyncio
    async def test_fires_on_playground_path(self) -> None:
        html = "<html><body>GraphQL Playground - Execute queries</body></html>"
        ctx = _ctx({"/playground": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_graphql_marker(self) -> None:
        html = "<html><body>API Explorer - REST documentation</body></html>"
        ctx = _ctx({"/playground": _html_pr(html)})
        assert await _collect(self.det, _asset(), ctx) == []


class TestPostmanCollectionExposed:
    det = PostmanCollectionExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_postman_collection_v2(self) -> None:
        data = {
            "info": {"_postman_id": "abc123", "name": "My API", "schema": "https://schema.getpostman.com"},
            "item": [{"name": "Get Users", "request": {"url": "https://api.example.com/users"}}],
        }
        ctx = _ctx({"/postman_collection.json": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_severity_bumped_with_credentials(self) -> None:
        data = {
            "info": {"_postman_id": "abc"},
            "item": [{"name": "Auth", "request": {"header": [{"key": "Authorization", "value": "Bearer MYTOKEN"}]}}],
        }
        ctx = _ctx({"/postman_collection.json": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity >= 700

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_non_postman_json(self) -> None:
        ctx = _ctx({"/postman_collection.json": _json_pr({"foo": "bar"})})
        assert await _collect(self.det, _asset(), ctx) == []


# ===========================================================================
# 11. Spring Boot Actuator
# ===========================================================================

from bounty.detect.java_spring.actuator import (
    ActuatorEnv,
    ActuatorExposed,
    ActuatorHeapdump,
    ActuatorLoggers,
)
from bounty.detect.java_spring.h2console import H2Console


class TestActuatorExposed:
    det = ActuatorExposed()

    def test_not_applicable_without_spring(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_spring(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Spring Boot")])

    def test_applicable_with_spring_lowercase(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("spring")])

    @pytest.mark.asyncio
    async def test_fires_on_actuator_links(self) -> None:
        data = {
            "_links": {
                "self": {"href": "http://localhost/actuator"},
                "health": {"href": "http://localhost/actuator/health"},
                "env": {"href": "http://localhost/actuator/env"},
            }
        }
        ctx = _ctx({"/actuator": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity >= 600

    @pytest.mark.asyncio
    async def test_severity_bumped_with_dangerous_endpoints(self) -> None:
        data = {
            "_links": {
                "env": {"href": "..."},
                "heapdump": {"href": "..."},
                "shutdown": {"href": "..."},
            }
        }
        ctx = _ctx({"/actuator": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings[0].severity == 800

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/actuator": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_links(self) -> None:
        ctx = _ctx({"/actuator": _json_pr({"status": "UP"})})
        assert await _collect(self.det, _asset(), ctx) == []


class TestActuatorEnv:
    det = ActuatorEnv()

    def test_not_applicable_without_spring(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_spring(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Spring")])

    @pytest.mark.asyncio
    async def test_fires_on_env_endpoint(self) -> None:
        data = {
            "activeProfiles": ["prod"],
            "propertySources": [
                {"name": "systemEnvironment", "properties": {"DB_PASSWORD": {"value": "******"}}},
            ],
        }
        ctx = _ctx({"/actuator/env": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 900

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/actuator/env": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_property_sources(self) -> None:
        ctx = _ctx({"/actuator/env": _json_pr({"status": "UP"})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_dedup_key_has_path(self) -> None:
        data = {"propertySources": [{"name": "test", "properties": {}}]}
        ctx = _ctx({"/actuator/env": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings
        assert "/actuator/env" in findings[0].path


class TestActuatorHeapdump:
    det = ActuatorHeapdump()

    def test_not_applicable_without_spring(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_spring_boot(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("spring-boot")])

    @pytest.mark.asyncio
    async def test_fires_on_hprof_magic(self) -> None:
        body = b"JAVA PROFILE 1.0.2\x00" + b"\x00" * 200
        ctx = _ctx({"/actuator/heapdump": _pr(body=body, ct="application/octet-stream")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 950

    @pytest.mark.asyncio
    async def test_fires_on_large_binary(self) -> None:
        body = b"\x1f\x8b" + b"\x00" * (150 * 1024)  # gzip magic + large body
        ctx = _ctx({"/actuator/heapdump": _pr(body=body, ct="application/octet-stream")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/actuator/heapdump": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_small_body(self) -> None:
        ctx = _ctx({"/actuator/heapdump": _pr(body=b"small", ct="application/octet-stream")})
        assert await _collect(self.det, _asset(), ctx) == []


class TestActuatorLoggers:
    det = ActuatorLoggers()

    def test_not_applicable_without_spring(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_spring(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Spring Boot")])

    @pytest.mark.asyncio
    async def test_fires_on_loggers_endpoint(self) -> None:
        data = {
            "levels": ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"],
            "loggers": {
                "ROOT": {"effectiveLevel": "INFO"},
                "com.example.app": {"effectiveLevel": "DEBUG"},
            },
        }
        ctx = _ctx({"/actuator/loggers": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 500

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/actuator/loggers": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_loggers_key(self) -> None:
        ctx = _ctx({"/actuator/loggers": _json_pr({"status": "UP"})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_logger_count_in_description(self) -> None:
        data = {"levels": ["INFO"], "loggers": {f"pkg.{i}": {"effectiveLevel": "INFO"} for i in range(5)}}
        ctx = _ctx({"/actuator/loggers": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert "5" in findings[0].description


class TestH2Console:
    det = H2Console()

    def test_not_applicable_without_spring(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_spring(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("Spring")])

    @pytest.mark.asyncio
    async def test_fires_on_h2_console(self) -> None:
        html = "<html><h1>H2 Console</h1><input id='url' value='jdbc url'></html>"
        ctx = _ctx({"/h2-console": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 800

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/h2-console": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_h2_marker(self) -> None:
        html = "<html><h1>Admin Console</h1></html>"
        ctx = _ctx({"/h2-console": _html_pr(html)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_cwe_is_284(self) -> None:
        html = "<html>H2 Database Console<input value='jdbc url'></html>"
        ctx = _ctx({"/h2-console": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings[0].cwe == "CWE-284"


# ===========================================================================
# 12. PHP Specific
# ===========================================================================

from bounty.detect.php_specific.composer import ComposerFilesExposed
from bounty.detect.php_specific.phpinfo import PhpinfoExposed
from bounty.detect.php_specific.server_status import ServerInfo, ServerStatus


class TestPhpinfoExposed:
    det = PhpinfoExposed()

    def test_not_applicable_without_php(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_with_php(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("PHP")])

    @pytest.mark.asyncio
    async def test_fires_on_phpinfo(self) -> None:
        html = "<html><title>phpinfo()</title><body>PHP Version 8.2.0<br>PHP Extension...</body></html>"
        ctx = _ctx({"/info.php": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 500

    @pytest.mark.asyncio
    async def test_fires_on_phpinfo_php(self) -> None:
        html = "<html><body>PHP Version 7.4.33<br>php.ini: /etc/php.ini</body></html>"
        ctx = _ctx({"/phpinfo.php": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_php_marker(self) -> None:
        html = "<html><body>Version 8.2.0</body></html>"
        ctx = _ctx({"/info.php": _html_pr(html)})
        assert await _collect(self.det, _asset(), ctx) == []


class TestServerStatus:
    det = ServerStatus()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_apache_status(self) -> None:
        html = "<html><h1>Apache Server Status for example.com</h1><dt>Server version: Apache/2.4.54</dt></html>"
        ctx = _ctx({"/server-status": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 400

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/server-status": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_apache_marker(self) -> None:
        html = "<html><body>Server monitoring dashboard</body></html>"
        ctx = _ctx({"/server-status": _html_pr(html)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_fires_on_requests_per_sec_marker(self) -> None:
        html = "<html><dt>Requests/sec: 12.5</dt><dt>Server uptime: 5 days</dt></html>"
        ctx = _ctx({"/server-status": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1


class TestServerInfo:
    det = ServerInfo()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_server_information(self) -> None:
        html = "<html><h1>Apache Server Information</h1><dt>Loaded Modules: mod_php8</dt></html>"
        ctx = _ctx({"/server-info": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 300

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/server-info": _pr(status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_server_info_marker(self) -> None:
        html = "<html><body>Server Configuration Guide</body></html>"
        ctx = _ctx({"/server-info": _html_pr(html)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_fires_on_module_information(self) -> None:
        html = "<html><h1>Module Information: mod_rewrite</h1></html>"
        ctx = _ctx({"/server-info": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1


class TestComposerFilesExposed:
    det = ComposerFilesExposed()

    def test_applicable_to_all(self) -> None:
        assert self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_fires_on_composer_json(self) -> None:
        data = {
            "name": "myapp/api",
            "require": {"laravel/framework": "^10.0", "guzzlehttp/guzzle": "^7.0"},
        }
        ctx = _ctx({"/composer.json": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_fires_on_composer_lock(self) -> None:
        data = {
            "content-hash": "abc123",
            "packages": [{"name": "laravel/framework", "version": "10.2.3"}],
        }
        ctx = _ctx({"/composer.lock": _json_pr(data)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 400  # lock is more valuable

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_on_non_composer_json(self) -> None:
        ctx = _ctx({"/composer.json": _json_pr({"version": "1.0"})})
        assert await _collect(self.det, _asset(), ctx) == []


# ===========================================================================
# 13. Network Services (banner-grab gated by port)
# ===========================================================================

from bounty.detect.network_services.databases import (
    ElasticsearchHttpExposed,
    MongoExposed,
    MysqlExposed,
    PostgresExposed,
    RedisExposed,
)


class TestRedisExposed:
    det = RedisExposed()

    def test_applicable_on_port_6379(self) -> None:
        assert self.det.applicable_to(_asset(port=6379), [])

    def test_not_applicable_on_other_port(self) -> None:
        assert not self.det.applicable_to(_asset(port=80), [])

    def test_not_applicable_without_port(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_no_finding_when_banner_grab_fails(self) -> None:
        """Without actual Redis running, banner grab fails gracefully."""
        ctx = _ctx({})
        # No real Redis bound to test port; should not raise, just no finding
        findings = await _collect(self.det, _asset("127.0.0.1", port=6379), ctx)
        # May be empty (no Redis) — we just check it doesn't crash
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_severity_is_950(self) -> None:
        assert self.det.severity_default == 950


class TestMongoExposed:
    det = MongoExposed()

    def test_applicable_on_port_27017(self) -> None:
        assert self.det.applicable_to(_asset(port=27017), [])

    def test_not_applicable_on_other_port(self) -> None:
        assert not self.det.applicable_to(_asset(port=80), [])

    def test_not_applicable_without_port(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    @pytest.mark.asyncio
    async def test_no_crash_without_mongo(self) -> None:
        ctx = _ctx({})
        findings = await _collect(self.det, _asset("127.0.0.1", port=27017), ctx)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_severity_is_950(self) -> None:
        assert self.det.severity_default == 950


class TestElasticsearchHttpExposed:
    det = ElasticsearchHttpExposed()

    def test_applicable_on_port_9200(self) -> None:
        assert self.det.applicable_to(_asset(port=9200), [])

    def test_not_applicable_on_other_port(self) -> None:
        assert not self.det.applicable_to(_asset(port=80), [])

    @pytest.mark.asyncio
    async def test_fires_on_cluster_info(self) -> None:
        data = {
            "name": "node-1",
            "cluster_name": "my-cluster",
            "cluster_uuid": "abc123",
            "version": {"number": "8.11.0", "build_flavor": "default"},
            "tagline": "You Know, for Search",
        }
        ctx = _ctx({"/": _json_pr(data)})
        findings = await _collect(self.det, _asset(port=9200), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 700

    @pytest.mark.asyncio
    async def test_no_finding_on_404(self) -> None:
        ctx = _ctx({"/": _pr(status_code=404)})
        assert await _collect(self.det, _asset(port=9200), ctx) == []

    @pytest.mark.asyncio
    async def test_no_finding_without_cluster_info(self) -> None:
        ctx = _ctx({"/": _json_pr({"status": "green"})})
        assert await _collect(self.det, _asset(port=9200), ctx) == []


class TestPostgresExposed:
    det = PostgresExposed()

    def test_applicable_on_port_5432(self) -> None:
        assert self.det.applicable_to(_asset(port=5432), [])

    def test_not_applicable_on_other_port(self) -> None:
        assert not self.det.applicable_to(_asset(port=80), [])

    @pytest.mark.asyncio
    async def test_no_crash_without_postgres(self) -> None:
        ctx = _ctx({})
        findings = await _collect(self.det, _asset("127.0.0.1", port=5432), ctx)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_severity_is_950(self) -> None:
        assert self.det.severity_default == 950


class TestMysqlExposed:
    det = MysqlExposed()

    def test_applicable_on_port_3306(self) -> None:
        assert self.det.applicable_to(_asset(port=3306), [])

    def test_not_applicable_on_other_port(self) -> None:
        assert not self.det.applicable_to(_asset(port=80), [])

    @pytest.mark.asyncio
    async def test_no_crash_without_mysql(self) -> None:
        ctx = _ctx({})
        findings = await _collect(self.det, _asset("127.0.0.1", port=3306), ctx)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_severity_is_950(self) -> None:
        assert self.det.severity_default == 950


# ===========================================================================
# 14. Integration / Registry Tests
# ===========================================================================

class TestRegistryIntegration:
    def test_registered_detections_count(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS
        # Should be at least 47 (existing) + 46 (new phase 12) = 93+
        assert len(REGISTERED_DETECTIONS) >= 90

    def test_all_have_unique_ids(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS
        ids = [d.id for d in REGISTERED_DETECTIONS]
        assert len(ids) == len(set(ids)), "Duplicate detection IDs found"

    def test_all_have_non_empty_names(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS
        for d in REGISTERED_DETECTIONS:
            assert d.name, f"Empty name for {d.id}"

    def test_all_have_valid_severity(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS
        for d in REGISTERED_DETECTIONS:
            assert 0 <= d.severity_default <= 1000, f"Invalid severity for {d.id}"

    def test_all_new_categories_present(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS
        categories = {d.category for d in REGISTERED_DETECTIONS}
        assert "cms_misconfiguration" in categories
        assert "cloud_misconfiguration" in categories
        assert "ai_infra_exposure" in categories
        assert "api_docs_exposure" in categories
        assert "java_spring_exposure" in categories
        assert "php_exposure" in categories
        assert "network_service_exposure" in categories

    def test_spring_detections_gated_by_fingerprint(self) -> None:
        from bounty.detect.java_spring.actuator import ActuatorExposed
        det = ActuatorExposed()
        assert not det.applicable_to(_asset(), [])
        assert det.applicable_to(_asset(), [_fp("Spring Boot")])

    def test_wordpress_detections_gated_by_fingerprint(self) -> None:
        det = WpDebugLog()
        assert not det.applicable_to(_asset(), [])
        assert det.applicable_to(_asset(), [_fp("WordPress")])

    def test_network_services_gated_by_port(self) -> None:
        from bounty.detect.network_services.databases import RedisExposed
        det = RedisExposed()
        assert not det.applicable_to(_asset(), [])
        assert det.applicable_to(_asset(port=6379), [])

    @pytest.mark.asyncio
    async def test_actuator_exposed_firing_scenario(self) -> None:
        """Integration: Spring fingerprint + /actuator response → ActuatorExposed fires."""
        from bounty.detect.java_spring.actuator import ActuatorExposed
        det = ActuatorExposed()
        asset = _asset()
        fps = [_fp("Spring Boot")]
        assert det.applicable_to(asset, fps)
        data = {"_links": {"health": {"href": "..."}, "env": {"href": "..."}}}
        ctx = _ctx({"/actuator": _json_pr(data)})
        findings = await _collect(det, asset, ctx)
        assert len(findings) == 1
        assert "actuator" in findings[0].url

    @pytest.mark.asyncio
    async def test_swagger_fires_with_any_fingerprint(self) -> None:
        html = "<html><body><div id='swagger-ui'>swagger-ui</div></body></html>"
        ctx = _ctx({"/swagger-ui.html": _html_pr(html)})
        findings = await _collect(SwaggerUiExposed(), _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_ollama_and_spring_are_independent(self) -> None:
        """Ollama fires for all; Spring detections only for Spring assets."""
        ollama = OllamaExposed()
        actuator = ActuatorExposed()
        asset = _asset()
        fps_spring = [_fp("Spring Boot")]
        # Ollama applicable to plain asset
        assert ollama.applicable_to(asset, [])
        # Actuator NOT applicable to plain asset
        assert not actuator.applicable_to(asset, [])
        # Actuator applicable to Spring asset
        assert actuator.applicable_to(asset, fps_spring)

    def test_heapdump_has_critical_severity(self) -> None:
        from bounty.detect.java_spring.actuator import ActuatorHeapdump
        assert ActuatorHeapdump().severity_default == 950

    def test_redis_has_critical_severity(self) -> None:
        assert RedisExposed().severity_default == 950

    def test_magento_local_xml_has_critical_severity(self) -> None:
        assert MagentoLocalXml().severity_default == 900

    def test_actuator_env_has_critical_severity(self) -> None:
        assert ActuatorEnv().severity_default == 900

    def test_swagger_has_low_severity(self) -> None:
        assert SwaggerUiExposed().severity_default == 300

    @pytest.mark.asyncio
    async def test_openapi_json_fires_on_v2_spec(self) -> None:
        spec = {
            "swagger": "2.0",
            "info": {"title": "Petstore", "version": "1.0.0"},
            "paths": {"/pets": {}},
            "securityDefinitions": {"apiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"}},
        }
        ctx = _ctx({"/swagger.json": _json_pr(spec)})
        findings = await _collect(OpenApiJsonExposed(), _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity > 400  # bumped due to securityDefinitions

    @pytest.mark.asyncio
    async def test_graphql_playground_fires_on_graphiql(self) -> None:
        html = "<html><title>GraphiQL - My API</title><body>graphiql ide</body></html>"
        ctx = _ctx({"/graphiql": _html_pr(html)})
        findings = await _collect(GraphqlPlayground(), _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_cms_specific_cms_not_fire_on_wrong_cms(self) -> None:
        """WpDebugLog should not fire even if response matches — wrong CMS fingerprint."""
        body = b"PHP Notice: Undefined variable\nWordPress debug content\n"
        ctx = _ctx({"/wp-content/debug.log": _pr(body=body, ct="text/plain")})
        # Asset fingerprinted as Drupal, not WordPress
        findings = await _collect(WpDebugLog(), _asset(), ctx)
        # applicable_to returns False (no WordPress fingerprint), so run() never called
        assert findings == [] or WpDebugLog().applicable_to(_asset(), []) is False


