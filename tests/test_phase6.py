"""
tests/test_phase6.py — Phase 6 (Admin Panel Detection) test suite.

Test sections:
1.  JenkinsAnonymousDashboard   — 4 tests
2.  JenkinsScriptConsole        — 4 tests
3.  JenkinsBuildHistoryExposed  — 4 tests
4.  GrafanaAnonymousAccess      — 4 tests
5.  GrafanaSnapshotExposed      — 4 tests
6.  KibanaAnonymousAccess       — 4 tests
7.  PhpMyAdminLoginExposed      — 4 tests
8.  AdminerLoginExposed         — 4 tests
9.  SolrAdminConsole            — 4 tests
10. SolrCoresExposed            — 4 tests
11. AirflowAnonymousAccess      — 4 tests
12. AirflowConfigExposed        — 4 tests
13. ArgoCDAnonymousAccess       — 4 tests
14. RabbitMQManagementExposed   — 4 tests
15. VaultUIExposed              — 4 tests
16. ConsulAPIExposed            — 4 tests
17. ElasticsearchClusterExposed — 4 tests
18. ElasticsearchIndicesExposed — 4 tests
19. PrometheusMetricsExposed    — 4 tests
20. K8sDashboardExposed         — 4 tests
21. PortainerAPIExposed         — 4 tests
22. SonarQubeAnonymousAccess    — 4 tests
23. HarborRegistryExposed       — 4 tests
24. NexusRepositoryExposed      — 4 tests
25. GitLabPublicProjectsExposed — 4 tests
26. GiteaPublicReposExposed     — 4 tests
27. Integration tests           — 5 tests
28. has_tech() parametrized     — 6 tests

Total: 26*4 + 5 + 6 = 115 tests
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import (
    is_json_response,
    is_admin_panel_html,
    json_has_keys,
    parse_json_body,
)
from bounty.detect.admin_panels.jenkins import (
    JenkinsAnonymousDashboard,
    JenkinsScriptConsole,
    JenkinsBuildHistoryExposed,
)
from bounty.detect.admin_panels.grafana import GrafanaAnonymousAccess, GrafanaSnapshotExposed
from bounty.detect.admin_panels.kibana import KibanaAnonymousAccess
from bounty.detect.admin_panels.phpmyadmin import PhpMyAdminLoginExposed
from bounty.detect.admin_panels.adminer import AdminerLoginExposed
from bounty.detect.admin_panels.solr import SolrAdminConsole, SolrCoresExposed
from bounty.detect.admin_panels.airflow import AirflowAnonymousAccess, AirflowConfigExposed
from bounty.detect.admin_panels.argocd import ArgoCDAnonymousAccess
from bounty.detect.admin_panels.rabbitmq import RabbitMQManagementExposed
from bounty.detect.admin_panels.vault import VaultUIExposed
from bounty.detect.admin_panels.consul import ConsulAPIExposed
from bounty.detect.admin_panels.elasticsearch import (
    ElasticsearchClusterExposed,
    ElasticsearchIndicesExposed,
)
from bounty.detect.admin_panels.prometheus import PrometheusMetricsExposed
from bounty.detect.admin_panels.kubernetes_dashboard import K8sDashboardExposed
from bounty.detect.admin_panels.portainer import PortainerAPIExposed
from bounty.detect.admin_panels.sonarqube import SonarQubeAnonymousAccess
from bounty.detect.admin_panels.harbor import HarborRegistryExposed
from bounty.detect.admin_panels.nexus import NexusRepositoryExposed
from bounty.detect.admin_panels.gitlab import GitLabPublicProjectsExposed
from bounty.detect.admin_panels.gitea import GiteaPublicReposExposed
from bounty.detect.base import DetectionContext
from bounty.models import Asset, EvidencePackage, FindingDraft, FingerprintResult, ProbeResult

# ============================================================================
# Shared helpers
# ============================================================================

def _pr(
    *,
    status_code: int = 200,
    body: bytes = b"",
    ct: str = "application/json",
    url: str = "https://example.com/",
) -> ProbeResult:
    """Build a minimal ProbeResult for tests."""
    headers: dict[str, str] = {"content-type": ct} if ct else {}
    return ProbeResult(
        url=url,
        final_url=url,
        status_code=status_code,
        headers=headers,
        body=body,
        body_text=body.decode("utf-8", errors="replace"),
    )


def _json_pr(data: Any, *, status_code: int = 200, url: str = "https://example.com/") -> ProbeResult:
    """Build a ProbeResult with JSON body."""
    body = json.dumps(data).encode()
    return _pr(status_code=status_code, body=body, ct="application/json", url=url)


def _html_pr(html: str, *, status_code: int = 200) -> ProbeResult:
    """Build a ProbeResult with HTML body."""
    return _pr(status_code=status_code, body=html.encode(), ct="text/html")


def _fp(tech: str, confidence: str = "strong") -> FingerprintResult:
    """Build a FingerprintResult fixture."""
    from typing import cast
    from bounty.models import ConfidenceTier
    return FingerprintResult(tech=tech, confidence=cast(ConfidenceTier, confidence))


def _asset(host: str = "example.com") -> Asset:
    return Asset(
        id="01TEST000000000000000000001",
        program_id="prog_test",
        host=host,
        url=f"https://{host}",
        scheme="https",
        primary_scheme="https",
    )


async def _noop_capture(url: str, pr: ProbeResult, scan_id: str) -> EvidencePackage:
    return EvidencePackage(kind="http", response_status=pr.status_code)


def _ctx(responses: dict[str, ProbeResult]) -> DetectionContext:
    """Build DetectionContext with URL-keyed probe mock (suffix-matching)."""
    import structlog
    from bounty.config import get_settings

    async def _probe(url: str) -> ProbeResult:
        if url in responses:
            return responses[url]
        for pattern, resp in responses.items():
            if url.endswith(pattern) or pattern in url:
                return resp
        return _pr(status_code=404, body=b"Not Found", ct="text/html")

    return DetectionContext(
        probe_fn=_probe,
        capture_fn=_noop_capture,
        scan_id="scan-test-phase6",
        settings=get_settings(),
        log=structlog.get_logger(),
    )


async def _collect(detection: Any, asset: Asset, ctx: DetectionContext) -> list[FindingDraft]:
    """Drain an async generator detection run into a list."""
    return [f async for f in detection.run(asset, ctx)]


# ============================================================================
# 1. JenkinsAnonymousDashboard
# ============================================================================

class TestJenkinsAnonymousDashboard:
    det = JenkinsAnonymousDashboard()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("nginx")])

    def test_applicable_with_jenkins(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("jenkins")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"jobs": [{"name": "deploy-prod", "url": "http://ci/job/deploy"}], "views": [{"name": "All"}]}
        ctx = _ctx({"/api/json": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "admin_panel_exposure"
        assert "admin_panel.jenkins.anonymous_dashboard" in f.dedup_key
        assert f.severity >= 700

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/api/json": _pr(status_code=404, body=b"Not Found", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_on_non_json(self) -> None:
        ctx = _ctx({"/api/json": _pr(body=b"<html>not json</html>", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_wrong_keys(self) -> None:
        ctx = _ctx({"/api/json": _json_pr({"unrelated": "data"})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_severity_bumped_with_jobs(self) -> None:
        body = {"jobs": [{"name": "prod-deploy"}], "views": []}
        ctx = _ctx({"/api/json": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert findings[0].severity == 900


# ============================================================================
# 2. JenkinsScriptConsole
# ============================================================================

class TestJenkinsScriptConsole:
    det = JenkinsScriptConsole()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("tomcat")])

    def test_applicable_with_jenkins(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("jenkins", "definitive")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        html = b"<html><h1>Groovy Script Console</h1><form></form></html>"
        ctx = _ctx({"/script": _pr(body=html, ct="text/html")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        f = findings[0]
        assert "admin_panel.jenkins.script_console" in f.dedup_key
        assert f.severity == 950

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/script": _pr(status_code=404, body=b"Not Found", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_no_markers(self) -> None:
        html = b"<html><body>Generic page</body></html>"
        ctx = _ctx({"/script": _pr(body=html, ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 3. JenkinsBuildHistoryExposed
# ============================================================================

class TestJenkinsBuildHistoryExposed:
    det = JenkinsBuildHistoryExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("gitlab")])

    def test_applicable_with_jenkins(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("jenkins")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"jobs": [{"name": "build", "builds": [{"number": 42, "result": "SUCCESS"}]}]}
        ctx = _ctx({"/api/json": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "build_history" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/api/json": _pr(status_code=404, body=b"N/A", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_wrong_structure(self) -> None:
        ctx = _ctx({"/api/json": _json_pr({"no_jobs_key": True})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 4. GrafanaAnonymousAccess
# ============================================================================

class TestGrafanaAnonymousAccess:
    det = GrafanaAnonymousAccess()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("prometheus")])

    def test_applicable_with_grafana(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("grafana")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = [{"id": 1, "type": "prometheus", "name": "Prometheus"}]
        ctx = _ctx({"/api/datasources": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "grafana.anonymous" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/api/datasources": _pr(status_code=401, body=b"Unauthorized", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_non_list_body(self) -> None:
        ctx = _ctx({"/api/datasources": _json_pr({"error": "not a list"})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 5. GrafanaSnapshotExposed
# ============================================================================

class TestGrafanaSnapshotExposed:
    det = GrafanaSnapshotExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("kibana")])

    def test_applicable_with_grafana(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("grafana", "weak")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = [{"key": "abcdef", "name": "CPU dashboard snapshot"}]
        ctx = _ctx({"/api/snapshots": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "grafana.snapshots" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/api/snapshots": _pr(status_code=404, body=b"Not Found", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_not_list(self) -> None:
        ctx = _ctx({"/api/snapshots": _json_pr({"snapshots": []})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 6. KibanaAnonymousAccess
# ============================================================================

class TestKibanaAnonymousAccess:
    det = KibanaAnonymousAccess()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("elasticsearch")])

    def test_applicable_with_kibana(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("kibana")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"version": {"number": "8.5.0"}, "name": "kibana-node-1"}
        ctx = _ctx({"/api/status": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "kibana.anonymous" in findings[0].dedup_key
        assert findings[0].severity == 800

    @pytest.mark.asyncio
    async def test_run_no_finding_on_403(self) -> None:
        ctx = _ctx({"/api/status": _pr(status_code=403, body=b"Forbidden", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_keys(self) -> None:
        ctx = _ctx({"/api/status": _json_pr({"status": "green"})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 7. PhpMyAdminLoginExposed
# ============================================================================

class TestPhpMyAdminLoginExposed:
    det = PhpMyAdminLoginExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("adminer")])

    def test_applicable_with_phpmyadmin(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("phpmyadmin")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        html = b"<html><body><input name='pma_username' /><input name='pma_password' /></body></html>"
        ctx = _ctx({"/": _html_pr(html.decode())})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "phpmyadmin.login_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/": _html_pr("Not Found", status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_no_markers(self) -> None:
        ctx = _ctx({"/": _html_pr("<html><body>Welcome to something else</body></html>")})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 8. AdminerLoginExposed
# ============================================================================

class TestAdminerLoginExposed:
    det = AdminerLoginExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("phpmyadmin")])

    def test_applicable_with_adminer(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("adminer")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        html = "<html><body><h1>Adminer</h1><form method='post'></form></body></html>"
        ctx = _ctx({"/": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "adminer.login_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/": _html_pr("Not Found", status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_no_markers(self) -> None:
        ctx = _ctx({"/": _html_pr("<html><body>Generic page</body></html>")})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 9. SolrAdminConsole
# ============================================================================

class TestSolrAdminConsole:
    det = SolrAdminConsole()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("elasticsearch")])

    def test_applicable_with_solr(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("solr")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        html = "<html><head><title>Apache Solr Admin</title></head><body>solr-logo</body></html>"
        ctx = _ctx({"/solr/": _html_pr(html)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "solr.admin_console" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/solr/": _html_pr("Not Found", status_code=404)})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_no_markers(self) -> None:
        ctx = _ctx({"/solr/": _html_pr("<html><body>nginx 404</body></html>")})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 10. SolrCoresExposed
# ============================================================================

class TestSolrCoresExposed:
    det = SolrCoresExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("prometheus")])

    def test_applicable_with_solr(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("solr", "definitive")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"status": {"core0": {"name": "core0", "instanceDir": "/var/solr/data/core0"}}, "initFailures": {}}
        ctx = _ctx({"/solr/admin/cores": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "solr.cores_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_403(self) -> None:
        ctx = _ctx({"/solr/admin/cores": _pr(status_code=403, body=b"Forbidden")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_status_key(self) -> None:
        ctx = _ctx({"/solr/admin/cores": _json_pr({"responseHeader": {"status": 0}})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 11. AirflowAnonymousAccess
# ============================================================================

class TestAirflowAnonymousAccess:
    det = AirflowAnonymousAccess()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("jenkins")])

    def test_applicable_with_airflow(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("airflow")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"dags": [{"dag_id": "etl_pipeline", "is_paused": False}], "total_entries": 1}
        ctx = _ctx({"/api/v1/dags": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "airflow.anonymous" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/api/v1/dags": _pr(status_code=401, body=b"Unauthorized", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_dags_key(self) -> None:
        ctx = _ctx({"/api/v1/dags": _json_pr({"connections": []})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 12. AirflowConfigExposed
# ============================================================================

class TestAirflowConfigExposed:
    det = AirflowConfigExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("argocd")])

    def test_applicable_with_airflow(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("airflow", "strong")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        config_body = b"[core]\nexecutor = SequentialExecutor\n[database]\nsql_alchemy_conn = sqlite:///airflow.db\n[webserver]\nbase_url = http://localhost:8080\n"
        ctx = _ctx({"/config": _pr(body=config_body, ct="text/plain")})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "airflow.config_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/config": _pr(status_code=404, body=b"Not Found", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_no_config_sections(self) -> None:
        ctx = _ctx({"/config": _pr(body=b"some random text without config sections", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 13. ArgoCDAnonymousAccess
# ============================================================================

class TestArgoCDAnonymousAccess:
    det = ArgoCDAnonymousAccess()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("jenkins")])

    def test_applicable_with_argocd(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("argocd")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"items": [{"metadata": {"name": "prod-app"}, "status": {"sync": {"status": "Synced"}}}]}
        ctx = _ctx({"/api/v1/applications": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "argocd.anonymous" in findings[0].dedup_key
        assert findings[0].severity == 900

    @pytest.mark.asyncio
    async def test_run_no_finding_on_403(self) -> None:
        ctx = _ctx({"/api/v1/applications": _pr(status_code=403, body=b"Forbidden", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_items_key(self) -> None:
        ctx = _ctx({"/api/v1/applications": _json_pr({"metadata": {}})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 14. RabbitMQManagementExposed
# ============================================================================

class TestRabbitMQManagementExposed:
    det = RabbitMQManagementExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("rabbitmq")])

    def test_applicable_with_rabbitmq_mgmt(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("rabbitmq-mgmt")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"rabbitmq_version": "3.11.0", "cluster_name": "rabbit@host", "management_version": "3.11.0"}
        ctx = _ctx({"/api/overview": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "rabbitmq.mgmt_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/api/overview": _pr(status_code=401, body=b"Unauthorized")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_version_key(self) -> None:
        ctx = _ctx({"/api/overview": _json_pr({"cluster_name": "rabbit@host"})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 15. VaultUIExposed
# ============================================================================

class TestVaultUIExposed:
    det = VaultUIExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("consul")])

    def test_applicable_with_vault(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("vault")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"sealed": False, "initialized": True, "version": "1.15.0"}
        ctx = _ctx({"/v1/sys/health": _json_pr(body, status_code=200)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "vault.ui_exposed" in findings[0].dedup_key
        # Initialized and unsealed — severity bumped to 700
        assert findings[0].severity == 700

    @pytest.mark.asyncio
    async def test_run_no_finding_on_unexpected_status(self) -> None:
        ctx = _ctx({"/v1/sys/health": _pr(status_code=404, body=b"Not Found", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_keys(self) -> None:
        ctx = _ctx({"/v1/sys/health": _json_pr({"version": "1.15.0"})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_yields_finding_on_503_sealed(self) -> None:
        """Vault returns 503 when sealed — still a valid finding."""
        body = {"sealed": True, "initialized": True, "version": "1.15.0"}
        ctx = _ctx({"/v1/sys/health": _json_pr(body, status_code=503)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        # Sealed vault — base severity
        assert findings[0].severity == 500


# ============================================================================
# 16. ConsulAPIExposed
# ============================================================================

class TestConsulAPIExposed:
    det = ConsulAPIExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("vault")])

    def test_applicable_with_consul(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("consul")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"Config": {"Datacenter": "dc1", "NodeName": "node-1", "Server": True}}
        ctx = _ctx({"/v1/agent/self": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "consul.api_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_403(self) -> None:
        ctx = _ctx({"/v1/agent/self": _pr(status_code=403, body=b"Permission denied", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_config_key(self) -> None:
        ctx = _ctx({"/v1/agent/self": _json_pr({"Member": {"Name": "node-1"}})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 17. ElasticsearchClusterExposed
# ============================================================================

class TestElasticsearchClusterExposed:
    det = ElasticsearchClusterExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("kibana")])

    def test_applicable_with_elasticsearch(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("elasticsearch")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {
            "name": "es-node-1",
            "cluster_name": "my-cluster",
            "version": {"number": "8.5.0", "lucene_version": "9.4.1"},
        }
        ctx = _ctx({"/": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "elasticsearch.cluster_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/": _pr(status_code=401, body=b"Unauthorized", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_keys(self) -> None:
        ctx = _ctx({"/": _json_pr({"name": "es-node-1"})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 18. ElasticsearchIndicesExposed
# ============================================================================

class TestElasticsearchIndicesExposed:
    det = ElasticsearchIndicesExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("solr")])

    def test_applicable_with_elasticsearch(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("elasticsearch", "strong")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = [
            {"index": "user_accounts", "health": "green", "status": "open", "docs.count": "15000"},
            {"index": "payment_logs", "health": "yellow", "status": "open", "docs.count": "8000"},
        ]
        ctx = _ctx({"/_cat/indices": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "elasticsearch.indices_exposed" in findings[0].dedup_key
        assert findings[0].severity == 900

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/_cat/indices": _pr(status_code=401, body=b"Unauthorized", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_non_list_body(self) -> None:
        ctx = _ctx({"/_cat/indices": _json_pr({"error": "security_exception"})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 19. PrometheusMetricsExposed
# ============================================================================

class TestPrometheusMetricsExposed:
    det = PrometheusMetricsExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("grafana")])

    def test_applicable_with_prometheus(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("prometheus")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        config_yaml = "global:\n  scrape_interval: 15s\nscrape_configs:\n  - job_name: 'prometheus'"
        body = {"status": "success", "data": {"yaml": config_yaml}}
        ctx = _ctx({"/api/v1/status/config": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "prometheus.metrics_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/api/v1/status/config": _pr(status_code=404, body=b"Not Found", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_data_yaml(self) -> None:
        ctx = _ctx({"/api/v1/status/config": _json_pr({"status": "success", "data": {}})})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_severity_bump_on_credentials(self) -> None:
        """Config containing password= should bump severity to 800."""
        config_yaml = "global:\n  scrape_interval: 15s\nscrape_configs:\n  - job_name: 'k8s'\n    basic_auth:\n      password: supersecret123\n"
        body = {"status": "success", "data": {"yaml": config_yaml}}
        ctx = _ctx({"/api/v1/status/config": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 800


# ============================================================================
# 20. K8sDashboardExposed
# ============================================================================

class TestK8sDashboardExposed:
    det = K8sDashboardExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("argocd")])

    def test_applicable_with_k8s_dashboard(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("k8s-dashboard")])

    @pytest.mark.asyncio
    async def test_run_yields_finding_via_api(self) -> None:
        api_body = {"tokenPresent": False, "headerPresent": False}
        ctx = _ctx({"/api/v1/login/status": _json_pr(api_body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "k8s_dashboard.exposed" in findings[0].dedup_key
        assert findings[0].severity == 950

    @pytest.mark.asyncio
    async def test_run_yields_finding_via_html_fallback(self) -> None:
        """Falls back to HTML check when API returns 404."""
        html = "<html><body><kubernetes-dashboard></kubernetes-dashboard></body></html>"
        ctx = _ctx({
            "/api/v1/login/status": _pr(status_code=404, body=b"Not Found", ct="text/html"),
            "/": _html_pr(html),
        })
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_run_no_finding_on_all_404(self) -> None:
        ctx = _ctx({
            "/api/v1/login/status": _pr(status_code=404, body=b"Not Found", ct="text/html"),
            "/": _html_pr("Generic homepage without dashboard markers"),
        })
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 21. PortainerAPIExposed
# ============================================================================

class TestPortainerAPIExposed:
    det = PortainerAPIExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("harbor")])

    def test_applicable_with_portainer(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("portainer")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = [{"ID": 1, "Name": "primary", "Type": 1, "URL": "unix:///var/run/docker.sock"}]
        ctx = _ctx({"/api/endpoints": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "portainer.api_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/api/endpoints": _pr(status_code=401, body=b"Unauthorized", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_non_list_body(self) -> None:
        ctx = _ctx({"/api/endpoints": _json_pr({"error": "access denied"})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 22. SonarQubeAnonymousAccess
# ============================================================================

class TestSonarQubeAnonymousAccess:
    det = SonarQubeAnonymousAccess()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("nexus")])

    def test_applicable_with_sonarqube(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("sonarqube")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"components": [{"key": "org.example:myapp", "name": "My App"}], "paging": {"total": 1}}
        ctx = _ctx({"/api/projects/search": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "sonarqube.anonymous" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/api/projects/search": _pr(status_code=401, body=b"Unauthorized", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_missing_components(self) -> None:
        ctx = _ctx({"/api/projects/search": _json_pr({"paging": {"total": 0}})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 23. HarborRegistryExposed
# ============================================================================

class TestHarborRegistryExposed:
    det = HarborRegistryExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("nexus")])

    def test_applicable_with_harbor(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("harbor")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = [{"name": "library", "public": True, "repo_count": 5}]
        ctx = _ctx({"/api/v2.0/projects": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "harbor.registry_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/api/v2.0/projects": _pr(status_code=401, body=b"Unauthorized", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_non_list_body(self) -> None:
        ctx = _ctx({"/api/v2.0/projects": _json_pr({"errors": [{"code": "UNAUTHORIZED"}]})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 24. NexusRepositoryExposed
# ============================================================================

class TestNexusRepositoryExposed:
    det = NexusRepositoryExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("harbor")])

    def test_applicable_with_nexus(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("nexus")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = [
            {"name": "maven-central", "format": "maven2", "type": "proxy", "url": "https://repo.example.com/service/rest/repository/browse/maven-central/"},
        ]
        ctx = _ctx({"/service/rest/v1/repositories": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "nexus.repository_exposed" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/service/rest/v1/repositories": _pr(status_code=401, body=b"Unauthorized", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_non_list_body(self) -> None:
        ctx = _ctx({"/service/rest/v1/repositories": _json_pr({"type": "object"})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 25. GitLabPublicProjectsExposed
# ============================================================================

class TestGitLabPublicProjectsExposed:
    det = GitLabPublicProjectsExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("gitea")])

    def test_applicable_with_gitlab(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("gitlab")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = [{"id": 1, "name": "myrepo", "visibility": "public", "path_with_namespace": "org/myrepo"}]
        ctx = _ctx({"/api/v4/projects": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "gitlab.public_projects" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_severity_bump_on_private_leak(self) -> None:
        """Private project appearing in public listing → severity 700."""
        body = [{"id": 1, "name": "secret-infra", "visibility": "private", "path_with_namespace": "org/secret-infra"}]
        ctx = _ctx({"/api/v4/projects": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 700

    @pytest.mark.asyncio
    async def test_run_no_finding_on_401(self) -> None:
        ctx = _ctx({"/api/v4/projects": _pr(status_code=401, body=b"Unauthorized", ct="text/plain")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_empty_list(self) -> None:
        ctx = _ctx({"/api/v4/projects": _json_pr([])})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 26. GiteaPublicReposExposed
# ============================================================================

class TestGiteaPublicReposExposed:
    det = GiteaPublicReposExposed()

    def test_applicable_no_fingerprint(self) -> None:
        assert not self.det.applicable_to(_asset(), [])

    def test_applicable_wrong_tech(self) -> None:
        assert not self.det.applicable_to(_asset(), [_fp("gitlab")])

    def test_applicable_with_gitea(self) -> None:
        assert self.det.applicable_to(_asset(), [_fp("gitea")])

    @pytest.mark.asyncio
    async def test_run_yields_finding(self) -> None:
        body = {"data": [{"name": "myrepo", "private": False, "full_name": "user/myrepo"}], "ok": True}
        ctx = _ctx({"/api/v1/repos/search": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert "gitea.public_repos" in findings[0].dedup_key

    @pytest.mark.asyncio
    async def test_run_severity_bump_on_private_leak(self) -> None:
        """Private repo in public listing → severity 700."""
        body = {"data": [{"name": "secret", "private": True, "full_name": "user/secret"}], "ok": True}
        ctx = _ctx({"/api/v1/repos/search": _json_pr(body)})
        findings = await _collect(self.det, _asset(), ctx)
        assert len(findings) == 1
        assert findings[0].severity == 700

    @pytest.mark.asyncio
    async def test_run_no_finding_on_404(self) -> None:
        ctx = _ctx({"/api/v1/repos/search": _pr(status_code=404, body=b"Not Found", ct="text/html")})
        assert await _collect(self.det, _asset(), ctx) == []

    @pytest.mark.asyncio
    async def test_run_no_finding_empty_data(self) -> None:
        ctx = _ctx({"/api/v1/repos/search": _json_pr({"data": [], "ok": True})})
        assert await _collect(self.det, _asset(), ctx) == []


# ============================================================================
# 27. Integration tests
# ============================================================================

class TestAdminPanelIntegration:
    def test_all_26_detections_registered(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS
        panels = [d for d in REGISTERED_DETECTIONS if d.id.startswith("admin_panel.")]
        assert len(panels) == 26

    def test_all_panels_have_correct_category(self) -> None:
        from bounty.detect import REGISTERED_DETECTIONS
        panels = [d for d in REGISTERED_DETECTIONS if d.id.startswith("admin_panel.")]
        for detection in panels:
            assert detection.category == "admin_panel_exposure", (
                f"{detection.id} has category {detection.category!r}"
            )

    def test_fingerprint_gating_no_panels_for_wrong_tech(self) -> None:
        """When asset is fingerprinted as nginx only, no admin panel runs."""
        from bounty.detect import REGISTERED_DETECTIONS
        panels = [d for d in REGISTERED_DETECTIONS if d.id.startswith("admin_panel.")]
        asset = _asset()
        fps = [_fp("nginx", "strong")]
        applicable = [d for d in panels if d.applicable_to(asset, fps)]
        assert len(applicable) == 0

    def test_fingerprint_gating_no_panels_for_empty_fingerprints(self) -> None:
        """With no fingerprints, no admin panel detections apply."""
        from bounty.detect import REGISTERED_DETECTIONS
        panels = [d for d in REGISTERED_DETECTIONS if d.id.startswith("admin_panel.")]
        asset = _asset()
        applicable = [d for d in panels if d.applicable_to(asset, [])]
        assert len(applicable) == 0

    @pytest.mark.asyncio
    async def test_admin_panel_pipeline_jenkins(self) -> None:
        """Jenkins asset with fingerprint and mocked API → at least 1 finding."""
        jenkins_api_body = {"jobs": [{"name": "deploy-prod"}], "views": [{"name": "All"}]}
        ctx = _ctx({
            "/api/json": _json_pr(jenkins_api_body),
            "/script": _pr(status_code=404, body=b"Not Found", ct="text/html"),
        })
        asset = _asset()
        fps = [_fp("jenkins", "strong")]

        all_findings: list[FindingDraft] = []
        for det in [JenkinsAnonymousDashboard(), JenkinsScriptConsole(), JenkinsBuildHistoryExposed()]:
            if det.applicable_to(asset, fps):
                findings = await _collect(det, asset, ctx)
                all_findings.extend(findings)

        admin_findings = [f for f in all_findings if "admin_panel.jenkins" in f.dedup_key]
        assert len(admin_findings) >= 1
        assert all(f.severity >= 600 for f in admin_findings)

    def test_common_helpers_is_json_response(self) -> None:
        assert is_json_response(_json_pr({"key": "value"}))
        assert not is_json_response(_html_pr("<html/>"))
        # Non-JSON content-type even with JSON body
        pr = _pr(body=b'{"key": "value"}', ct="text/plain")
        assert not is_json_response(pr)

    def test_common_helpers_json_has_keys(self) -> None:
        pr = _json_pr({"a": 1, "b": 2, "c": 3})
        assert json_has_keys(pr, ["a", "b"])
        assert not json_has_keys(pr, ["a", "d"])
        assert not json_has_keys(_html_pr("<html/>"), ["a"])

    def test_common_helpers_is_admin_panel_html(self) -> None:
        pr = _html_pr("<html><body>phpMyAdmin database admin</body></html>")
        assert is_admin_panel_html(pr, ["phpmyadmin"])
        assert not is_admin_panel_html(pr, ["jenkins", "grafana"])
        # 404 should not match
        pr_404 = _html_pr("<html><body>phpMyAdmin</body></html>", status_code=404)
        assert not is_admin_panel_html(pr_404, ["phpmyadmin"])

    def test_common_helpers_parse_json_body(self) -> None:
        pr = _json_pr({"key": "value"})
        result = parse_json_body(pr)
        assert isinstance(result, dict)
        assert result["key"] == "value"  # type: ignore[index]
        # Invalid JSON
        bad_pr = _pr(body=b"not json", ct="application/json")
        assert parse_json_body(bad_pr) is None


# ============================================================================
# 28. has_tech() parametrized tests
# ============================================================================

class TestHasTech:
    @pytest.mark.parametrize("tech,fps,expected", [
        # Matching tech at correct tier
        ("jenkins", [_fp("jenkins", "strong")], True),
        # Matching tech but below min_tier
        ("jenkins", [_fp("jenkins", "hint")], False),
        # Wrong tech
        ("jenkins", [_fp("nginx", "strong")], False),
        # Empty list
        ("jenkins", [], False),
        # Multiple fps, one matches
        ("grafana", [_fp("nginx", "strong"), _fp("grafana", "weak")], True),
        # Definitive confidence passes
        ("vault", [_fp("vault", "definitive")], True),
    ])
    def test_has_tech(
        self,
        tech: str,
        fps: list[FingerprintResult],
        expected: bool,
    ) -> None:
        assert has_tech(fps, tech) is expected

    def test_has_tech_weak_min_tier_accepts_strong(self) -> None:
        """Default min_tier=weak should accept strong confidence."""
        assert has_tech([_fp("elasticsearch", "strong")], "elasticsearch")

    def test_has_tech_strong_min_tier_rejects_weak(self) -> None:
        """min_tier=strong should reject weak confidence."""
        assert not has_tech([_fp("consul", "weak")], "consul", min_tier="strong")

    def test_has_tech_strong_min_tier_accepts_definitive(self) -> None:
        """min_tier=strong should accept definitive confidence."""
        assert has_tech([_fp("consul", "definitive")], "consul", min_tier="strong")


