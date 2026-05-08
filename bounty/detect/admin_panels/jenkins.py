"""
bounty.detect.admin_panels.jenkins — Jenkins admin panel detections.

Three detections:
- JenkinsAnonymousDashboard  (anonymous READ access via /api/json)
- JenkinsScriptConsole       (unauthenticated Groovy RCE console at /script)
- JenkinsBuildHistoryExposed (build history / job names via /api/json?tree=…)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys, parse_json_body
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult


class JenkinsAnonymousDashboard(Detection):
    """Jenkins anonymous read access — /api/json returns job/view data."""

    id = "admin_panel.jenkins.anonymous_dashboard"
    name = "Jenkins Anonymous Dashboard Access"
    category = "admin_panel_exposure"
    severity_default = 700
    cwe = "CWE-284"
    tags = ("admin-panel", "jenkins", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "jenkins")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/json"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["jobs"]) and not json_has_keys(pr, ["views"]):
            return

        # Bump severity if real job data is present
        data = parse_json_body(pr)
        job_count = 0
        if isinstance(data, dict):
            jobs = data.get("jobs")
            if isinstance(jobs, list):
                job_count = len(jobs)
        sev = 900 if job_count > 0 else self.severity_default

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/json",
            title=f"Jenkins anonymous access at {asset.host}",
            category=self.category,
            severity=sev,
            url=url,
            path="/api/json",
            description=(
                f"The Jenkins instance at {asset.url} allows unauthenticated access "
                f"to its REST API. The /api/json endpoint returned job and view data "
                f"({job_count} job(s) exposed) without requiring authentication."
            ),
            remediation=(
                "Enable the Matrix Authorization Strategy or Role-Based Access Control "
                "plugin in Jenkins. Under Manage Jenkins → Configure Global Security, "
                "disable 'Allow anonymous read access'."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class JenkinsScriptConsole(Detection):
    """Jenkins Groovy Script Console accessible without authentication — RCE risk."""

    id = "admin_panel.jenkins.script_console"
    name = "Jenkins Script Console Exposed"
    category = "admin_panel_exposure"
    severity_default = 950
    cwe = "CWE-78"
    tags = ("admin-panel", "jenkins", "rce", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "jenkins")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/script"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        body_lower = pr.body_text.lower()
        if "groovy" not in body_lower and "script console" not in body_lower:
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/script",
            title=f"Jenkins Script Console exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/script",
            description=(
                f"The Jenkins Groovy Script Console at {url} is accessible without "
                "authentication. The Script Console allows arbitrary code execution "
                "on the Jenkins server — this constitutes unauthenticated Remote Code Execution."
            ),
            remediation=(
                "Restrict access to /script and /scriptText with Jenkins security. "
                "Enable the Authorize Project plugin and disable anonymous access. "
                "Apply network-level controls (firewall / reverse-proxy) to limit "
                "exposure of the Jenkins UI."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class JenkinsBuildHistoryExposed(Detection):
    """Jenkins build history accessible without authentication — job metadata leak."""

    id = "admin_panel.jenkins.build_history"
    name = "Jenkins Build History Exposed"
    category = "admin_panel_exposure"
    severity_default = 600
    cwe = "CWE-284"
    tags = ("admin-panel", "jenkins", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "jenkins")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        path = "/api/json?tree=jobs[name,builds[number,url,timestamp,result]]"
        url = asset.url.rstrip("/") + path
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        data = parse_json_body(pr)
        if not isinstance(data, dict) or "jobs" not in data:
            return

        # Bump severity if build entries contain environment-like keys
        body_lower = pr.body_text.lower()
        sev = self.severity_default
        if "actions" in body_lower or "environment" in body_lower or "parameters" in body_lower:
            sev = 800

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/json",
            title=f"Jenkins build history exposed at {asset.host}",
            category=self.category,
            severity=sev,
            url=url,
            path="/api/json",
            description=(
                f"The Jenkins instance at {asset.url} exposes build history including "
                "job names, build numbers, timestamps, and results without requiring "
                "authentication. Build metadata can reveal deployment pipelines and "
                "infrastructure naming conventions."
            ),
            remediation=(
                "Enable the Matrix Authorization Strategy or Role-Based Access Control "
                "plugin. Disable anonymous read access in Jenkins Global Security settings."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

