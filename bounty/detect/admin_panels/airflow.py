"""
bounty.detect.admin_panels.airflow — Apache Airflow admin panel detections.

Two detections:
- AirflowAnonymousAccess  (/api/v1/dags returns DAG list without auth)
- AirflowConfigExposed    (/config exposes airflow.cfg with secrets)
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

from bounty.detect._fingerprint_helpers import has_tech
from bounty.detect.admin_panels._common import is_json_response, json_has_keys
from bounty.detect.base import Detection, DetectionContext
from bounty.models import Asset, FindingDraft, FingerprintResult

_CONFIG_SECTION_RE = re.compile(r"\[core\]|\[database\]|\[webserver\]", re.IGNORECASE)


class AirflowAnonymousAccess(Detection):
    """Apache Airflow anonymous API access — /api/v1/dags returns DAG listing."""

    id = "admin_panel.airflow.anonymous"
    name = "Apache Airflow Anonymous Access"
    category = "admin_panel_exposure"
    severity_default = 850
    cwe = "CWE-284"
    tags = ("admin-panel", "airflow", "unauthenticated")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "airflow")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/api/v1/dags"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        if not is_json_response(pr):
            return
        if not json_has_keys(pr, ["dags"]):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/api/v1/dags",
            title=f"Apache Airflow anonymous access at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/api/v1/dags",
            description=(
                f"The Apache Airflow instance at {asset.url} allows unauthenticated "
                "access to its REST API. The /api/v1/dags endpoint returned DAG names, "
                "schedules, and execution history without requiring authentication. "
                "DAG metadata can reveal infrastructure names, schedules, and pipeline architecture."
            ),
            remediation=(
                "In airflow.cfg, set `[webserver] auth_backend = airflow.api.auth.backend.basic_auth` "
                "or configure OAuth2/LDAP. Remove `auth_backend = airflow.api.auth.backend.deny_all` "
                "if set to a permissive backend. Apply network-level access controls."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )


class AirflowConfigExposed(Detection):
    """Apache Airflow /config endpoint exposes airflow.cfg with secrets."""

    id = "admin_panel.airflow.config_exposed"
    name = "Apache Airflow Config Exposed"
    category = "admin_panel_exposure"
    severity_default = 950
    cwe = "CWE-312"
    tags = ("admin-panel", "airflow", "config-exposure", "secrets")

    def applicable_to(
        self, asset: Asset, fingerprints: list[FingerprintResult]
    ) -> bool:
        return has_tech(fingerprints, "airflow")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        url = asset.url.rstrip("/") + "/config"
        pr = await ctx.probe_fn(url)
        if pr.status_code != 200:
            return
        # Must contain INI-style section headers
        if not _CONFIG_SECTION_RE.search(pr.body_text):
            return

        await ctx.capture_evidence(url, pr)
        yield FindingDraft(
            asset_id=asset.id,
            scan_id=ctx.scan_id,
            dedup_key=f"{self.id}:{asset.id}:/config",
            title=f"Apache Airflow config exposed at {asset.host}",
            category=self.category,
            severity=self.severity_default,
            url=url,
            path="/config",
            description=(
                f"The Apache Airflow /config endpoint at {url} is publicly accessible "
                "and returned the full airflow.cfg configuration file. This configuration "
                "contains database connection strings, Fernet encryption keys, secret backends, "
                "and other sensitive credentials."
            ),
            remediation=(
                "Restrict access to /config in Airflow's webserver. "
                "In airflow.cfg, set `[webserver] expose_config = False`. "
                "Apply access controls at the reverse proxy level."
            ),
            cwe=self.cwe,
            tags=list(self.tags),
        )

