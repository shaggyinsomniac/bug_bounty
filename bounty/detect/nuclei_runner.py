"""
bounty.detect.nuclei_runner — Nuclei subprocess wrapper.

Runs Nuclei OSS as a subprocess to scan assets for CVEs and
misconfigurations using the community template library (~10,000 templates).

Usage::

    from bounty.detect.nuclei_runner import NucleiRunner

    runner = NucleiRunner()
    findings = await runner.scan(asset, fingerprints)
    for f in findings:
        print(f.template_id, f.severity, f.matched_at)

Nuclei must be installed first::

    bounty tools install-nuclei
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from bounty import get_logger
from bounty.tools import get_nuclei_path, nuclei_install_hint

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Safety: always excluded template tags
# ---------------------------------------------------------------------------

_BLOCKED_TAGS: frozenset[str] = frozenset({
    "dos",
    "intrusive",
    "fuzz",
    "brute-force",
    "bruteforce",
    "slow",
    "destructive",
    "waf-bypass",
})

# ---------------------------------------------------------------------------
# Tech name → nuclei tag mapping
# ---------------------------------------------------------------------------

_TECH_TO_TAGS: dict[str, list[str]] = {
    # CMS
    "wordpress": ["wordpress"],
    "wp-plugins": ["wordpress"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "magento": ["magento"],
    "opencart": ["opencart"],
    "ghost": ["ghost"],
    "strapi": ["strapi"],
    # Web servers
    "apache": ["apache"],
    "nginx": ["nginx"],
    "iis": ["iis"],
    "microsoft-iis": ["iis"],
    "apache-tomcat": ["tomcat"],
    "tomcat": ["tomcat"],
    "lighttpd": ["lighttpd"],
    # Frameworks / languages
    "spring": ["spring"],
    "laravel": ["laravel"],
    "django": ["django"],
    "rails": ["rails"],
    "ruby-on-rails": ["rails"],
    "php": ["php"],
    "symfony": ["symfony"],
    "codeigniter": ["codeigniter"],
    "express": ["nodejs"],
    "node.js": ["nodejs"],
    "coldfusion": ["coldfusion"],
    # Admin / CI-CD panels
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "kibana": ["kibana"],
    "phpmyadmin": ["phpmyadmin"],
    "adminer": ["adminer"],
    "cpanel": ["cpanel"],
    "plesk": ["plesk"],
    "webmin": ["webmin"],
    "sonarqube": ["sonarqube"],
    "nexus": ["nexus"],
    "artifactory": ["artifactory"],
    "confluence": ["confluence"],
    "jira": ["jira"],
    "sharepoint": ["sharepoint"],
    "airflow": ["airflow"],
    "grafana": ["grafana"],
    # Infrastructure / devops
    "consul": ["consul"],
    "vault": ["vault"],
    "kubernetes": ["kubernetes", "k8s"],
    "docker": ["docker"],
    "portainer": ["portainer"],
    "rabbitmq": ["rabbitmq"],
    "prometheus": ["prometheus"],
    "harbor": ["harbor"],
    # Data stores
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql"],
    "mssql": ["mssql"],
    "elasticsearch": ["elasticsearch"],
    "solr": ["solr"],
    # Content editors
    "ckeditor": ["ckeditor"],
    "tinymce": ["tinymce"],
    "vbulletin": ["vbulletin"],
}

# Fallback when no fingerprint maps to a known tag
_FALLBACK_TAGS: list[str] = ["exposure", "misconfig"]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class NucleiFinding:
    """A single finding emitted by a Nuclei scan."""

    template_id: str
    """Nuclei template ID, e.g. ``'CVE-2021-44228'``."""

    name: str
    """Human-readable template name."""

    severity: str
    """Severity string: ``info``, ``low``, ``medium``, ``high``, ``critical``."""

    info_dict: dict[str, Any]
    """Full ``info`` block from the Nuclei JSON output."""

    matched_at: str
    """URL/endpoint where the template matched."""

    extracted_results: list[str] = field(default_factory=list)
    """Captured values from the match (e.g. version strings)."""

    curl_command: str = ""
    """cURL command to reproduce the finding (provided by Nuclei)."""

    tags: list[str] = field(default_factory=list)
    """Template tags from the nuclei template info block."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_tags_from_fingerprints(fingerprints: list[Any]) -> list[str]:
    """Build a Nuclei tag list from fingerprint results.

    Performs case-insensitive prefix matching against _TECH_TO_TAGS.
    Falls back to ``["exposure", "misconfig"]`` when nothing matches.

    Args:
        fingerprints: Objects with a ``tech`` attribute (FingerprintResult).

    Returns:
        Sorted, deduplicated list of Nuclei tag strings.
    """
    tags: set[str] = set()
    for fp in fingerprints:
        tech: str = (getattr(fp, "tech", "") or "").lower().strip()
        if not tech:
            continue
        if tech in _TECH_TO_TAGS:
            tags.update(_TECH_TO_TAGS[tech])
        else:
            # Prefix match: "wordpress-5.8" → "wordpress"
            for key, mapped in _TECH_TO_TAGS.items():
                if tech.startswith(key):
                    tags.update(mapped)
                    break
    if not tags:
        return list(_FALLBACK_TAGS)
    return sorted(tags)


def _parse_nuclei_line(line: str) -> NucleiFinding | None:
    """Parse a single JSON line from Nuclei ``--json`` stdout.

    Returns ``None`` for empty/non-JSON lines or output missing a template-id.
    """
    line = line.strip()
    if not line:
        return None
    try:
        obj: dict[str, Any] = json.loads(line)
    except json.JSONDecodeError:
        return None

    template_id: str = (
        obj.get("template-id")
        or obj.get("templateID")
        or obj.get("template_id")
        or ""
    )
    if not template_id:
        return None

    info: dict[str, Any] = obj.get("info") or {}
    name: str = str(info.get("name") or template_id)
    severity: str = str(info.get("severity") or "unknown").lower()

    matched_at: str = str(obj.get("matched-at") or obj.get("host") or "")

    extracted: list[str] = []
    extracted_raw = obj.get("extracted-results")
    if isinstance(extracted_raw, list):
        extracted = [str(x) for x in extracted_raw]

    curl_command: str = str(obj.get("curl-command") or "")

    # Parse tags from info block (can be comma-separated string or list)
    raw_tags = info.get("tags") or []
    if isinstance(raw_tags, str):
        tags: list[str] = [t.strip() for t in raw_tags.split(",") if t.strip()]
    elif isinstance(raw_tags, list):
        tags = [str(t) for t in raw_tags]
    else:
        tags = []

    return NucleiFinding(
        template_id=str(template_id),
        name=name,
        severity=severity,
        info_dict=info,
        matched_at=matched_at,
        extracted_results=extracted,
        curl_command=curl_command,
        tags=tags,
    )


# ---------------------------------------------------------------------------
# NucleiRunner
# ---------------------------------------------------------------------------


class NucleiRunner:
    """Runs Nuclei as a subprocess and returns parsed findings.

    Args:
        binary_path: Override the Nuclei binary path.
        timeout: Per-asset scan timeout in seconds.
        rate_limit: Maximum requests per second.
        blocked_tags: Tags whose templates are always filtered out
            (dos, intrusive, fuzz, etc.).
    """

    def __init__(
        self,
        binary_path: Path | None = None,
        timeout: int = 300,
        rate_limit: int = 50,
        blocked_tags: frozenset[str] | None = None,
    ) -> None:
        self.binary_path = binary_path
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.blocked_tags: frozenset[str] = (
            blocked_tags if blocked_tags is not None else _BLOCKED_TAGS
        )

    def _effective_path(self) -> Path | None:
        from bounty.config import get_settings
        settings = get_settings()
        override: Path | None = None
        if settings.nuclei_binary_path:
            override = Path(str(settings.nuclei_binary_path)).expanduser()
        return self.binary_path or get_nuclei_path(override)

    def _build_target_url(self, asset: Any) -> str:
        """Extract a scannable URL from an asset object."""
        url = getattr(asset, "url", None)
        if url:
            return str(url)
        scheme: str = str(getattr(asset, "primary_scheme", None) or "http")
        host: str = str(getattr(asset, "host", None) or "")
        port_raw = getattr(asset, "port", None)
        if host and port_raw is not None:
            port = int(port_raw)
            default = 443 if scheme == "https" else 80
            if port == default:
                return f"{scheme}://{host}"
            return f"{scheme}://{host}:{port}"
        if host:
            return f"http://{host}"
        return ""

    def _build_command(
        self,
        binary: Path,
        target: str,
        tags: list[str],
        severities: list[str],
    ) -> list[str]:
        """Assemble the Nuclei command list."""
        return [
            str(binary),
            "-target", target,
            "-json",
            "-silent",
            "-no-color",
            "-severity", ",".join(severities),
            "-tags", ",".join(tags),
            "-rate-limit", str(self.rate_limit),
            "-bulk-size", "25",
            "-timeout", "10",
            "-no-update-check",
        ]

    async def scan(
        self,
        asset: Any,
        fingerprints: list[Any],
        severities: Sequence[str] = ("medium", "high", "critical"),
        db_path: Path | None = None,
        scan_id: str = "",
    ) -> list[NucleiFinding]:
        """Scan an asset with Nuclei and return parsed findings.

        Args:
            asset: Asset object with ``.url`` or ``.host``/``.port`` attributes.
            fingerprints: FingerprintResult objects used to select template tags.
            severities: Severity levels to include.

        Returns:
            List of :class:`NucleiFinding` objects.  Returns an empty list if
            Nuclei is not installed, times out, or finds nothing.
        """
        effective_path = self._effective_path()
        if effective_path is None or not effective_path.exists():
            log.warning("nuclei_not_found", hint=nuclei_install_hint())
            return []

        target_url = self._build_target_url(asset)
        if not target_url:
            log.warning(
                "nuclei_no_target_url",
                asset_id=getattr(asset, "id", None),
            )
            return []

        tags = _build_tags_from_fingerprints(fingerprints)
        cmd = self._build_command(
            effective_path, target_url, tags, list(severities)
        )

        log.debug(
            "nuclei_scan_start",
            target=target_url,
            tags=tags,
            severities=list(severities),
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(self.timeout),
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                log.warning(
                    "nuclei_timeout",
                    timeout=self.timeout,
                    target=target_url,
                )
                if db_path and scan_id:
                    try:
                        from bounty.errors import record_error as _rec_err
                        _to_exc = TimeoutError(
                            f"nuclei timed out after {self.timeout}s on {target_url}"
                        )
                        await _rec_err(db_path, scan_id, "nuclei", _to_exc,
                                       asset_id=str(getattr(asset, "id", "") or ""))
                    except Exception:  # noqa: BLE001
                        pass
                return []

            if stderr_bytes:
                stderr_text = stderr_bytes.decode(
                    "utf-8", errors="replace"
                ).strip()
                if stderr_text:
                    log.debug("nuclei_stderr", stderr=stderr_text[:500])

            results: list[NucleiFinding] = []
            for line in stdout_bytes.decode(
                "utf-8", errors="replace"
            ).splitlines():
                finding = _parse_nuclei_line(line)
                if finding is None:
                    continue
                # Filter out blocked (dangerous/intrusive) tags
                blocked = self.blocked_tags.intersection(finding.tags)
                if blocked:
                    log.debug(
                        "nuclei_filtered_blocked_tags",
                        template_id=finding.template_id,
                        blocked=sorted(blocked),
                    )
                    continue
                results.append(finding)

            log.info(
                "nuclei_scan_done",
                target=target_url,
                findings=len(results),
            )
            return results

        except FileNotFoundError:
            log.warning(
                "nuclei_binary_missing",
                path=str(effective_path),
                hint=nuclei_install_hint(),
            )
            return []
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "nuclei_scan_error",
                error=str(exc),
                target=target_url,
            )
            if db_path and scan_id:
                try:
                    from bounty.errors import record_error as _rec_err
                    await _rec_err(db_path, scan_id, "nuclei", exc,
                                   asset_id=str(getattr(asset, "id", "") or ""))
                except Exception:  # noqa: BLE001
                    pass
            return []

