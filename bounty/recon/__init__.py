"""
bounty.recon — Recon pipeline: subdomains → resolve → HTTP probe → port scan.

Re-exports for convenience:
  probe         — from http_probe
  enumerate     — from subdomains
  resolve_batch — from resolve
  scan_ports    — from port_scan

High-level entry point:
  recon_pipeline(program_id, targets, intensity, db_path, scan_id)
  — runs all recon phases and persists results to the database.

Pipeline phases:
  a) For each in-scope domain: enumerate subdomains via subfinder
  b) Resolve all discovered FQDNs to IPs
  c) HTTP probe all alive hosts (80/443 + any open web ports from port scan)
  d) Port scan alive hosts (skipped for intensity='gentle')

Each phase publishes SSE events so the UI stays live during long runs.
Failures in individual per-asset steps are logged and stored in scan_phases
but do not abort the pipeline.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from bounty import get_logger
from bounty.config import get_settings
from bounty.db import get_conn
from bounty.events import publish
from bounty.exceptions import ToolMissingError
from bounty.models import Asset, Target
from bounty.recon.http_probe import probe
from bounty.recon.port_scan import OpenPort, scan_ports
from bounty.recon.resolve import ResolveResult, resolve_batch
from bounty.recon.subdomains import enumerate as enumerate_subdomains

log = get_logger(__name__)

__all__ = [
    "probe",
    "enumerate_subdomains",
    "resolve_batch",
    "scan_ports",
    "recon_pipeline",
]

# Web ports to probe with HTTP after DNS resolution
_DEFAULT_WEB_PORTS = [80, 443]
# Additional web ports discovered by port scan that get HTTP-probed
_EXTRA_WEB_PORT_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt", "dev-http"}


def _now_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _asset_url(scheme: str, host: str, port: int) -> str:
    """Build canonical URL for a host+port combination.

    Omits the port for scheme defaults (80→http, 443→https).

    Args:
        scheme: ``"http"`` or ``"https"``.
        host: Hostname.
        port: TCP port.

    Returns:
        URL string.
    """
    default_ports = {"http": 80, "https": 443}
    if default_ports.get(scheme) == port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


async def _upsert_asset(
    db_path: Path,
    program_id: str,
    host: str,
    scheme: str,
    port: int,
    ip: str | None,
    http_status: int | None,
    title: str | None,
    server: str | None,
    tags: list[str],
) -> int | None:
    """Insert or update an asset row, returning the asset ID.

    Args:
        db_path: Path to the SQLite database.
        program_id: Owning program.
        host: Hostname.
        scheme: HTTP scheme.
        port: TCP port.
        ip: Resolved IP.
        http_status: HTTP response status code.
        title: Page title.
        server: Server header value.
        tags: List of tag strings.

    Returns:
        The asset row ID (integer), or ``None`` on error.
    """
    url = _asset_url(scheme, host, port)
    try:
        def _db_op() -> int | None:
            with get_conn(db_path) as conn:
                existing = conn.execute(
                    "SELECT id FROM assets WHERE program_id=? AND url=?",
                    (program_id, url),
                ).fetchone()
                if existing:
                    conn.execute(
                        """
                        UPDATE assets SET
                            ip=COALESCE(?,ip), http_status=COALESCE(?,http_status),
                            title=COALESCE(?,title), server=COALESCE(?,server),
                            status='alive', last_seen=?, updated_at=?
                        WHERE id=?
                        """,
                        (ip, http_status, title, server, _now_iso(), _now_iso(), existing["id"]),
                    )
                    conn.commit()
                    return int(existing["id"])
                conn.execute(
                    """
                    INSERT INTO assets
                        (program_id, host, port, scheme, url, ip, status,
                         http_status, title, server, tags, last_seen, first_seen,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,'alive',?,?,?,?,?,?,?,?)
                    """,
                    (
                        program_id, host, port if port not in (80, 443) else None,
                        scheme, url, ip, http_status, title, server,
                        json.dumps(tags), _now_iso(), _now_iso(),
                        _now_iso(), _now_iso(),
                    ),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT id FROM assets WHERE program_id=? AND url=?",
                    (program_id, url),
                ).fetchone()
                return int(row["id"]) if row else None
        return await asyncio.to_thread(_db_op)
    except Exception as exc:  # noqa: BLE001
        log.error("asset_upsert_failed", url=url, error=str(exc))
        return None


async def _update_scan_phase(
    db_path: Path,
    scan_id: int,
    phase: str,
    status: str,
    detail: dict[str, object] | None = None,
) -> None:
    """Upsert a scan_phases row for the given scan + phase name.

    Args:
        db_path: DB path.
        scan_id: Parent scan ID.
        phase: Phase name (e.g. ``"recon"``, ``"http_probe"``).
        status: One of ``"running"``, ``"completed"``, ``"failed"``.
        detail: JSON-serialisable progress dict.
    """
    detail_json = json.dumps(detail or {})
    ts = _now_iso()

    def _op() -> None:
        with get_conn(db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM scan_phases WHERE scan_id=? AND phase=?",
                (scan_id, phase),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE scan_phases SET status=?, detail=?,
                        finished_at=CASE WHEN ?!='running' THEN ? ELSE finished_at END
                    WHERE id=?
                    """,
                    (status, detail_json, status, ts, existing["id"]),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO scan_phases (scan_id, phase, status, started_at, detail)
                    VALUES (?,?,?,?,?)
                    """,
                    (scan_id, phase, status, ts, detail_json),
                )
            conn.commit()

    try:
        await asyncio.to_thread(_op)
    except Exception as exc:  # noqa: BLE001
        log.warning("scan_phase_update_failed", scan_id=scan_id, phase=phase, error=str(exc))


def _extract_title(body_text: str) -> str | None:
    """Extract the HTML <title> value from a response body.

    Args:
        body_text: UTF-8 decoded response body.

    Returns:
        Title text or ``None``.
    """
    import re  # local import to keep module-level imports clean
    m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body_text, re.IGNORECASE)
    return m.group(1).strip() if m else None


async def recon_pipeline(
    program_id: str,
    targets: list[Target],
    *,
    intensity: str = "normal",
    db_path: Path | None = None,
    scan_id: int | None = None,
) -> dict[str, list[int]]:
    """Run the full recon pipeline for a program's in-scope targets.

    Phases executed in order:
    1. Subdomain enumeration (subfinder) — skipped if tool not installed
    2. DNS resolution (resolve_batch)
    3. Optional port scan (naabu) — skipped for gentle intensity
    4. HTTP probe of alive hosts

    Progress is written to ``scan_phases`` and SSE events are published.

    Args:
        program_id: The program being scanned.
        targets: In-scope target rules (wildcards, URLs, CIDRs).
        intensity: Scan intensity — ``"gentle"``, ``"normal"``, or
                   ``"aggressive"``.
        db_path: Path to the SQLite database.  Defaults to
                 ``settings.db_path``.
        scan_id: Parent scan ID for phase tracking.  If ``None``, DB
                 phase updates are skipped.

    Returns:
        Dict with keys ``"assets"`` (list of asset IDs) and
        ``"failed_hosts"`` (list of hostnames that errored).
    """
    settings = get_settings()
    effective_db = db_path or settings.db_path
    bound_log = log.bind(program_id=program_id, intensity=intensity, scan_id=scan_id)
    bound_log.info("recon_pipeline_start", targets=len(targets))

    discovered_hosts: set[str] = set()
    asset_ids: list[int] = []

    # ── Phase 1: Subdomain enumeration ───────────────────────────────────────
    if scan_id:
        await _update_scan_phase(effective_db, scan_id, "recon", "running")

    in_scope_domains = [
        t.value.lstrip("*.") for t in targets
        if t.scope_type == "in_scope"
        and t.asset_type in ("wildcard", "url", "cidr")
        and "." in t.value
    ]

    # Seed with exact domains even without subfinder
    for t in targets:
        if t.scope_type == "in_scope" and t.asset_type in ("url", "wildcard"):
            host = t.value.lstrip("*.")
            if host:
                discovered_hosts.add(host.lower())

    for domain in list(dict.fromkeys(in_scope_domains)):
        try:
            async for hostname in enumerate_subdomains(
                domain,
                intensity=intensity,
                known_hosts=discovered_hosts,
            ):
                discovered_hosts.add(hostname)
                await publish(
                    "asset:new",
                    {"hostname": hostname, "source": "subfinder", "program_id": program_id},
                    program_id=program_id,
                )
        except ToolMissingError:
            bound_log.warning(
                "subfinder_not_installed",
                domain=domain,
                hint="Install subfinder to enable subdomain enumeration",
            )
            break
        except Exception as exc:  # noqa: BLE001
            bound_log.error("subfinder_error", domain=domain, error=str(exc))

    bound_log.info("enumeration_done", hosts=len(discovered_hosts))

    # ── Phase 2: DNS resolution ───────────────────────────────────────────────
    if scan_id:
        await _update_scan_phase(
            effective_db, scan_id, "resolve", "running",
            {"queued": len(discovered_hosts)},
        )

    resolve_results: dict[str, ResolveResult] = {}
    if discovered_hosts:
        resolve_results = await resolve_batch(list(discovered_hosts), concurrency=50)

    alive_hosts = {h: r for h, r in resolve_results.items() if r.alive}
    bound_log.info("resolve_done", total=len(resolve_results), alive=len(alive_hosts))

    if scan_id:
        await _update_scan_phase(
            effective_db, scan_id, "resolve", "completed",
            {"total": len(resolve_results), "alive": len(alive_hosts)},
        )

    # ── Phase 3: Port scan (intensity != gentle) ──────────────────────────────
    open_ports_by_ip: dict[str, list[OpenPort]] = {}

    if intensity != "gentle" and alive_hosts:
        if scan_id:
            await _update_scan_phase(effective_db, scan_id, "port_scan", "running")

        unique_ips = list({r.primary_ip for r in alive_hosts.values() if r.primary_ip})
        bound_log.info("port_scan_start", ips=len(unique_ips))

        async def _scan_one(ip: str) -> None:
            try:
                ports = await scan_ports(ip, port_set="web", intensity=intensity)
                open_ports_by_ip[ip] = ports
            except ToolMissingError:
                bound_log.warning("naabu_not_installed")
            except Exception as exc:  # noqa: BLE001
                bound_log.debug("port_scan_error", ip=ip, error=str(exc))

        await asyncio.gather(*[_scan_one(ip) for ip in unique_ips])

        if scan_id:
            await _update_scan_phase(
                effective_db, scan_id, "port_scan", "completed",
                {"scanned_ips": len(unique_ips)},
            )

    # ── Phase 4: HTTP probe ───────────────────────────────────────────────────
    if scan_id:
        await _update_scan_phase(effective_db, scan_id, "http_probe", "running")

    probed_count = 0

    async def _probe_host(hostname: str, resolve_res: ResolveResult) -> None:
        nonlocal probed_count
        ip = resolve_res.primary_ip
        host_log = bound_log.bind(hostname=hostname, ip=ip)

        # Build list of (scheme, port) to probe
        scheme_ports: list[tuple[str, int]] = [("https", 443), ("http", 80)]

        # Add extra web ports found by port scan
        if ip and ip in open_ports_by_ip:
            for op in open_ports_by_ip[ip]:
                if op.service_guess in _EXTRA_WEB_PORT_SERVICES and op.port not in (80, 443):
                    scheme = "https" if "https" in op.service_guess else "http"
                    scheme_ports.append((scheme, op.port))

        for scheme, port in scheme_ports:
            url = _asset_url(scheme, hostname, port)
            result = await probe(url, verify=False)
            if not result.ok:
                host_log.debug("probe_failed", url=url, error=result.error)
                continue

            title = _extract_title(result.body_text)
            asset_id = await _upsert_asset(
                effective_db,
                program_id=program_id,
                host=hostname,
                scheme=scheme,
                port=port,
                ip=ip,
                http_status=result.status_code,
                title=title,
                server=result.server or None,
                tags=["wildcard_zone"] if resolve_res.wildcard_zone else [],
            )
            if asset_id:
                asset_ids.append(asset_id)
                await publish(
                    "asset:updated",
                    {
                        "asset_id": asset_id,
                        "url": url,
                        "status_code": result.status_code,
                        "program_id": program_id,
                    },
                    program_id=program_id,
                )
        probed_count += 1

    probe_tasks = [
        asyncio.create_task(_probe_host(h, r))
        for h, r in alive_hosts.items()
    ]
    if probe_tasks:
        await asyncio.gather(*probe_tasks, return_exceptions=True)

    bound_log.info(
        "http_probe_done",
        probed=probed_count,
        assets_found=len(asset_ids),
    )
    if scan_id:
        await _update_scan_phase(
            effective_db, scan_id, "http_probe", "completed",
            {"probed": probed_count, "assets": len(asset_ids)},
        )

    bound_log.info("recon_pipeline_done", asset_ids=len(asset_ids))
    return {"assets": asset_ids, "failed_hosts": []}

