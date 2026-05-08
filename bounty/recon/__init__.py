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
  a) For each in-scope domain: enumerate subdomains via subfinder + crt.sh
  b) Resolve all discovered FQDNs to IPs
  c) HTTP probe all alive hosts (80/443 + any open web ports from port scan)
  d) Port scan alive hosts (skipped for intensity='gentle')

Each phase publishes SSE events so the UI stays live during long runs.
Failures in individual per-asset steps are logged and stored in scan_phases
but do not abort the pipeline.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from bounty import get_logger
from bounty.config import get_settings
from bounty.db import get_conn
from bounty.events import publish
from bounty.exceptions import ToolMissingError
from bounty.fingerprint import fingerprint_asset
from bounty.models import Asset, Target
from bounty.recon.http_probe import probe
from bounty.recon.ip_ranges import expand_asn, expand_cidr
from bounty.recon.port_scan import OpenPort, scan_ports
from bounty.recon.resolve import ResolveResult, resolve_batch
from bounty.recon.subdomains import enumerate as enumerate_subdomains
from bounty.ulid import make_ulid
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
# Extra ports tried when probing IP-based targets directly (non-gentle intensity)
_IP_EXTRA_PORTS: list[tuple[str, int]] = [
    ("http", 8080),
    ("https", 8443),
    ("http", 8000),
    ("http", 9000),
    ("http", 9090),
    ("http", 3000),
    ("http", 5000),
    ("http", 8888),
]


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


async def _ensure_program(db_path: Path, program_id: str) -> None:
    """INSERT OR IGNORE a placeholder program row so FK constraints pass.

    Args:
        db_path: Path to the SQLite database.
        program_id: Program ID to create if missing.
    """
    async with get_conn(db_path) as conn:
        await conn.execute(
            """
            INSERT OR IGNORE INTO programs (id, platform, handle, name)
            VALUES (?, 'manual', ?, '[manual]')
            """,
            (program_id, program_id),
        )
        await conn.commit()


async def _ensure_scan(
    db_path: Path,
    scan_id: str,
    program_id: str,
    intensity: str,
) -> None:
    """INSERT OR IGNORE a scan row so scan_phases FK constraints pass.

    Args:
        db_path: Path to the SQLite database.
        scan_id: ULID or external string identifier for this scan.
        program_id: Owning program.
        intensity: Scan intensity label.
    """
    ts = _now_iso()
    async with get_conn(db_path) as conn:
        await conn.execute(
            """
            INSERT OR IGNORE INTO scans
                (id, program_id, scan_type, status, intensity, triggered_by,
                 started_at, created_at)
            VALUES (?, ?, 'recon', 'running', ?, 'cli', ?, ?)
            """,
            (scan_id, program_id, intensity, ts, ts),
        )
        await conn.commit()


async def _finish_scan(db_path: Path, scan_id: str, status: str, error: str | None = None) -> None:
    """UPDATE scans SET status and finished_at for the given scan.

    Args:
        db_path: Path to the SQLite database.
        scan_id: The scan to update.
        status: Final status — ``"completed"`` or ``"failed"``.
        error: Error message if status is ``"failed"``.
    """
    async with get_conn(db_path) as conn:
        await conn.execute(
            """
            UPDATE scans SET status=?, finished_at=?, error=?
            WHERE id=?
            """,
            (status, _now_iso(), error, scan_id),
        )
        await conn.commit()


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
) -> str | None:
    """Insert or update an asset row, returning the asset ID (ULID).

    Deduplication key is (program_id, host, canonical_port) where
    canonical_port is NULL for standard ports (80/443).  http:// and https://
    variants of the same host are collapsed into one row; seen_protocols tracks
    which schemes have been observed, and primary_scheme prefers 'https'.

    Args:
        db_path: Path to the SQLite database.
        program_id: Owning program.
        host: Hostname or IP.
        scheme: HTTP scheme for this probe result.
        port: TCP port (80/443 stored as NULL canonical).
        ip: Resolved IP.
        http_status: HTTP response status code.
        title: Page title.
        server: Server header value.
        tags: List of tag strings.

    Returns:
        The asset row ID (ULID string), or ``None`` on error.
    """
    # Canonicalise port: store NULL for scheme-default ports so that
    # http://host (port 80) and https://host (port 443) map to the SAME row.
    canonical_port: int | None = port if port not in (80, 443) else None

    def _make_url(s: str, p: int | None) -> str:
        return f"{s}://{host}" if p is None else f"{s}://{host}:{p}"

    try:
        async with get_conn(db_path) as conn:
            # Lookup by (program_id, host, canonical_port).  Use COALESCE(-1)
            # so that NULL==NULL comparisons work correctly in WHERE.
            cursor = await conn.execute(
                """
                SELECT id, seen_protocols, primary_scheme, http_status AS existing_status, title AS existing_title
                FROM assets
                WHERE program_id=? AND host=? AND COALESCE(port,-1)=COALESCE(?,-1)
                """,
                (program_id, host, canonical_port),
            )
            existing = await cursor.fetchone()

            if existing:
                # Merge seen_protocols — add current scheme if not already recorded.
                try:
                    proto_list: list[str] = json.loads(existing["seen_protocols"] or "[]")
                except (json.JSONDecodeError, TypeError):
                    proto_list = []
                if scheme not in proto_list:
                    proto_list.append(scheme)
                proto_list = sorted(set(proto_list))

                # Prefer https when both observed.
                new_primary = "https" if "https" in proto_list else "http"
                new_url = _make_url(new_primary, canonical_port)

                # "Better data wins": prefer successful HTTP status over error.
                existing_status: int | None = existing["existing_status"]

                def _is_ok(s: int | None) -> bool:
                    return s is not None and s < 400

                use_status: int | None
                if _is_ok(existing_status) and not _is_ok(http_status):
                    # Keep existing good status; don't overwrite with 404 etc.
                    use_status = None
                else:
                    use_status = http_status

                # Prefer non-empty title.
                use_title: str | None = title if (title and not existing["existing_title"]) else None

                await conn.execute(
                    """
                    UPDATE assets SET
                        seen_protocols=?, primary_scheme=?, scheme=?, url=?,
                        ip=COALESCE(?,ip),
                        http_status=COALESCE(?,http_status),
                        title=COALESCE(?,title),
                        server=COALESCE(?,server),
                        status='alive', last_seen=?, updated_at=?
                    WHERE id=?
                    """,
                    (
                        json.dumps(proto_list),
                        new_primary, new_primary, new_url,
                        ip,
                        use_status,
                        use_title,
                        server,
                        _now_iso(), _now_iso(), existing["id"],
                    ),
                )
                await conn.commit()
                return str(existing["id"])

            # ── New row ─────────────────────────────────────────────────────
            new_id = make_ulid()
            insert_url = _make_url(scheme, canonical_port)
            await conn.execute(
                """
                INSERT INTO assets
                    (id, program_id, host, port, scheme, url, ip, status,
                     http_status, title, server, tags,
                     seen_protocols, primary_scheme,
                     last_seen, first_seen, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,'alive',?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    new_id,
                    program_id, host, canonical_port,
                    scheme, insert_url, ip, http_status, title, server,
                    json.dumps(tags),
                    json.dumps([scheme]),  # seen_protocols = [current scheme]
                    scheme,               # primary_scheme
                    _now_iso(), _now_iso(),
                    _now_iso(), _now_iso(),
                ),
            )
            await conn.commit()
            return new_id
    except Exception as exc:  # noqa: BLE001
        log.error(
            "asset_upsert_failed",
            host=host, scheme=scheme, port=port,
            error=str(exc), exc_info=True,
        )
        return None


async def _update_scan_phase(
    db_path: Path,
    scan_id: str,
    phase: str,
    status: str,
    detail: dict[str, object] | None = None,
) -> None:
    """Upsert a scan_phases row for the given scan + phase name.

    Args:
        db_path: DB path.
        scan_id: Parent scan ID (TEXT / ULID).
        phase: Phase name (e.g. ``"recon"``, ``"http_probe"``).
        status: One of ``"running"``, ``"completed"``, ``"failed"``.
        detail: JSON-serialisable progress dict.
    """
    detail_json = json.dumps(detail or {})
    ts = _now_iso()

    try:
        async with get_conn(db_path) as conn:
            cursor = await conn.execute(
                "SELECT id FROM scan_phases WHERE scan_id=? AND phase=?",
                (scan_id, phase),
            )
            existing = await cursor.fetchone()
            if existing:
                await conn.execute(
                    """
                    UPDATE scan_phases SET status=?, detail=?,
                        finished_at=CASE WHEN ?!='running' THEN ? ELSE finished_at END
                    WHERE id=?
                    """,
                    (status, detail_json, status, ts, existing["id"]),
                )
            else:
                await conn.execute(
                    """
                    INSERT INTO scan_phases (scan_id, phase, status, started_at, detail)
                    VALUES (?,?,?,?,?)
                    """,
                    (scan_id, phase, status, ts, detail_json),
                )
            await conn.commit()
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


async def _run_fingerprint_phase(
    db_path: Path,
    program_id: str,
    asset_ids: list[str],
    probe_fn: Any,
    bound_log: Any,
) -> None:
    """Run fingerprint_asset for every asset in ``asset_ids`` (concurrency=50).

    Failures are logged as warnings and do NOT propagate — fingerprinting
    failures must never fail an asset in the scan result.

    Args:
        db_path: Path to the SQLite database.
        program_id: Program ID (used for SAN asset inserts).
        asset_ids: Asset row IDs to fingerprint.
        probe_fn: The ``probe`` callable from http_probe.
        bound_log: Bound structlog logger.
    """
    import asyncio as _asyncio

    favicon_cache: dict[str, tuple[int, str]] = {}
    sem = _asyncio.Semaphore(50)

    async def _fp_one(asset_id: str) -> None:
        async with sem:
            try:
                async with get_conn(db_path) as conn:
                    cursor = await conn.execute(
                        "SELECT id, program_id, host, port, scheme, url, ip, status,"
                        " http_status, title, server, cdn, waf, tls_issuer, tls_expiry,"
                        " tags, seen_protocols, primary_scheme FROM assets WHERE id=?",
                        (asset_id,),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        return

                    import json as _json

                    tags_raw = row["tags"] or "[]"
                    try:
                        tags: list[str] = _json.loads(tags_raw)
                    except Exception:  # noqa: BLE001
                        tags = []

                    seen_proto_raw = row["seen_protocols"] or "[]"
                    try:
                        seen_protocols: list[str] = _json.loads(seen_proto_raw)
                    except Exception:  # noqa: BLE001
                        seen_protocols = []

                    from bounty.models import Asset as _Asset

                    asset = _Asset(
                        id=str(row["id"]),
                        program_id=str(row["program_id"]),
                        host=str(row["host"]),
                        port=row["port"],
                        scheme=str(row["scheme"] or "https"),
                        url=str(row["url"]),
                        ip=row["ip"],
                        status=str(row["status"] or "alive"),
                        http_status=row["http_status"],
                        title=row["title"],
                        server=row["server"],
                        cdn=row["cdn"],
                        waf=row["waf"],
                        tls_issuer=row["tls_issuer"],
                        tls_expiry=row["tls_expiry"],
                        tags=tags,
                        seen_protocols=seen_protocols,
                        primary_scheme=str(row["primary_scheme"] or "https"),
                    )

                    # Re-probe to get fresh probe_result
                    probe_result = await probe(asset.url, verify=False)
                    if not probe_result.ok:
                        return

                    await fingerprint_asset(
                        asset, probe_result, probe_fn,
                        conn, favicon_cache=favicon_cache,
                    )
            except Exception as exc:  # noqa: BLE001
                if bound_log is not None:
                    bound_log.warning(
                        "fingerprint_phase_error", asset_id=asset_id, error=str(exc)
                    )

    await _asyncio.gather(*[_fp_one(aid) for aid in asset_ids], return_exceptions=True)


async def _run_detect_phase(
    db_path: Path,
    program_id: str,
    asset_ids: list[str],
    probe_fn: Any,
    bound_log: Any,
    scan_id: str,
) -> int:
    """Run the detection phase for every unique asset.

    Returns the total number of findings emitted.
    Failures per-asset are logged and do NOT propagate.
    """
    import asyncio as _asyncio
    import json as _json

    from bounty.config import get_settings as _get_settings
    from bounty.detect.base import DetectionContext
    from bounty.detect.runner import run_detections
    from bounty.detect.exposed_files._common import soft_404_check
    from bounty.evidence.capture import capture_http_evidence
    from bounty.models import Asset as _Asset, FingerprintResult as _FPR

    settings = _get_settings()
    sem = _asyncio.Semaphore(10)  # lower concurrency than fingerprint
    total_findings = 0

    async def _capture_fn(url: str, pr: Any, sid: str) -> Any:
        return await capture_http_evidence(
            url, pr, sid, db_path=db_path, data_dir=settings.data_dir
        )

    async def _detect_one(asset_id: str) -> int:
        nonlocal total_findings
        async with sem:
            found = 0
            try:
                async with get_conn(db_path) as conn:
                    # Load asset
                    cursor = await conn.execute(
                        "SELECT id, program_id, host, port, scheme, url, ip, status,"
                        " http_status, title, server, cdn, waf, tls_issuer, tls_expiry,"
                        " tags, seen_protocols, primary_scheme FROM assets WHERE id=?",
                        (asset_id,),
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        return 0

                    tags_raw = row["tags"] or "[]"
                    try:
                        tags: list[str] = _json.loads(tags_raw)
                    except Exception:  # noqa: BLE001
                        tags = []

                    seen_proto_raw = row["seen_protocols"] or "[]"
                    try:
                        seen_protocols: list[str] = _json.loads(seen_proto_raw)
                    except Exception:  # noqa: BLE001
                        seen_protocols = []

                    asset = _Asset(
                        id=str(row["id"]),
                        program_id=str(row["program_id"]),
                        host=str(row["host"]),
                        port=row["port"],
                        scheme=str(row["scheme"] or "https"),
                        url=str(row["url"]),
                        ip=row["ip"],
                        status=str(row["status"] or "alive"),
                        http_status=row["http_status"],
                        title=row["title"],
                        server=row["server"],
                        cdn=row["cdn"],
                        waf=row["waf"],
                        tls_issuer=row["tls_issuer"],
                        tls_expiry=row["tls_expiry"],
                        tags=tags,
                        seen_protocols=seen_protocols,
                        primary_scheme=str(row["primary_scheme"] or "https"),
                    )

                    # Load fingerprints for gating
                    fp_cur = await conn.execute(
                        "SELECT tech, category, confidence, evidence FROM fingerprints WHERE asset_id=?",
                        (asset_id,),
                    )
                    fp_rows = await fp_cur.fetchall()
                    fingerprints = [
                        _FPR(
                            tech=str(r["tech"]),
                            category=str(r["category"] or "other"),  # type: ignore[arg-type]
                            confidence=str(r["confidence"] or "weak"),  # type: ignore[arg-type]
                            evidence=r["evidence"] or "",
                        )
                        for r in fp_rows
                    ]

                det_log = bound_log.bind(asset=asset.host)

                ctx = DetectionContext(
                    probe_fn=probe_fn,
                    capture_fn=_capture_fn,
                    scan_id=scan_id,
                    settings=settings,
                    log=det_log,
                )

                # Pre-compute soft-404 status
                is_soft_404 = await soft_404_check(asset, probe_fn)
                ctx.set_soft_404(asset, is_soft_404)
                if is_soft_404:
                    det_log.debug("soft_404_detected", asset=asset.host)

                async for finding in run_detections(asset, fingerprints, ctx, db_path):
                    found += 1

            except Exception as exc:  # noqa: BLE001
                if bound_log is not None:
                    bound_log.warning(
                        "detect_phase_error", asset_id=asset_id, error=str(exc)
                    )
            return found

    results = await _asyncio.gather(
        *[_detect_one(aid) for aid in asset_ids], return_exceptions=True
    )
    for r in results:
        if isinstance(r, int):
            total_findings += r
    return total_findings


async def recon_pipeline(
    program_id: str,
    targets: list[Target],
    *,
    intensity: str = "normal",
    db_path: Path | None = None,
    scan_id: str | None = None,
) -> dict[str, list[str]]:
    """Run the full recon pipeline for a program's in-scope targets.

    Phases executed in order:
    1. Subdomain enumeration (subfinder + crt.sh) — skipped if tool not
       installed, crt.sh always attempted
    2. DNS resolution (resolve_batch)
    3. Optional port scan (naabu) — skipped for gentle intensity
    4. HTTP probe of alive hosts

    The pipeline guarantees:
    - A ``scans`` row exists for ``scan_id`` before any ``scan_phases`` writes
    - A ``programs`` row exists for ``program_id`` (placeholder if missing)
    - ``scans.status`` is set to ``"completed"`` or ``"failed"`` on exit
    - All DB writes use ``PRAGMA foreign_keys = ON`` (set by ``get_conn``)

    Progress is written to ``scan_phases`` and SSE events are published.

    Args:
        program_id: The program being scanned.
        targets: In-scope target rules (wildcards, URLs, CIDRs).
        intensity: Scan intensity — ``"gentle"``, ``"normal"``, or
                   ``"aggressive"``.
        db_path: Path to the SQLite database.  Defaults to
                 ``settings.db_path``.
        scan_id: Parent scan ID for phase tracking.  If ``None``, a new
                 ULID is generated automatically.

    Returns:
        Dict with keys ``"assets"`` (list of asset ID strings) and
        ``"failed_hosts"`` (list of hostnames that errored).
    """
    settings = get_settings()
    effective_db = db_path or settings.db_path

    # Auto-generate scan_id if not provided
    if scan_id is None:
        scan_id = make_ulid()

    bound_log = log.bind(program_id=program_id, intensity=intensity, scan_id=scan_id)
    bound_log.info("recon_pipeline_start", targets=len(targets))

    # ── Pre-flight: ensure program + scan rows exist in DB ────────────────────
    await _ensure_program(effective_db, program_id)
    await _ensure_scan(effective_db, scan_id, program_id, intensity)

    discovered_hosts: set[str] = set()
    asset_ids: list[str] = []
    pipeline_error: str | None = None
    probes_completed: int = 0

    # Determine target mix — controls which pipeline phases are relevant.
    in_scope_targets = [t for t in targets if t.scope_type == "in_scope"]

    # Wildcard targets and bare-hostname url targets seed subdomain enumeration
    # + DNS resolution.  Full URL targets (containing "://") are concrete
    # endpoints and are probed directly without enumeration.
    def _is_url_with_scheme(value: str) -> bool:
        return "://" in value

    has_wildcard_domains = any(
        t.asset_type == "wildcard"
        or (t.asset_type == "url" and not _is_url_with_scheme(t.value))
        for t in in_scope_targets
    )

    # ── IP-range targets: collect direct IPs before subdomain phases ─────────
    # These bypass subdomain enumeration and DNS resolution.
    # No internal-IP filter — the operator decides what's reachable.
    direct_ips: set[str] = set()
    # Full URL targets: concrete (scheme, host, port) endpoints to probe exactly.
    # No subfinder/DNS enumeration; port is taken from the URL literally.
    direct_url_probes: list[tuple[str, str, int]] = []

    try:
        # ── Phase 0: Expand / collect all IP, CIDR, ASN, and URL targets ─────
        # Returns all IPs without filtering. Operator decides what's reachable.
        for t in in_scope_targets:
            if t.asset_type == "ip":
                ip = t.value.strip()
                direct_ips.add(ip)
            elif t.asset_type == "cidr":
                try:
                    expanded = await expand_cidr(t.value)
                    direct_ips.update(expanded)
                except (ValueError, NotImplementedError) as exc:
                    bound_log.warning("cidr_expansion_failed", value=t.value, error=str(exc))
            elif t.asset_type == "asn":
                try:
                    cidrs = await expand_asn(t.value)
                    for cidr in cidrs:
                        try:
                            direct_ips.update(await expand_cidr(cidr))
                        except (ValueError, NotImplementedError):
                            pass  # CIDRs too large or IPv6 — skip silently
                except ValueError as exc:
                    bound_log.warning("asn_expansion_failed", value=t.value, error=str(exc))
            elif t.asset_type == "url":
                # Only full URL targets (with scheme) are concrete endpoints.
                # Bare-hostname url targets (no "://") are domain seeds and
                # get handled in Phase 1 via the has_wildcard_domains path.
                if _is_url_with_scheme(t.value):
                    parsed = urlparse(t.value)
                    raw_host = (parsed.hostname or "").strip()
                    explicit_port = parsed.port
                    scheme = (parsed.scheme or "https").lower()
                    if raw_host:
                        effective_port = explicit_port or (443 if scheme == "https" else 80)
                        direct_url_probes.append((scheme, raw_host, effective_port))
                        bound_log.debug(
                            "url_target_queued",
                            url=t.value, scheme=scheme, host=raw_host, port=effective_port,
                        )

        if direct_ips:
            bound_log.info("direct_ips_collected", count=len(direct_ips))
        if direct_url_probes:
            bound_log.info("direct_url_probes_collected", count=len(direct_url_probes))

        # ── Phase 1: Subdomain enumeration (wildcard + bare-hostname url targets) ─
        alive_hosts: dict[str, ResolveResult] = {}

        if has_wildcard_domains:
            await _update_scan_phase(effective_db, scan_id, "recon", "running")

            # Extract the bare domain from wildcard targets.
            # Defense-in-depth: strip URL scheme or path if accidentally present.
            def _sanitise_domain(raw: str) -> str:
                s = raw.lstrip("*.")
                if "://" in s:
                    s = (urlparse(s).hostname or s)
                return s.split("/")[0].strip()

            # Wildcard targets → seed subfinder
            in_scope_domains = list(dict.fromkeys(
                _sanitise_domain(t.value)
                for t in targets
                if t.scope_type == "in_scope"
                and t.asset_type == "wildcard"
                and "." in t.value.lstrip("*.")
            ))

            # Seed discovered_hosts: wildcard domains + bare-hostname url values.
            for t in targets:
                if t.scope_type == "in_scope":
                    if t.asset_type == "wildcard":
                        host = _sanitise_domain(t.value)
                        if host:
                            discovered_hosts.add(host.lower())
                    elif t.asset_type == "url" and not _is_url_with_scheme(t.value):
                        # Bare hostname in url target — resolve it like a domain.
                        host = t.value.strip().lower()
                        if host:
                            discovered_hosts.add(host)

            for domain in in_scope_domains:
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

            await _update_scan_phase(
                effective_db, scan_id, "recon", "completed",
                {"discovered": len(discovered_hosts)},
            )

            # ── Phase 2: DNS resolution ───────────────────────────────────────
            await _update_scan_phase(
                effective_db, scan_id, "resolve", "running",
                {"queued": len(discovered_hosts)},
            )

            resolve_results: dict[str, ResolveResult] = {}
            if discovered_hosts:
                resolve_results = await resolve_batch(list(discovered_hosts), concurrency=50)

            alive_hosts = {h: r for h, r in resolve_results.items() if r.alive}
            bound_log.info("resolve_done", total=len(resolve_results), alive=len(alive_hosts))

            if not alive_hosts:
                bound_log.warning(
                    "zero_alive_hosts",
                    hint="Check DNS / scope config",
                    domains_tried=len(discovered_hosts),
                )

            await _update_scan_phase(
                effective_db, scan_id, "resolve", "completed",
                {"total": len(resolve_results), "alive": len(alive_hosts)},
            )
        else:
            # IP-only / URL-only scan: enumerate and resolve phases not relevant.
            bound_log.info("skip_domain_phases", reason="no wildcard domain targets in scope")

        # ── Phase 3: Port scan (intensity != gentle) ──────────────────────────
        open_ports_by_ip: dict[str, list[OpenPort]] = {}

        # Combine IPs from resolved hosts + direct IP targets for port scanning
        _domain_ips = {r.primary_ip for r in alive_hosts.values() if r.primary_ip}
        all_scan_ips = list(_domain_ips | direct_ips)

        if intensity != "gentle" and all_scan_ips:
            await _update_scan_phase(effective_db, scan_id, "port_scan", "running")
            bound_log.info("port_scan_start", ips=len(all_scan_ips))

            async def _scan_one(ip: str) -> None:
                try:
                    ports = await scan_ports(ip, port_set="web", intensity=intensity)
                    open_ports_by_ip[ip] = ports
                except ToolMissingError:
                    bound_log.warning("naabu_not_installed")
                except Exception as exc:  # noqa: BLE001
                    bound_log.debug("port_scan_error", ip=ip, error=str(exc))

            await asyncio.gather(*[_scan_one(ip) for ip in all_scan_ips])

            await _update_scan_phase(
                effective_db, scan_id, "port_scan", "completed",
                {"scanned_ips": len(all_scan_ips)},
            )

        # ── Phase 4: HTTP probe ───────────────────────────────────────────────
        await _update_scan_phase(effective_db, scan_id, "http_probe", "running")

        # probes_completed counts each individual HTTP request attempted
        # (one per scheme+port combination, not per hostname).

        async def _probe_host(hostname: str, resolve_res: ResolveResult) -> None:
            nonlocal probes_completed
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
                probes_completed += 1
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

        # Per-scan unreachability tracking for direct IP probing
        fast_fail_counts: dict[str, int] = {}
        unreachable_ips: set[str] = set()
        successful_ips: set[str] = set()  # IPs with at least one successful probe

        async def _probe_direct_ip(ip: str) -> None:
            """Probe a direct IP target at standard + extra web ports."""
            nonlocal probes_completed
            if ip in unreachable_ips:
                return
            ip_log = bound_log.bind(ip=ip)

            # Standard ports always; extra ports for non-gentle intensity
            scheme_ports: list[tuple[str, int]] = [("https", 443), ("http", 80)]
            if intensity != "gentle":
                scheme_ports.extend(_IP_EXTRA_PORTS)

            # Merge ports found by port scanner
            existing_ports = {p for _, p in scheme_ports}
            for op in open_ports_by_ip.get(ip, []):
                if op.service_guess in _EXTRA_WEB_PORT_SERVICES and op.port not in existing_ports:
                    op_scheme = "https" if "https" in op.service_guess else "http"
                    scheme_ports.append((op_scheme, op.port))
                    existing_ports.add(op.port)

            for scheme, port in scheme_ports:
                if ip in unreachable_ips:
                    break
                url = _asset_url(scheme, ip, port)
                probes_completed += 1
                result = await probe(url, verify=False)

                if not result.ok:
                    # Fast failure (<3 s) = host is not answering on this port.
                    # Only mark as unreachable if NO probe has succeeded yet — once
                    # the IP has responded on any port it is clearly reachable and
                    # we should not skip remaining ports (e.g. port 8000 after a
                    # success on 443 and fast-fails on 80/8080).
                    if result.elapsed_ms < 3_000 and ip not in successful_ips:
                        fast_fail_counts[ip] = fast_fail_counts.get(ip, 0) + 1
                        if fast_fail_counts[ip] >= 2:
                            unreachable_ips.add(ip)
                            ip_log.debug(
                                "ip_marked_unreachable",
                                fast_fails=fast_fail_counts[ip],
                            )
                    ip_log.debug("probe_failed", url=url, error=result.error)
                    continue

                successful_ips.add(ip)
                fast_fail_counts[ip] = 0  # reset on success
                title = _extract_title(result.body_text)
                asset_id = await _upsert_asset(
                    effective_db,
                    program_id=program_id,
                    host=ip,
                    scheme=scheme,
                    port=port,
                    ip=ip,
                    http_status=result.status_code,
                    title=title,
                    server=result.server or None,
                    tags=["ip_range"],
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

        probe_tasks = [asyncio.create_task(_probe_host(h, r)) for h, r in alive_hosts.items()]
        ip_tasks = [asyncio.create_task(_probe_direct_ip(ip)) for ip in direct_ips]

        async def _probe_url_target(scheme: str, host: str, port: int) -> None:
            """Probe a concrete URL target at the exact (scheme, host, port) given.

            Skips extra-port probing — the URL specification is authoritative.
            Resolves the hostname for the IP field when host is not already an IP.
            """
            nonlocal probes_completed
            url = _asset_url(scheme, host, port)
            url_log = bound_log.bind(url=url, host=host, port=port)
            probes_completed += 1
            result = await probe(url, verify=False)
            if not result.ok:
                url_log.debug("probe_failed", error=result.error)
                return

            # Best-effort IP resolution (for asset row metadata only).
            resolved_ip: str | None = None
            try:
                ipaddress.ip_address(host)
                resolved_ip = host  # host is already an IP literal
            except ValueError:
                # Hostname — resolve it once for the ip column.
                try:
                    rr = await resolve_batch([host], concurrency=1)
                    resolved_ip = rr[host].primary_ip if host in rr and rr[host].alive else None
                except Exception:  # noqa: BLE001
                    pass

            title = _extract_title(result.body_text)
            asset_id = await _upsert_asset(
                effective_db,
                program_id=program_id,
                host=host,
                scheme=scheme,
                port=port,
                ip=resolved_ip,
                http_status=result.status_code,
                title=title,
                server=result.server or None,
                tags=["url_target"],
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

        url_tasks = [
            asyncio.create_task(_probe_url_target(s, h, p))
            for s, h, p in direct_url_probes
        ]
        all_probe_tasks = probe_tasks + ip_tasks + url_tasks
        if all_probe_tasks:
            await asyncio.gather(*all_probe_tasks, return_exceptions=True)

        bound_log.info(
            "http_probe_done",
            probes_completed=probes_completed,
            unique_assets=len(set(asset_ids)),
            unreachable_ips=len(unreachable_ips),
        )
        await _update_scan_phase(
            effective_db, scan_id, "http_probe", "completed",
            {"probes_completed": probes_completed, "unique_assets": len(set(asset_ids))},
        )

        # ── Phase 5: Fingerprinting ───────────────────────────────────────
        unique_asset_ids = list(dict.fromkeys(asset_ids))  # dedup, preserve order
        if unique_asset_ids:
            await _update_scan_phase(effective_db, scan_id, "fingerprint", "running")
            await _run_fingerprint_phase(
                effective_db, program_id, unique_asset_ids, probe_fn=probe, bound_log=bound_log
            )
            await _update_scan_phase(
                effective_db, scan_id, "fingerprint", "completed",
                {"assets_processed": len(unique_asset_ids)},
            )

            # ── Phase 6: Detection ─────────────────────────────────────────
            await _update_scan_phase(effective_db, scan_id, "detect", "running")
            findings_count = await _run_detect_phase(
                effective_db, program_id, unique_asset_ids,
                probe_fn=probe, bound_log=bound_log, scan_id=scan_id,
            )
            await _update_scan_phase(
                effective_db, scan_id, "detect", "completed",
                {"assets_processed": len(unique_asset_ids), "findings": findings_count},
            )

    except Exception as exc:  # noqa: BLE001
        pipeline_error = str(exc)
        bound_log.error("recon_pipeline_error", error=pipeline_error, exc_info=True)
    finally:
        # Always update scan status so the row reflects final state
        final_status = "failed" if pipeline_error else "completed"
        await _finish_scan(effective_db, scan_id, final_status, pipeline_error)

    bound_log.info(
        "recon_pipeline_done",
        probes_completed=probes_completed,
        unique_assets=len(set(asset_ids)),
        scan_id=scan_id,
        status="failed" if pipeline_error else "completed",
    )
    return {"assets": list(dict.fromkeys(asset_ids)), "failed_hosts": []}

