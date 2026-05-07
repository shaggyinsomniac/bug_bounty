"""
bounty.cli -- Command-line interface for the bug bounty automation system.

Commands:
  init-db       Initialise (or migrate) the SQLite database.
  smoke-recon   End-to-end recon against a target domain.
  intel-credits Print remaining Shodan query credits.
  intel-sweep   Run a Shodan query and store results as leads.
  leads list    List triage leads (filterable by program / status).
  leads promote Convert a lead to an asset row.
  leads dismiss Mark a lead as dismissed.
  scan-ips      Read IPs/CIDRs/ASNs from a file and run the recon pipeline.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

import typer

from bounty import get_logger
from bounty.config import get_settings
from bounty.db import apply_migrations, get_conn, init_db
from bounty.models import Target
from bounty.recon import recon_pipeline
from bounty.ulid import make_ulid

app = typer.Typer(
    name="bounty",
    help="Bug bounty automation tool.",
    no_args_is_help=True,
    rich_markup_mode="markdown",
)

leads_app = typer.Typer(help="Lead triage commands (Shodan / manual intel).")
app.add_typer(leads_app, name="leads")

log = get_logger(__name__)

_INTENSITY_CHOICES = ("gentle", "normal", "aggressive")

# Asset types accepted by scan-ips (narrowed Literal for mypy)
_IpAssetType = Literal["ip", "cidr", "asn"]


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _detect_asset_type(value: str) -> tuple[_IpAssetType, str] | None:
    """Auto-detect asset_type from a raw line value.

    Returns (asset_type, normalised_value) or None if unrecognised.
    """
    v = value.strip()
    # ASN: AS12345 or as12345
    if re.match(r"^[Aa][Ss]\d+$", v):
        return ("asn", v.upper())
    # CIDR: contains /
    if "/" in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
            return ("cidr", str(net))
        except ValueError:
            return None
    # Bare IP address
    try:
        ipaddress.ip_address(v)
        return ("ip", v)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# init-db
# ---------------------------------------------------------------------------

@app.command("init-db")
def init_db_cmd(
    db: Annotated[
        Path | None,
        typer.Option("--db", help="Path to SQLite database (default: data/bounty.db)"),
    ] = None,
) -> None:
    """Initialise (or migrate) the SQLite database.

    Safe to run multiple times -- idempotent.
    """
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)
    typer.echo(f"[bounty init-db] database ready at {db_path}")


# ---------------------------------------------------------------------------
# smoke-recon
# ---------------------------------------------------------------------------

async def _smoke_recon_async(
    db_path: Path,
    program_id: str,
    target: str,
    scan_id: str,
    targets: list[Target],
    intensity: str,
) -> tuple[dict[str, list[str]], sqlite3.Row | None, list[sqlite3.Row], list[sqlite3.Row]]:
    """Async implementation of smoke-recon: setup → pipeline → DB query."""
    async with get_conn(db_path) as conn:
        await conn.execute(
            """
            INSERT OR IGNORE INTO programs (id, platform, handle, name)
            VALUES (?, 'manual', ?, ?)
            """,
            (program_id, target, target),
        )
        await conn.commit()

    result = await recon_pipeline(
        program_id=program_id,
        targets=targets,
        intensity=intensity,
        db_path=db_path,
        scan_id=scan_id,
    )

    async with get_conn(db_path) as conn:
        cursor = await conn.execute(
            "SELECT status, started_at, finished_at, error FROM scans WHERE id=?",
            (scan_id,),
        )
        scan_row: sqlite3.Row | None = await cursor.fetchone()

        # BUG 3 FIX: Query ONLY the assets found in this scan run, not all program assets.
        asset_ids = result.get("assets", [])
        asset_rows: list[sqlite3.Row] = []
        if asset_ids:
            placeholders = ",".join("?" * len(asset_ids))
            cursor = await conn.execute(
                f"SELECT host, http_status, title, server, url FROM assets WHERE id IN ({placeholders}) ORDER BY http_status ASC, host ASC",
                asset_ids,
            )
            asset_rows = list(await cursor.fetchall())

        cursor = await conn.execute(
            "SELECT phase, status FROM scan_phases WHERE scan_id=? ORDER BY phase",
            (scan_id,),
        )
        phase_rows: list[sqlite3.Row] = list(await cursor.fetchall())

    return result, scan_row, asset_rows, phase_rows


@app.command("smoke-recon")
def smoke_recon(
    target: Annotated[str, typer.Option("--target", "-t", help="Domain to scan, e.g. hackerone.com")],
    intensity: Annotated[
        str,
        typer.Option(
            "--intensity",
            "-i",
            help=f"Scan intensity: {' | '.join(_INTENSITY_CHOICES)}",
        ),
    ] = "gentle",
    db: Annotated[
        Path | None,
        typer.Option("--db", help="Path to SQLite database (default: data/bounty.db)"),
    ] = None,
) -> None:
    """Run an end-to-end recon sanity check against TARGET."""
    if intensity not in _INTENSITY_CHOICES:
        typer.echo(
            f"[error] intensity must be one of: {', '.join(_INTENSITY_CHOICES)}",
            err=True,
        )
        raise typer.Exit(1)

    settings = get_settings()
    db_path = db or settings.db_path

    typer.echo(f"[bounty smoke-recon] target={target}  intensity={intensity}  db={db_path}")

    init_db(db_path)
    apply_migrations(db_path)

    program_id = f"manual:{target}"
    scan_id = make_ulid()

    targets = [
        Target(
            program_id=program_id,
            scope_type="in_scope",
            asset_type="wildcard",
            value=f"*.{target}",
        ),
        Target(
            program_id=program_id,
            scope_type="in_scope",
            asset_type="url",
            value=target,
        ),
    ]

    typer.echo(f"[bounty smoke-recon] scan_id={scan_id}")
    typer.echo("[bounty smoke-recon] running pipeline…")

    try:
        result, scan_row, asset_rows, phase_rows = asyncio.run(
            _smoke_recon_async(db_path, program_id, target, scan_id, targets, intensity)
        )
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[bounty smoke-recon] pipeline error: {exc}", err=True)
        raise typer.Exit(1)

    typer.echo("")
    typer.echo("=" * 70)
    typer.echo(f"  SCAN SUMMARY  id={scan_id}")
    typer.echo("=" * 70)

    if scan_row:
        typer.echo(
            f"  status={scan_row['status']}  "
            f"started={scan_row['started_at']}  finished={scan_row['finished_at']}"
        )
        if scan_row["error"]:
            typer.echo(f"  error: {scan_row['error']}", err=True)
    else:
        typer.echo("  WARNING: scan row not found in DB!", err=True)

    typer.echo("")
    typer.echo(f"  PHASES ({len(phase_rows)}):")
    for ph in phase_rows:
        typer.echo(f"    {ph['phase']:15s}  {ph['status']}")

    typer.echo("")
    typer.echo(f"  ASSETS DISCOVERED: {len(asset_rows)}")
    for row in asset_rows[:50]:
        status_str = str(row["http_status"]) if row["http_status"] else "---"
        title_str = (row["title"] or "")[:50]
        typer.echo(f"    [{status_str:3s}] {row['host']:<40s}  {title_str}")

    if len(asset_rows) > 50:
        typer.echo(f"    … and {len(asset_rows) - 50} more")

    typer.echo("=" * 70)

    if not asset_rows:
        typer.echo(
            "\n[bounty smoke-recon] FAIL -- no assets persisted to DB.\n"
            "  Check logs for asset_upsert_failed or probe_failed events.\n",
            err=True,
        )
        raise typer.Exit(1)

    if scan_row and scan_row["status"] != "completed":
        typer.echo(
            f"\n[bounty smoke-recon] WARN -- scan status is '{scan_row['status']}' (expected 'completed').\n",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(f"\n[bounty smoke-recon] OK -- {len(asset_rows)} asset(s) persisted, scan completed.\n")


# ---------------------------------------------------------------------------
# intel-credits
# ---------------------------------------------------------------------------

@app.command("intel-credits")
def intel_credits_cmd(
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Print remaining Shodan query credits.

    Requires the SHODAN_API_KEY environment variable (or .env entry).
    """
    settings = get_settings()
    if not settings.shodan_api_key:
        typer.echo(
            "[error] SHODAN_API_KEY is not configured.  "
            "Set it in .env or as the SHODAN_API_KEY environment variable.",
            err=True,
        )
        raise typer.Exit(1)

    async def _check() -> int:
        from bounty.intel.shodan import ShodanClient
        async with ShodanClient(settings.shodan_api_key) as client:
            return await client.credits_remaining()

    try:
        remaining = asyncio.run(_check())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    status = "OK" if remaining >= settings.shodan_min_credits else "LOW"
    typer.echo(f"[bounty intel-credits] {remaining} query credits remaining  [{status}]")
    if remaining < settings.shodan_min_credits:
        typer.echo(
            f"  WARNING: below minimum threshold ({settings.shodan_min_credits}).  "
            "Consider purchasing more credits.",
            err=True,
        )


# ---------------------------------------------------------------------------
# intel-sweep
# ---------------------------------------------------------------------------

async def _intel_sweep_async(
    query: str,
    program_id: str | None,
    max_pages: int,
    db_path: Path,
) -> dict[str, int]:
    """Run Shodan search and insert results as lead rows."""
    from bounty.intel.shodan import ShodanClient

    settings = get_settings()

    async with ShodanClient(settings.shodan_api_key) as client:
        credits_before = await client.credits_remaining()
        results = await client.search(query, max_pages=max_pages)
        try:
            credits_after = await client.credits_remaining()
            credits_used = credits_before - credits_after
        except Exception:  # noqa: BLE001
            credits_used = max_pages  # fallback estimate

    new_count = 0
    async with get_conn(db_path) as conn:
        for match in results:
            lead_id = make_ulid()
            ip: str = str(match.get("ip_str") or "")
            port: int | None = match.get("port")
            hostnames_raw: Any = match.get("hostnames") or []
            hostnames_json = json.dumps(hostnames_raw if isinstance(hostnames_raw, list) else [])
            org: str | None = match.get("org")
            asn: str | None = match.get("asn")
            product: str | None = match.get("product")
            http_block: Any = match.get("http")
            title: str | None = (
                http_block.get("title")
                if isinstance(http_block, dict)
                else None
            )
            raw_data = json.dumps(match)

            cursor = await conn.execute(
                """
                INSERT OR IGNORE INTO leads
                    (id, source, source_query, ip, port, hostnames, org, asn,
                     product, title, raw_data, program_id)
                VALUES (?, 'shodan', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lead_id, query, ip, port, hostnames_json,
                    org, asn, product, title, raw_data, program_id,
                ),
            )
            if cursor.rowcount and cursor.rowcount > 0:
                new_count += 1

        await conn.commit()

    return {"leads": len(results), "new": new_count, "credits_used": credits_used}


@app.command("intel-sweep")
def intel_sweep_cmd(
    query: Annotated[str, typer.Option("--query", "-q", help="Shodan search query string")],
    program: Annotated[
        str | None,
        typer.Option("--program", "-p", help="Program ID to associate leads with"),
    ] = None,
    max_pages: Annotated[
        int,
        typer.Option("--max-pages", help="Pages to fetch (100 results/page = 1 credit/page)"),
    ] = 1,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Run a Shodan search query and store results as leads.

    Each Shodan search page costs one query credit.
    Requires SHODAN_API_KEY to be configured.
    """
    settings = get_settings()
    if not settings.shodan_api_key:
        typer.echo(
            "[error] SHODAN_API_KEY is not configured.  Set via .env or env var.",
            err=True,
        )
        raise typer.Exit(1)

    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    typer.echo(f"[bounty intel-sweep] query={query!r}  max_pages={max_pages}")

    try:
        summary = asyncio.run(_intel_sweep_async(query, program, max_pages, db_path))
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    typer.echo(f"  results:      {summary['leads']}")
    typer.echo(f"  new leads:    {summary['new']}")
    typer.echo(f"  credits used: {summary['credits_used']}")
    if program:
        typer.echo(f"  program:      {program}")


# ---------------------------------------------------------------------------
# leads sub-commands
# ---------------------------------------------------------------------------

@leads_app.command("list")
def leads_list_cmd(
    program: Annotated[str | None, typer.Option("--program", "-p", help="Filter by program ID")] = None,
    status: Annotated[str | None, typer.Option("--status", "-s", help="Filter by status: new|promoted|dismissed")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Maximum rows to display")] = 50,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """List leads (filterable by program and/or status)."""
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    async def _query() -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []
        if program:
            clauses.append("program_id = ?")
            params.append(program)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT id, ip, port, org, asn, title, status, program_id, discovered_at FROM leads {where} ORDER BY discovered_at DESC LIMIT ?"
        params.append(limit)
        async with get_conn(db_path) as conn:
            cursor = await conn.execute(sql, params)
            return list(await cursor.fetchall())

    try:
        rows = asyncio.run(_query())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not rows:
        typer.echo("No leads found.")
        return

    header = f"{'ID':<26}  {'IP':<15}  {'PORT':>5}  {'ORG':<25}  {'STATUS':<10}  {'TITLE':<35}"
    typer.echo(header)
    typer.echo("-" * len(header))
    for row in rows:
        title_str = (row["title"] or "")[:35]
        org_str = (row["org"] or "")[:25]
        port_str = str(row["port"]) if row["port"] else "—"
        typer.echo(
            f"{row['id']:<26}  {row['ip']:<15}  {port_str:>5}  "
            f"{org_str:<25}  {row['status']:<10}  {title_str:<35}"
        )
    typer.echo(f"\n{len(rows)} lead(s) shown.")


@leads_app.command("promote")
def leads_promote_cmd(
    lead_id: Annotated[str, typer.Argument(help="Lead ID to promote to an asset")],
    program: Annotated[
        str | None,
        typer.Option("--program", "-p", help="Override program ID for the new asset"),
    ] = None,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Promote a lead to an asset row and mark it as promoted."""
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    async def _promote() -> str | None:
        async with get_conn(db_path) as conn:
            cursor = await conn.execute("SELECT * FROM leads WHERE id=?", (lead_id,))
            lead_row = await cursor.fetchone()
            if not lead_row:
                return None

            effective_pid: str | None = program or lead_row["program_id"]
            if not effective_pid:
                raise typer.BadParameter(
                    "No program_id on the lead and --program not specified."
                )

            # Ensure program exists
            await conn.execute(
                "INSERT OR IGNORE INTO programs (id, platform, handle, name) VALUES (?, 'manual', ?, ?)",
                (effective_pid, effective_pid, effective_pid),
            )

            # Build canonical URL for the asset
            ip_val: str = lead_row["ip"]
            port_val: int | None = lead_row["port"]
            scheme = "https" if port_val == 443 else "http"
            canonical_port: int | None = port_val if port_val not in (80, 443, None) else None
            if canonical_port is not None:
                url = f"{scheme}://{ip_val}:{canonical_port}"
            else:
                url = f"{scheme}://{ip_val}"

            # BUG 2 FIX: Lookup by (program_id, host, canonical_port), not by url.
            # Use COALESCE(-1) trick so NULL compares equal to NULL.
            cursor = await conn.execute(
                "SELECT id FROM assets WHERE program_id=? AND host=? AND COALESCE(port,-1)=COALESCE(?,-1)",
                (effective_pid, ip_val, canonical_port),
            )
            existing_asset = await cursor.fetchone()

            ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if existing_asset:
                asset_id = str(existing_asset["id"])
            else:
                asset_id = make_ulid()
                await conn.execute(
                    """
                    INSERT INTO assets
                        (id, program_id, host, port, scheme, url, ip, status,
                         seen_protocols, primary_scheme,
                         tags, first_seen, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'discovered', ?, ?, '["lead"]', ?, ?, ?)
                    """,
                    (
                        asset_id, effective_pid, ip_val,
                        canonical_port,
                        scheme, url, ip_val,
                        json.dumps([scheme]),  # seen_protocols
                        scheme,                # primary_scheme
                        ts, ts, ts,
                    ),
                )

            # Mark lead as promoted
            await conn.execute(
                "UPDATE leads SET status='promoted' WHERE id=?",
                (lead_id,),
            )
            await conn.commit()
            return asset_id

    try:
        asset_id = asyncio.run(_promote())
    except typer.BadParameter as exc:
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if asset_id is None:
        typer.echo(f"[error] Lead {lead_id!r} not found.", err=True)
        raise typer.Exit(1)

    typer.echo(f"[bounty leads promote] lead {lead_id} → asset {asset_id}")


@leads_app.command("dismiss")
def leads_dismiss_cmd(
    lead_id: Annotated[str, typer.Argument(help="Lead ID to dismiss")],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Mark a lead as dismissed."""
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    async def _dismiss() -> bool:
        async with get_conn(db_path) as conn:
            cursor = await conn.execute(
                "UPDATE leads SET status='dismissed' WHERE id=?", (lead_id,)
            )
            await conn.commit()
            return bool(cursor.rowcount and cursor.rowcount > 0)

    try:
        updated = asyncio.run(_dismiss())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not updated:
        typer.echo(f"[error] Lead {lead_id!r} not found.", err=True)
        raise typer.Exit(1)

    typer.echo(f"[bounty leads dismiss] lead {lead_id} → dismissed")


# ---------------------------------------------------------------------------
# scan-ips
# ---------------------------------------------------------------------------

async def _scan_ips_async(
    db_path: Path,
    program_id: str,
    targets: list[Target],
    scan_id: str,
    intensity: str,
) -> tuple[dict[str, list[str]], sqlite3.Row | None, list[sqlite3.Row], list[sqlite3.Row]]:
    """Async implementation of scan-ips: persist targets → pipeline → results."""
    async with get_conn(db_path) as conn:
        # Ensure program exists
        await conn.execute(
            "INSERT OR IGNORE INTO programs (id, platform, handle, name) VALUES (?, 'manual', ?, ?)",
            (program_id, program_id, program_id),
        )
        # Persist the targets
        for t in targets:
            await conn.execute(
                """
                INSERT OR IGNORE INTO targets (program_id, scope_type, asset_type, value)
                VALUES (?, ?, ?, ?)
                """,
                (t.program_id, t.scope_type, t.asset_type, t.value),
            )
        await conn.commit()

    result = await recon_pipeline(
        program_id=program_id,
        targets=targets,
        intensity=intensity,
        db_path=db_path,
        scan_id=scan_id,
    )

    async with get_conn(db_path) as conn:
        cursor = await conn.execute(
            "SELECT status, started_at, finished_at, error FROM scans WHERE id=?",
            (scan_id,),
        )
        scan_row: sqlite3.Row | None = await cursor.fetchone()

        # BUG 3 FIX: use the asset IDs returned by the pipeline, NOT a re-query of
        # all program assets (which would include pre-existing rows from prior scans
        # and cause both count mismatch and cross-scan contamination in the display).
        asset_ids = result.get("assets", [])
        asset_rows: list[sqlite3.Row] = []
        if asset_ids:
            placeholders = ",".join("?" * len(asset_ids))
            cursor = await conn.execute(
                f"SELECT host, http_status, title FROM assets WHERE id IN ({placeholders}) ORDER BY host",
                asset_ids,
            )
            asset_rows = list(await cursor.fetchall())

        cursor = await conn.execute(
            "SELECT phase, status FROM scan_phases WHERE scan_id=? ORDER BY phase",
            (scan_id,),
        )
        phase_rows: list[sqlite3.Row] = list(await cursor.fetchall())

    return result, scan_row, asset_rows, phase_rows


@app.command("scan-ips")
def scan_ips_cmd(
    program: Annotated[str, typer.Option("--program", "-p", help="Program ID")],
    file: Annotated[
        Path,
        typer.Option("--file", "-f", help="File with IPs / CIDRs / ASNs, one per line"),
    ],
    intensity: Annotated[
        str,
        typer.Option("--intensity", "-i", help=f"Scan intensity: {' | '.join(_INTENSITY_CHOICES)}"),
    ] = "gentle",
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Read IPs / CIDRs / ASNs from FILE and run the recon pipeline.

    Lines starting with # are treated as comments and skipped.
    Asset type is auto-detected:
      - ``AS12345`` → asn
      - ``1.2.3.0/24`` → cidr
      - ``1.2.3.4`` → ip
    """
    if intensity not in _INTENSITY_CHOICES:
        typer.echo(f"[error] intensity must be one of: {', '.join(_INTENSITY_CHOICES)}", err=True)
        raise typer.Exit(1)

    if not file.exists():
        typer.echo(f"[error] File not found: {file}", err=True)
        raise typer.Exit(1)

    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    targets: list[Target] = []
    with open(file, encoding="utf-8") as fh:
        for lineno, raw_line in enumerate(fh, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = _detect_asset_type(line)
            if parsed is None:
                typer.echo(
                    f"[warn] line {lineno}: cannot parse {line!r} as IP/CIDR/ASN — skipping",
                    err=True,
                )
                continue
            asset_type, value = parsed
            targets.append(
                Target(
                    program_id=program,
                    scope_type="in_scope",
                    asset_type=asset_type,
                    value=value,
                )
            )

    if not targets:
        typer.echo("[error] No valid targets found in file.", err=True)
        raise typer.Exit(1)

    typer.echo(
        f"[bounty scan-ips] program={program}  targets={len(targets)}  "
        f"intensity={intensity}  db={db_path}"
    )
    for t in targets:
        typer.echo(f"  [{t.asset_type}] {t.value}")

    scan_id = make_ulid()
    typer.echo(f"  scan_id={scan_id}")
    typer.echo("  running pipeline…")

    try:
        result, scan_row, asset_rows, phase_rows = asyncio.run(
            _scan_ips_async(db_path, program, targets, scan_id, intensity)
        )
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] pipeline failed: {exc}", err=True)
        raise typer.Exit(1)

    typer.echo("")
    typer.echo("=" * 60)
    if scan_row:
        typer.echo(f"  scan status: {scan_row['status']}")
        if scan_row["error"]:
            typer.echo(f"  error: {scan_row['error']}", err=True)

    typer.echo(f"  phases ({len(phase_rows)}):")
    for ph in phase_rows:
        typer.echo(f"    {ph['phase']:15s}  {ph['status']}")

    typer.echo(f"  assets discovered: {len(asset_rows)}")
    for row in asset_rows[:30]:
        status_str = str(row["http_status"]) if row["http_status"] else "---"
        typer.echo(f"    [{status_str}] {row['host']}")
    if len(asset_rows) > 30:
        typer.echo(f"    … and {len(asset_rows) - 30} more")
    typer.echo("=" * 60)


# ---------------------------------------------------------------------------
# wipe-program
# ---------------------------------------------------------------------------

@app.command("wipe-program")
def wipe_program_cmd(
    program_id: Annotated[str, typer.Argument(help="Program ID to wipe")],
    confirm: Annotated[bool, typer.Option("--confirm", help="Actually delete (dry-run without this flag)")] = False,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Delete all data for a program (assets, scans, findings, leads, targets).

    Without --confirm, prints a summary of what would be deleted and exits.
    With --confirm, permanently deletes the data.  CASCADE handles child rows.
    """
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    async def _count_and_wipe(dry_run: bool) -> dict[str, int]:
        async with get_conn(db_path) as conn:
            counts: dict[str, int] = {}
            for table in ("assets", "scans", "findings", "leads", "targets"):
                col = "program_id"
                cur = await conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {col}=?", (program_id,)
                )
                row = await cur.fetchone()
                counts[table] = row[0] if row else 0

            if not dry_run:
                # Delete in dependency order; CASCADE handles child rows.
                for table in ("leads", "findings", "scans"):
                    await conn.execute(f"DELETE FROM {table} WHERE program_id=?", (program_id,))
                # Deleting the program cascades to assets and targets.
                await conn.execute("DELETE FROM programs WHERE id=?", (program_id,))
                await conn.commit()
        return counts

    try:
        counts = asyncio.run(_count_and_wipe(dry_run=not confirm))
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    total = sum(counts.values())
    if not confirm:
        typer.echo(f"[bounty wipe-program] DRY RUN — would delete from program {program_id!r}:")
        for table, n in counts.items():
            typer.echo(f"  {table}: {n} row(s)")
        typer.echo(f"  total:  {total} row(s)")
        typer.echo("\nRe-run with --confirm to actually delete.")
        return

    if total == 0:
        typer.echo(f"[bounty wipe-program] Nothing found for program {program_id!r}.")
        return

    typer.echo(f"[bounty wipe-program] Deleted program {program_id!r}:")
    for table, n in counts.items():
        typer.echo(f"  {table}: {n} row(s) deleted")


# ---------------------------------------------------------------------------
# wipe-test-data
# ---------------------------------------------------------------------------

@app.command("wipe-test-data")
def wipe_test_data_cmd(
    confirm: Annotated[bool, typer.Option("--confirm", help="Actually delete (dry-run without this flag)")] = False,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Delete all programs matching test-* or manual:* patterns and their data.

    Without --confirm, prints what would be deleted.  Use --confirm to execute.
    """
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    async def _find_and_wipe(dry_run: bool) -> list[str]:
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                "SELECT id FROM programs WHERE id LIKE 'test-%' OR id LIKE 'manual:%'"
            )
            rows = await cur.fetchall()
            pids = [row["id"] for row in rows]

            if not dry_run:
                for pid in pids:
                    for table in ("leads", "findings", "scans"):
                        await conn.execute(f"DELETE FROM {table} WHERE program_id=?", (pid,))
                    await conn.execute("DELETE FROM programs WHERE id=?", (pid,))
                await conn.commit()
        return pids

    try:
        pids = asyncio.run(_find_and_wipe(dry_run=not confirm))
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not pids:
        typer.echo("[bounty wipe-test-data] No test/manual programs found.")
        return

    if not confirm:
        typer.echo(f"[bounty wipe-test-data] DRY RUN — would delete {len(pids)} program(s):")
        for pid in pids:
            typer.echo(f"  {pid}")
        typer.echo("\nRe-run with --confirm to actually delete.")
        return

    typer.echo(f"[bounty wipe-test-data] Deleted {len(pids)} program(s):")
    for pid in pids:
        typer.echo(f"  {pid}")


# ---------------------------------------------------------------------------
# cleanup-orphan-assets
# ---------------------------------------------------------------------------

@app.command("cleanup-orphan-assets")
def cleanup_orphan_assets_cmd(
    confirm: Annotated[bool, typer.Option("--confirm", help="Actually delete (dry-run without this flag)")] = False,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Delete assets whose program_id has no matching row in programs.

    This removes historical contamination from prior buggy runs where assets
    were written under a program_id that no longer exists or was never created.
    Without --confirm, prints the count and sample assets that would be removed.
    """
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    async def _find_and_wipe(dry_run: bool) -> list[sqlite3.Row]:
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                """
                SELECT id, program_id, host, url
                FROM assets
                WHERE program_id NOT IN (SELECT id FROM programs)
                ORDER BY program_id, host
                LIMIT 200
                """
            )
            orphans = list(await cur.fetchall())
            if not dry_run and orphans:
                await conn.execute(
                    "DELETE FROM assets WHERE program_id NOT IN (SELECT id FROM programs)"
                )
                await conn.commit()
        return orphans

    try:
        orphans = asyncio.run(_find_and_wipe(dry_run=not confirm))
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not orphans:
        typer.echo("[bounty cleanup-orphan-assets] No orphan assets found.")
        return

    verb = "Would delete" if not confirm else "Deleted"
    typer.echo(f"[bounty cleanup-orphan-assets] {verb} {len(orphans)} orphan asset(s):")
    for row in orphans[:20]:
        typer.echo(f"  program={row['program_id']!r:30s}  host={row['host']}")
    if len(orphans) > 20:
        typer.echo(f"  … and {len(orphans) - 20} more")

    if not confirm:
        typer.echo("\nRe-run with --confirm to actually delete.")


if __name__ == "__main__":
    app()












