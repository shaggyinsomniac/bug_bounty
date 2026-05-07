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
from typing import Annotated, Any

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


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _detect_asset_type(value: str) -> tuple[str, str] | None:
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

        cursor = await conn.execute(
            """
            SELECT host, http_status, title, server, url
            FROM assets
            WHERE program_id=?
            ORDER BY http_status ASC, host ASC
            """,
            (program_id,),
        )
        asset_rows: list[sqlite3.Row] = list(await cursor.fetchall())

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
            if port_val and port_val not in (80, 443):
                url = f"{scheme}://{ip_val}:{port_val}"
            else:
                url = f"{scheme}://{ip_val}"

            # Check if asset already exists for this URL
            cursor = await conn.execute(
                "SELECT id FROM assets WHERE program_id=? AND url=?",
                (effective_pid, url),
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
                         tags, first_seen, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'discovered', '["lead"]', ?, ?, ?)
                    """,
                    (
                        asset_id, effective_pid, ip_val,
                        port_val if port_val not in (80, 443, None) else None,
                        scheme, url, ip_val,
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

        cursor = await conn.execute(
            "SELECT host, http_status, title FROM assets WHERE program_id=? ORDER BY host",
            (program_id,),
        )
        asset_rows: list[sqlite3.Row] = list(await cursor.fetchall())

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
            result = _detect_asset_type(line)
            if result is None:
                typer.echo(
                    f"[warn] line {lineno}: cannot parse {line!r} as IP/CIDR/ASN — skipping",
                    err=True,
                )
                continue
            asset_type, value = result
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


if __name__ == "__main__":
    app()

