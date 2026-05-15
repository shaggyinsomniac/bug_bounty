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

findings_app = typer.Typer(help="Query and export findings from the database.")
app.add_typer(findings_app, name="findings")

secrets_app = typer.Typer(help="Query and revalidate discovered secret tokens.")
app.add_typer(secrets_app, name="secrets")

tools_app = typer.Typer(help="Manage external tool binaries (trufflehog, etc.).")
app.add_typer(tools_app, name="tools")

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
                f"SELECT id, host, http_status, title, server, cdn, waf, url FROM assets WHERE id IN ({placeholders}) ORDER BY http_status ASC, host ASC",
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
    typer.echo(f"  UNIQUE ASSETS DISCOVERED: {len(set(result.get('assets', [])))}")

    async def _get_fingerprints_for_assets(db_path: Path, asset_ids: list[str]) -> dict[str, list[dict[str, object]]]:
        result: dict[str, list[dict[str, object]]] = {}
        if not asset_ids:
            return result
        async with get_conn(db_path) as conn:
            placeholders = ",".join("?" * len(asset_ids))
            cur = await conn.execute(
                f"SELECT asset_id, tech, category, confidence FROM fingerprints"
                f" WHERE asset_id IN ({placeholders})"
                f" ORDER BY asset_id, confidence DESC",
                asset_ids,
            )
            for fp_row in await cur.fetchall():
                result.setdefault(fp_row["asset_id"], []).append(dict(fp_row))
        return result

    fp_by_asset: dict[str, list[dict[str, object]]] = {}
    if asset_rows:
        fp_by_asset = asyncio.run(
            _get_fingerprints_for_assets(db_path, [str(r["id"]) for r in asset_rows[:50]])
        )

    _TIER_RANK = {"hint": 0, "weak": 1, "strong": 2, "definitive": 3}

    for row in asset_rows[:50]:
        status_str = str(row["http_status"]) if row["http_status"] else "---"
        title_str = (row["title"] or "")[:40]
        server_val = row["server"] if row["server"] else None
        cdn_val = row["cdn"] if row["cdn"] else None
        waf_val = row["waf"] if row["waf"] else None
        server_str = f"  server={server_val}" if server_val else ""
        cdn_str = f" cdn={cdn_val}" if cdn_val else ""
        waf_str = f" waf={waf_val}" if waf_val else ""
        # Use print() directly so Rich/typer markup processing never touches
        # hostnames or URLs — prevents `[host](url)` auto-link rendering.
        print(f"    [{status_str:>3s}] {row['host']:<40s}  {title_str}{server_str}{cdn_str}{waf_str}")

        fps: list[dict[str, object]] = fp_by_asset.get(str(row["id"]), [])
        if fps:
            # Deduplicate by tech name (keep highest-tier)
            seen_techs: dict[str, dict[str, object]] = {}
            for fp in fps:
                t = str(fp["tech"])
                fp_rank = _TIER_RANK.get(str(fp["confidence"]).lower(), 0)
                cur_rank = _TIER_RANK.get(str(seen_techs.get(t, {}).get("confidence", "hint")).lower(), 0)
                if t not in seen_techs or fp_rank > cur_rank:
                    seen_techs[t] = fp
            top_fps = sorted(
                seen_techs.values(),
                key=lambda x: -_TIER_RANK.get(str(x["confidence"]).lower(), 0),
            )[:5]
            tech_strs = [
                f"{fp['tech']}({fp['category']},{str(fp['confidence']).upper()})"
                for fp in top_fps
            ]
            print(f"           techs: {',  '.join(tech_strs)}")

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


# ---------------------------------------------------------------------------
# Fingerprint sub-commands
# ---------------------------------------------------------------------------

fingerprint_app = typer.Typer(help="Fingerprint commands — query and manage technology detections.")
app.add_typer(fingerprint_app, name="fingerprint")


@fingerprint_app.command("show")
def fingerprint_show(
    asset_id: Annotated[str, typer.Argument(help="Asset ID (ULID)")],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Print all FingerprintResult rows for an asset, sorted by confidence."""
    from bounty.config import get_settings as _get_settings

    db_path = db or _get_settings().db_path

    async def _show(aid: str) -> list[dict[str, object]]:
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                """
                SELECT id, tech, version, category, confidence, evidence, created_at
                FROM fingerprints WHERE asset_id=?
                ORDER BY confidence DESC
                """,
                (aid,),
            )
            return [dict(r) for r in await cur.fetchall()]

    try:
        rows = asyncio.run(_show(asset_id))
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not rows:
        typer.echo(f"No fingerprint rows found for asset {asset_id!r}.")
        raise typer.Exit(0)

    typer.echo(f"Fingerprints for asset {asset_id} ({len(rows)} results):")
    typer.echo(f"  {'TECH':<30s}  {'CAT':<12s}  {'CONF':>4s}  {'VERSION':<12s}  EVIDENCE")
    typer.echo("  " + "-" * 100)
    for r in rows:
        ver = (str(r.get("version") or ""))[:12]
        ev = (str(r.get("evidence") or ""))[:60]
        typer.echo(
            f"  {str(r['tech']):<30s}  {str(r['category']):<12s}  "
            f"{str(r['confidence']):>4s}  {ver:<12s}  {ev}"
        )


@fingerprint_app.command("add-favicon-hash")
def fingerprint_add_favicon_hash(
    tech: Annotated[str, typer.Argument(help="Tech name (e.g. jenkins)")],
    hash_val: Annotated[int, typer.Argument(help="mmh3 favicon hash (integer)")],
    category: Annotated[str, typer.Option("--category")] = "other",
) -> None:
    """Append or update a favicon hash entry in favicon_db.json."""
    import json as _json
    from pathlib import Path as _Path

    db_file = _Path(__file__).parent / "fingerprint" / "data" / "favicon_db.json"
    try:
        entries: list[dict[str, object]] = _json.loads(db_file.read_text())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] reading favicon_db.json: {exc}", err=True)
        raise typer.Exit(1)

    # Update existing entry or append new one
    updated = False
    for entry in entries:
        if entry.get("tech") == tech:
            entry["hash"] = hash_val
            entry["category"] = category
            updated = True
            break
    if not updated:
        entries.append({"hash": hash_val, "tech": tech, "category": category})

    db_file.write_text(_json.dumps(entries, indent=2))
    verb = "Updated" if updated else "Added"
    typer.echo(f"[bounty fingerprint add-favicon-hash] {verb} hash={hash_val} for tech={tech!r} (category={category})")

    # Invalidate module cache
    from bounty.fingerprint import favicon as _fav_module
    _fav_module._FAVICON_DB = None


# ===========================================================================
# findings sub-commands
# ===========================================================================

_SEVERITY_LABELS = ("critical", "high", "medium", "low", "info")
_SEVERITY_MIN: dict[str, int] = {
    "critical": 800,
    "high": 600,
    "medium": 400,
    "low": 200,
    "info": 0,
}


@findings_app.command("list")
def findings_list(
    program: Annotated[str | None, typer.Option("--program", "-p")] = None,
    severity: Annotated[str | None, typer.Option("--severity", "-s",
        help="Filter by minimum severity label: critical|high|medium|low|info")] = None,
    category: Annotated[str | None, typer.Option("--category", "-c")] = None,
    validated_only: Annotated[bool, typer.Option("--validated-only")] = False,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 50,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """List findings with optional filters."""
    settings = get_settings()
    db_path = db or settings.db_path

    async def _query() -> list[Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if program:
            clauses.append("program_id = ?")
            params.append(program)
        if severity and severity in _SEVERITY_MIN:
            clauses.append("severity >= ?")
            params.append(_SEVERITY_MIN[severity])
        if category:
            clauses.append("category = ?")
            params.append(category)
        if validated_only:
            clauses.append("validated = 1")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                f"SELECT id, severity_label, asset_id, title, dedup_key, category, "
                f"severity, url FROM findings {where} ORDER BY severity DESC LIMIT ?",
                params,
            )
            return list(await cur.fetchall())

    try:
        rows = asyncio.run(_query())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not rows:
        typer.echo("No findings found.")
        return

    typer.echo(f"{'ID':<28}  {'SEV':<8}  {'CATEGORY':<25}  TITLE")
    typer.echo("-" * 90)
    for row in rows:
        sev_label = str(row["severity_label"]).upper()
        cat = str(row["category"])[:25]
        title = str(row["title"])[:60]
        print(f"{row['id']!s:<28}  {sev_label:<8}  {cat:<25}  {title}")

    typer.echo(f"\n{len(rows)} finding(s) shown.")


@findings_app.command("show")
def findings_show(
    finding_id: Annotated[str, typer.Argument()],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Show full details for a single finding including evidence."""
    settings = get_settings()
    db_path = db or settings.db_path

    async def _fetch() -> tuple[Any, list[Any]]:
        async with get_conn(db_path) as conn:
            cur = await conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,))
            row = await cur.fetchone()
            if not row:
                # Try prefix search
                cur2 = await conn.execute(
                    "SELECT * FROM findings WHERE id LIKE ? LIMIT 1", (finding_id + "%",)
                )
                row = await cur2.fetchone()
            if not row:
                return None, []
            ev_cur = await conn.execute(
                "SELECT id, request_raw, response_raw, curl_cmd, captured_at "
                "FROM evidence_packages WHERE finding_id=? ORDER BY captured_at",
                (str(row["id"]),),
            )
            ev_rows = list(await ev_cur.fetchall())
            return row, ev_rows

    try:
        finding, evidence = asyncio.run(_fetch())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if finding is None:
        typer.echo(f"Finding not found: {finding_id}", err=True)
        raise typer.Exit(1)

    typer.echo("=" * 70)
    typer.echo(f"  ID:         {finding['id']}")
    typer.echo(f"  Title:      {finding['title']}")
    typer.echo(f"  Severity:   {finding['severity']} ({finding['severity_label'].upper()})")
    typer.echo(f"  Category:   {finding['category']}")
    typer.echo(f"  URL:        {finding['url']}")
    typer.echo(f"  Dedup Key:  {finding['dedup_key']}")
    typer.echo(f"  Validated:  {bool(finding['validated'])}")
    typer.echo(f"  Status:     {finding['status']}")
    typer.echo(f"  CWE:        {finding['cwe'] or 'n/a'}")
    typer.echo("")
    typer.echo("  DESCRIPTION:")
    typer.echo(f"    {finding['description']}")
    typer.echo("")
    typer.echo("  REMEDIATION:")
    typer.echo(f"    {finding['remediation']}")

    for i, ev in enumerate(evidence):
        typer.echo("")
        typer.echo(f"  ── Evidence #{i + 1} (captured {ev['captured_at']}) ──────────")
        if ev["curl_cmd"]:
            print(f"    curl_cmd: {ev['curl_cmd']}")
        if ev["request_raw"]:
            typer.echo("  REQUEST:")
            for ln in str(ev["request_raw"]).splitlines()[:8]:
                print(f"    {ln}")
        if ev["response_raw"]:
            typer.echo("  RESPONSE (first 20 lines):")
            for ln in str(ev["response_raw"]).splitlines()[:20]:
                print(f"    {ln}")

    typer.echo("=" * 70)


@findings_app.command("export")
def findings_export(
    format: Annotated[str, typer.Option("--format", "-f",
        help="Output format: json or csv")] = "json",
    out: Annotated[str | None, typer.Option("--out", "-o")] = None,
    program: Annotated[str | None, typer.Option("--program", "-p")] = None,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Export findings to JSON or CSV."""
    import csv
    import io
    settings = get_settings()
    db_path = db or settings.db_path

    async def _fetch() -> list[Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if program:
            clauses.append("program_id = ?")
            params.append(program)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                f"SELECT f.*, "
                f"  (SELECT GROUP_CONCAT(e.curl_cmd, '|||') FROM evidence_packages e WHERE e.finding_id=f.id) AS evidence_curls "
                f"FROM findings f {where} ORDER BY f.severity DESC",
                params,
            )
            return list(await cur.fetchall())

    try:
        rows = asyncio.run(_fetch())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if format.lower() == "json":
        output = json.dumps(
            [dict(zip(row.keys(), tuple(row))) for row in rows],
            indent=2,
            default=str,
        )
    else:
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(zip(row.keys(), tuple(row))))
        output = buf.getvalue()

    if out:
        Path(out).write_text(output)
        typer.echo(f"Exported {len(rows)} findings to {out}")
    else:
        typer.echo(output)


@findings_app.command("count")
def findings_count(
    program: Annotated[str | None, typer.Option("--program", "-p")] = None,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Print a severity histogram of findings."""
    settings = get_settings()
    db_path = db or settings.db_path

    async def _count() -> list[Any]:
        clause = "WHERE program_id=?" if program else ""
        params = [program] if program else []
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                f"SELECT severity_label, COUNT(*) as cnt FROM findings {clause} "
                f"GROUP BY severity_label ORDER BY MAX(severity) DESC",
                params,
            )
            return list(await cur.fetchall())

    try:
        rows = asyncio.run(_count())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not rows:
        typer.echo("No findings in database.")
        return

    total = sum(int(r["cnt"]) for r in rows)
    typer.echo(f"Findings{' for ' + program if program else ''}:")
    for row in rows:
        label = str(row["severity_label"]).upper()
        bar = "█" * min(int(row["cnt"]), 40)
        typer.echo(f"  {label:<10}  {row['cnt']:>4}  {bar}")
    typer.echo(f"  {'TOTAL':<10}  {total:>4}")


# ── secrets sub-commands ──────────────────────────────────────────────────

@secrets_app.command("list")
def secrets_list(
    status: Annotated[str | None, typer.Option("--status", help="Filter by status (live|invalid|pending|error|all)")] = None,
    provider: Annotated[str | None, typer.Option("--provider")] = None,
    finding: Annotated[str | None, typer.Option("--finding", help="Filter by finding ID")] = None,
    limit: Annotated[int, typer.Option("--limit")] = 50,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """List secret validations with optional filters."""
    settings = get_settings()
    db_path = db or settings.db_path

    async def _list() -> list[Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if status and status != "all":
            clauses.append("status=?")
            params.append(status)
        if provider:
            clauses.append("provider=?")
            params.append(provider)
        if finding:
            clauses.append("finding_id=?")
            params.append(finding)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                f"SELECT id, provider, secret_preview, status, identity, finding_id, last_checked "
                f"FROM secrets_validations {where} ORDER BY created_at DESC LIMIT ?",
                params,
            )
            return list(await cur.fetchall())

    try:
        rows = asyncio.run(_list())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not rows:
        typer.echo("No secret validations found.")
        return

    header = f"{'ID':<26}  {'PROVIDER':<12}  {'PREVIEW':<16}  {'STATUS':<8}  {'IDENTITY':<30}  FINDING"
    typer.echo(header)
    typer.echo("-" * len(header))
    for row in rows:
        sid = str(row["id"] or "")[:26]
        prov = str(row["provider"] or "")[:12]
        prev = str(row["secret_preview"] or "")[:16]
        stat = str(row["status"] or "")[:8]
        ident = str(row["identity"] or "")[:30]
        fid = str(row["finding_id"] or "")[:26]
        typer.echo(f"{sid:<26}  {prov:<12}  {prev:<16}  {stat:<8}  {ident:<30}  {fid}")


@secrets_app.command("show")
def secrets_show(
    secret_id: Annotated[str, typer.Argument(help="Secret validation ID (or prefix)")],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Show full details of a secret validation record."""
    settings = get_settings()
    db_path = db or settings.db_path

    async def _show() -> Any:
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM secrets_validations WHERE id=?", (secret_id,)
            )
            row = await cur.fetchone()
            if row is None:
                cur = await conn.execute(
                    "SELECT * FROM secrets_validations WHERE id LIKE ? LIMIT 1",
                    (secret_id + "%",),
                )
                row = await cur.fetchone()
            return row

    try:
        row = asyncio.run(_show())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if row is None:
        typer.echo(f"Secret validation '{secret_id}' not found.")
        raise typer.Exit(1)

    import json as _json
    typer.echo(f"ID:           {row['id']}")
    typer.echo(f"Provider:     {row['provider']}")
    typer.echo(f"Preview:      {row['secret_preview']}")
    typer.echo(f"Hash:         {row['secret_hash']}")
    typer.echo(f"Pattern:      {row['secret_pattern']}")
    typer.echo(f"Status:       {row['status']}")
    typer.echo(f"Identity:     {row['identity'] or '—'}")
    typer.echo(f"Last checked: {row['last_checked'] or '—'}")
    typer.echo(f"Error:        {row['error_message'] or '—'}")
    typer.echo(f"Finding ID:   {row['finding_id'] or '—'}")
    typer.echo(f"Asset ID:     {row['asset_id'] or '—'}")
    scope_raw = row["scope"]
    if scope_raw:
        try:
            typer.echo(f"Scope:        {_json.dumps(_json.loads(scope_raw), indent=2)}")
        except Exception:  # noqa: BLE001
            typer.echo(f"Scope:        {scope_raw}")


@secrets_app.command("revalidate")
def secrets_revalidate(
    secret_id: Annotated[str, typer.Argument(help="Secret validation ID to force revalidate")],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Force re-validation of a secret regardless of cache TTL."""
    import json as _json
    settings = get_settings()
    db_path = db or settings.db_path

    async def _revalidate() -> str:
        import bounty.validate.registry as _reg_mod  # noqa: F401
        from bounty.validate._base import REGISTRY
        from bounty.secrets.scanner import SecretCandidate

        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM secrets_validations WHERE id=? OR id LIKE ? LIMIT 1",
                (secret_id, secret_id + "%"),
            )
            row = await cur.fetchone()
            if row is None:
                return "NOT_FOUND"

            provider = str(row["provider"])
            secret_hash = str(row["secret_hash"])
            validator = REGISTRY.get(provider)
            if validator is None:
                return f"NO_VALIDATOR:{provider}"

            # Build a minimal candidate from stored fields (no context available at this point)
            candidate = SecretCandidate(
                provider=provider,
                pattern_name=str(row["secret_pattern"]),
                value=secret_hash,  # hash is what we have; can't recover raw value
                context_before="",
                context_after="",
            )
            # Override hash so it uses the stored one
            import httpx as _httpx
            async with _httpx.AsyncClient(timeout=15) as http:
                result = await validator.validate(candidate, http)

            ts = _now_iso()
            scope_json = _json.dumps(result.scope) if result.scope else None
            await conn.execute(
                """
                UPDATE secrets_validations
                SET status=?, scope=?, identity=?, last_checked=?,
                    error_message=?, updated_at=?
                WHERE id=?
                """,
                (
                    result.status, scope_json, result.identity,
                    ts, result.error_message, ts, str(row["id"]),
                ),
            )
            await conn.commit()
            return result.status

    try:
        status = asyncio.run(_revalidate())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if status == "NOT_FOUND":
        typer.echo(f"Secret validation '{secret_id}' not found.")
    elif status.startswith("NO_VALIDATOR:"):
        typer.echo(f"No validator registered for provider: {status.split(':')[1]}")
    else:
        typer.echo(f"Revalidation complete. New status: {status}")


@secrets_app.command("stats")
def secrets_stats(
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Show counts of secrets by provider and status."""
    settings = get_settings()
    db_path = db or settings.db_path

    async def _stats() -> tuple[list[Any], list[Any]]:
        async with get_conn(db_path) as conn:
            cur1 = await conn.execute(
                "SELECT provider, COUNT(*) as cnt FROM secrets_validations "
                "GROUP BY provider ORDER BY cnt DESC"
            )
            by_provider = list(await cur1.fetchall())
            cur2 = await conn.execute(
                "SELECT status, COUNT(*) as cnt FROM secrets_validations "
                "GROUP BY status ORDER BY cnt DESC"
            )
            by_status = list(await cur2.fetchall())
            return by_provider, by_status

    try:
        by_provider, by_status = asyncio.run(_stats())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not by_provider:
        typer.echo("No secret validations in database.")
        return

    typer.echo("By provider:")
    for row in by_provider:
        typer.echo(f"  {str(row['provider']):<20}  {row['cnt']:>4}")
    typer.echo("")
    typer.echo("By status:")
    for row in by_status:
        typer.echo(f"  {str(row['status']):<12}  {row['cnt']:>4}")


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------

@app.command("serve")
def serve_cmd(
    host: Annotated[str, typer.Option("--host", help="Interface to bind to")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="TCP port")] = 8765,
    reload: Annotated[bool, typer.Option("--reload", help="Enable hot-reload (dev only)")] = False,
) -> None:
    """Start the Bounty web UI server.

    Visit http://<HOST>:<PORT>/ in your browser.
    Set UI_TOKEN env var to enable authentication in production.
    """
    import uvicorn

    settings = get_settings()
    db_path = settings.db_path

    # Ensure the DB is ready before uvicorn starts serving requests.
    init_db(db_path)
    apply_migrations(db_path)

    typer.echo(f"[bounty serve] starting at http://{host}:{port}/")
    typer.echo(f"[bounty serve] database: {db_path}")
    if settings.ui_token:
        typer.echo("[bounty serve] auth: UI_TOKEN is set")
    else:
        typer.echo("[bounty serve] auth: disabled (set UI_TOKEN to enable)")

    uvicorn.run(
        "bounty.ui.app:app",
        host=host,
        port=port,
        reload=reload,
    )


# ---------------------------------------------------------------------------
# tools sub-commands
# ---------------------------------------------------------------------------

_TRUFFLEHOG_GITHUB_RELEASES = (
    "https://github.com/trufflesecurity/trufflehog/releases/latest/download/"
)
_TRUFFLEHOG_GITHUB_API = (
    "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest"
)


def _trufflehog_asset_name(version: str = "") -> str:
    """Return the platform-specific TruffleHog release asset filename.

    Args:
        version: Version string without 'v' prefix (e.g. '3.95.3').
                 When empty a versionless name is returned as a fallback.
    """
    import platform as _platform

    system = _platform.system().lower()
    machine = _platform.machine().lower()

    if system == "darwin":
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    elif system == "linux":
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    elif system == "windows":
        arch = "amd64"
    else:
        arch = "amd64"

    if version:
        return f"trufflehog_{version}_{system}_{arch}.tar.gz"
    # Legacy / fallback (no version in name)
    return f"trufflehog_{system}_{arch}.tar.gz"


@tools_app.command("install-trufflehog")
def install_trufflehog_cmd(
    dest: Annotated[
        Path | None,
        typer.Option(
            "--dest",
            "-d",
            help="Destination path for the binary (default: ~/.bounty/tools/trufflehog)",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Re-download even if binary already exists"),
    ] = False,
) -> None:
    """Download the TruffleHog OSS binary for this platform.

    Downloads from GitHub Releases into ``~/.bounty/tools/trufflehog`` (or
    a custom path supplied via ``--dest``) and makes it executable.

    Run this once before using TruffleHog-backed secret detection::

        bounty tools install-trufflehog
    """
    import os
    import stat
    import tarfile
    import tempfile
    import urllib.request

    install_path = dest or (Path.home() / ".bounty" / "tools" / "trufflehog")

    if install_path.exists() and not force:
        typer.echo(
            f"[bounty tools install-trufflehog] TruffleHog already installed at {install_path}"
        )
        typer.echo("  Use --force to re-download.")
        return

    install_path.parent.mkdir(parents=True, exist_ok=True)

    # Resolve the actual versioned download URL via the GitHub API so we don't
    # depend on the /releases/latest/download/ redirect (which can 404 on some
    # networks/proxies).
    try:
        import json as _json
        api_req = urllib.request.Request(
            _TRUFFLEHOG_GITHUB_API,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "bounty-installer/1"},
        )
        with urllib.request.urlopen(api_req, timeout=15) as _resp:
            release_data = _json.loads(_resp.read())
        tag = release_data.get("tag_name", "")
        version_str = tag.lstrip("v")
        asset_name = _trufflehog_asset_name(version_str)
        # Look for the exact asset in the release
        assets = release_data.get("assets", [])
        download_url: str | None = None
        for asset in assets:
            if asset.get("name") == asset_name:
                download_url = asset["browser_download_url"]
                break
        if download_url is None:
            # Fallback to constructed URL
            download_url = (
                f"https://github.com/trufflesecurity/trufflehog/releases/download/"
                f"{tag}/{asset_name}"
                if tag
                else _TRUFFLEHOG_GITHUB_RELEASES + _trufflehog_asset_name()
            )
    except Exception as _api_exc:  # noqa: BLE001
        # If API lookup fails just try the direct /latest/download/ URL
        asset_name = _trufflehog_asset_name()
        download_url = _TRUFFLEHOG_GITHUB_RELEASES + asset_name

    url = download_url

    typer.echo(f"[bounty tools install-trufflehog] Downloading {url}")
    typer.echo(f"  → {install_path}")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tarball_path = Path(tmpdir) / asset_name

            # Download with progress indicator
            def _report(count: int, block_size: int, total_size: int) -> None:
                if total_size > 0:
                    pct = min(count * block_size * 100 // total_size, 100)
                    typer.echo(f"\r  {pct}%", nl=False)

            urllib.request.urlretrieve(url, str(tarball_path), _report)
            typer.echo("")  # newline after progress

            # Extract the 'trufflehog' binary from the tarball
            with tarfile.open(str(tarball_path), "r:gz") as tar:
                # Find the binary member
                binary_member = None
                for member in tar.getmembers():
                    name = member.name.lstrip("./")
                    if name == "trufflehog" or name.endswith("/trufflehog"):
                        binary_member = member
                        break

                if binary_member is None:
                    typer.echo(
                        "[error] Could not find 'trufflehog' binary in the downloaded archive.",
                        err=True,
                    )
                    raise typer.Exit(1)

                extracted = tar.extractfile(binary_member)
                if extracted is None:
                    typer.echo("[error] Could not extract trufflehog binary.", err=True)
                    raise typer.Exit(1)

                install_path.write_bytes(extracted.read())

        # chmod +x
        current_mode = install_path.stat().st_mode
        install_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] Download failed: {exc}", err=True)
        typer.echo(
            "\nManual install alternative:\n"
            f"  Download: {url}\n"
            f"  Extract binary to: {install_path}\n"
            "  chmod +x <path>",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(
        f"[bounty tools install-trufflehog] ✓ Installed TruffleHog at {install_path}"
    )


@tools_app.command("check")
def tools_check_cmd() -> None:
    """Check which external tool binaries are available."""
    from bounty.tools import get_nuclei_path, get_trufflehog_path

    settings = get_settings()
    trufflehog = get_trufflehog_path(
        Path(str(settings.trufflehog_binary_path)).expanduser()
        if settings.trufflehog_binary_path
        else None
    )
    nuclei = get_nuclei_path(
        Path(str(settings.nuclei_binary_path)).expanduser()
        if settings.nuclei_binary_path
        else None
    )

    typer.echo("External tools status:")
    if trufflehog:
        typer.echo(f"  trufflehog  ✓  {trufflehog}")
    else:
        typer.echo(
            "  trufflehog  ✗  not found  "
            "(run: bounty tools install-trufflehog)"
        )
    if nuclei:
        typer.echo(f"  nuclei      ✓  {nuclei}")
    else:
        typer.echo(
            "  nuclei      ✗  not found  "
            "(run: bounty tools install-nuclei)"
        )


# ---------------------------------------------------------------------------
# Nuclei install / update helpers
# ---------------------------------------------------------------------------

_NUCLEI_GITHUB_API = (
    "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
)


def _nuclei_asset_name(version: str = "") -> str:
    """Return the platform-specific Nuclei release asset filename.

    Nuclei releases use zip archives (not tar.gz) named:
    ``nuclei_{version}_{os}_{arch}.zip``

    Note: Nuclei uses ``macOS`` (not ``darwin``) for macOS assets.
    """
    import platform as _platform

    system = _platform.system().lower()
    machine = _platform.machine().lower()

    if system == "darwin":
        os_str = "macOS"
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    elif system == "linux":
        os_str = "linux"
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    elif system == "windows":
        os_str = "windows"
        arch = "amd64"
    else:
        os_str = system
        arch = "amd64"

    if version:
        return f"nuclei_{version}_{os_str}_{arch}.zip"
    return f"nuclei_{os_str}_{arch}.zip"


@tools_app.command("install-nuclei")
def install_nuclei_cmd(
    dest: Annotated[
        Path | None,
        typer.Option(
            "--dest",
            "-d",
            help="Destination path for the binary (default: ~/.bounty/tools/nuclei)",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Re-download even if binary already exists"),
    ] = False,
    skip_templates: Annotated[
        bool,
        typer.Option("--skip-templates", help="Skip nuclei -update-templates after install"),
    ] = False,
) -> None:
    """Download the Nuclei OSS binary for this platform and fetch templates.

    Downloads from GitHub Releases into ``~/.bounty/tools/nuclei`` (or a
    custom path via ``--dest``) and makes it executable.  Then runs
    ``nuclei -update-templates`` to fetch the community template library.

    Run this once before using Nuclei-backed vulnerability detection::

        bounty tools install-nuclei
    """
    import json as _json
    import os
    import stat
    import tempfile
    import urllib.request
    import zipfile

    install_path = dest or (Path.home() / ".bounty" / "tools" / "nuclei")

    if install_path.exists() and not force:
        typer.echo(
            f"[bounty tools install-nuclei] Nuclei already installed at {install_path}"
        )
        typer.echo("  Use --force to re-download.")
        return

    install_path.parent.mkdir(parents=True, exist_ok=True)

    # Resolve the actual versioned download URL via the GitHub API
    try:
        api_req = urllib.request.Request(
            _NUCLEI_GITHUB_API,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "bounty-installer/1",
            },
        )
        with urllib.request.urlopen(api_req, timeout=15) as _resp:
            release_data = _json.loads(_resp.read())
        tag: str = release_data.get("tag_name", "")
        version_str = tag.lstrip("v")
        asset_name = _nuclei_asset_name(version_str)
        assets = release_data.get("assets", [])
        download_url: str | None = None
        for asset in assets:
            if asset.get("name") == asset_name:
                download_url = asset["browser_download_url"]
                break
        if download_url is None:
            download_url = (
                f"https://github.com/projectdiscovery/nuclei/releases/download/"
                f"{tag}/{asset_name}"
                if tag
                else f"https://github.com/projectdiscovery/nuclei/releases/latest/download/{_nuclei_asset_name()}"
            )
    except Exception as _api_exc:  # noqa: BLE001
        asset_name = _nuclei_asset_name()
        download_url = (
            f"https://github.com/projectdiscovery/nuclei/releases/latest/download/{asset_name}"
        )

    url = download_url
    typer.echo(f"[bounty tools install-nuclei] Downloading {url}")
    typer.echo(f"  → {install_path}")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / asset_name

            def _report(count: int, block_size: int, total_size: int) -> None:
                if total_size > 0:
                    pct = min(count * block_size * 100 // total_size, 100)
                    typer.echo(f"\r  {pct}%", nl=False)

            urllib.request.urlretrieve(url, str(zip_path), _report)
            typer.echo("")  # newline after progress

            # Extract the 'nuclei' binary from the zip
            with zipfile.ZipFile(str(zip_path), "r") as zf:
                binary_name: str | None = None
                for member in zf.namelist():
                    base = member.rstrip("/").split("/")[-1]
                    if base in ("nuclei", "nuclei.exe"):
                        binary_name = member
                        break

                if binary_name is None:
                    typer.echo(
                        "[error] Could not find 'nuclei' binary in the downloaded archive.",
                        err=True,
                    )
                    raise typer.Exit(1)

                install_path.write_bytes(zf.read(binary_name))

        # chmod +x
        current_mode = install_path.stat().st_mode
        install_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] Download failed: {exc}", err=True)
        typer.echo(
            "\nManual install alternative:\n"
            f"  Download: {url}\n"
            f"  Extract binary to: {install_path}\n"
            "  chmod +x <path>",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(
        f"[bounty tools install-nuclei] ✓ Installed Nuclei at {install_path}"
    )

    if not skip_templates:
        typer.echo("[bounty tools install-nuclei] Fetching nuclei templates…")
        try:
            import subprocess as _subprocess
            result = _subprocess.run(
                [str(install_path), "-update-templates", "-silent"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                typer.echo("[bounty tools install-nuclei] ✓ Templates updated.")
            else:
                typer.echo(
                    f"[warn] Template update exited {result.returncode}: "
                    f"{result.stderr.strip()[:200]}",
                    err=True,
                )
        except Exception as _tmpl_exc:  # noqa: BLE001
            typer.echo(
                f"[warn] Could not update templates: {_tmpl_exc}",
                err=True,
            )


@tools_app.command("update-nuclei-templates")
def update_nuclei_templates_cmd() -> None:
    """Fetch the latest Nuclei community templates.

    Runs ``nuclei -update-templates -silent`` using the installed binary.
    """
    import subprocess as _subprocess
    from bounty.tools import get_nuclei_path

    settings = get_settings()
    nuclei_path = get_nuclei_path(
        Path(str(settings.nuclei_binary_path)).expanduser()
        if settings.nuclei_binary_path
        else None
    )
    if nuclei_path is None:
        typer.echo(
            "[error] Nuclei binary not found. Run: bounty tools install-nuclei",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo("[bounty tools update-nuclei-templates] Updating templates…")
    try:
        result = _subprocess.run(
            [str(nuclei_path), "-update-templates", "-silent"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            typer.echo("[bounty tools update-nuclei-templates] ✓ Templates updated.")
        else:
            typer.echo(
                f"[error] Template update failed (exit {result.returncode}):\n"
                f"{result.stderr.strip()[:500]}",
                err=True,
            )
            raise typer.Exit(1)
    except TimeoutError:
        typer.echo("[error] Template update timed out.", err=True)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# nuclei sub-app
# ---------------------------------------------------------------------------

nuclei_app = typer.Typer(help="Nuclei scanner management commands.")
app.add_typer(nuclei_app, name="nuclei")


@nuclei_app.command("status")
def nuclei_status_cmd() -> None:
    """Show Nuclei version, template count, and last update."""
    import subprocess as _subprocess
    from bounty.tools import get_nuclei_path

    settings = get_settings()
    nuclei_path = get_nuclei_path(
        Path(str(settings.nuclei_binary_path)).expanduser()
        if settings.nuclei_binary_path
        else None
    )

    if nuclei_path is None:
        typer.echo("Nuclei: ✗  not installed  (run: bounty tools install-nuclei)")
        return

    typer.echo(f"Nuclei binary : {nuclei_path}")

    # Version
    try:
        ver = _subprocess.run(
            [str(nuclei_path), "-version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version_line = (ver.stdout + ver.stderr).strip().splitlines()
        typer.echo(f"Version       : {version_line[0] if version_line else 'unknown'}")
    except Exception:  # noqa: BLE001
        typer.echo("Version       : (could not determine)")

    # Template count
    templates_dir = Path.home() / "nuclei-templates"
    if not templates_dir.exists():
        templates_dir = Path.home() / ".nuclei-templates"
    if templates_dir.exists():
        yaml_count = len(list(templates_dir.rglob("*.yaml")))
        typer.echo(f"Templates     : {yaml_count:,} YAML files in {templates_dir}")
    else:
        typer.echo(
            "Templates     : none found  (run: bounty tools update-nuclei-templates)"
        )


# ---------------------------------------------------------------------------
# schedule sub-commands
# ---------------------------------------------------------------------------

schedule_app = typer.Typer(help="Manage recurring scan schedules.")
app.add_typer(schedule_app, name="schedule")


@schedule_app.command("list")
def schedule_list_cmd(
    program: Annotated[str | None, typer.Option("--program", "-p")] = None,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """List all scan schedules."""
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    async def _list() -> list[Any]:
        async with get_conn(db_path) as conn:
            if program:
                cur = await conn.execute(
                    "SELECT * FROM scan_schedules WHERE program_id=? ORDER BY created_at DESC",
                    (program,),
                )
            else:
                cur = await conn.execute(
                    "SELECT * FROM scan_schedules ORDER BY created_at DESC"
                )
            return list(await cur.fetchall())

    try:
        rows = asyncio.run(_list())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not rows:
        typer.echo("No schedules found.")
        return

    header = f"{'ID':<26}  {'NAME':<20}  {'PROGRAM':<25}  {'TRIGGER':<20}  {'INTENSITY':<10}  ENABLED"
    typer.echo(header)
    typer.echo("-" * len(header))
    for row in rows:
        trigger = row["cron_expression"] or f"every {row['interval_minutes']}m"
        enabled = "yes" if row["enabled"] else "no"
        typer.echo(
            f"{row['id']:<26}  {str(row['name'])[:20]:<20}  "
            f"{str(row['program_id'])[:25]:<25}  {trigger[:20]:<20}  "
            f"{str(row['intensity']):<10}  {enabled}"
        )


@schedule_app.command("add")
def schedule_add_cmd(
    program: Annotated[str, typer.Option("--program", "-p", help="Program ID")],
    name: Annotated[str, typer.Option("--name", "-n", help="Schedule name")],
    cron: Annotated[str | None, typer.Option("--cron", help="Cron expression (e.g. '0 * * * *')")] = None,
    interval_minutes: Annotated[int | None, typer.Option("--interval-minutes", help="Run every N minutes")] = None,
    intensity: Annotated[str, typer.Option("--intensity", "-i")] = "gentle",
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Add a new recurring scan schedule."""
    if cron is None and interval_minutes is None:
        typer.echo("[error] Either --cron or --interval-minutes is required.", err=True)
        raise typer.Exit(1)

    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    from bounty.ulid import make_ulid as _ulid
    from datetime import timezone as _tz

    schedule_id = _ulid()
    now = datetime.now(tz=_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    async def _insert() -> None:
        async with get_conn(db_path) as conn:
            await conn.execute(
                """
                INSERT INTO scan_schedules
                    (id, program_id, name, cron_expression, interval_minutes,
                     intensity, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (schedule_id, program, name, cron, interval_minutes, intensity, now, now),
            )
            await conn.commit()

    try:
        asyncio.run(_insert())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    typer.echo(f"[bounty schedule add] created schedule {schedule_id}  ({name})")


@schedule_app.command("rm")
def schedule_rm_cmd(
    schedule_id: Annotated[str, typer.Argument(help="Schedule ID to remove")],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Remove a schedule."""
    settings = get_settings()
    db_path = db or settings.db_path

    async def _delete() -> bool:
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                "DELETE FROM scan_schedules WHERE id=?", (schedule_id,)
            )
            await conn.commit()
            return bool(cur.rowcount and cur.rowcount > 0)

    try:
        ok = asyncio.run(_delete())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not ok:
        typer.echo(f"[error] Schedule {schedule_id!r} not found.", err=True)
        raise typer.Exit(1)
    typer.echo(f"[bounty schedule rm] deleted {schedule_id}")


@schedule_app.command("enable")
def schedule_enable_cmd(
    schedule_id: Annotated[str, typer.Argument()],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Enable a schedule."""
    _set_enabled(schedule_id, True, db)


@schedule_app.command("disable")
def schedule_disable_cmd(
    schedule_id: Annotated[str, typer.Argument()],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Disable a schedule."""
    _set_enabled(schedule_id, False, db)


def _set_enabled(schedule_id: str, enabled: bool, db: Path | None) -> None:
    settings = get_settings()
    db_path = db or settings.db_path

    async def _update() -> bool:
        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                "UPDATE scan_schedules SET enabled=? WHERE id=?",
                (1 if enabled else 0, schedule_id),
            )
            await conn.commit()
            return bool(cur.rowcount and cur.rowcount > 0)

    try:
        ok = asyncio.run(_update())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not ok:
        typer.echo(f"[error] Schedule {schedule_id!r} not found.", err=True)
        raise typer.Exit(1)

    verb = "enabled" if enabled else "disabled"
    typer.echo(f"[bounty schedule {verb}] {schedule_id}")


# ---------------------------------------------------------------------------
# queue sub-commands
# ---------------------------------------------------------------------------

queue_app = typer.Typer(help="Manage the scan queue.")
app.add_typer(queue_app, name="queue")


@queue_app.command("list")
def queue_list_cmd(
    status: Annotated[
        str,
        typer.Option("--status", help="Filter: queued|running|completed|failed|all"),
    ] = "queued,running",
    limit: Annotated[int, typer.Option("--limit")] = 50,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """List scan queue entries showing priority and age."""
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    statuses = [s.strip() for s in status.split(",") if s.strip()] if status != "all" else []

    async def _list() -> list[Any]:
        async with get_conn(db_path) as conn:
            if statuses:
                placeholders = ",".join("?" * len(statuses))
                cur = await conn.execute(
                    f"SELECT * FROM scan_queue WHERE status IN ({placeholders}) "
                    "ORDER BY priority DESC, submitted_at ASC LIMIT ?",
                    [*statuses, limit],
                )
            else:
                cur = await conn.execute(
                    "SELECT * FROM scan_queue ORDER BY priority DESC, submitted_at ASC LIMIT ?",
                    (limit,),
                )
            return list(await cur.fetchall())

    try:
        rows = asyncio.run(_list())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not rows:
        typer.echo("Queue is empty.")
        return

    header = f"{'ID':<26}  {'PROGRAM':<25}  {'STATUS':<10}  {'PRI':>4}  {'RETRIES':>7}  SUBMITTED"
    typer.echo(header)
    typer.echo("-" * len(header))
    for row in rows:
        typer.echo(
            f"{row['id']:<26}  {str(row['program_id'] or '')[:25]:<25}  "
            f"{str(row['status']):<10}  {row['priority']:>4}  "
            f"{row['retry_count']:>7}  {row['submitted_at'] or '—'}"
        )
    typer.echo(f"\n{len(rows)} entries shown.")


@queue_app.command("cancel")
def queue_cancel_cmd(
    entry_id: Annotated[str, typer.Argument(help="Queue entry ID to cancel")],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Cancel a queued or running scan entry."""
    settings = get_settings()
    db_path = db or settings.db_path

    async def _cancel() -> bool:
        from bounty.scheduler import ScanQueue
        q = ScanQueue(db_path)
        return await q.cancel(entry_id)

    try:
        ok = asyncio.run(_cancel())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not ok:
        typer.echo(f"[error] Entry {entry_id!r} not found or already finished.", err=True)
        raise typer.Exit(1)
    typer.echo(f"[bounty queue cancel] {entry_id} → cancelled")


@queue_app.command("retry")
def queue_retry_cmd(
    entry_id: Annotated[str, typer.Argument(help="Failed queue entry ID to re-enqueue")],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Re-enqueue a failed scan entry."""
    settings = get_settings()
    db_path = db or settings.db_path

    async def _retry() -> str | None:
        from bounty.scheduler import ScanQueue
        q = ScanQueue(db_path)
        new = await q.retry(entry_id)
        return new.id if new else None

    try:
        new_id = asyncio.run(_retry())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)

    if not new_id:
        typer.echo(f"[error] Entry {entry_id!r} not found or not in 'failed' state.", err=True)
        raise typer.Exit(1)
    typer.echo(f"[bounty queue retry] {entry_id} → new entry {new_id}")


# ---------------------------------------------------------------------------
# ai sub-commands
# ---------------------------------------------------------------------------

ai_app = typer.Typer(help="AI-powered assistance commands (decorative, operator confirms).")
app.add_typer(ai_app, name="ai")

_SEVERITY_MIN_AI: dict[str, int] = {
    "critical": 800,
    "high": 600,
    "medium": 400,
    "low": 200,
    "info": 0,
}


@ai_app.command("dedup")
def ai_dedup_cmd(
    severity_min: Annotated[
        str | None,
        typer.Option("--severity-min", help="Minimum severity label: critical|high|medium|low|info"),
    ] = None,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Scan all findings for likely duplicates using AI (DECORATIVE — operator confirms).

    Prints suggested merges; never modifies the database automatically.
    """
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    if not settings.ai_enabled:
        typer.echo("[bounty ai dedup] AI is disabled (ai_enabled=False).")
        raise typer.Exit(0)
    if not settings.anthropic_api_key:
        typer.echo("[error] ANTHROPIC_API_KEY is not set.", err=True)
        raise typer.Exit(1)

    sev_floor = _SEVERITY_MIN_AI.get(severity_min or "info", 0) if severity_min else 0

    async def _run() -> None:
        from bounty.ai.dedup import find_duplicate_findings
        from bounty.ai.client import get_client as _get_client
        from bounty.models import Finding as _Finding
        import json as _json

        client = _get_client()

        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM findings WHERE severity >= ? AND status NOT IN "
                "('duplicate','wont_fix','resolved') ORDER BY severity DESC LIMIT 200",
                (sev_floor,),
            )
            rows = list(await cur.fetchall())

        findings_list: list[Any] = []
        for row in rows:
            d = {k: row[k] for k in row.keys()}
            tags_raw = d.get("tags", "[]")
            d["tags"] = _json.loads(tags_raw) if isinstance(tags_raw, str) else tags_raw
            d["validated"] = bool(d.get("validated"))
            findings_list.append(_Finding.model_validate(d))

        if not findings_list:
            typer.echo("[bounty ai dedup] No findings found.")
            return

        typer.echo(f"[bounty ai dedup] Checking {len(findings_list)} findings for duplicates...")
        found_any = False
        for target in findings_list:
            candidates = [f for f in findings_list if f.id != target.id]
            try:
                results = await find_duplicate_findings(target, candidates[:20], client=client)
            except Exception as exc:  # noqa: BLE001
                typer.echo(f"  [warn] Error for {target.id}: {exc}", err=True)
                continue

            high = [(cid, c, r) for cid, c, r in results if c >= 70]
            if high:
                found_any = True
                typer.echo(f"\n  Finding: {str(target.id or '')[:12]}... {target.title[:50]}")
                for cid, conf, reason in high:
                    typer.echo(f"    -> {cid[:12]}... ({conf}% confidence): {reason}")

        if not found_any:
            typer.echo("[bounty ai dedup] No high-confidence duplicates found.")

    try:
        asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)


@ai_app.command("check-severity")
def ai_check_severity_cmd(
    finding_id: Annotated[
        str | None,
        typer.Option("--finding-id", "-f", help="Finding ID (or prefix)"),
    ] = None,
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Review severity of a finding using AI (DECORATIVE - operator confirms).

    Prints suggested severity + rationale. Never modifies the database.
    """
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    if not settings.ai_enabled:
        typer.echo("[bounty ai check-severity] AI is disabled (ai_enabled=False).")
        raise typer.Exit(0)
    if not settings.anthropic_api_key:
        typer.echo("[error] ANTHROPIC_API_KEY is not set.", err=True)
        raise typer.Exit(1)

    async def _run() -> None:
        from bounty.ai.severity_check import review_severity
        from bounty.models import Finding as _Finding, EvidencePackage as _EvidencePkg
        import json as _json

        async with get_conn(db_path) as conn:
            if finding_id:
                cur = await conn.execute(
                    "SELECT * FROM findings WHERE id=? OR id LIKE ? LIMIT 1",
                    (finding_id, finding_id + "%"),
                )
            else:
                cur = await conn.execute(
                    "SELECT * FROM findings ORDER BY severity DESC LIMIT 1"
                )
            row = await cur.fetchone()
            if not row:
                typer.echo("[error] No finding found.", err=True)
                raise typer.Exit(1)

            d = {k: row[k] for k in row.keys()}
            tags_raw = d.get("tags", "[]")
            d["tags"] = _json.loads(tags_raw) if isinstance(tags_raw, str) else tags_raw
            d["validated"] = bool(d.get("validated"))
            finding = _Finding.model_validate(d)

            ev_cur = await conn.execute(
                "SELECT * FROM evidence_packages WHERE finding_id=? LIMIT 3",
                (finding.id,),
            )
            ev_rows = await ev_cur.fetchall()
            evidence = [_EvidencePkg.model_validate({k: r[k] for k in r.keys()}) for r in ev_rows]

        typer.echo(f"[bounty ai check-severity] Finding: {finding.id}")
        typer.echo(f"  Title:    {finding.title}")
        typer.echo(f"  Current:  {finding.severity} ({finding.severity_label})")
        typer.echo("  Asking AI...")

        suggested, rationale = await review_severity(finding, evidence)

        typer.echo("")
        typer.echo("  -- AI Suggestion (DECORATIVE -- not applied) --")
        typer.echo(f"  Suggested severity: {suggested}")
        typer.echo(f"  Rationale: {rationale}")
        typer.echo("")
        typer.echo("  To apply: use the UI 'Apply' button on the finding detail page.")

    try:
        asyncio.run(_run())
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)


@ai_app.command("polish-report")
def ai_polish_report_cmd(
    report_id: Annotated[int, typer.Argument(help="Report ID to polish")],
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Rewrite a report body for clarity using AI (DECORATIVE - operator confirms).

    Prints the polished body to stdout. Never auto-saves to the database.
    """
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    if not settings.ai_enabled:
        typer.echo("[bounty ai polish-report] AI is disabled (ai_enabled=False).")
        raise typer.Exit(0)
    if not settings.anthropic_api_key:
        typer.echo("[error] ANTHROPIC_API_KEY is not set.", err=True)
        raise typer.Exit(1)

    async def _run() -> None:
        from bounty.ai.report_polish import polish_report_body

        async with get_conn(db_path) as conn:
            cur = await conn.execute(
                "SELECT id, body, template FROM reports WHERE id=?", (report_id,)
            )
            row = await cur.fetchone()
            if not row:
                typer.echo(f"[error] Report {report_id} not found.", err=True)
                raise typer.Exit(1)
            body: str = row["body"] or ""
            template: str = row["template"] or "markdown"

        typer.echo(f"[bounty ai polish-report] Report #{report_id}  (template={template})")
        typer.echo("  Asking AI...")
        polished = await polish_report_body(body, template)
        typer.echo("")
        typer.echo("-" * 60)
        typer.echo("  AI-POLISHED BODY (DECORATIVE -- not saved)")
        typer.echo("-" * 60)
        typer.echo(polished)
        typer.echo("-" * 60)
        typer.echo("  To apply: use the UI 'Accept Changes' button on the report page.")

    try:
        asyncio.run(_run())
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)


@ai_app.command("usage")
def ai_usage_cmd(
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Print today's AI request count and estimated cost."""
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)

    async def _run() -> None:
        from bounty.ai.client import get_client as _get_client

        client = _get_client()
        usage = await client.get_today_usage()
        typer.echo(f"[bounty ai usage] date={usage['date']}")
        typer.echo(f"  requests today: {usage['request_count']}")
        typer.echo(f"  cost estimate:  ${usage['cost_estimate']:.6f} USD")
        typer.echo(f"  daily cap:      ${settings.ai_daily_cost_cap_usd:.2f} USD")
        remaining = settings.ai_daily_cost_cap_usd - float(usage["cost_estimate"])
        typer.echo(f"  remaining:      ${max(0.0, remaining):.6f} USD")
        if float(usage["cost_estimate"]) >= settings.ai_daily_cost_cap_usd:
            typer.echo("  WARNING: Daily cap reached -- new AI requests will be refused.")

    try:
        asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[error] {exc}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
