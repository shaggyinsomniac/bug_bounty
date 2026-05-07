"""
bounty.cli — Command-line interface for the bug bounty automation system.

Commands:
  smoke-recon   End-to-end recon sanity check against a target domain.
                Initialises the DB, runs the full recon pipeline, then
                queries the DB to confirm assets were persisted and prints
                a human-readable summary.  Exit 0 on success.

Usage::

    bounty smoke-recon --target hackerone.com
    bounty smoke-recon --target hackerone.com --intensity gentle
    bounty smoke-recon --target hackerone.com --intensity aggressive

Entrypoint is declared in pyproject.toml:

    [project.scripts]
    bounty = "bounty.cli:app"
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

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

log = get_logger(__name__)

_INTENSITY_CHOICES = ("gentle", "normal", "aggressive")


@app.command("init-db")
def init_db_cmd(
    db: Annotated[
        Path | None,
        typer.Option("--db", help="Path to SQLite database (default: data/bounty.db)"),
    ] = None,
) -> None:
    """Initialise (or migrate) the SQLite database.

    Safe to run multiple times — idempotent.
    """
    settings = get_settings()
    db_path = db or settings.db_path
    init_db(db_path)
    apply_migrations(db_path)
    typer.echo(f"[bounty init-db] database ready at {db_path}")


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
    """Run an end-to-end recon sanity check against TARGET.

    Initialises the database, creates a manual program entry for the target,
    runs the recon pipeline (subdomain enumeration via subfinder/crt.sh, DNS
    resolution, HTTP probing), then queries the database to confirm assets
    were actually persisted.

    **Expected output:** 5+ subdomains with HTTP statuses, scan status
    ``completed``.

    **Exit codes:** 0 = success, 1 = failure (pipeline error or no assets
    persisted).

    This command is the canonical "is the system working end-to-end?" check.
    Only scan targets you have explicit authorisation to test.
    """
    if intensity not in _INTENSITY_CHOICES:
        typer.echo(
            f"[error] intensity must be one of: {', '.join(_INTENSITY_CHOICES)}",
            err=True,
        )
        raise typer.Exit(1)

    settings = get_settings()
    db_path = db or settings.db_path

    typer.echo(f"[bounty smoke-recon] target={target}  intensity={intensity}  db={db_path}")

    # Initialise DB (idempotent)
    init_db(db_path)
    apply_migrations(db_path)

    program_id = f"manual:{target}"

    # Upsert a program row for the target
    with get_conn(db_path) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO programs (id, platform, handle, name)
            VALUES (?, 'manual', ?, ?)
            """,
            (program_id, target, target),
        )
        conn.commit()

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
        result = asyncio.run(
            recon_pipeline(
                program_id=program_id,
                targets=targets,
                intensity=intensity,
                db_path=db_path,
                scan_id=scan_id,
            )
        )
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[bounty smoke-recon] pipeline error: {exc}", err=True)
        raise typer.Exit(1)

    # ── Query DB for results ─────────────────────────────────────────────────
    with get_conn(db_path) as conn:
        scan_row = conn.execute(
            "SELECT status, started_at, finished_at, error FROM scans WHERE id=?",
            (scan_id,),
        ).fetchone()

        asset_rows = conn.execute(
            """
            SELECT host, http_status, title, server, url
            FROM assets
            WHERE program_id=?
            ORDER BY http_status ASC, host ASC
            """,
            (program_id,),
        ).fetchall()

        phase_rows = conn.execute(
            "SELECT phase, status FROM scan_phases WHERE scan_id=? ORDER BY phase",
            (scan_id,),
        ).fetchall()

    # ── Print summary ────────────────────────────────────────────────────────
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
    for row in asset_rows[:50]:  # cap output at 50 rows
        status_str = str(row["http_status"]) if row["http_status"] else "---"
        title_str = (row["title"] or "")[:50]
        typer.echo(f"    [{status_str:3s}] {row['host']:<40s}  {title_str}")

    if len(asset_rows) > 50:
        typer.echo(f"    … and {len(asset_rows) - 50} more")

    typer.echo("=" * 70)

    # ── Exit code ────────────────────────────────────────────────────────────
    if not asset_rows:
        typer.echo(
            "\n[bounce smoke-recon] FAIL — no assets persisted to DB.\n"
            "  Check logs for asset_upsert_failed or probe_failed events.\n",
            err=True,
        )
        raise typer.Exit(1)

    if scan_row and scan_row["status"] != "completed":
        typer.echo(
            f"\n[bounty smoke-recon] WARN — scan status is '{scan_row['status']}' (expected 'completed').\n",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(f"\n[bounty smoke-recon] OK — {len(asset_rows)} asset(s) persisted, scan completed.\n")


if __name__ == "__main__":
    app()


