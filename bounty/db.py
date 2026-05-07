"""
bounty.db — SQLite schema, migrations, and connection management.

Design decisions:
- Raw SQL only (no ORM) for transparency and minimal dependencies.
- WAL journal mode for concurrent read/write from the UI and background workers.
- ``get_conn()`` is an async context manager that yields a synchronous
  ``sqlite3.Connection``; all DB calls are wrapped with
  ``asyncio.to_thread()`` at the call site to avoid blocking the event loop.
- Migrations are forward-only, keyed by an integer version stored in
  ``PRAGMA user_version``.  Run ``apply_migrations()`` on startup.
- Foreign keys are enabled per-connection.

Schema overview:
  programs            — HackerOne / Bugcrowd / Intigriti / manual programs
  targets             — scope rules (wildcards, domains, IP ranges) per program
  assets              — discovered live hosts / URLs
  asset_history       — change log for assets (redirect chain changes, etc.)
  fingerprints        — technology detections per asset
  scans               — scan job records
  scan_phases         — recon / fingerprint / detect phases within a scan
  findings            — validated misconfigurations / vulnerabilities
  evidence_packages   — request/response + screenshot blobs per finding
  secrets_validations — token validation results (live / invalid / error)
  reports             — draft/submitted reports per finding
  audit_log           — immutable operation log (single-user audit trail)
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from bounty import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Schema — each string is one DDL statement executed in order.
# ---------------------------------------------------------------------------

_SCHEMA: list[str] = [
    # ------------------------------------------------------------------
    # programs
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS programs (
        id          TEXT PRIMARY KEY,          -- stable slug, e.g. "h1:shopify"
        platform    TEXT NOT NULL,             -- h1 | bugcrowd | intigriti | manual
        handle      TEXT NOT NULL,             -- platform-specific handle / slug
        name        TEXT NOT NULL,
        url         TEXT NOT NULL DEFAULT '',
        policy_url  TEXT NOT NULL DEFAULT '',
        bounty_table TEXT,                     -- JSON blob: {severity: max_bounty}
        active      INTEGER NOT NULL DEFAULT 1,-- 1 = in scope, 0 = archived
        created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    # ------------------------------------------------------------------
    # targets (scope rules)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS targets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id  TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
        scope_type  TEXT NOT NULL,  -- in_scope | out_of_scope
        asset_type  TEXT NOT NULL,  -- url | wildcard | cidr | android | ios | other
        value       TEXT NOT NULL,  -- e.g. "*.example.com" or "10.0.0.0/8"
        max_severity TEXT,          -- optional ceiling for this scope entry
        notes       TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_targets_program ON targets(program_id)",
    # ------------------------------------------------------------------
    # assets
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS assets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id  TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
        host        TEXT NOT NULL,  -- FQDN or IP
        port        INTEGER,        -- NULL = default for scheme
        scheme      TEXT NOT NULL DEFAULT 'https',
        url         TEXT NOT NULL,  -- canonical URL (scheme://host[:port])
        ip          TEXT,           -- resolved IP at last probe time
        status      TEXT NOT NULL DEFAULT 'discovered',
        -- discovered | alive | dead | out_of_scope
        http_status INTEGER,
        title       TEXT,
        server      TEXT,
        cdn         TEXT,
        waf         TEXT,
        tls_issuer  TEXT,
        tls_expiry  TEXT,
        tags        TEXT NOT NULL DEFAULT '[]',  -- JSON array of strings
        last_seen   TEXT,
        first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        UNIQUE(program_id, url)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program_id)",
    "CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host)",
    # ------------------------------------------------------------------
    # asset_history
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS asset_history (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        field      TEXT NOT NULL,   -- which field changed
        old_value  TEXT,
        new_value  TEXT,
        changed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_asset_history_asset ON asset_history(asset_id)",
    # ------------------------------------------------------------------
    # fingerprints
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS fingerprints (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        tech       TEXT NOT NULL,    -- e.g. "WordPress", "nginx", "React"
        version    TEXT,
        category   TEXT NOT NULL DEFAULT 'other',
        -- web-server | cms | framework | language | cdn | waf | other
        evidence   TEXT NOT NULL DEFAULT '',  -- short human note on *how* detected
        confidence INTEGER NOT NULL DEFAULT 50,  -- 0-100
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_fingerprints_asset ON fingerprints(asset_id)",
    # ------------------------------------------------------------------
    # scans
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id  TEXT REFERENCES programs(id) ON DELETE SET NULL,
        asset_id    INTEGER REFERENCES assets(id) ON DELETE SET NULL,
        scan_type   TEXT NOT NULL DEFAULT 'full',
        -- full | recon | detect | validate | custom
        status      TEXT NOT NULL DEFAULT 'queued',
        -- queued | running | completed | failed | cancelled
        intensity   TEXT NOT NULL DEFAULT 'normal',
        triggered_by TEXT NOT NULL DEFAULT 'scheduler',
        -- scheduler | ui | cli
        started_at  TEXT,
        finished_at TEXT,
        finding_count INTEGER NOT NULL DEFAULT 0,
        error       TEXT,
        meta        TEXT NOT NULL DEFAULT '{}',  -- JSON blob for extra data
        created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_scans_program ON scans(program_id)",
    "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
    # ------------------------------------------------------------------
    # scan_phases
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS scan_phases (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        phase       TEXT NOT NULL,   -- recon | fingerprint | detect | validate
        status      TEXT NOT NULL DEFAULT 'pending',
        started_at  TEXT,
        finished_at TEXT,
        detail      TEXT NOT NULL DEFAULT '{}'  -- JSON progress blob
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_scan_phases_scan ON scan_phases(scan_id)",
    # ------------------------------------------------------------------
    # findings
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS findings (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id      TEXT REFERENCES programs(id) ON DELETE SET NULL,
        asset_id        INTEGER REFERENCES assets(id) ON DELETE SET NULL,
        scan_id         INTEGER REFERENCES scans(id) ON DELETE SET NULL,
        dedup_key       TEXT NOT NULL UNIQUE,  -- stable hash for deduplication
        title           TEXT NOT NULL,
        category        TEXT NOT NULL,  -- matches corpus category slugs
        severity        INTEGER NOT NULL DEFAULT 500,  -- 0-1000
        severity_label  TEXT NOT NULL DEFAULT 'medium',
        -- critical | high | medium | low | info
        status          TEXT NOT NULL DEFAULT 'new',
        -- new | triaged | reported | accepted | duplicate | wont_fix | resolved
        url             TEXT NOT NULL,
        path            TEXT NOT NULL DEFAULT '',
        description     TEXT NOT NULL DEFAULT '',
        remediation     TEXT NOT NULL DEFAULT '',
        cvss_score      REAL,
        cve             TEXT,
        cwe             TEXT,
        validated       INTEGER NOT NULL DEFAULT 0,  -- boolean
        validated_at    TEXT,
        tags            TEXT NOT NULL DEFAULT '[]',  -- JSON array
        created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
    "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)",
    "CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(dedup_key)",
    # ------------------------------------------------------------------
    # evidence_packages
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS evidence_packages (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id      INTEGER REFERENCES findings(id) ON DELETE SET NULL,
        secret_val_id   INTEGER REFERENCES secrets_validations(id) ON DELETE SET NULL,
        kind            TEXT NOT NULL DEFAULT 'http',  -- http | screenshot | log
        request_raw     TEXT,   -- full HTTP request as text
        response_raw    TEXT,   -- full HTTP response headers + body snippet
        response_status INTEGER,
        response_body_path TEXT, -- path under data/evidence/ for large bodies
        screenshot_path TEXT,    -- path under data/evidence/ for PNG
        curl_cmd        TEXT,    -- reproducible curl command
        notes           TEXT NOT NULL DEFAULT '',
        captured_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence_packages(finding_id)",
    # ------------------------------------------------------------------
    # secrets_validations
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS secrets_validations (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id        INTEGER REFERENCES assets(id) ON DELETE SET NULL,
        finding_id      INTEGER REFERENCES findings(id) ON DELETE SET NULL,
        provider        TEXT NOT NULL,   -- e.g. "aws", "stripe", "github"
        secret_hash     TEXT NOT NULL,   -- SHA-256 of the raw secret value
        secret_preview  TEXT NOT NULL,   -- first 8 chars + "…" for display
        secret_pattern  TEXT NOT NULL,   -- regex name that matched
        status          TEXT NOT NULL DEFAULT 'pending',
        -- pending | live | invalid | error | revoked
        scope           TEXT,            -- JSON blob: permissions/scopes if live
        identity        TEXT,            -- account/user id from validation call
        last_checked    TEXT,
        next_check      TEXT,
        error_message   TEXT,
        created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        UNIQUE(secret_hash, provider)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_secrets_status ON secrets_validations(status)",
    "CREATE INDEX IF NOT EXISTS idx_secrets_provider ON secrets_validations(provider)",
    # ------------------------------------------------------------------
    # reports
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS reports (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        platform    TEXT NOT NULL,   -- h1 | bugcrowd | intigriti | generic
        status      TEXT NOT NULL DEFAULT 'draft',
        -- draft | submitted | accepted | closed
        title       TEXT NOT NULL,
        body        TEXT NOT NULL,   -- rendered Markdown
        submitted_at TEXT,
        platform_id TEXT,            -- e.g. H1 report #12345
        bounty_usd  REAL,
        notes       TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_reports_finding ON reports(finding_id)",
    # ------------------------------------------------------------------
    # audit_log
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        operation   TEXT NOT NULL,   -- e.g. "scan.start", "finding.status_change"
        entity_type TEXT,
        entity_id   TEXT,
        detail      TEXT NOT NULL DEFAULT '{}',  -- JSON blob
        ts          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)",
    "CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_log(operation)",
]

# ---------------------------------------------------------------------------
# Migrations list — append new SQL strings here; never edit existing entries.
# ---------------------------------------------------------------------------

_MIGRATIONS: list[str] = [
    # v1 → initial schema (all tables above)
    # Applied via init_db(); nothing additional required for v1.
    # Future migrations go here as plain SQL strings.
]


def init_db(db_path: Path) -> None:
    """Create the database and apply the baseline schema.

    Idempotent: safe to call on an existing database.  Uses WAL mode and
    sets ``PRAGMA foreign_keys = ON`` and ``PRAGMA journal_mode = WAL``.

    Args:
        db_path: Filesystem path to the SQLite database file.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA mmap_size = 134217728")  # 128 MiB

        for stmt in _SCHEMA:
            stmt = stmt.strip()
            if stmt:
                conn.execute(stmt)

        conn.commit()
        log.info("database_initialised", path=str(db_path))
    finally:
        conn.close()


def apply_migrations(db_path: Path) -> None:
    """Run any pending forward-only migrations.

    The current schema version is stored in ``PRAGMA user_version``.  Each
    entry in ``_MIGRATIONS`` increments the version by 1.

    Args:
        db_path: Filesystem path to the SQLite database file.
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        row = conn.execute("PRAGMA user_version").fetchone()
        current_version: int = row[0] if row else 0
        for idx, migration_sql in enumerate(_MIGRATIONS):
            migration_version = idx + 1
            if current_version >= migration_version:
                continue
            log.info(
                "applying_migration",
                version=migration_version,
                path=str(db_path),
            )
            conn.executescript(migration_sql)
            conn.execute(f"PRAGMA user_version = {migration_version}")
            conn.commit()
            current_version = migration_version
    finally:
        conn.close()


@contextmanager
def get_conn(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """Context manager that yields a configured ``sqlite3.Connection``.

    The connection enables row factory (``sqlite3.Row``) so columns can be
    accessed by name.  Foreign keys are enforced.  The caller is responsible
    for committing; the context manager rolls back on exception.

    Usage::

        from bounty.db import get_conn
        from bounty.config import get_settings

        with get_conn(get_settings().db_path) as conn:
            row = conn.execute("SELECT * FROM programs WHERE id = ?", (pid,)).fetchone()

    Args:
        db_path: Path to the SQLite database file.

    Yields:
        An open ``sqlite3.Connection``.

    Raises:
        sqlite3.Error: On any database error (after rollback).
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

