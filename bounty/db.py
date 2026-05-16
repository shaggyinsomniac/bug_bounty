"""
bounty.db — SQLite schema, migrations, and connection management.

Design decisions:
- Raw SQL only (no ORM) for transparency and minimal dependencies.
- WAL journal mode for concurrent read/write from the UI and background workers.
- ``get_conn()`` is an ``@asynccontextmanager`` that yields an
  ``aiosqlite.Connection``; all DB calls are awaited directly without any
  ``asyncio.to_thread()`` wrappers.
- ``init_db()`` and ``apply_migrations()`` remain synchronous — they run once
  at startup before the event loop starts and use the raw ``sqlite3`` module.
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
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

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
        id          TEXT PRIMARY KEY,
        program_id  TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
        host        TEXT NOT NULL,  -- FQDN or IP
        port        INTEGER,        -- NULL = default for scheme (80/443 omitted)
        scheme      TEXT NOT NULL DEFAULT 'https',
        url         TEXT NOT NULL,  -- canonical URL (primary_scheme://host[:port])
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
        tags        TEXT NOT NULL DEFAULT '[]',      -- JSON array of strings
        seen_protocols TEXT NOT NULL DEFAULT '[]',   -- JSON array of observed schemes
        primary_scheme TEXT NOT NULL DEFAULT 'https',-- preferred scheme for canonical URL
        last_seen   TEXT,
        first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        -- Uniqueness enforced via partial indexes: idx_assets_unique_base / idx_assets_unique_port
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program_id)",
    "CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host)",
    # NOTE: The partial unique indexes (idx_assets_unique_base / idx_assets_unique_port)
    # are NOT created here because init_db runs on both fresh and existing databases.
    # On existing pre-V3 databases the data has not been deduplicated yet and the unique
    # index creation would fail with IntegrityError.  The indexes are created by
    # _recreate_indexes() after migration V3 has collapsed http/https duplicates.
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
        id         TEXT PRIMARY KEY,
        asset_id   TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        tech       TEXT NOT NULL,    -- e.g. "WordPress", "nginx", "React"
        version    TEXT,
        category   TEXT NOT NULL DEFAULT 'other',
        -- web-server | cms | framework | language | cdn | waf | other
        evidence   TEXT NOT NULL DEFAULT '',  -- structured "source:key=value" per P5
        confidence TEXT NOT NULL DEFAULT 'weak',  -- definitive | strong | weak | hint
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_fingerprints_asset ON fingerprints(asset_id)",
    "CREATE INDEX IF NOT EXISTS idx_fingerprints_tech ON fingerprints(tech)",
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
        id              TEXT PRIMARY KEY,
        program_id      TEXT REFERENCES programs(id) ON DELETE SET NULL,
        asset_id        TEXT REFERENCES assets(id) ON DELETE SET NULL,
        scan_id         TEXT REFERENCES scans(id) ON DELETE SET NULL,
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
        id              TEXT PRIMARY KEY,
        finding_id      TEXT REFERENCES findings(id) ON DELETE SET NULL,
        secret_val_id   TEXT REFERENCES secrets_validations(id) ON DELETE SET NULL,
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
        asset_id        TEXT REFERENCES assets(id) ON DELETE SET NULL,
        finding_id      TEXT REFERENCES findings(id) ON DELETE SET NULL,
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
        finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
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
    # ------------------------------------------------------------------
    # leads  (intel / Shodan triage)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS leads (
        id            TEXT PRIMARY KEY,
        source        TEXT NOT NULL DEFAULT 'shodan',
        source_query  TEXT,
        ip            TEXT NOT NULL,
        port          INTEGER,
        hostnames     TEXT NOT NULL DEFAULT '[]',
        org           TEXT,
        asn           TEXT,
        product       TEXT,
        title         TEXT,
        raw_data      TEXT NOT NULL DEFAULT '{}',
        program_id    TEXT REFERENCES programs(id) ON DELETE SET NULL,
        status        TEXT NOT NULL DEFAULT 'new',
        discovered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
        UNIQUE(source, ip, port)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status)",
    "CREATE INDEX IF NOT EXISTS idx_leads_program ON leads(program_id)",
    # ------------------------------------------------------------------
    # scan_errors  (Phase 17 — operator error visibility)
    # scan_id is intentionally NOT a FK so errors can be recorded for
    # arbitrary / orphaned scan IDs without constraint violations.
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS scan_errors (
        id             TEXT PRIMARY KEY,
        scan_id        TEXT,
        asset_id       TEXT,
        detection_id   TEXT,
        kind           TEXT NOT NULL DEFAULT 'other',
        exception_type TEXT,
        message        TEXT,
        traceback      TEXT,
        created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_scan_errors_scan    ON scan_errors(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_errors_kind    ON scan_errors(kind)",
    "CREATE INDEX IF NOT EXISTS idx_scan_errors_created ON scan_errors(created_at DESC)",
]

# ---------------------------------------------------------------------------
# Migrations list — append new SQL strings here; never edit existing entries.
# ---------------------------------------------------------------------------

# v1 migration: convert INTEGER PRIMARY KEY ids to TEXT (ULID-compatible).
# Uses the SQLite rename-table-and-copy pattern because ALTER COLUMN is
# not supported.  Safe to run on a DB with 1 row in programs and no other
# data.  Wrapped in BEGIN/COMMIT so it either fully applies or rolls back.
_MIGRATION_V1 = """
BEGIN TRANSACTION;

CREATE TABLE assets_new (
    id          TEXT PRIMARY KEY,
    program_id  TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    host        TEXT NOT NULL,
    port        INTEGER,
    scheme      TEXT NOT NULL DEFAULT 'https',
    url         TEXT NOT NULL,
    ip          TEXT,
    status      TEXT NOT NULL DEFAULT 'discovered',
    http_status INTEGER,
    title       TEXT,
    server      TEXT,
    cdn         TEXT,
    waf         TEXT,
    tls_issuer  TEXT,
    tls_expiry  TEXT,
    tags        TEXT NOT NULL DEFAULT '[]',
    last_seen   TEXT,
    first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(program_id, url)
);
INSERT INTO assets_new
    SELECT CAST(id AS TEXT), program_id, host, port, scheme, url, ip, status,
           http_status, title, server, cdn, waf, tls_issuer, tls_expiry, tags,
           last_seen, first_seen, created_at, updated_at FROM assets;
DROP TABLE assets;
ALTER TABLE assets_new RENAME TO assets;

CREATE TABLE asset_history_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    field      TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT,
    changed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO asset_history_new
    SELECT id, CAST(asset_id AS TEXT), field, old_value, new_value, changed_at
    FROM asset_history;
DROP TABLE asset_history;
ALTER TABLE asset_history_new RENAME TO asset_history;

CREATE TABLE fingerprints_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id   TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tech       TEXT NOT NULL,
    version    TEXT,
    category   TEXT NOT NULL DEFAULT 'other',
    evidence   TEXT NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 50,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO fingerprints_new
    SELECT id, CAST(asset_id AS TEXT), tech, version, category, evidence,
           confidence, created_at FROM fingerprints;
DROP TABLE fingerprints;
ALTER TABLE fingerprints_new RENAME TO fingerprints;

CREATE TABLE scans_new (
    id           TEXT PRIMARY KEY,
    program_id   TEXT REFERENCES programs(id) ON DELETE SET NULL,
    asset_id     TEXT REFERENCES assets(id) ON DELETE SET NULL,
    scan_type    TEXT NOT NULL DEFAULT 'full',
    status       TEXT NOT NULL DEFAULT 'queued',
    intensity    TEXT NOT NULL DEFAULT 'normal',
    triggered_by TEXT NOT NULL DEFAULT 'scheduler',
    started_at   TEXT,
    finished_at  TEXT,
    finding_count INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    meta         TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO scans_new
    SELECT CAST(id AS TEXT), program_id, CAST(asset_id AS TEXT), scan_type,
           status, intensity, triggered_by, started_at, finished_at,
           finding_count, error, meta, created_at FROM scans;
DROP TABLE scans;
ALTER TABLE scans_new RENAME TO scans;

CREATE TABLE scan_phases_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    phase       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    started_at  TEXT,
    finished_at TEXT,
    detail      TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO scan_phases_new
    SELECT id, CAST(scan_id AS TEXT), phase, status, started_at, finished_at,
           detail FROM scan_phases;
DROP TABLE scan_phases;
ALTER TABLE scan_phases_new RENAME TO scan_phases;

CREATE TABLE findings_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id      TEXT REFERENCES programs(id) ON DELETE SET NULL,
    asset_id        TEXT REFERENCES assets(id) ON DELETE SET NULL,
    scan_id         TEXT REFERENCES scans(id) ON DELETE SET NULL,
    dedup_key       TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        INTEGER NOT NULL DEFAULT 500,
    severity_label  TEXT NOT NULL DEFAULT 'medium',
    status          TEXT NOT NULL DEFAULT 'new',
    url             TEXT NOT NULL,
    path            TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    cvss_score      REAL,
    cve             TEXT,
    cwe             TEXT,
    validated       INTEGER NOT NULL DEFAULT 0,
    validated_at    TEXT,
    tags            TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO findings_new
    SELECT id, program_id, CAST(asset_id AS TEXT), CAST(scan_id AS TEXT),
           dedup_key, title, category, severity, severity_label, status, url,
           path, description, remediation, cvss_score, cve, cwe, validated,
           validated_at, tags, created_at, updated_at FROM findings;
DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;

CREATE TABLE secrets_validations_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        TEXT REFERENCES assets(id) ON DELETE SET NULL,
    finding_id      INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    provider        TEXT NOT NULL,
    secret_hash     TEXT NOT NULL,
    secret_preview  TEXT NOT NULL,
    secret_pattern  TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    scope           TEXT,
    identity        TEXT,
    last_checked    TEXT,
    next_check      TEXT,
    error_message   TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(secret_hash, provider)
);
INSERT INTO secrets_validations_new
    SELECT id, CAST(asset_id AS TEXT), finding_id, provider, secret_hash,
           secret_preview, secret_pattern, status, scope, identity,
           last_checked, next_check, error_message, created_at, updated_at
    FROM secrets_validations;
DROP TABLE secrets_validations;
ALTER TABLE secrets_validations_new RENAME TO secrets_validations;

COMMIT;
"""

_MIGRATION_V2 = """
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS leads (
    id            TEXT PRIMARY KEY,
    source        TEXT NOT NULL DEFAULT 'shodan',
    source_query  TEXT,
    ip            TEXT NOT NULL,
    port          INTEGER,
    hostnames     TEXT NOT NULL DEFAULT '[]',
    org           TEXT,
    asn           TEXT,
    product       TEXT,
    title         TEXT,
    raw_data      TEXT NOT NULL DEFAULT '{}',
    program_id    TEXT REFERENCES programs(id) ON DELETE SET NULL,
    status        TEXT NOT NULL DEFAULT 'new',
    discovered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(source, ip, port)
);

COMMIT;
"""

# v3 migration: collapse http/https duplicates, add seen_protocols + primary_scheme columns,
# and replace UNIQUE(program_id, url) with partial unique indexes on (program_id, host[, port]).
# The partial-index approach is required because NULL != NULL in SQLite UNIQUE constraints.
_MIGRATION_V3 = """BEGIN TRANSACTION;

CREATE TABLE assets_new (
    id          TEXT PRIMARY KEY,
    program_id  TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    host        TEXT NOT NULL,
    port        INTEGER,
    scheme      TEXT NOT NULL DEFAULT 'https',
    url         TEXT NOT NULL,
    ip          TEXT,
    status      TEXT NOT NULL DEFAULT 'discovered',
    http_status INTEGER,
    title       TEXT,
    server      TEXT,
    cdn         TEXT,
    waf         TEXT,
    tls_issuer  TEXT,
    tls_expiry  TEXT,
    tags        TEXT NOT NULL DEFAULT '[]',
    seen_protocols TEXT NOT NULL DEFAULT '[]',
    primary_scheme TEXT NOT NULL DEFAULT 'https',
    last_seen   TEXT,
    first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO assets_new
    (id, program_id, host, port, scheme, url, ip, status, http_status, title,
     server, cdn, waf, tls_issuer, tls_expiry, tags, seen_protocols, primary_scheme,
     last_seen, first_seen, created_at, updated_at)
SELECT
    a.id,
    a.program_id,
    a.host,
    a.port,
    CASE WHEN (SELECT COUNT(*) FROM assets s WHERE s.program_id=a.program_id AND s.host=a.host AND COALESCE(s.port,-1)=COALESCE(a.port,-1) AND s.scheme='https') > 0 THEN 'https' ELSE 'http' END,
    CASE WHEN (SELECT COUNT(*) FROM assets s WHERE s.program_id=a.program_id AND s.host=a.host AND COALESCE(s.port,-1)=COALESCE(a.port,-1) AND s.scheme='https') > 0
         THEN CASE WHEN a.port IS NULL THEN 'https://' || a.host ELSE 'https://' || a.host || ':' || a.port END
         ELSE CASE WHEN a.port IS NULL THEN 'http://'  || a.host ELSE 'http://'  || a.host || ':' || a.port END
    END,
    a.ip, a.status, a.http_status, a.title,
    a.server, a.cdn, a.waf, a.tls_issuer, a.tls_expiry, a.tags,
    '[' || (SELECT GROUP_CONCAT('"' || qs.s || '"') FROM (SELECT DISTINCT scheme AS s FROM assets q WHERE q.program_id=a.program_id AND q.host=a.host AND COALESCE(q.port,-1)=COALESCE(a.port,-1) ORDER BY scheme) qs) || ']',
    CASE WHEN (SELECT COUNT(*) FROM assets s WHERE s.program_id=a.program_id AND s.host=a.host AND COALESCE(s.port,-1)=COALESCE(a.port,-1) AND s.scheme='https') > 0 THEN 'https' ELSE 'http' END,
    a.last_seen, a.first_seen, a.created_at, a.updated_at
FROM assets a
WHERE a.id = (
    SELECT w.id FROM assets w
    WHERE w.program_id=a.program_id AND w.host=a.host AND COALESCE(w.port,-1)=COALESCE(a.port,-1)
    ORDER BY
        CASE WHEN w.http_status IS NOT NULL AND w.http_status < 400 THEN 0 ELSE 1 END ASC,
        w.scheme DESC
    LIMIT 1
);

DELETE FROM asset_history WHERE asset_id NOT IN (SELECT id FROM assets_new);
DELETE FROM fingerprints WHERE asset_id NOT IN (SELECT id FROM assets_new);
DROP TABLE assets;
ALTER TABLE assets_new RENAME TO assets;

COMMIT;
"""

_MIGRATION_V4 = """
BEGIN TRANSACTION;

CREATE TABLE fingerprints_new (
    id         TEXT PRIMARY KEY,
    asset_id   TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tech       TEXT NOT NULL,
    version    TEXT,
    category   TEXT NOT NULL DEFAULT 'other',
    evidence   TEXT NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 50,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO fingerprints_new
    SELECT CAST(id AS TEXT), asset_id, tech, version, category, evidence,
           confidence, created_at FROM fingerprints;
DROP TABLE fingerprints;
ALTER TABLE fingerprints_new RENAME TO fingerprints;

COMMIT;
"""

_MIGRATION_V5 = """
BEGIN TRANSACTION;

CREATE TABLE fingerprints_v5 (
    id         TEXT PRIMARY KEY,
    asset_id   TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tech       TEXT NOT NULL,
    version    TEXT,
    category   TEXT NOT NULL DEFAULT 'other',
    evidence   TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'weak',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO fingerprints_v5
    SELECT id, asset_id, tech, version, category, evidence,
        CASE
            WHEN typeof(confidence) = 'text' THEN confidence
            WHEN CAST(confidence AS INTEGER) >= 90 THEN 'definitive'
            WHEN CAST(confidence AS INTEGER) >= 75 THEN 'strong'
            WHEN CAST(confidence AS INTEGER) >= 50 THEN 'weak'
            ELSE 'hint'
        END,
        created_at
    FROM fingerprints;

DROP TABLE fingerprints;
ALTER TABLE fingerprints_v5 RENAME TO fingerprints;

COMMIT;
"""

_MIGRATION_V6 = """
BEGIN TRANSACTION;

-- Recreate findings with TEXT id (convert existing INTEGER ids via CAST).
CREATE TABLE findings_v6 (
    id              TEXT PRIMARY KEY,
    program_id      TEXT REFERENCES programs(id) ON DELETE SET NULL,
    asset_id        TEXT REFERENCES assets(id) ON DELETE SET NULL,
    scan_id         TEXT REFERENCES scans(id) ON DELETE SET NULL,
    dedup_key       TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        INTEGER NOT NULL DEFAULT 500,
    severity_label  TEXT NOT NULL DEFAULT 'medium',
    status          TEXT NOT NULL DEFAULT 'new',
    url             TEXT NOT NULL,
    path            TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    cvss_score      REAL,
    cve             TEXT,
    cwe             TEXT,
    validated       INTEGER NOT NULL DEFAULT 0,
    validated_at    TEXT,
    tags            TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO findings_v6
    SELECT CAST(id AS TEXT), program_id, asset_id, scan_id, dedup_key, title,
           category, severity, severity_label, status, url, path, description,
           remediation, cvss_score, cve, cwe, validated, validated_at, tags,
           created_at, updated_at
    FROM findings;

-- Recreate evidence_packages with TEXT id and updated FKs.
CREATE TABLE evidence_packages_v6 (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT REFERENCES findings_v6(id) ON DELETE SET NULL,
    secret_val_id   TEXT REFERENCES secrets_validations(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL DEFAULT 'http',
    request_raw     TEXT,
    response_raw    TEXT,
    response_status INTEGER,
    response_body_path TEXT,
    screenshot_path TEXT,
    curl_cmd        TEXT,
    notes           TEXT NOT NULL DEFAULT '',
    captured_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO evidence_packages_v6
    SELECT CAST(id AS TEXT), CAST(finding_id AS TEXT), CAST(secret_val_id AS TEXT),
           kind, request_raw, response_raw, response_status, response_body_path,
           screenshot_path, curl_cmd, notes, captured_at
    FROM evidence_packages;

-- Recreate reports with updated finding_id FK (TEXT).
CREATE TABLE reports_v6 (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL REFERENCES findings_v6(id) ON DELETE CASCADE,
    platform    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'draft',
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    submitted_at TEXT,
    platform_id TEXT,
    bounty_usd  REAL,
    notes       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT INTO reports_v6
    SELECT id, CAST(finding_id AS TEXT), platform, status, title, body,
           submitted_at, platform_id, bounty_usd, notes, created_at, updated_at
    FROM reports;

-- Recreate secrets_validations with updated finding_id FK (TEXT).
CREATE TABLE secrets_validations_v6 (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        TEXT REFERENCES assets(id) ON DELETE SET NULL,
    finding_id      TEXT REFERENCES findings_v6(id) ON DELETE SET NULL,
    provider        TEXT NOT NULL,
    secret_hash     TEXT NOT NULL,
    secret_preview  TEXT NOT NULL,
    secret_pattern  TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    scope           TEXT,
    identity        TEXT,
    last_checked    TEXT,
    next_check      TEXT,
    error_message   TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(secret_hash, provider)
);
INSERT INTO secrets_validations_v6
    SELECT id, asset_id, CAST(finding_id AS TEXT), provider, secret_hash,
           secret_preview, secret_pattern, status, scope, identity,
           last_checked, next_check, error_message, created_at, updated_at
    FROM secrets_validations;

DROP TABLE reports;
ALTER TABLE reports_v6 RENAME TO reports;

DROP TABLE evidence_packages;
ALTER TABLE evidence_packages_v6 RENAME TO evidence_packages;

DROP TABLE findings;
ALTER TABLE findings_v6 RENAME TO findings;

DROP TABLE secrets_validations;
ALTER TABLE secrets_validations_v6 RENAME TO secrets_validations;

COMMIT;
"""

_MIGRATION_V7 = """
BEGIN TRANSACTION;

-- Convert secrets_validations.id from INTEGER AUTOINCREMENT to TEXT (ULID).
-- Existing rows get CAST(id AS TEXT) IDs; new rows will receive real ULIDs
-- from application code.
CREATE TABLE secrets_validations_v7 (
    id              TEXT PRIMARY KEY,
    asset_id        TEXT REFERENCES assets(id) ON DELETE SET NULL,
    finding_id      TEXT REFERENCES findings(id) ON DELETE SET NULL,
    provider        TEXT NOT NULL,
    secret_hash     TEXT NOT NULL,
    secret_preview  TEXT NOT NULL,
    secret_pattern  TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    scope           TEXT,
    identity        TEXT,
    last_checked    TEXT,
    next_check      TEXT,
    error_message   TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(secret_hash, provider)
);

INSERT INTO secrets_validations_v7
    SELECT CAST(id AS TEXT), asset_id, finding_id, provider, secret_hash,
           secret_preview, secret_pattern, status, scope, identity,
           last_checked, next_check, error_message, created_at, updated_at
    FROM secrets_validations;

-- evidence_packages.secret_val_id already TEXT; FK target changes to same table name.
DROP TABLE secrets_validations;
ALTER TABLE secrets_validations_v7 RENAME TO secrets_validations;

COMMIT;
"""

_MIGRATION_V8 = """
BEGIN TRANSACTION;

-- Recreate reports with new multi-finding schema.
-- Old schema: finding_id (single TEXT), platform, status (draft/submitted/accepted/closed)
-- New schema: program_id, finding_ids (JSON array), template, status (draft/sent/accepted/rejected),
--             platform_submission_id, sent_at
CREATE TABLE reports_v8 (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id              TEXT REFERENCES programs(id) ON DELETE SET NULL,
    finding_ids             TEXT NOT NULL DEFAULT '[]',
    title                   TEXT NOT NULL DEFAULT '',
    template                TEXT NOT NULL DEFAULT 'markdown',
    body                    TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'draft',
    platform_submission_id  TEXT,
    sent_at                 TEXT,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO reports_v8 (id, finding_ids, title, template, body, status, sent_at, created_at, updated_at)
    SELECT
        id,
        '["' || finding_id || '"]',
        COALESCE(title, ''),
        CASE platform
            WHEN 'h1' THEN 'h1'
            WHEN 'bugcrowd' THEN 'bugcrowd'
            ELSE 'markdown'
        END,
        COALESCE(body, ''),
        CASE status
            WHEN 'submitted' THEN 'sent'
            WHEN 'accepted' THEN 'accepted'
            WHEN 'closed' THEN 'rejected'
            ELSE 'draft'
        END,
        submitted_at,
        created_at,
        updated_at
    FROM reports;

DROP TABLE reports;
ALTER TABLE reports_v8 RENAME TO reports;

COMMIT;
"""

# v9 migration: add source column to secrets_validations.
# 'native' = detected by bounty's own scanner/validators.
# 'trufflehog' = detected by the TruffleHog subprocess (Phase 14a).
_MIGRATION_V9 = """
BEGIN TRANSACTION;

ALTER TABLE secrets_validations ADD COLUMN source TEXT NOT NULL DEFAULT 'native';

COMMIT;
"""

# v10 migration (Phase 14b): add source column to findings.
# 'native'  = detected by bounty's own Detection classes.
# 'nuclei'  = detected by the Nuclei subprocess scanner.
_MIGRATION_V10 = """
BEGIN TRANSACTION;

ALTER TABLE findings ADD COLUMN source TEXT NOT NULL DEFAULT 'native';

COMMIT;
"""

_MIGRATION_V11 = """
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS scan_schedules (
    id               TEXT PRIMARY KEY,
    program_id       TEXT REFERENCES programs(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    cron_expression  TEXT,
    interval_minutes INTEGER,
    intensity        TEXT NOT NULL DEFAULT 'gentle',
    enabled          INTEGER NOT NULL DEFAULT 1,
    last_run_at      TEXT,
    next_run_at      TEXT,
    created_at       TEXT,
    updated_at       TEXT,
    UNIQUE(program_id, name),
    CHECK(cron_expression IS NOT NULL OR interval_minutes IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS scan_queue (
    id            TEXT PRIMARY KEY,
    program_id    TEXT,
    intensity     TEXT NOT NULL DEFAULT 'gentle',
    priority      INTEGER NOT NULL DEFAULT 100,
    status        TEXT NOT NULL DEFAULT 'queued',
    reason        TEXT,
    submitted_at  TEXT,
    started_at    TEXT,
    finished_at   TEXT,
    scan_id       TEXT,
    error_message TEXT,
    retry_count   INTEGER NOT NULL DEFAULT 0
);

COMMIT;
"""

_MIGRATION_V12 = """
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS ai_usage (
    date TEXT PRIMARY KEY,
    request_count INTEGER NOT NULL DEFAULT 0,
    cost_estimate REAL NOT NULL DEFAULT 0.0
);

COMMIT;
"""

_MIGRATION_V13 = """
BEGIN TRANSACTION;

-- Metadata index for the filesystem AI response cache.
-- Actual cached responses live in data/ai_cache/<hash>.json (30-day TTL).
-- This table lets SQL tooling inspect cache state without touching the filesystem.
CREATE TABLE IF NOT EXISTS ai_cache (
    cache_key  TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

COMMIT;
"""

_MIGRATION_V16 = """
BEGIN TRANSACTION;

-- Phase 17 fix: recreate scan_errors without FK on scan_id so that
-- error records can be inserted for arbitrary / orphaned scan IDs.
CREATE TABLE IF NOT EXISTS scan_errors_v16 (
    id             TEXT PRIMARY KEY,
    scan_id        TEXT,
    asset_id       TEXT,
    detection_id   TEXT,
    kind           TEXT NOT NULL DEFAULT 'other',
    exception_type TEXT,
    message        TEXT,
    traceback      TEXT,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT OR IGNORE INTO scan_errors_v16
    SELECT id, scan_id, asset_id, detection_id, kind,
           exception_type, message, traceback, created_at
    FROM scan_errors;

DROP TABLE IF EXISTS scan_errors;
ALTER TABLE scan_errors_v16 RENAME TO scan_errors;

COMMIT;
"""

_MIGRATION_V15 = """
BEGIN TRANSACTION;

-- scan_errors: per-scan error records for operator visibility (Phase 17).
CREATE TABLE IF NOT EXISTS scan_errors (
    id             TEXT PRIMARY KEY,
    scan_id        TEXT REFERENCES scans(id) ON DELETE CASCADE,
    asset_id       TEXT,
    detection_id   TEXT,
    kind           TEXT NOT NULL DEFAULT 'other',
    exception_type TEXT,
    message        TEXT,
    traceback      TEXT,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_scan_errors_scan    ON scan_errors(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_errors_kind    ON scan_errors(kind);
CREATE INDEX IF NOT EXISTS idx_scan_errors_created ON scan_errors(created_at DESC);

COMMIT;
"""

_MIGRATION_V14 = """
BEGIN TRANSACTION;

-- Recon enrichment table: stores whois, ASN, favicon hash, rDNS results.
CREATE TABLE IF NOT EXISTS recon_enrichment (
    id         TEXT PRIMARY KEY,
    asset_id   TEXT REFERENCES assets(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,  -- whois | asn | favicon | rdns | related_tld
    data       TEXT NOT NULL DEFAULT '{}',  -- JSON blob
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_recon_enrichment_asset ON recon_enrichment(asset_id);
CREATE INDEX IF NOT EXISTS idx_recon_enrichment_kind ON recon_enrichment(kind);

-- Favicon mmh3 column on assets (nullable; populated by toolbox)
ALTER TABLE assets ADD COLUMN favicon_mmh3 TEXT;

COMMIT;
"""

_MIGRATIONS: list[str] = [
    _MIGRATION_V1,
    # v2 → add leads table for intel / Shodan triage.
    _MIGRATION_V2,
    # v3 → collapse http/https asset duplicates; add seen_protocols + primary_scheme;
    #       replace UNIQUE(program_id, url) with partial unique indexes on (host, port).
    _MIGRATION_V3,
    # v4 → convert fingerprints.id to TEXT (ULID); add idx_fingerprints_tech index.
    _MIGRATION_V4,
    # v5 → convert fingerprints.confidence from INTEGER (0-100) to TEXT tier
    #       (definitive | strong | weak | hint) per Phase 3.2 Principle 1.
    _MIGRATION_V5,
    # v6 → convert findings.id and evidence_packages.id from INTEGER to TEXT (ULID).
    #       Updates FK references in reports and secrets_validations.
    _MIGRATION_V6,
    # v7 → convert secrets_validations.id from INTEGER to TEXT (ULID).
    _MIGRATION_V7,
    # v8 → restructure reports: multi-finding (finding_ids JSON array), program_id,
    #       template field (h1/bugcrowd/markdown), status normalised to draft/sent/accepted/rejected.
    _MIGRATION_V8,
    # v9 (Phase 14a) → add source column to secrets_validations.
    #   'native'     = detected + validated by bounty's own scanner/validators.
    #   'trufflehog' = detected by TruffleHog subprocess.
    _MIGRATION_V9,
    # v10 (Phase 14b) → add source column to findings.
    #   'native' = detected by bounty's own Detection classes.
    #   'nuclei' = detected by the Nuclei subprocess scanner.
    _MIGRATION_V10,
    # v11 (Phase 8) → add scan_schedules and scan_queue tables.
    _MIGRATION_V11,
    # v12 (Phase 10) → add ai_usage table for LLM cost tracking.
    _MIGRATION_V12,
    # v13 (Phase 10) → add ai_cache metadata table (actual cache is filesystem).
    _MIGRATION_V13,
    # v14 (Phase 16) → add recon_enrichment table and favicon_mmh3 column.
    _MIGRATION_V14,
    # v15 (Phase 17) → add scan_errors table for per-scan error visibility.
    _MIGRATION_V15,
    # v16 (Phase 17 fix) → recreate scan_errors without FK on scan_id.
    _MIGRATION_V16,
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
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError:
                    # Index/column may not exist yet (if schema references a column
                    # that was added/removed in a later migration).  Safe to skip —
                    # the migration will create the correct version.
                    pass

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
            # Disable FK checks for the duration of the migration so that
            # rename-table-and-copy steps don't trip over FK cycles.
            # PRAGMA foreign_keys cannot be changed inside a transaction, so
            # we set it before executescript (which auto-commits first).
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.commit()
            conn.executescript(migration_sql)
            # Recreate indexes that were implicitly dropped with the old tables.
            conn.execute("PRAGMA foreign_keys = ON")
            _recreate_indexes(conn)
            conn.execute(f"PRAGMA user_version = {migration_version}")
            conn.commit()
            current_version = migration_version
    finally:
        conn.close()


def _recreate_indexes(conn: sqlite3.Connection) -> None:
    """Recreate all application indexes (idempotent — uses IF NOT EXISTS).

    Called after a migration that drops and recreates tables, since SQLite
    drops indexes automatically when the underlying table is dropped.

    Args:
        conn: Open SQLite connection.
    """
    index_stmts = [
        "CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program_id)",
        "CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host)",
        # Partial unique indexes for the (program_id, host, port) dedup key.
        # NULL != NULL in UNIQUE constraints, so we use two partial indexes:
        # one for default-port rows (port IS NULL) and one for custom-port rows.
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_unique_base ON assets(program_id, host) WHERE port IS NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_unique_port ON assets(program_id, host, port) WHERE port IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_asset_history_asset ON asset_history(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_fingerprints_asset ON fingerprints(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_fingerprints_tech ON fingerprints(tech)",
        "CREATE INDEX IF NOT EXISTS idx_scan_phases_scan ON scan_phases(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
        "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)",
        "CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(dedup_key)",
        "CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence_packages(finding_id)",
        "CREATE INDEX IF NOT EXISTS idx_secrets_status ON secrets_validations(status)",
        "CREATE INDEX IF NOT EXISTS idx_secrets_provider ON secrets_validations(provider)",
        "CREATE INDEX IF NOT EXISTS idx_reports_program ON reports(program_id)",
        "CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)",
        "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)",
        "CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_log(operation)",
        "CREATE INDEX IF NOT EXISTS idx_targets_program ON targets(program_id)",
        "CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status)",
        "CREATE INDEX IF NOT EXISTS idx_leads_program ON leads(program_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_errors_scan    ON scan_errors(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_errors_kind    ON scan_errors(kind)",
        "CREATE INDEX IF NOT EXISTS idx_scan_errors_created ON scan_errors(created_at DESC)",
    ]
    for stmt in index_stmts:
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            # Index references a column that doesn't exist yet in this migration
            # step (e.g. program_id added in a later migration). Safe to skip —
            # the index will be created once the column-adding migration runs.
            pass
    conn.commit()


@asynccontextmanager
async def get_conn(db_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    """Async context manager that yields a configured ``aiosqlite.Connection``.

    The connection enables row factory (``sqlite3.Row``) so columns can be
    accessed by name.  Foreign keys are enforced and WAL mode is active.
    The caller is responsible for committing; the context manager rolls back
    on exception and always closes the connection on exit.

    Usage::

        from bounty.db import get_conn
        from bounty.config import get_settings

        async with get_conn(get_settings().db_path) as conn:
            cursor = await conn.execute("SELECT * FROM programs WHERE id = ?", (pid,))
            row = await cursor.fetchone()

    Args:
        db_path: Path to the SQLite database file.

    Yields:
        An open ``aiosqlite.Connection``.

    Raises:
        aiosqlite.Error: On any database error (after rollback).
    """
    conn = await aiosqlite.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute("PRAGMA journal_mode = WAL")
        yield conn
    except Exception:
        await conn.rollback()
        raise
    finally:
        await conn.close()

