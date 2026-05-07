"""
bounty.detect.exposed_files.backups — Exposed backup & archive detections.

Four detections: database dumps, filesystem archives, JS source maps, and
editor swap files of sensitive paths.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import datetime, timezone

from bounty.detect.base import Detection, DetectionContext
from bounty.detect.exposed_files._common import is_real_file_response
from bounty.models import Asset, FindingDraft

# ---------------------------------------------------------------------------
# Database dump
# ---------------------------------------------------------------------------

_SQL_DUMP_PATHS = [
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/db.sql",
    "/db_backup.sql",
    "/mysql.sql",
    "/mysqldump.sql",
    "/backup/database.sql",
    "/sql/backup.sql",
    "/data/backup.sql",
]

_SQL_SIGNATURES = [
    b"CREATE TABLE",
    b"INSERT INTO",
    b"-- MySQL dump",
    b"-- PostgreSQL database dump",
    b"-- MariaDB dump",
    b"PRAGMA",
    b"CREATE DATABASE",
]


class ExposedDatabaseDump(Detection):
    """Exposed SQL database dump file."""

    id = "exposed.backups.database-dump"
    name = "Exposed database dump"
    category = "exposed_backup"
    severity_default = 900
    cwe = "CWE-312"
    tags = ("exposed-files", "database", "backup")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _SQL_DUMP_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if pr.status_code != 200:
                continue
            if len(pr.body) < 20:
                continue
            # Check SQL signatures — body starts with SQL DDL
            if not any(sig in pr.body[:8192] for sig in _SQL_SIGNATURES):
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed database dump at {asset.host}{path}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    "A SQL database dump file is publicly accessible. "
                    "This may expose all user data, passwords, and application "
                    "secrets stored in the database."
                ),
                remediation=(
                    "Remove the dump file from the web root immediately. "
                    "Store database backups outside the web-accessible directory. "
                    "If user data was exposed, follow breach notification requirements."
                ),
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# Filesystem backup archive
# ---------------------------------------------------------------------------

_ARCHIVE_MAGIC = {
    ".zip": b"PK\x03\x04",
    ".tar.gz": b"\x1f\x8b",
    ".gz": b"\x1f\x8b",
    ".tar": b"ustar",
    ".tar.bz2": b"BZh",
    ".7z": b"7z\xbc\xaf'\x1c",
}

_ARCHIVE_CONTENT_TYPES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/x-gzip",
    "application/gzip",
    "application/x-tar",
    "application/x-bzip2",
    "application/x-7z-compressed",
    "application/octet-stream",
}


def _archive_backup_paths(host: str) -> list[str]:
    """Generate the list of archive paths to probe, including host-derived names."""
    # Strip TLD for hostname-based backup names
    parts = host.rstrip(".").split(".")
    host_stem = parts[0] if parts else host

    now = datetime.now(tz=timezone.utc)
    year = now.year
    month = now.strftime("%m")

    # Generate last 6 months of date-suffixed names
    date_suffixes: list[str] = []
    for delta_months in range(7):
        y = year
        m = now.month - delta_months
        while m <= 0:
            m += 12
            y -= 1
        suffix = f"{y}-{m:02d}"
        date_suffixes.append(suffix)

    paths: list[str] = [
        "/backup.zip",
        "/backup.tar.gz",
        "/backup.tar",
        "/site.zip",
        "/www.zip",
        "/public_html.zip",
        "/wwwroot.zip",
        f"/{host_stem}.zip",
        "/html.zip",
        "/web.zip",
    ]
    for ds in date_suffixes[:4]:
        paths.append(f"/backup-{ds}.zip")
        paths.append(f"/backup-{ds}.tar.gz")

    return paths


class ExposedFilesystemBackup(Detection):
    """Exposed filesystem backup archive."""

    id = "exposed.backups.filesystem-archive"
    name = "Exposed filesystem backup archive"
    category = "exposed_backup"
    severity_default = 800
    cwe = "CWE-312"
    tags = ("exposed-files", "backup", "archive")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _archive_backup_paths(asset.host):
            url = base + path
            pr = await ctx.probe_fn(url)
            if pr.status_code != 200:
                continue
            if len(pr.body) < 1024:
                continue

            # Check Content-Type
            ct = pr.headers.get("content-type", "").lower().split(";")[0].strip()
            if ct not in _ARCHIVE_CONTENT_TYPES and "zip" not in ct and "tar" not in ct:
                # Fallback: check magic bytes
                ext = next((e for e in _ARCHIVE_MAGIC if path.endswith(e)), None)
                if ext:
                    if not pr.body.startswith(_ARCHIVE_MAGIC[ext]):
                        continue
                else:
                    continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed filesystem backup at {asset.host}{path}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    "A filesystem backup archive is publicly accessible. "
                    "It likely contains the full web application source code, "
                    "configuration files, and potentially database dumps."
                ),
                remediation=(
                    "Remove the backup archive from the web root. "
                    "Store backups in a non-web-accessible location."
                ),
                cwe="CWE-312",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# JavaScript source map
# ---------------------------------------------------------------------------

_SOURCEMAP_PATHS = [
    "/static/js/main.js.map",
    "/static/js/app.js.map",
    "/static/js/bundle.js.map",
    "/assets/main.js.map",
    "/assets/app.js.map",
    "/js/app.js.map",
    "/dist/main.js.map",
    "/build/static/js/main.js.map",
]


class ExposedSourceMap(Detection):
    """Exposed JavaScript source map — reveals original pre-minified source."""

    id = "exposed.backups.source-map"
    name = "Exposed JavaScript source map"
    category = "exposed_backup"
    severity_default = 400
    cwe = "CWE-540"
    tags = ("exposed-files", "source-disclosure")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for path in _SOURCEMAP_PATHS:
            url = base + path
            pr = await ctx.probe_fn(url)
            if not is_real_file_response(pr, [b'"sources"', b'"sourcesContent"', b'"mappings"']):
                continue
            if b'"sources"' not in pr.body:
                continue

            await ctx.capture_evidence(url, pr)
            yield FindingDraft(
                asset_id=asset.id,
                scan_id=ctx.scan_id,
                dedup_key=f"{self.id}:{asset.id}:{path}",
                title=f"Exposed JS source map at {asset.host}{path}",
                category=self.category,
                severity=self.severity_default,
                url=url,
                path=path,
                description=(
                    "A JavaScript source map is publicly accessible, revealing the "
                    "original un-minified source code. Source maps may contain "
                    "hardcoded API keys, internal infrastructure details, or "
                    "business logic that aids attackers."
                ),
                remediation=(
                    "Disable source map generation for production builds, or "
                    "serve them only to authenticated users / internal networks."
                ),
                cwe="CWE-540",
                tags=list(self.tags),
            )
            return


# ---------------------------------------------------------------------------
# Editor swap / backup of sensitive files
# ---------------------------------------------------------------------------

_SENSITIVE_BASE_FILES = [
    "index.php",
    "config.php",
    ".env",
    "wp-config.php",
    "settings.py",
    "secrets.py",
    "database.yml",
    "config.rb",
]

_SWAP_SUFFIXES = [".swp", "~", ".bak", ".old", ".orig"]


class ExposedEditorSwap(Detection):
    """Editor swap / backup files of sensitive paths."""

    id = "exposed.backups.editor-swap"
    name = "Exposed editor swap / backup file"
    category = "exposed_backup"
    severity_default = 500
    cwe = "CWE-540"
    tags = ("exposed-files", "editor-artifact")

    async def run(
        self, asset: Asset, ctx: DetectionContext
    ) -> AsyncGenerator[FindingDraft, None]:
        if ctx.is_soft_404_site(asset):
            return

        base = asset.url.rstrip("/")
        for base_file in _SENSITIVE_BASE_FILES:
            for suffix in _SWAP_SUFFIXES:
                if suffix == ".swp":
                    path = f"/.{base_file}{suffix}"
                else:
                    path = f"/{base_file}{suffix}"
                url = base + path
                pr = await ctx.probe_fn(url)
                if pr.status_code != 200 or len(pr.body) < 20:
                    continue
                # Any non-HTML content is worth flagging
                ct = pr.headers.get("content-type", "").lower()
                if "html" in ct and b"<html" in pr.body.lower()[:200]:
                    continue
                # Vim swap: starts with b23456 header
                if suffix == ".swp" and not pr.body.startswith(b"b"):
                    if not pr.body[:6] in (b"Vim sw", b"b2345"):
                        # Accept anyway if non-HTML content
                        pass

                await ctx.capture_evidence(url, pr)
                yield FindingDraft(
                    asset_id=asset.id,
                    scan_id=ctx.scan_id,
                    dedup_key=f"{self.id}:{asset.id}:{path}",
                    title=f"Exposed editor artifact at {asset.host}{path}",
                    category=self.category,
                    severity=self.severity_default,
                    url=url,
                    path=path,
                    description=(
                        f"An editor swap or backup file ({path}) is publicly "
                        "accessible. It may contain plain-text source code, "
                        "credentials, or configuration data."
                    ),
                    remediation=(
                        "Remove editor swap and backup files from your web root. "
                        "Add *.swp, *.bak, *~, *.old to .gitignore."
                    ),
                    cwe="CWE-540",
                    tags=list(self.tags),
                )
                return  # One finding per asset

