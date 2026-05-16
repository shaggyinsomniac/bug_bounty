"""
bounty.detect.runner — Detection runner: orchestrates all registered detections.

For each asset, the runner:
  1. Pre-computes soft-404 status (probe a random path once per asset).
  2. Iterates REGISTERED_DETECTIONS, skipping non-applicable detections.
  3. For each yielded FindingDraft:
     a. Persists a Finding row (UPSERT on dedup_key → re-detection updates timestamps).
     b. Links evidence packages captured during run() to the Finding.
     c. Sets validated=True (deterministic read-only checks).
     d. Publishes finding.discovered SSE event.
  4. Detection errors are logged and swallowed — never fail the asset.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator, AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from bounty import get_logger
from bounty.config import Settings, get_settings
from bounty.db import get_conn
from bounty.detect import REGISTERED_DETECTIONS
from bounty.detect.base import Detection, DetectionContext, DetectionError
from bounty.detect.exposed_files._common import soft_404_check
from bounty.events import publish
from bounty.models import Asset, EvidencePackage, Finding, FindingDraft, FingerprintResult, severity_label
from bounty.ulid import make_ulid

log = get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _persist_finding(
    draft: FindingDraft,
    conn: aiosqlite.Connection,
) -> Finding:
    """Insert or update a finding row.  Returns the persisted Finding.

    If the draft's scan_id doesn't reference an existing scan row the FK will
    fail; in that case we retry with scan_id=NULL so the finding is still
    persisted (scan_id is informational, not load-bearing).
    """
    ts = _now_iso()
    finding_id = make_ulid()
    label = severity_label(draft.severity)
    tags_json = json.dumps(draft.tags)

    async def _do_insert(scan_id_val: str | None) -> None:
        await conn.execute(
            """
            INSERT INTO findings
                (id, program_id, asset_id, scan_id, dedup_key, title, category,
                 severity, severity_label, status, url, path, description,
                 remediation, cve, cwe, validated, validated_at, tags, source,
                 created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,'new',?,?,?,?,?,?,1,?,?,?,?,?)
            ON CONFLICT(dedup_key) DO UPDATE SET
                updated_at = excluded.updated_at,
                scan_id    = COALESCE(excluded.scan_id, scan_id)
            """,
            (
                finding_id,
                draft.program_id,
                draft.asset_id,
                scan_id_val,
                draft.dedup_key,
                draft.title,
                draft.category,
                draft.severity,
                label,
                draft.url,
                draft.path,
                draft.description,
                draft.remediation,
                draft.cve,
                draft.cwe,
                ts,  # validated_at
                tags_json,
                draft.source,
                ts,  # created_at
                ts,  # updated_at
            ),
        )

    import sqlite3 as _sqlite3
    try:
        await _do_insert(draft.scan_id)
        await conn.commit()
    except (_sqlite3.IntegrityError, Exception) as exc:  # noqa: BLE001
        # FK failure (scan_id not in scans) — retry with NULL scan_id
        if "FOREIGN KEY" in str(exc):
            await conn.rollback()
            await _do_insert(None)
            await conn.commit()
        else:
            await conn.rollback()
            raise

    # Fetch the actual ID (may differ from finding_id if row already existed).
    cur = await conn.execute(
        "SELECT id, created_at FROM findings WHERE dedup_key=?", (draft.dedup_key,)
    )
    row = await cur.fetchone()
    actual_id: str = str(row["id"]) if row else finding_id

    return Finding(
        id=actual_id,
        program_id=draft.program_id,
        asset_id=draft.asset_id,
        scan_id=draft.scan_id,
        dedup_key=draft.dedup_key,
        title=draft.title,
        category=draft.category,
        severity=draft.severity,
        severity_label=label,
        url=draft.url,
        path=draft.path,
        description=draft.description,
        remediation=draft.remediation,
        cve=draft.cve,
        cwe=draft.cwe,
        validated=True,
        validated_at=datetime.fromisoformat(ts.replace("Z", "+00:00")),
        tags=draft.tags,
        source=draft.source,
        created_at=datetime.fromisoformat(ts.replace("Z", "+00:00")),
        updated_at=datetime.fromisoformat(ts.replace("Z", "+00:00")),
    )


async def _link_evidence(
    finding_id: str,
    evidence_pkgs: list[EvidencePackage],
    conn: aiosqlite.Connection,
) -> None:
    """Update evidence_packages.finding_id for all packages linked to a finding."""
    if not evidence_pkgs:
        return
    for pkg in evidence_pkgs:
        if pkg.id:
            await conn.execute(
                "UPDATE evidence_packages SET finding_id=? WHERE id=?",
                (finding_id, pkg.id),
            )
    await conn.commit()


async def run_detections(
    asset: Asset,
    fingerprints: list[FingerprintResult],
    ctx: DetectionContext,
    db_path: Path,
    detections: list[Detection] | None = None,
) -> AsyncGenerator[Finding, None]:
    """Run all registered detections against an asset and persist findings.

    Args:
        asset: The asset to scan.
        fingerprints: Fingerprint results for this asset (used by applicable_to).
        ctx: Shared detection context (probe_fn, capture_fn, scan_id, …).
        db_path: Path to the SQLite database.
        detections: Override the detection list (used in tests).

    Yields:
        Persisted ``Finding`` objects for each confirmed vulnerability.
    """
    registry = detections if detections is not None else REGISTERED_DETECTIONS
    bound_log = ctx.log.bind(asset=asset.host)

    # Expose fingerprints on ctx so Nuclei and other detections can access them
    ctx.fingerprints = fingerprints

    for detection in registry:
        try:
            applicable = detection.applicable_to(asset, fingerprints)
        except Exception as exc:  # noqa: BLE001
            bound_log.warning(
                "detection_applicable_check_failed",
                detection=detection.id,
                error=str(exc),
            )
            continue

        if not applicable:
            bound_log.debug("detection_skipped", detection=detection.id, reason="not_applicable")
            continue

        det_log = bound_log.bind(detection=detection.id)
        try:
            async for draft in detection.run(asset, ctx):
                # Drain evidence captured during this yield
                evidence_pkgs = ctx.drain_evidence()

                async with get_conn(db_path) as conn:
                    finding = await _persist_finding(draft, conn)
                    await _link_evidence(finding.id or "", evidence_pkgs, conn)

                # ── Secret scanning + validation (inline, best-effort) ──────
                if evidence_pkgs:
                    try:
                        from bounty.secrets import process_finding_secrets
                        import httpx as _httpx
                        _settings = get_settings()
                        async with get_conn(db_path) as _sv_conn:
                            async with _httpx.AsyncClient(timeout=15) as _http:
                                await process_finding_secrets(
                                    finding, evidence_pkgs, _sv_conn, _http, _settings
                                )
                    except Exception as _sec_exc:  # noqa: BLE001
                        det_log.warning("secret_scan_error", error=str(_sec_exc))

                await publish(
                    "finding.discovered",
                    {
                        "finding_id": finding.id,
                        "dedup_key": finding.dedup_key,
                        "title": finding.title,
                        "severity": finding.severity,
                        "severity_label": finding.severity_label,
                        "asset_id": asset.id,
                        "scan_id": ctx.scan_id,
                    },
                    program_id=asset.program_id,
                )

                det_log.info(
                    "finding_detected",
                    finding_id=finding.id,
                    dedup_key=finding.dedup_key,
                    severity=finding.severity,
                    severity_label=finding.severity_label,
                )
                yield finding

        except DetectionError as exc:
            det_log.warning("detection_error", error=str(exc))
            try:
                from bounty.errors import record_error as _rec_err
                await _rec_err(
                    db_path=db_path,
                    scan_id=ctx.scan_id or "",
                    kind="detection",
                    exception=exc,
                    asset_id=asset.id or "",
                    detection_id=detection.id,
                )
            except Exception:  # noqa: BLE001
                pass
        except Exception as exc:  # noqa: BLE001
            det_log.warning("detection_unexpected_error", error=str(exc), exc_info=True)
            try:
                from bounty.errors import record_error as _rec_err
                await _rec_err(
                    db_path=db_path,
                    scan_id=ctx.scan_id or "",
                    kind="detection",
                    exception=exc,
                    asset_id=asset.id or "",
                    detection_id=detection.id,
                )
            except Exception:  # noqa: BLE001
                pass


