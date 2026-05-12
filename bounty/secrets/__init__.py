"""
bounty.secrets — Secret scanning and token validation pipeline.

Entry point: ``process_finding_secrets()``

Workflow per finding:
  1. Scan all evidence packages for secret patterns (scanner.scan_evidence_package)
  2. Deduplicate candidates by (provider, sha256(value+paired_value))
  3. For each candidate, check cache (secrets_validations table)
  4. Validate fresh or return cached result
  5. Persist SecretValidation row (UPSERT) with source='native'
  6. If trufflehog_enabled, also run TruffleHog on evidence bodies
  7. For each TruffleHog result: skip if native validator exists, else persist
     with source='trufflehog'
  8. If any live secrets, bump finding severity and add tags
  9. Publish 'secret.validated' SSE event per validation row
  10. Return list of persisted SecretValidation rows
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import aiosqlite
import httpx

from bounty import get_logger
from bounty.config import Settings, get_settings
from bounty.events import publish
from bounty.models import EvidencePackage, Finding, SecretValidation, make_secret_preview, severity_label
from bounty.secrets.scanner import SecretCandidate, scan_evidence_package
from bounty.ulid import make_ulid

log = get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Severity bumps per provider for live secrets
_SEVERITY_BUMPS: dict[str, int] = {
    "aws": 950,
    "gcp": 950,
    "azure": 950,
    "stripe": 950,
    "paypal": 950,
    "razorpay": 950,
    "shopify": 950,
    "github": 850,
    "gitlab": 850,
    "sendgrid": 800,
    "mailgun": 800,
    "twilio": 800,
    "slack": 700,
    "discord": 700,
}


def _severity_bump_for(provider: str) -> int:
    return _SEVERITY_BUMPS.get(provider, 750)


async def _load_cached(
    conn: aiosqlite.Connection,
    secret_hash: str,
    provider: str,
    cache_ttl_days: int,
) -> SecretValidation | None:
    """Return an existing SecretValidation if it's within the TTL window."""
    cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=cache_ttl_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    cur = await conn.execute(
        """
        SELECT id, asset_id, finding_id, provider, secret_hash, secret_preview,
               secret_pattern, status, scope, identity, last_checked, next_check,
               error_message, source, created_at, updated_at
        FROM secrets_validations
        WHERE secret_hash=? AND provider=?
          AND status IN ('live', 'invalid')
          AND last_checked >= ?
        """,
        (secret_hash, provider, cutoff),
    )
    row = await cur.fetchone()
    if row is None:
        return None
    scope = None
    if row["scope"]:
        try:
            scope = json.loads(row["scope"])
        except Exception:  # noqa: BLE001
            scope = None
    # Handle databases that don't yet have the source column (before migration v9)
    try:
        source_val: str = row["source"] or "native"
    except (IndexError, KeyError):
        source_val = "native"
    return SecretValidation(
        id=str(row["id"]) if row["id"] else None,
        asset_id=row["asset_id"],
        finding_id=row["finding_id"],
        provider=row["provider"],
        secret_hash=row["secret_hash"],
        secret_preview=row["secret_preview"],
        secret_pattern=row["secret_pattern"],
        status=row["status"],
        scope=scope,
        identity=row["identity"],
        last_checked=row["last_checked"],
        error_message=row["error_message"],
        source=source_val,
    )


async def _upsert_secret_validation(
    conn: aiosqlite.Connection,
    sv: "SecretValidationRow",
) -> str:
    """UPSERT a secrets_validations row. Returns the row id."""
    ts = _now_iso()
    row_id = make_ulid()
    scope_json = json.dumps(sv["scope"]) if sv["scope"] else None
    source = sv.get("source", "native")  # type: ignore[call-overload]
    await conn.execute(
        """
        INSERT INTO secrets_validations
            (id, asset_id, finding_id, provider, secret_hash, secret_preview,
             secret_pattern, status, scope, identity, last_checked,
             error_message, source, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(secret_hash, provider) DO UPDATE SET
            finding_id    = COALESCE(excluded.finding_id, finding_id),
            asset_id      = COALESCE(excluded.asset_id, asset_id),
            status        = excluded.status,
            scope         = COALESCE(excluded.scope, scope),
            identity      = COALESCE(excluded.identity, identity),
            last_checked  = excluded.last_checked,
            error_message = excluded.error_message,
            updated_at    = excluded.updated_at
        """,
        (
            row_id,
            sv["asset_id"],
            sv["finding_id"],
            sv["provider"],
            sv["secret_hash"],
            sv["secret_preview"],
            sv["secret_pattern"],
            sv["status"],
            scope_json,
            sv["identity"],
            ts,  # last_checked
            sv["error_message"],
            source,
            ts,  # created_at
            ts,  # updated_at
        ),
    )
    await conn.commit()
    # Return actual id (may be existing row's id if conflict occurred)
    cur = await conn.execute(
        "SELECT id FROM secrets_validations WHERE secret_hash=? AND provider=?",
        (sv["secret_hash"], sv["provider"]),
    )
    r = await cur.fetchone()
    return str(r["id"]) if r else row_id


class SecretValidationRow(dict):  # type: ignore[type-arg]
    """Typed helper for the upsert payload."""


async def process_finding_secrets(
    finding: Finding,
    evidence: list[EvidencePackage],
    conn: aiosqlite.Connection,
    http: httpx.AsyncClient,
    settings: Settings | None = None,
) -> list[SecretValidation]:
    """Scan evidence for secrets, validate them, persist results.

    Args:
        finding: The persisted Finding to attach validations to.
        evidence: Evidence packages captured for this finding.
        conn: Open aiosqlite connection.
        http: Shared async HTTP client.
        settings: Application settings (uses get_settings() if None).

    Returns:
        List of persisted :class:`SecretValidation` rows.
    """
    if settings is None:
        settings = get_settings()

    if not settings.secret_validation_enabled:
        return []

    # Import registry (lazy to avoid circular imports at module load time)
    import bounty.validate.registry as _reg_mod  # noqa: F401
    from bounty.validate._base import REGISTRY

    bound_log = log.bind(finding_id=finding.id)

    # ── Step 1: Scan evidence packages for secrets ──────────────────────────
    all_candidates: dict[tuple[str, str, str | None], SecretCandidate] = {}
    for ep in evidence:
        for candidate in scan_evidence_package(ep):
            key = (candidate.provider, candidate.value, candidate.paired_value)
            if key not in all_candidates:
                all_candidates[key] = candidate

    # Collect which providers have been handled by native (for trufflehog dedup)
    native_hashes: set[str] = set()

    # ── Step 2: Validate (respect concurrency cap) ──────────────────────────
    sem = asyncio.Semaphore(settings.secret_validation_max_concurrent)
    persisted: list[SecretValidation] = []
    live_providers: list[str] = []

    async def _validate_one(candidate: SecretCandidate) -> None:
        async with sem:
            provider = candidate.provider
            try:
                # Check cache first
                cached = await _load_cached(
                    conn, candidate.secret_hash, provider,
                    settings.secret_validation_cache_ttl_days,
                )
                if cached is not None:
                    # Re-link to this finding (UPSERT will update finding_id)
                    row: dict[str, Any] = {
                        "asset_id": finding.asset_id,
                        "finding_id": finding.id,
                        "provider": provider,
                        "secret_hash": candidate.secret_hash,
                        "secret_preview": candidate.secret_preview,
                        "secret_pattern": candidate.pattern_name,
                        "status": cached.status,
                        "scope": cached.scope,
                        "identity": cached.identity,
                        "error_message": cached.error_message,
                        "source": cached.source,
                    }
                    actual_id = await _upsert_secret_validation(conn, row)  # type: ignore[arg-type]
                    native_hashes.add(candidate.secret_hash)
                    if cached.status == "live":
                        live_providers.append(provider)
                    persisted.append(SecretValidation(
                        id=actual_id,
                        asset_id=finding.asset_id,
                        finding_id=finding.id,
                        provider=provider,
                        secret_hash=candidate.secret_hash,
                        secret_preview=candidate.secret_preview,
                        secret_pattern=candidate.pattern_name,
                        status=cached.status,
                        scope=cached.scope,
                        identity=cached.identity,
                        error_message=cached.error_message,
                        source=cached.source,
                    ))
                    bound_log.debug("secret_cache_hit", provider=provider, status=cached.status)
                    return

                # Fresh validation
                validator = REGISTRY.get(provider)
                if validator is None:
                    bound_log.debug("no_validator", provider=provider)
                    return

                result = await validator.validate(candidate, http)

                row = {
                    "asset_id": finding.asset_id,
                    "finding_id": finding.id,
                    "provider": provider,
                    "secret_hash": candidate.secret_hash,
                    "secret_preview": candidate.secret_preview,
                    "secret_pattern": candidate.pattern_name,
                    "status": result.status,
                    "scope": result.scope,
                    "identity": result.identity,
                    "error_message": result.error_message,
                    "source": "native",
                }
                actual_id = await _upsert_secret_validation(conn, row)  # type: ignore[arg-type]
                native_hashes.add(candidate.secret_hash)

                sv = SecretValidation(
                    id=actual_id,
                    asset_id=finding.asset_id,
                    finding_id=finding.id,
                    provider=provider,
                    secret_hash=candidate.secret_hash,
                    secret_preview=candidate.secret_preview,
                    secret_pattern=candidate.pattern_name,
                    status=result.status,
                    scope=result.scope,
                    identity=result.identity,
                    error_message=result.error_message,
                    source="native",
                )
                persisted.append(sv)

                if result.status == "live":
                    live_providers.append(provider)

                await publish(
                    "secret.validated",
                    {
                        "finding_id": finding.id,
                        "provider": provider,
                        "status": result.status,
                        "identity": result.identity,
                        "secret_preview": candidate.secret_preview,
                    },
                    program_id=finding.program_id,
                )

                bound_log.info(
                    "secret_validated",
                    provider=provider,
                    status=result.status,
                    preview=candidate.secret_preview,
                )

            except Exception as exc:  # noqa: BLE001
                bound_log.warning("secret_validation_error", provider=provider, error=str(exc))

    if all_candidates:
        bound_log.info("secrets_found", count=len(all_candidates))
        tasks = [_validate_one(c) for c in all_candidates.values()]
        # Run sequentially to avoid concurrent writes on the shared conn.
        # The HTTP calls themselves are fast; sequential is fine for 1-5 secrets.
        for task in tasks:
            await task

    # ── Step 3: TruffleHog scan ─────────────────────────────────────────────
    if settings.trufflehog_enabled and evidence:
        trufflehog_live_providers: list[str] = []
        try:
            from bounty.secrets.trufflehog import map_detector_to_provider, scan_with_trufflehog

            # Collect all unique evidence bodies to scan
            evidence_bodies: list[bytes] = []
            for ep in evidence:
                if ep.response_raw:
                    evidence_bodies.append(
                        ep.response_raw.encode("utf-8", errors="replace")
                        if isinstance(ep.response_raw, str)
                        else ep.response_raw
                    )

            for body in evidence_bodies:
                th_results = await scan_with_trufflehog(
                    body,
                    timeout=settings.trufflehog_timeout_seconds,
                )

                for th in th_results:
                    provider = map_detector_to_provider(th.detector_name)

                    # Compute a hash for the secret from trufflehog
                    secret_val = th.decoded_secret or th.raw_secret
                    secret_hash = hashlib.sha256(secret_val.encode("utf-8", errors="replace")).hexdigest()

                    # Skip if native validator already handled this provider
                    if REGISTRY.get(provider) is not None:
                        bound_log.debug(
                            "trufflehog_skipped_native_validator",
                            provider=provider,
                            detector=th.detector_name,
                        )
                        continue

                    # Skip if this exact hash was already handled natively
                    if secret_hash in native_hashes:
                        bound_log.debug(
                            "trufflehog_skipped_native_hash",
                            provider=provider,
                        )
                        continue

                    status = "live" if th.verified else "invalid"
                    identity = th.extra_data.get("identity")
                    preview = make_secret_preview(secret_val) if secret_val else "…"

                    th_row: dict[str, Any] = {
                        "asset_id": finding.asset_id,
                        "finding_id": finding.id,
                        "provider": provider,
                        "secret_hash": secret_hash,
                        "secret_preview": preview,
                        "secret_pattern": f"trufflehog:{th.detector_name}",
                        "status": status,
                        "scope": None,
                        "identity": str(identity) if identity else None,
                        "error_message": None,
                        "source": "trufflehog",
                    }

                    try:
                        actual_id = await _upsert_secret_validation(conn, th_row)  # type: ignore[arg-type]
                    except Exception as exc:  # noqa: BLE001
                        bound_log.warning(
                            "trufflehog_upsert_error",
                            provider=provider,
                            error=str(exc),
                        )
                        continue

                    th_sv = SecretValidation(
                        id=actual_id,
                        asset_id=finding.asset_id,
                        finding_id=finding.id,
                        provider=provider,
                        secret_hash=secret_hash,
                        secret_preview=preview,
                        secret_pattern=f"trufflehog:{th.detector_name}",
                        status=status,
                        identity=str(identity) if identity else None,
                        source="trufflehog",
                    )
                    persisted.append(th_sv)

                    if status == "live":
                        trufflehog_live_providers.append(provider)

                    bound_log.info(
                        "trufflehog_detected",
                        provider=provider,
                        detector=th.detector_name,
                        status=status,
                        verified=th.verified,
                    )

        except Exception as exc:  # noqa: BLE001
            bound_log.warning("trufflehog_scan_error", error=str(exc))

        live_providers.extend(trufflehog_live_providers)

    # ── Step 4: Severity bump + tags ────────────────────────────────────────
    if live_providers and finding.id:
        max_bump = max(_severity_bump_for(p) for p in live_providers)
        new_severity = max(finding.severity, max_bump)
        new_label = severity_label(new_severity)
        new_tags = list(finding.tags)
        for p in live_providers:
            tag = f"validated-secret:{p}"
            if tag not in new_tags:
                new_tags.append(tag)

        # Add trufflehog-detected tags for all trufflehog results
        for sv in persisted:
            if sv.source == "trufflehog":
                tag = f"trufflehog-detected:{sv.provider}"
                if tag not in new_tags:
                    new_tags.append(tag)

        await conn.execute(
            """
            UPDATE findings
            SET severity=?, severity_label=?, tags=?, updated_at=?
            WHERE id=?
            """,
            (new_severity, new_label, json.dumps(new_tags), _now_iso(), finding.id),
        )
        await conn.commit()
        bound_log.info(
            "severity_bumped",
            old=finding.severity,
            new=new_severity,
            live_providers=live_providers,
        )
    elif finding.id:
        # Still tag with validated-secret even for invalid/error
        new_tags = list(finding.tags)
        for sv in persisted:
            tag = f"validated-secret:{sv.provider}"
            if tag not in new_tags:
                new_tags.append(tag)
            # Add trufflehog-detected tags
            if sv.source == "trufflehog":
                th_tag = f"trufflehog-detected:{sv.provider}"
                if th_tag not in new_tags:
                    new_tags.append(th_tag)
        if new_tags != finding.tags:
            await conn.execute(
                "UPDATE findings SET tags=?, updated_at=? WHERE id=?",
                (json.dumps(new_tags), _now_iso(), finding.id),
            )
            await conn.commit()

    return persisted

