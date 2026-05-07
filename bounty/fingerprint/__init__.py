"""
bounty.fingerprint — Technology fingerprinting engine.

Entry point: ``fingerprint_asset(asset, probe_result, probe_fn, conn)``

Runs all sub-parsers (headers, cookies, body, TLS, favicon), deduplicates and
boosts confidence for multi-signal matches, persists to the ``fingerprints``
table, updates the ``assets`` summary columns (server/cdn/waf), handles SAN
hostname discovery, and publishes an ``asset.fingerprinted`` event.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine

import aiosqlite
import structlog

from bounty.events import publish
from bounty.models import Asset, FingerprintResult, ProbeResult
from bounty.ulid import make_ulid

from .body import parse_body
from .cookies import parse_cookies
from .favicon import hash_favicon, lookup_favicon_db
from .headers import parse_headers
from .tls import parse_tls

__all__ = ["fingerprint_asset"]

log = structlog.get_logger(__name__)

_ProbeFn = Callable[[str], Coroutine[Any, Any, ProbeResult]]


# ---------------------------------------------------------------------------
# Confidence-boost deduplication logic
# ---------------------------------------------------------------------------

def _dedupe(results: list[FingerprintResult]) -> list[FingerprintResult]:
    """Merge multiple detections of the same tech into a single result.

    Confidence boost rules (spec §CONFIDENCE SCORING):
    - 1 signal  → max(confidences) as-is
    - 2 signals → max + 10, capped at 100
    - 3+ signals → max + 20, capped at 100
    """
    groups: dict[str, list[FingerprintResult]] = {}
    for r in results:
        groups.setdefault(r.tech, []).append(r)

    merged: list[FingerprintResult] = []
    for tech, items in groups.items():
        best = max(items, key=lambda x: x.confidence)
        n = len(items)
        boost = 0 if n == 1 else (10 if n == 2 else 20)
        final_conf = min(100, best.confidence + boost)

        evidence_parts = list(dict.fromkeys(i.evidence for i in items if i.evidence))
        combined_evidence = "; ".join(evidence_parts)[:500]

        merged.append(
            FingerprintResult(
                tech=tech,
                version=best.version,
                category=best.category,
                confidence=final_conf,
                evidence=combined_evidence,
            )
        )

    return sorted(merged, key=lambda x: -x.confidence)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

async def _persist_fingerprints(
    conn: aiosqlite.Connection,
    asset_id: str,
    results: list[FingerprintResult],
) -> list[FingerprintResult]:
    """Insert fingerprint rows and return results with id/asset_id/created_at populated."""
    from datetime import datetime, timezone

    persisted: list[FingerprintResult] = []
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for r in results:
        fp_id = make_ulid()
        await conn.execute(
            """
            INSERT OR REPLACE INTO fingerprints
                (id, asset_id, tech, version, category, evidence, confidence, created_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (fp_id, asset_id, r.tech, r.version, r.category, r.evidence, r.confidence, now),
        )
        persisted.append(
            FingerprintResult(
                id=fp_id,
                asset_id=asset_id,
                tech=r.tech,
                version=r.version,
                category=r.category,
                evidence=r.evidence,
                confidence=r.confidence,
            )
        )
    await conn.commit()
    return persisted


async def _update_asset_summary(
    conn: aiosqlite.Connection,
    asset_id: str,
    results: list[FingerprintResult],
) -> None:
    """Update asset.server / cdn / waf columns from the highest-confidence tech."""

    def _best_of(cat: str) -> str | None:
        matches = [r for r in results if r.category == cat]
        if not matches:
            return None
        return max(matches, key=lambda x: x.confidence).tech

    server = _best_of("web-server")
    cdn = _best_of("cdn")
    waf = _best_of("waf")

    await conn.execute(
        """
        UPDATE assets
        SET server=COALESCE(?,server),
            cdn=COALESCE(?,cdn),
            waf=COALESCE(?,waf)
        WHERE id=?
        """,
        (server, cdn, waf, asset_id),
    )
    await conn.commit()


async def _insert_san_asset(
    conn: aiosqlite.Connection,
    program_id: str,
    hostname: str,
    parent_asset: Asset,
) -> None:
    """Insert a placeholder asset row for a SAN-discovered hostname."""
    from datetime import datetime, timezone

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_id = make_ulid()
    scheme = parent_asset.primary_scheme or "https"
    url = f"{scheme}://{hostname}"
    try:
        await conn.execute(
            """
            INSERT OR IGNORE INTO assets
                (id, program_id, host, port, scheme, url, ip, status,
                 seen_protocols, primary_scheme,
                 tags, last_seen, first_seen, created_at, updated_at)
            VALUES (?,?,?,NULL,?,?,NULL,'discovered_via_san',?,?,
                    '[]',?,?,?,?)
            """,
            (
                new_id, program_id, hostname,
                scheme, url,
                f'["{scheme}"]', scheme,
                now, now, now, now,
            ),
        )
        await conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("san_asset_insert_skipped", hostname=hostname, error=str(exc))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def fingerprint_asset(
    asset: Asset,
    probe_result: ProbeResult,
    probe_fn: _ProbeFn,
    conn: aiosqlite.Connection,
    *,
    favicon_cache: dict[str, tuple[int, str]] | None = None,
) -> list[FingerprintResult]:
    """Run all fingerprint parsers on a probe result, persist, and update asset.

    Args:
        asset: The asset being fingerprinted (must have ``id`` set).
        probe_result: HTTP probe result for the asset's canonical URL.
        probe_fn: Async probe callable (reuses rate limiting / settings).
        conn: Open aiosqlite connection for DB writes.
        favicon_cache: Optional shared dict for favicon URL dedup across assets.

    Returns:
        List of persisted ``FingerprintResult`` rows (with id/asset_id/created_at set).
    """
    assert asset.id is not None, "asset.id must be set before fingerprinting"

    bound = log.bind(asset_id=asset.id, host=asset.host)
    raw_results: list[FingerprintResult] = []

    # ── 1. Header parser ───────────────────────────────────────────────────
    try:
        raw_results.extend(parse_headers(probe_result.headers))
    except Exception as exc:  # noqa: BLE001
        bound.warning("header_parser_error", error=str(exc))

    # ── 2. Cookie parser ───────────────────────────────────────────────────
    try:
        # headers is a flat dict; collect Set-Cookie from it
        set_cookie_raw = probe_result.headers.get("set-cookie", "")
        cookie_headers: list[str] = [v.strip() for v in set_cookie_raw.split("\n") if v.strip()] if set_cookie_raw else []
        raw_results.extend(parse_cookies(cookie_headers))
    except Exception as exc:  # noqa: BLE001
        bound.warning("cookie_parser_error", error=str(exc))

    # ── 3. Body parser ─────────────────────────────────────────────────────
    try:
        raw_results.extend(
            parse_body(probe_result.body, probe_result.content_type or None, probe_result.url)
        )
    except Exception as exc:  # noqa: BLE001
        bound.warning("body_parser_error", error=str(exc))

    # ── 4. TLS parser ──────────────────────────────────────────────────────
    additional_hostnames: list[str] = []
    try:
        tls_fps, additional_hostnames = parse_tls(probe_result, asset)
        raw_results.extend(tls_fps)
    except Exception as exc:  # noqa: BLE001
        bound.warning("tls_parser_error", error=str(exc))

    # ── 5. Favicon hash (async) ────────────────────────────────────────────
    try:
        fav_result: tuple[int, str] | None = await hash_favicon(
            asset, probe_result, probe_fn, favicon_cache
        )
        if fav_result is not None:
            h, fav_url = fav_result
            fav_fp = lookup_favicon_db(h)
            if fav_fp is not None:
                raw_results.append(fav_fp)
    except Exception as exc:  # noqa: BLE001
        bound.warning("favicon_error", error=str(exc))

    # ── 6. De-duplicate + confidence boost ────────────────────────────────
    merged = _dedupe(raw_results)
    bound.debug("fingerprint_dedupe", raw=len(raw_results), merged=len(merged))

    # ── 7. Persist to DB ───────────────────────────────────────────────────
    persisted: list[FingerprintResult] = []
    try:
        persisted = await _persist_fingerprints(conn, asset.id, merged)
    except Exception as exc:  # noqa: BLE001
        bound.warning("fingerprint_persist_error", error=str(exc))

    # ── 8. Update asset summary columns ───────────────────────────────────
    try:
        await _update_asset_summary(conn, asset.id, merged)
    except Exception as exc:  # noqa: BLE001
        bound.warning("asset_summary_update_error", error=str(exc))

    # ── 9. SAN hostname discovery ─────────────────────────────────────────
    for hostname in additional_hostnames:
        try:
            await _insert_san_asset(conn, asset.program_id, hostname, asset)
        except Exception as exc:  # noqa: BLE001
            bound.debug("san_insert_error", hostname=hostname, error=str(exc))

    # ── 10. Publish event ─────────────────────────────────────────────────
    top3 = [
        {"tech": r.tech, "category": r.category, "confidence": r.confidence}
        for r in merged[:3]
    ]
    try:
        await publish(
            "asset.fingerprinted",
            {
                "asset_id": asset.id,
                "tech_count": len(merged),
                "primary_techs": top3,
            },
            program_id=asset.program_id,
        )
    except Exception as exc:  # noqa: BLE001
        bound.debug("event_publish_error", error=str(exc))

    return persisted

