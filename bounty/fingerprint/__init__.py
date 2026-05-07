"""
bounty.fingerprint — Technology fingerprinting engine.

Entry point: ``fingerprint_asset(asset, probe_result, probe_fn, conn)``

Design principles (Phase 3.2):
  P1 — Confidence is a tier, not a sliding scale.
       Tiers: definitive > strong > weak > hint.
       A 'weak' signal with no corroboration is dropped.
       A 'hint' is ALWAYS dropped when alone.
  P2 — Same-category mutual exclusion.
       DEFINITIVE in a category suppresses WEAK in the same category.
       Two DEFINITIVEs in the same category: first wins, second demoted to STRONG.
  P3 — Vendor precedence over generic.
       Loaded from data/vendor_overrides.json — specific hosting platforms
       suppress misleading framework/CMS detections.
  P4 — Corroboration boost is conservative.
       Two independent signals at the SAME tier → upgrade ONE tier (max definitive).
       Three or more same-tier signals → still only one-tier upgrade (no double-jump).
       One DEFINITIVE + any weaker → stays DEFINITIVE; weaker absorbed.
  P5 — Evidence is structured per source.
       Format: ``source:key=value`` e.g. ``header:server=nginx/1.18.0``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Coroutine

import aiosqlite
import structlog

from bounty.events import publish
from bounty.models import Asset, ConfidenceTier, FingerprintResult, ProbeResult, TIER_ORDER, TIER_UP
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
# Vendor overrides table (Principle 3)
# ---------------------------------------------------------------------------

_OVERRIDES_FILE = Path(__file__).parent / "data" / "vendor_overrides.json"
_VENDOR_OVERRIDES: dict[str, dict[str, list[str]]] = {}


def _load_vendor_overrides() -> dict[str, dict[str, list[str]]]:
    """Load vendor_overrides.json once at import time."""
    global _VENDOR_OVERRIDES
    if _VENDOR_OVERRIDES:
        return _VENDOR_OVERRIDES
    try:
        entries: list[dict[str, Any]] = json.loads(_OVERRIDES_FILE.read_text())
        _VENDOR_OVERRIDES = {
            e["vendor"]: {
                "suppress_categories": e.get("suppress_categories", []),
                "suppress_techs": e.get("suppress_techs", []),
            }
            for e in entries
        }
    except Exception:  # noqa: BLE001
        _VENDOR_OVERRIDES = {}
    return _VENDOR_OVERRIDES


_load_vendor_overrides()


# ---------------------------------------------------------------------------
# Principle 4 + Principle 1 — deduplication and corroboration
# ---------------------------------------------------------------------------

def _dedupe(results: list[FingerprintResult]) -> list[FingerprintResult]:
    """Apply Principles 1 and 4: corroboration boost + drop unsupported signals.

    P4 corroboration rules (applied per-tech group):
    - 1 signal at any tier → keep tier as-is
    - 2+ signals at the BEST tier → upgrade best tier by ONE step
    - One DEFINITIVE + any weaker → stays DEFINITIVE (weaker absorbed)
    - No double-jump: output tier is always at most one step above best input tier

    P1 drop rules (applied after boost):
    - 'hint' alone → dropped (hint never produces a standalone result)
    - 'weak' with only 1 total signal → dropped (needs corroboration)
    - 'weak' with 2+ signals → corroborated, survives

    Evidence is concatenated as ``"; "``-joined structured evidence strings
    per Principle 5.
    """
    groups: dict[str, list[FingerprintResult]] = {}
    for r in results:
        groups.setdefault(r.tech, []).append(r)

    merged: list[FingerprintResult] = []
    for tech, signals in groups.items():
        best: FingerprintResult = max(signals, key=lambda x: TIER_ORDER[x.confidence])
        best_tier: ConfidenceTier = best.confidence

        # Count signals AT the best tier
        same_tier_count = sum(1 for s in signals if s.confidence == best_tier)

        if best_tier == "definitive":
            # DEFINITIVE absorbs all weaker signals — no change
            final_tier: ConfidenceTier = "definitive"
        elif same_tier_count >= 2:
            # Two or more at the same tier → one-tier upgrade (P4)
            final_tier = TIER_UP[best_tier]
        else:
            final_tier = best_tier

        # P1: drop unsupported signals
        if final_tier == "hint":
            continue  # hint alone always dropped
        if final_tier == "weak" and len(signals) == 1:
            continue  # uncorroborated weak always dropped

        # P5: structured evidence — deduplicate and join
        evidence_parts = list(dict.fromkeys(s.evidence for s in signals if s.evidence))
        combined_evidence = "; ".join(evidence_parts)[:500]

        merged.append(
            FingerprintResult(
                tech=tech,
                version=best.version,
                category=best.category,
                confidence=final_tier,
                evidence=combined_evidence,
            )
        )

    return sorted(merged, key=lambda x: -TIER_ORDER[x.confidence])


# ---------------------------------------------------------------------------
# Principle 3 — vendor overrides
# ---------------------------------------------------------------------------

def _apply_vendor_overrides(results: list[FingerprintResult]) -> list[FingerprintResult]:
    """Apply vendor precedence rules (Principle 3).

    When a vendor in the overrides table is detected at STRONG or DEFINITIVE,
    suppress its listed tech and category targets in the same result set.
    The vendor detection itself is always preserved.

    Args:
        results: Merged fingerprint list (post-P4).

    Returns:
        Filtered list with overridden techs/categories removed.
    """
    overrides = _VENDOR_OVERRIDES
    if not overrides:
        return results

    active_vendors: set[str] = {
        r.tech
        for r in results
        if r.tech in overrides and TIER_ORDER[r.confidence] >= TIER_ORDER["strong"]
    }
    if not active_vendors:
        return results

    suppress_cats: set[str] = set()
    suppress_techs: set[str] = set()
    for vendor in active_vendors:
        ovr = overrides[vendor]
        suppress_cats.update(ovr.get("suppress_categories", []))
        suppress_techs.update(ovr.get("suppress_techs", []))

    out: list[FingerprintResult] = []
    for r in results:
        if r.tech in active_vendors:
            out.append(r)  # always keep the vendor detection itself
            continue
        if r.tech in suppress_techs:
            log.debug("vendor_override_suppressed", tech=r.tech, vendors=list(active_vendors))
            continue
        if r.category in suppress_cats:
            log.debug("vendor_override_suppressed_category",
                      tech=r.tech, category=r.category, vendors=list(active_vendors))
            continue
        out.append(r)
    return out


# ---------------------------------------------------------------------------
# Principle 2 — same-category mutual exclusion
# ---------------------------------------------------------------------------

def _apply_category_exclusion(results: list[FingerprintResult]) -> list[FingerprintResult]:
    """Apply same-category mutual exclusion (Principle 2).

    Rules per category:
    - If DEFINITIVE exists: drop all WEAK (and HINT) in that category.
    - If two DEFINITIVEs exist in the same category: first (by input order) wins;
      second is demoted to STRONG with a warning.
    - If STRONG exists (no DEFINITIVE): drop all HINT in that category.

    Args:
        results: Merged + vendor-filtered fingerprint list.

    Returns:
        List with intra-category conflicts resolved.
    """
    by_category: dict[str, list[FingerprintResult]] = {}
    for r in results:
        by_category.setdefault(r.category, []).append(r)

    out: list[FingerprintResult] = []
    for cat, items in by_category.items():
        # Preserve original order within category for deterministic winner selection
        # (first DEFINITIVE encountered wins)
        adjusted: list[FingerprintResult] = []
        def_count = 0
        for r in items:
            if r.confidence == "definitive":
                def_count += 1
                if def_count > 1:
                    # Second (or further) DEFINITIVE in same category → demote to STRONG
                    log.warning(
                        "category_definitive_collision",
                        category=cat,
                        winner=items[0].tech,
                        demoted=r.tech,
                    )
                    r = r.model_copy(update={"confidence": "strong"})
            adjusted.append(r)

        # Determine the best surviving tier after demotion
        best_tier = max((TIER_ORDER[r.confidence] for r in adjusted), default=0)

        for r in adjusted:
            r_tier = TIER_ORDER[r.confidence]
            # DEFINITIVE present: suppress WEAK (1) and HINT (0)
            if best_tier >= TIER_ORDER["definitive"] and r_tier <= TIER_ORDER["weak"]:
                log.debug(
                    "category_exclusion_suppressed",
                    category=cat,
                    tech=r.tech,
                    tier=r.confidence,
                    reason="definitive_present",
                )
                continue
            # STRONG present (no DEFINITIVE): suppress HINT (0)
            if best_tier >= TIER_ORDER["strong"] and r_tier < TIER_ORDER["weak"]:
                log.debug(
                    "category_exclusion_suppressed",
                    category=cat,
                    tech=r.tech,
                    tier=r.confidence,
                    reason="strong_present",
                )
                continue
            out.append(r)

    return sorted(out, key=lambda x: -TIER_ORDER[x.confidence])


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

async def _persist_fingerprints(
    conn: aiosqlite.Connection,
    asset_id: str,
    results: list[FingerprintResult],
) -> list[FingerprintResult]:
    """Insert fingerprint rows and return results with id/asset_id populated."""
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
    """Update asset.server / cdn / waf columns from the highest-tier tech."""

    def _best_of(cat: str) -> str | None:
        matches = [r for r in results if r.category == cat]
        if not matches:
            return None
        return max(matches, key=lambda x: TIER_ORDER[x.confidence]).tech

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
    """Run all fingerprint parsers, apply principles, persist, and update asset.

    Pipeline (per spec Phase 3.2):
      a) Run all parsers → collect raw signals
      b) _dedupe → corroboration boost (P4) + drop unsupported (P1)
      c) _apply_vendor_overrides → vendor precedence (P3)
      d) _apply_category_exclusion → same-category mutual exclusion (P2)
      e) Persist survivors to DB
      f) Update asset summary columns

    Args:
        asset: The asset being fingerprinted (must have ``id`` set).
        probe_result: HTTP probe result for the asset's canonical URL.
        probe_fn: Async probe callable (reuses rate limiting / settings).
        conn: Open aiosqlite connection for DB writes.
        favicon_cache: Optional shared dict for favicon URL dedup across assets.

    Returns:
        List of persisted ``FingerprintResult`` rows (with id/asset_id set).
    """
    assert asset.id is not None, "asset.id must be set before fingerprinting"

    bound = log.bind(asset_id=asset.id, host=asset.host)
    raw_results: list[FingerprintResult] = []

    # ── a.1 Header parser ──────────────────────────────────────────────────
    try:
        raw_results.extend(parse_headers(probe_result.headers))
    except Exception as exc:  # noqa: BLE001
        bound.warning("header_parser_error", error=str(exc))

    # ── a.2 Cookie parser ──────────────────────────────────────────────────
    try:
        set_cookie_raw = probe_result.headers.get("set-cookie", "")
        cookie_headers = [v.strip() for v in set_cookie_raw.split("\n") if v.strip()]
        raw_results.extend(parse_cookies(cookie_headers))
    except Exception as exc:  # noqa: BLE001
        bound.warning("cookie_parser_error", error=str(exc))

    # ── a.3 Body parser ────────────────────────────────────────────────────
    try:
        raw_results.extend(
            parse_body(probe_result.body, probe_result.content_type or None, probe_result.url)
        )
    except Exception as exc:  # noqa: BLE001
        bound.warning("body_parser_error", error=str(exc))

    # ── a.4 TLS parser ─────────────────────────────────────────────────────
    additional_hostnames: list[str] = []
    try:
        tls_fps, additional_hostnames = parse_tls(probe_result, asset)
        raw_results.extend(tls_fps)
    except Exception as exc:  # noqa: BLE001
        bound.warning("tls_parser_error", error=str(exc))

    # ── a.5 Favicon hash (async) ───────────────────────────────────────────
    try:
        fav_result: tuple[int, str] | None = await hash_favicon(
            asset, probe_result, probe_fn, favicon_cache
        )
        if fav_result is not None:
            h, _fav_url = fav_result
            fav_fp = lookup_favicon_db(h)
            if fav_fp is not None:
                raw_results.append(fav_fp)
    except Exception as exc:  # noqa: BLE001
        bound.warning("favicon_error", error=str(exc))

    # ── b. Corroboration boost + drop unsupported (P1 + P4) ───────────────
    deduped = _dedupe(raw_results)
    bound.debug("fingerprint_dedupe", raw=len(raw_results), deduped=len(deduped))

    # ── c. Vendor overrides (P3) ───────────────────────────────────────────
    vendor_filtered = _apply_vendor_overrides(deduped)

    # ── d. Same-category mutual exclusion (P2) ─────────────────────────────
    final = _apply_category_exclusion(vendor_filtered)
    bound.debug("fingerprint_final", surviving=len(final))

    # ── e. Persist to DB ───────────────────────────────────────────────────
    persisted: list[FingerprintResult] = []
    try:
        persisted = await _persist_fingerprints(conn, asset.id, final)
    except Exception as exc:  # noqa: BLE001
        bound.warning("fingerprint_persist_error", error=str(exc))

    # ── f. Update asset summary columns ────────────────────────────────────
    try:
        await _update_asset_summary(conn, asset.id, final)
    except Exception as exc:  # noqa: BLE001
        bound.warning("asset_summary_update_error", error=str(exc))

    # ── g. SAN hostname discovery ──────────────────────────────────────────
    for hostname in additional_hostnames:
        try:
            await _insert_san_asset(conn, asset.program_id, hostname, asset)
        except Exception as exc:  # noqa: BLE001
            bound.debug("san_insert_error", hostname=hostname, error=str(exc))

    # ── h. Publish event ───────────────────────────────────────────────────
    top3 = [
        {"tech": r.tech, "category": r.category, "confidence": r.confidence}
        for r in final[:3]
    ]
    try:
        await publish(
            "asset.fingerprinted",
            {
                "asset_id": asset.id,
                "tech_count": len(final),
                "primary_techs": top3,
            },
            program_id=asset.program_id,
        )
    except Exception as exc:  # noqa: BLE001
        bound.debug("event_publish_error", error=str(exc))

    return persisted

