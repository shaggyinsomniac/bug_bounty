"""
bounty.ui.routes.ai — LLM-powered AI assistance endpoints.

All results are SUGGESTIONS for the operator.  No changes are applied
automatically; every action requires explicit operator confirmation.

Routes:
    POST /api/ai/severity-check/{finding_id}  → severity suggestion
    POST /api/ai/dedup/{finding_id}           → duplicate candidates
    POST /api/ai/polish-report/{report_id}    → polished report body
    GET  /api/ai/usage                        → today's cost + cap
    POST /api/ai/apply-severity/{finding_id}  → operator applies suggested severity
    POST /api/ai/mark-duplicate/{finding_id}  → operator marks finding as duplicate
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bounty.db import get_conn
from bounty.exceptions import AICostCapExceededError
from bounty.models import EvidencePackage, Finding
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/ai", tags=["ai"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ApplySeverityRequest(BaseModel):
    severity: int
    """Operator-confirmed severity score (0-1000)."""


class MarkDuplicateRequest(BaseModel):
    duplicate_of: str
    """ID of the finding that this finding is a duplicate of."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _get_finding(conn: Any, finding_id: str) -> Finding:
    """Fetch a finding row and return a Finding model."""
    cur = await conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id!r} not found")
    d = {k: row[k] for k in row.keys()}
    tags_raw = d.get("tags", "[]")
    d["tags"] = json.loads(tags_raw) if isinstance(tags_raw, str) else tags_raw
    d["validated"] = bool(d.get("validated"))
    return Finding.model_validate(d)


async def _get_evidence(conn: Any, finding_id: str) -> list[EvidencePackage]:
    """Fetch evidence packages for a finding."""
    cur = await conn.execute(
        "SELECT * FROM evidence_packages WHERE finding_id = ? ORDER BY captured_at LIMIT 5",
        (finding_id,),
    )
    rows = await cur.fetchall()
    result: list[EvidencePackage] = []
    for row in rows:
        result.append(EvidencePackage.model_validate({k: row[k] for k in row.keys()}))
    return result


# ---------------------------------------------------------------------------
# GET /api/ai/usage
# ---------------------------------------------------------------------------

@router.get("/usage")
async def ai_usage(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Return today's AI request count, cost estimate, and configured cap."""
    from bounty.ai.client import get_client, _today

    client = get_client()
    usage = await client.get_today_usage()
    from bounty.config import get_settings
    settings = get_settings()
    return JSONResponse({
        **usage,
        "cap_usd": settings.ai_daily_cost_cap_usd,
        "ai_enabled": settings.ai_enabled,
    })


# ---------------------------------------------------------------------------
# POST /api/ai/severity-check/{finding_id}
# ---------------------------------------------------------------------------

@router.post("/severity-check/{finding_id}")
async def ai_severity_check(
    finding_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Suggest a severity adjustment for a finding (NEVER auto-applies)."""
    from bounty.ai.severity_check import review_severity

    async with get_conn(db_path) as conn:
        finding = await _get_finding(conn, finding_id)
        evidence = await _get_evidence(conn, finding_id)

    try:
        suggested, rationale = await review_severity(finding, evidence)
    except AICostCapExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"AI error: {exc}") from exc

    return JSONResponse({
        "finding_id": finding_id,
        "current_severity": finding.severity,
        "suggested_severity": suggested,
        "rationale": rationale,
        "auto_applied": False,
    })


# ---------------------------------------------------------------------------
# POST /api/ai/dedup/{finding_id}
# ---------------------------------------------------------------------------

@router.post("/dedup/{finding_id}")
async def ai_dedup(
    finding_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Return top-3 duplicate candidates for a finding (NEVER auto-merges)."""
    from bounty.ai.dedup import find_duplicate_findings

    async with get_conn(db_path) as conn:
        finding = await _get_finding(conn, finding_id)

        # Load all other findings as candidates (same severity tier ±200 to limit scope)
        sev_min = max(0, finding.severity - 200)
        sev_max = min(1000, finding.severity + 200)
        cur = await conn.execute(
            "SELECT * FROM findings WHERE id != ? AND severity >= ? AND severity <= ? "
            "AND status NOT IN ('duplicate', 'wont_fix', 'resolved') LIMIT 100",
            (finding_id, sev_min, sev_max),
        )
        rows = await cur.fetchall()
        candidates: list[Finding] = []
        for row in rows:
            d = {k: row[k] for k in row.keys()}
            tags_raw = d.get("tags", "[]")
            d["tags"] = json.loads(tags_raw) if isinstance(tags_raw, str) else tags_raw
            d["validated"] = bool(d.get("validated"))
            candidates.append(Finding.model_validate(d))

    try:
        raw_results = await find_duplicate_findings(finding, candidates)
    except AICostCapExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"AI error: {exc}") from exc

    # Enrich results with titles
    cand_map = {c.id: c for c in candidates if c.id}
    enriched: list[dict[str, Any]] = []
    for cand_id, confidence, reason in raw_results:
        cand = cand_map.get(cand_id)
        enriched.append({
            "candidate_id": cand_id,
            "title": cand.title if cand else "",
            "url": cand.url if cand else "",
            "confidence_pct": confidence,
            "reason": reason,
        })

    return JSONResponse({
        "finding_id": finding_id,
        "candidates": enriched,
        "auto_applied": False,
    })


# ---------------------------------------------------------------------------
# POST /api/ai/polish-report/{report_id}
# ---------------------------------------------------------------------------

@router.post("/polish-report/{report_id}")
async def ai_polish_report(
    report_id: int,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Return an AI-polished version of the report body (NEVER auto-saves)."""
    from bounty.ai.report_polish import polish_report_body

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "SELECT id, body, template FROM reports WHERE id = ?", (report_id,)
        )
        row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        original_body: str = row["body"] or ""
        template: str = row["template"] or "markdown"

    try:
        polished = await polish_report_body(original_body, template)
    except AICostCapExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"AI error: {exc}") from exc

    return JSONResponse({
        "report_id": report_id,
        "original_body": original_body,
        "polished_body": polished,
        "auto_applied": False,
    })


# ---------------------------------------------------------------------------
# POST /api/ai/apply-severity/{finding_id}  (operator confirms)
# ---------------------------------------------------------------------------

@router.post("/apply-severity/{finding_id}")
async def apply_severity(
    finding_id: str,
    body: ApplySeverityRequest,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Operator applies a suggested severity to a finding."""
    from bounty.models import severity_label as _sev_label

    if not (0 <= body.severity <= 1000):
        raise HTTPException(status_code=422, detail="Severity must be 0-1000")

    label = _sev_label(body.severity)
    ts = _now_iso()

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "UPDATE findings SET severity = ?, severity_label = ?, updated_at = ? "
            "WHERE id = ?",
            (body.severity, label, ts, finding_id),
        )
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail=f"Finding {finding_id!r} not found")
        await conn.commit()

    return JSONResponse({
        "finding_id": finding_id,
        "severity": body.severity,
        "severity_label": label,
        "updated_at": ts,
    })


# ---------------------------------------------------------------------------
# POST /api/ai/mark-duplicate/{finding_id}  (operator confirms)
# ---------------------------------------------------------------------------

@router.post("/mark-duplicate/{finding_id}")
async def mark_duplicate(
    finding_id: str,
    body: MarkDuplicateRequest,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Operator marks a finding as a duplicate of another finding."""
    ts = _now_iso()

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "UPDATE findings SET status = 'duplicate', updated_at = ? WHERE id = ?",
            (ts, finding_id),
        )
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail=f"Finding {finding_id!r} not found")
        await conn.commit()

    return JSONResponse({
        "finding_id": finding_id,
        "status": "duplicate",
        "duplicate_of": body.duplicate_of,
        "updated_at": ts,
    })

