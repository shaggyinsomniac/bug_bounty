"""
bounty.ui.routes.intel — /api/intel endpoints (Shodan credits, sweep, leads).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bounty.db import get_conn
from bounty.ui.deps import ApiAuthDep, DbPathDep, SettingsDep
from bounty.ulid import make_ulid

router = APIRouter(prefix="/api/intel", tags=["intel"])


def _lead_row(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    for field in ("hostnames", "raw_data"):
        if isinstance(d.get(field), str):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, ValueError):
                d[field] = [] if field == "hostnames" else {}
    return d


@router.get("/credits")
async def intel_credits(
    settings: SettingsDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Return remaining Shodan query credits."""
    if not settings.shodan_api_key:
        raise HTTPException(status_code=422, detail="SHODAN_API_KEY not configured")
    try:
        from bounty.intel.shodan import ShodanClient

        async with ShodanClient(settings.shodan_api_key) as client:
            remaining = await client.credits_remaining()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return JSONResponse({"credits": remaining})


class SweepRequest(BaseModel):
    query: str
    max_pages: int = 1
    program_id: str | None = None


async def _bg_sweep(query: str, max_pages: int, program_id: str | None, db_path: Any, api_key: str) -> None:
    from bounty.intel.shodan import ShodanClient

    async with ShodanClient(api_key) as client:
        results = await client.search(query, max_pages=max_pages)

    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with get_conn(db_path) as conn:
        for match in results:
            lead_id = make_ulid()
            ip: str = str(match.get("ip_str") or "")
            port: int | None = match.get("port")
            hostnames_raw: Any = match.get("hostnames") or []
            hostnames_json = json.dumps(hostnames_raw if isinstance(hostnames_raw, list) else [])
            await conn.execute(
                """
                INSERT OR IGNORE INTO leads
                    (id, source, source_query, ip, port, hostnames, org, asn,
                     product, title, raw_data, program_id, discovered_at)
                VALUES (?, 'shodan', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lead_id, query, ip, port, hostnames_json,
                    match.get("org"), match.get("asn"), match.get("product"),
                    (match.get("http") or {}).get("title") if isinstance(match.get("http"), dict) else None,
                    json.dumps(match), program_id, ts,
                ),
            )
        await conn.commit()


@router.post("/sweep", status_code=202)
async def intel_sweep(
    body: SweepRequest,
    background_tasks: BackgroundTasks,
    db_path: DbPathDep,
    settings: SettingsDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Trigger a Shodan sweep in the background."""
    if not settings.shodan_api_key:
        raise HTTPException(status_code=422, detail="SHODAN_API_KEY not configured")
    sweep_id = make_ulid()
    background_tasks.add_task(
        _bg_sweep, body.query, body.max_pages, body.program_id, db_path, settings.shodan_api_key
    )
    return JSONResponse({"sweep_id": sweep_id}, status_code=202)


@router.get("/leads")
async def list_leads(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    program_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """Paginated leads list."""
    clauses: list[str] = []
    params: list[Any] = []
    if program_id:
        clauses.append("program_id = ?")
        params.append(program_id)
    if status:
        clauses.append("status = ?")
        params.append(status)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    params.extend([limit, offset])

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"SELECT * FROM leads {where} ORDER BY discovered_at DESC LIMIT ? OFFSET ?",
            params,
        )
        rows = await cur.fetchall()
        cnt_cur = await conn.execute(
            f"SELECT COUNT(*) FROM leads {where}", count_params
        )
        cnt_row = await cnt_cur.fetchone()

    total: int = cnt_row[0] if cnt_row else 0
    return JSONResponse(
        {"items": [_lead_row(r) for r in rows], "total": total, "limit": limit, "offset": offset}
    )


class LeadPatch(BaseModel):
    action: str  # "promote" | "dismiss"
    program_id: str | None = None


@router.patch("/leads/{lead_id}")
async def patch_lead(
    lead_id: str,
    body: LeadPatch,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Promote a lead to an asset or dismiss it."""
    if body.action not in ("promote", "dismiss"):
        raise HTTPException(status_code=422, detail="action must be 'promote' or 'dismiss'")

    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM leads WHERE id = ?", (lead_id,))
        lead = await cur.fetchone()
        if lead is None:
            raise HTTPException(status_code=404, detail="Lead not found")

        if body.action == "dismiss":
            await conn.execute("UPDATE leads SET status='dismissed' WHERE id=?", (lead_id,))
            await conn.commit()
            return JSONResponse({"status": "dismissed", "lead_id": lead_id})

        # Promote: create asset
        effective_pid: str | None = body.program_id or lead["program_id"]
        if not effective_pid:
            raise HTTPException(status_code=422, detail="program_id required to promote")

        await conn.execute(
            "INSERT OR IGNORE INTO programs (id, platform, handle, name) VALUES (?, 'manual', ?, ?)",
            (effective_pid, effective_pid, effective_pid),
        )

        ip_val: str = str(lead["ip"])
        port_val: int | None = lead["port"]
        scheme = "https" if port_val == 443 else "http"
        canonical_port: int | None = port_val if port_val not in (80, 443, None) else None
        url = (
            f"{scheme}://{ip_val}:{canonical_port}"
            if canonical_port is not None
            else f"{scheme}://{ip_val}"
        )

        chk = await conn.execute(
            "SELECT id FROM assets WHERE program_id=? AND host=? AND COALESCE(port,-1)=COALESCE(?,-1)",
            (effective_pid, ip_val, canonical_port),
        )
        existing = await chk.fetchone()
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if existing:
            asset_id = str(existing["id"])
        else:
            asset_id = make_ulid()
            await conn.execute(
                """
                INSERT INTO assets
                    (id, program_id, host, port, scheme, url, ip, status,
                     seen_protocols, primary_scheme, tags, first_seen, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'discovered', ?, ?, '["lead"]', ?, ?, ?)
                """,
                (
                    asset_id, effective_pid, ip_val, canonical_port, scheme, url, ip_val,
                    json.dumps([scheme]), scheme, ts, ts, ts,
                ),
            )

        await conn.execute("UPDATE leads SET status='promoted' WHERE id=?", (lead_id,))
        await conn.commit()

    return JSONResponse({"status": "promoted", "lead_id": lead_id, "asset_id": asset_id})

