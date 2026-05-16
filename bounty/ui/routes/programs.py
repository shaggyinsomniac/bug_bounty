"""
bounty.ui.routes.programs — /api/programs endpoints.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bounty.db import get_conn
from bounty.models import Platform
from bounty.ui.deps import ApiAuthDep, DbPathDep
from bounty.ulid import make_ulid

router = APIRouter(prefix="/api/programs", tags=["programs"])


def _prog_row(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    if isinstance(d.get("bounty_table"), str):
        try:
            d["bounty_table"] = json.loads(d["bounty_table"])
        except (json.JSONDecodeError, ValueError):
            d["bounty_table"] = None
    d["active"] = bool(d.get("active"))
    return d


def _target_row(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


@router.get("")
async def list_programs(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    active_only: bool = Query(default=False),
) -> JSONResponse:
    """List all programs."""
    where = "WHERE active = 1" if active_only else ""
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"SELECT * FROM programs {where} ORDER BY name"
        )
        rows = await cur.fetchall()
    return JSONResponse({"items": [_prog_row(r) for r in rows]})


@router.get("/{program_id}")
async def get_program(
    program_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Program detail with targets, asset count, and finding count."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute("SELECT * FROM programs WHERE id = ?", (program_id,))
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Program not found")

        prog = _prog_row(row)

        t_cur = await conn.execute(
            "SELECT * FROM targets WHERE program_id = ? ORDER BY scope_type, asset_type",
            (program_id,),
        )
        targets = [_target_row(r) for r in await t_cur.fetchall()]

        a_cur = await conn.execute(
            "SELECT COUNT(*) FROM assets WHERE program_id = ?", (program_id,)
        )
        a_row = await a_cur.fetchone()

        f_cur = await conn.execute(
            "SELECT COUNT(*) FROM findings WHERE program_id = ?", (program_id,)
        )
        f_row = await f_cur.fetchone()

    prog["targets"] = targets
    prog["asset_count"] = a_row[0] if a_row else 0
    prog["finding_count"] = f_row[0] if f_row else 0
    return JSONResponse(prog)


class TargetSpec(BaseModel):
    scope_type: Literal["in_scope", "out_of_scope"] = "in_scope"
    asset_type: Literal["url", "wildcard", "cidr", "android", "ios", "other", "ip", "asn", "domain"] = "domain"
    value: str


class ProgramCreateRequest(BaseModel):
    platform: Platform
    handle: str
    name: str
    url: str = ""
    policy_url: str = ""
    scope: list[TargetSpec] = []


@router.post("", status_code=201)
async def create_program(
    body: ProgramCreateRequest,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Create a manual program with optional scope rules."""
    program_id = make_ulid()
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with get_conn(db_path) as conn:
        try:
            await conn.execute(
                """
                INSERT INTO programs (id, platform, handle, name, url, policy_url, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (program_id, body.platform, body.handle, body.name, body.url, body.policy_url, ts, ts),
            )
        except Exception as exc:
            raise HTTPException(status_code=409, detail=f"Program already exists: {exc}") from exc

        for t in body.scope:
            await conn.execute(
                "INSERT INTO targets (program_id, scope_type, asset_type, value) VALUES (?, ?, ?, ?)",
                (program_id, t.scope_type, t.asset_type, t.value),
            )
        await conn.commit()

        cur = await conn.execute("SELECT * FROM programs WHERE id = ?", (program_id,))
        row = await cur.fetchone()

    return JSONResponse(_prog_row(row), status_code=201)  # type: ignore[arg-type]


class ProgramPatch(BaseModel):
    name: str | None = None
    active: bool | None = None
    url: str | None = None
    policy_url: str | None = None


@router.patch("/{program_id}")
async def patch_program(
    program_id: str,
    body: ProgramPatch,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Update program fields."""
    sets: list[str] = []
    params: list[Any] = []

    if body.name is not None:
        sets.append("name = ?")
        params.append(body.name)
    if body.active is not None:
        sets.append("active = ?")
        params.append(1 if body.active else 0)
    if body.url is not None:
        sets.append("url = ?")
        params.append(body.url)
    if body.policy_url is not None:
        sets.append("policy_url = ?")
        params.append(body.policy_url)
    if not sets:
        raise HTTPException(status_code=422, detail="No fields to update")

    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sets.append("updated_at = ?")
    params.append(ts)
    params.append(program_id)

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"UPDATE programs SET {', '.join(sets)} WHERE id = ?", params
        )
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Program not found")

        row_cur = await conn.execute("SELECT * FROM programs WHERE id = ?", (program_id,))
        updated = await row_cur.fetchone()

    return JSONResponse(_prog_row(updated))  # type: ignore[arg-type]


@router.delete("/{program_id}", status_code=204)
async def delete_program(
    program_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> None:
    """Delete a program (CASCADE removes assets, scans, findings, targets)."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute("DELETE FROM programs WHERE id = ?", (program_id,))
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Program not found")

