"""
bounty.ui.routes.secrets — /api/secrets endpoints.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from bounty.db import get_conn
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/secrets", tags=["secrets"])


def _sv_row(row: sqlite3.Row) -> dict[str, Any]:
    d: dict[str, Any] = {k: row[k] for k in row.keys()}
    if isinstance(d.get("scope"), str):
        try:
            d["scope"] = json.loads(d["scope"])
        except (json.JSONDecodeError, ValueError):
            d["scope"] = None
    return d


@router.get("")
async def list_secrets(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
    status: str | None = Query(default=None),
    provider: str | None = Query(default=None),
    finding_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """Paginated secrets list with optional filters."""
    clauses: list[str] = []
    params: list[Any] = []

    if status:
        clauses.append("status = ?")
        params.append(status)
    if provider:
        clauses.append("provider = ?")
        params.append(provider)
    if finding_id:
        clauses.append("finding_id = ?")
        params.append(finding_id)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_params = list(params)
    params.extend([limit, offset])

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            f"SELECT * FROM secrets_validations {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        rows = await cur.fetchall()
        cnt_cur = await conn.execute(
            f"SELECT COUNT(*) FROM secrets_validations {where}", count_params
        )
        cnt_row = await cnt_cur.fetchone()

    total: int = cnt_row[0] if cnt_row else 0
    return JSONResponse(
        {
            "items": [_sv_row(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@router.get("/{secret_id}")
async def get_secret(
    secret_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Full SecretValidation record."""
    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "SELECT * FROM secrets_validations WHERE id = ?", (secret_id,)
        )
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Secret validation not found")
    return JSONResponse(_sv_row(row))


@router.post("/{secret_id}/revalidate")
async def revalidate_secret(
    secret_id: str,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Force re-validation of a secret token."""
    import bounty.validate.registry as _reg  # noqa: F401 — side-effect: populates REGISTRY
    from bounty.secrets.scanner import SecretCandidate
    from bounty.validate._base import REGISTRY

    async with get_conn(db_path) as conn:
        cur = await conn.execute(
            "SELECT * FROM secrets_validations WHERE id = ?", (secret_id,)
        )
        row = await cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Secret validation not found")

        provider: str = str(row["provider"])
        validator = REGISTRY.get(provider)
        if validator is None:
            raise HTTPException(
                status_code=422, detail=f"No validator registered for provider: {provider}"
            )

        candidate = SecretCandidate(
            provider=provider,
            pattern_name=str(row["secret_pattern"]),
            value=str(row["secret_hash"]),
            context_before="",
            context_after="",
        )

        async with httpx.AsyncClient(timeout=15.0) as http:
            result = await validator.validate(candidate, http)

        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        scope_json = json.dumps(result.scope) if result.scope else None

        await conn.execute(
            """
            UPDATE secrets_validations
            SET status=?, scope=?, identity=?, last_checked=?, error_message=?, updated_at=?
            WHERE id=?
            """,
            (result.status, scope_json, result.identity, ts, result.error_message, ts, secret_id),
        )
        await conn.commit()

        updated_cur = await conn.execute(
            "SELECT * FROM secrets_validations WHERE id = ?", (secret_id,)
        )
        updated = await updated_cur.fetchone()

    return JSONResponse(_sv_row(updated))  # type: ignore[arg-type]

