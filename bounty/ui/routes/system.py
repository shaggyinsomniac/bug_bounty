"""
bounty.ui.routes.system — /api/system/* endpoints.

Provides system info, DB maintenance, and settings persistence.
"""

from __future__ import annotations

import platform
import sqlite3
import sys
from pathlib import Path
from typing import Any

import fastapi
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import bounty
from bounty.db import get_conn
from bounty.ui.deps import ApiAuthDep, DbPathDep

router = APIRouter(prefix="/api/system", tags=["system"])

# Stand-alone router for /api/seed (not under /api/system prefix)
seed_router = APIRouter(tags=["seed"])


# ---------------------------------------------------------------------------
# Info
# ---------------------------------------------------------------------------

@router.get("/info")
async def system_info(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Return version info, DB path, and directory sizes."""
    bounty_version: str = getattr(bounty, "__version__", "0.1.0")

    ev_dir = db_path.parent / "evidence"
    ev_bytes = sum(
        f.stat().st_size for f in ev_dir.rglob("*") if f.is_file()
    ) if ev_dir.exists() else 0

    db_bytes = db_path.stat().st_size if db_path.exists() else 0

    return JSONResponse({
        "bounty_version": bounty_version,
        "python_version": sys.version,
        "fastapi_version": fastapi.__version__,
        "db_path": str(db_path),
        "db_size_bytes": db_bytes,
        "evidence_dir": str(ev_dir),
        "evidence_size_bytes": ev_bytes,
        "platform": platform.platform(),
    })


# ---------------------------------------------------------------------------
# Wipe test data
# ---------------------------------------------------------------------------

class WipeRequest(BaseModel):
    confirm: bool = False


@router.post("/wipe-test-data")
async def wipe_test_data(
    body: WipeRequest,
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Remove rows with test/dummy data from all tables. Requires confirm=true."""
    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="Must pass confirm=true to wipe test data",
        )

    deleted: dict[str, int] = {}
    async with get_conn(db_path) as conn:
        for table, col in [
            ("findings", "title"),
            ("assets", "host"),
            ("scans", "id"),
        ]:
            try:
                cur = await conn.execute(
                    f"DELETE FROM {table} WHERE {col} LIKE '%test%' OR {col} LIKE '%dummy%'"
                )
                deleted[table] = cur.rowcount
            except Exception:
                deleted[table] = 0
        await conn.commit()

    return JSONResponse({"deleted": deleted, "status": "ok"})


# ---------------------------------------------------------------------------
# Vacuum
# ---------------------------------------------------------------------------

@router.post("/vacuum")
async def vacuum_db(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Run SQLITE VACUUM to compact the database."""
    try:
        conn_sync = sqlite3.connect(str(db_path))
        conn_sync.execute("VACUUM")
        conn_sync.close()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"VACUUM failed: {exc}") from exc
    return JSONResponse({"status": "ok", "db_path": str(db_path)})


# ---------------------------------------------------------------------------
# Settings write (append to .env)
# ---------------------------------------------------------------------------

class SettingsWrite(BaseModel):
    key: str
    value: str


@router.post("/settings")
async def write_setting(
    body: SettingsWrite,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Append or update a single key in the .env file."""
    allowed_keys = {"UI_TOKEN", "SHODAN_API_KEY", "DISCORD_WEBHOOK_FINDINGS",
                    "DISCORD_WEBHOOK_SECRETS", "DEFAULT_INTENSITY"}
    if body.key.upper() not in allowed_keys:
        raise HTTPException(status_code=422, detail=f"Key not allowed: {body.key}")

    env_path = Path(".env")
    try:
        lines: list[str] = []
        if env_path.exists():
            lines = env_path.read_text().splitlines()

        key_upper = body.key.upper()
        replaced = False
        new_lines: list[str] = []
        for line in lines:
            if line.startswith(f"{key_upper}=") or line.startswith(f"{key_upper} ="):
                new_lines.append(f"{key_upper}={body.value}")
                replaced = True
            else:
                new_lines.append(line)
        if not replaced:
            new_lines.append(f"{key_upper}={body.value}")

        env_path.write_text("\n".join(new_lines) + "\n")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not write .env: {exc}") from exc

    return JSONResponse({"status": "ok", "key": body.key.upper()})


# ---------------------------------------------------------------------------
# POST /api/seed  (Phase 18 — first-run seed endpoint)
# ---------------------------------------------------------------------------

@seed_router.post("/api/seed")
async def seed_endpoint(
    db_path: DbPathDep,
    _auth: ApiAuthDep,
) -> JSONResponse:
    """Insert built-in seed programs (idempotent — skips existing programs).

    Returns ``{"inserted": N, "skipped": N}``.
    """
    from bounty.seed import seed_database

    try:
        result = await seed_database(db_path, force=False)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Seed failed: {exc}") from exc

    return JSONResponse({
        "inserted": result["inserted"],
        "skipped": result["skipped"],
        "programs": result.get("programs", []),
    })


