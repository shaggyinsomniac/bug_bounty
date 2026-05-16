"""
bounty.seed — Seed data for first-run experience.

Provides SEED_PROGRAMS (the canonical seed list) and seed_database(),
an async helper that idempotently inserts seed programs and their targets.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, TypedDict

from bounty import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Seed program definitions
# ---------------------------------------------------------------------------

class SeedTarget(TypedDict):
    scope_type: str
    asset_type: str
    value: str


class SeedProgram(TypedDict):
    id: str
    name: str
    platform: str
    handle: str
    description: str | None
    url: str
    policy_url: str
    targets: list[SeedTarget]


SEED_PROGRAMS: list[SeedProgram] = [
    {
        "id": "seed:hackerone",
        "name": "HackerOne (practice)",
        "platform": "manual",
        "handle": "hackerone-practice",
        "description": (
            "HackerOne explicitly permits scanning their main site for practice "
            "and to test bounty tools. https://hackerone.com/security"
        ),
        "url": "https://hackerone.com",
        "policy_url": "https://hackerone.com/security",
        "targets": [
            {"scope_type": "in_scope", "asset_type": "domain", "value": "hackerone.com"},
        ],
    },
    {
        "id": "seed:bugcrowd",
        "name": "Bugcrowd VRT reference",
        "platform": "manual",
        "handle": "bugcrowd-reference",
        "description": (
            "Bugcrowd's main site — useful for testing report templates "
            "against their format."
        ),
        "url": "https://bugcrowd.com",
        "policy_url": "",
        "targets": [
            {"scope_type": "in_scope", "asset_type": "domain", "value": "bugcrowd.com"},
        ],
    },
    {
        "id": "seed:localhost",
        "name": "Local synthetic target",
        "platform": "manual",
        "handle": "localhost-synthetic",
        "description": (
            "Use with tools/synthetic_target.py for verification scanning. "
            "Run python tools/synthetic_target.py --port 8765 then scan this program."
        ),
        "url": "http://127.0.0.1:8765",
        "policy_url": "",
        "targets": [
            {"scope_type": "in_scope", "asset_type": "url", "value": "http://127.0.0.1:8765"},
        ],
    },
]


# ---------------------------------------------------------------------------
# Synchronous seed helper (used by init_db which is synchronous)
# ---------------------------------------------------------------------------

def seed_sync(
    db_path: Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Synchronously insert seed data using raw sqlite3.

    This is the low-level implementation used by ``init_db()`` and the
    async ``seed_database()`` wrapper.

    Args:
        db_path: Path to the SQLite database file.
        force: If True, delete existing seed programs before re-inserting.

    Returns:
        ``{inserted: N, skipped: N, programs: [...names...]}``
    """
    inserted = 0
    skipped = 0
    programs_seeded: list[str] = []

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        for prog in SEED_PROGRAMS:
            row = conn.execute(
                "SELECT id FROM programs WHERE id=?", (prog["id"],)
            ).fetchone()

            if row is not None and not force:
                skipped += 1
                continue

            if row is not None and force:
                conn.execute("DELETE FROM programs WHERE id=?", (prog["id"],))

            conn.execute(
                """
                INSERT OR IGNORE INTO programs
                    (id, platform, handle, name, url, policy_url)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    prog["id"],
                    prog["platform"],
                    prog["handle"],
                    prog["name"],
                    prog["url"],
                    prog["policy_url"],
                ),
            )
            for target in prog["targets"]:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO targets
                        (program_id, scope_type, asset_type, value)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        prog["id"],
                        target["scope_type"],
                        target["asset_type"],
                        target["value"],
                    ),
                )
            inserted += 1
            programs_seeded.append(prog["name"])

        conn.commit()
    finally:
        conn.close()

    log.info("seed_complete", inserted=inserted, skipped=skipped)
    return {"inserted": inserted, "skipped": skipped, "programs": programs_seeded}


# ---------------------------------------------------------------------------
# Async seed_database — public API
# ---------------------------------------------------------------------------

async def seed_database(
    db_path: Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Idempotently insert seed programs and targets into the database.

    For each entry in :data:`SEED_PROGRAMS`:

    * If a program with the same ``id`` already exists and *force* is ``False``
      the program is skipped (idempotent).
    * If *force* is ``True`` the existing program (and its cascaded targets /
      assets) are deleted and re-inserted.

    Uses ``ON CONFLICT DO NOTHING`` semantics for target rows so that running
    twice never produces duplicates.

    Args:
        db_path: Path to the SQLite database file.
        force: When ``True``, delete and re-insert even if the program exists.

    Returns:
        ``{"inserted": N, "skipped": N, "programs": [name, ...]}``
    """
    import asyncio

    return await asyncio.to_thread(seed_sync, db_path, force=force)

