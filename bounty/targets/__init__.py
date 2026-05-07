"""
bounty.targets — Program scope fetching and management.

Re-exports:
- ``load_scope`` — parse a YAML/JSON scope file
- ``fetch_for_platform`` — unified dispatcher to fetch scope from any platform
- Per-platform ``fetch_program_scope`` — direct access if needed
"""

from __future__ import annotations

from bounty.models import Program, Target
from bounty.targets.manual import ScopeRules, load_scope

__all__ = [
    "load_scope",
    "ScopeRules",
    "fetch_for_platform",
]


async def fetch_for_platform(
    platform: str,
    identifier: str,
) -> tuple[Program, list[Target]]:
    """Unified dispatcher: fetch program scope from any supported platform.

    Args:
        platform: One of ``"h1"``, ``"bugcrowd"``, ``"intigriti"``.
        identifier: Platform-specific program handle or slug.

    Returns:
        A tuple of ``(Program, list[Target])``.

    Raises:
        ValueError: If ``platform`` is not recognised.
        PlatformError: On API failures.
    """
    if platform == "h1":
        from bounty.targets.h1 import fetch_program_scope
        return await fetch_program_scope(identifier)
    if platform == "bugcrowd":
        from bounty.targets.bugcrowd import fetch_program_scope as bc_fetch
        return await bc_fetch(identifier)
    if platform == "intigriti":
        from bounty.targets.intigriti import fetch_program_scope as ig_fetch
        return await ig_fetch(identifier)
    raise ValueError(
        f"Unknown platform {platform!r}. "
        "Choose one of: h1, bugcrowd, intigriti"
    )

