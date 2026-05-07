"""
bounty.targets.bugcrowd — Fetch Bugcrowd program scope.

Bugcrowd exposes a public JSON scope endpoint at:

  https://bugcrowd.com/<slug>/target_groups.json

This returns the targets grouped by type.  For programs that don't expose
this endpoint the HTML page is scraped as a fallback (the scope table is
rendered server-side with semantic markup).

Authentication:
  Set ``BC_EMAIL`` and ``BC_PASSWORD`` env vars for session auth, OR
  ``BC_API_TOKEN`` for Bearer token auth.  Both are optional; unauthenticated
  requests work for public programs.

Rate limiting:
  Bugcrowd doesn't publish rate limit headers consistently; we use a fixed
  1-second delay between retries.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any

import httpx

from bounty import get_logger
from bounty.exceptions import PlatformError
from bounty.models import Program, Target

log = get_logger(__name__)

_MAX_RETRIES = 3
_RETRY_DELAY = 1.5  # seconds


def _build_headers() -> dict[str, str]:
    """Build request headers, adding Bearer auth if token configured.

    Returns:
        Headers dict.
    """
    headers: dict[str, str] = {
        "User-Agent": "BountyScanner/1.0 (security research)",
        "Accept": "application/json",
    }
    token = os.environ.get("BC_API_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _asset_type_to_internal(bc_type: str) -> str:
    """Map a Bugcrowd target type to internal asset_type.

    Args:
        bc_type: e.g. ``"website"``, ``"api"``, ``"android"``, ``"ios"``.

    Returns:
        Internal asset_type string.
    """
    t = bc_type.lower()
    if t in {"website", "api", "url"}:
        return "url"
    if t in {"android", "google_play"}:
        return "android"
    if t in {"ios", "apple_store"}:
        return "ios"
    if t in {"cidr", "ip_range"}:
        return "cidr"
    if t in {"wildcard"}:
        return "wildcard"
    return "other"


def _parse_target_groups(
    groups: list[dict[str, Any]], program_id: str
) -> list[Target]:
    """Parse Bugcrowd target_groups JSON into Target objects.

    Args:
        groups: The ``target_groups`` list from the API response.
        program_id: Program ID for the Target.

    Returns:
        List of ``Target`` objects.
    """
    targets: list[Target] = []
    for group in groups:
        in_scope_flag: bool = not bool(group.get("out_of_scope", False))
        scope_type = "in_scope" if in_scope_flag else "out_of_scope"
        for target_item in group.get("targets", []):
            identifier = str(
                target_item.get("target", target_item.get("name", ""))
            ).strip()
            if not identifier:
                continue
            raw_type = str(target_item.get("type", "website"))
            targets.append(
                Target(
                    program_id=program_id,
                    scope_type=scope_type,  # type: ignore[arg-type]
                    asset_type=_asset_type_to_internal(raw_type),  # type: ignore[arg-type]
                    value=identifier,
                    notes=str(target_item.get("description", "") or ""),
                )
            )
    return targets


def _scrape_html_scope(html: str, program_id: str) -> list[Target]:
    """Extract scope entries from Bugcrowd's HTML program page as fallback.

    Looks for ``<li>`` elements inside a ``<div>`` with class ``target-list``
    or a ``<table>`` with ``id="scope-table"``.  This is fragile and should
    only be used if the JSON endpoint fails.

    Args:
        html: Full page HTML.
        program_id: Program ID for the Target.

    Returns:
        List of ``Target`` objects (may be empty if the page format changed).
    """
    targets: list[Target] = []
    # Pattern: look for scope list items like "*.example.com"
    pattern = re.compile(
        r'class="[^"]*target[^"]*"[^>]*>\s*<[^>]+>\s*([\w.*\-/:]+)\s*</[^>]+>',
        re.IGNORECASE,
    )
    for match in pattern.finditer(html):
        identifier = match.group(1).strip()
        if len(identifier) < 3 or " " in identifier:
            continue
        asset_type = "wildcard" if identifier.startswith("*.") else "url"
        targets.append(
            Target(
                program_id=program_id,
                scope_type="in_scope",
                asset_type=asset_type,  # type: ignore[arg-type]
                value=identifier,
            )
        )
    return targets


async def fetch_program_scope(slug: str) -> tuple[Program, list[Target]]:
    """Fetch the public scope for a Bugcrowd program.

    Args:
        slug: The Bugcrowd program slug, e.g. ``"tesla"``.

    Returns:
        A tuple of ``(Program, list[Target])``.

    Raises:
        PlatformError: On 404,[403, or repeated failures.
    """
    log.info("bugcrowd_fetch_scope_start", slug=slug)
    program_id = f"bugcrowd:{slug}"
    headers = _build_headers()

    # Try the JSON target groups endpoint first
    json_url = f"https://bugcrowd.com/{slug}/target_groups.json"

    for attempt in range(_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
                headers=headers,
            ) as client:
                resp = await client.get(json_url)

            if resp.status_code == 200:
                data: dict[str, Any] = resp.json()
                groups: list[dict[str, Any]] = data.get("target_groups", [])
                targets = _parse_target_groups(groups, program_id)

                program = Program(
                    id=program_id,
                    platform="bugcrowd",
                    handle=slug,
                    name=data.get("name", slug),
                    url=f"https://bugcrowd.com/{slug}",
                    policy_url=f"https://bugcrowd.com/{slug}",
                )
                log.info(
                    "bugcrowd_scope_fetched",
                    slug=slug,
                    targets=len(targets),
                )
                return program, targets

            if resp.status_code == 404:
                # Try HTML fallback before giving up
                break

            if resp.status_code in {401, 403}:
                raise PlatformError(
                    "bugcrowd",
                    resp.status_code,
                    f"Program {slug!r} requires authentication",
                )

            if resp.status_code == 429:
                if attempt < _MAX_RETRIES - 1:
                    await asyncio.sleep(_RETRY_DELAY * (attempt + 1))
                    continue
                raise PlatformError("bugcrowd", 429, "Rate limited")

            # Unexpected status — break to HTML fallback
            break

        except PlatformError:
            raise
        except Exception as exc:
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(_RETRY_DELAY)
                continue
            raise PlatformError("bugcrowd", 0, str(exc)) from exc

    # HTML fallback
    log.info("bugcrowd_falling_back_to_html", slug=slug)
    html_url = f"https://bugcrowd.com/{slug}"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
            headers={**headers, "Accept": "text/html"},
        ) as client:
            resp = await client.get(html_url)

        if resp.status_code == 404:
            raise PlatformError("bugcrowd", 404, f"Program {slug!r} not found")

        if resp.status_code != 200:
            raise PlatformError(
                "bugcrowd", resp.status_code, f"Unexpected status for {slug!r}"
            )

        targets = _scrape_html_scope(resp.text, program_id)
        program = Program(
            id=program_id,
            platform="bugcrowd",
            handle=slug,
            name=slug,
            url=html_url,
            policy_url=html_url,
        )
        log.info(
            "bugcrowd_scope_html_scraped",
            slug=slug,
            targets=len(targets),
        )
        return program, targets

    except PlatformError:
        raise
    except Exception as exc:
        raise PlatformError("bugcrowd", 0, str(exc)) from exc

