"""
bounty.targets.intigriti — Fetch Intigriti program scope.

Intigriti exposes a public API at:

  https://api.intigriti.com/core/public/program/<company>/<program>

The endpoint returns a JSON document including a ``domains`` array and an
``outOfScope`` array.

Authentication:
  Set ``INTIGRITI_TOKEN`` env var for Bearer token auth.  Not required for
  public programs.

Rate limiting:
  Intigriti doesn't document rate limits for the public API.  We use 2-second
  back-off on 429s.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from bounty import get_logger
from bounty.exceptions import PlatformError
from bounty.models import Program, Target

log = get_logger(__name__)

_MAX_RETRIES = 3
_RETRY_DELAY = 2.0


def _build_headers() -> dict[str, str]:
    """Build request headers, adding Bearer auth if token configured."""
    headers: dict[str, str] = {
        "User-Agent": "BountyScanner/1.0 (security research)",
        "Accept": "application/json",
    }
    token = os.environ.get("INTIGRITI_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _endpoint_for(identifier: str) -> str:
    """Resolve the API endpoint URL from an identifier.

    Accepts either:
    - ``company/program`` (two-part slug)
    - ``program`` (bare slug — we'll hit the search endpoint)

    Args:
        identifier: Program identifier.

    Returns:
        Full API URL.
    """
    if "/" in identifier:
        company, program = identifier.split("/", 1)
        return f"https://api.intigriti.com/core/public/program/{company}/{program}"
    # Try the single-identifier search endpoint
    return f"https://api.intigriti.com/core/public/program/{identifier}"


def _parse_domain_entry(
    entry: dict[str, Any],
    program_id: str,
    scope_type: str,
) -> Target | None:
    """Parse a single domain entry from the Intigriti API.

    Args:
        entry: Dict with ``endpoint`` and ``type`` keys.
        program_id: Program ID for the Target.
        scope_type: ``"in_scope"`` or ``"out_of_scope"``.

    Returns:
        A ``Target`` object, or ``None`` if the entry is invalid.
    """
    endpoint = str(entry.get("endpoint", "")).strip()
    if not endpoint:
        return None

    raw_type = str(entry.get("type", "url")).lower()
    type_map: dict[str, str] = {
        "url": "url",
        "wildcard": "wildcard",
        "cidr": "cidr",
        "iprange": "cidr",
        "ios": "ios",
        "android": "android",
        "apk": "android",
        "ipa": "ios",
    }
    asset_type = type_map.get(raw_type, "other")

    return Target(
        program_id=program_id,
        scope_type=scope_type,  # type: ignore[arg-type]
        asset_type=asset_type,  # type: ignore[arg-type]
        value=endpoint,
        notes=str(entry.get("description", "") or ""),
    )


async def fetch_program_scope(
    identifier: str,
) -> tuple[Program, list[Target]]:
    """Fetch the public scope for an Intigriti program.

    Args:
        identifier: Either ``"company/program"`` or just ``"program"``.

    Returns:
        A tuple of ``(Program, list[Target])``.

    Raises:
        PlatformError: On 404, 403, or repeated failures.
    """
    log.info("intigriti_fetch_scope_start", identifier=identifier)
    program_id = f"intigriti:{identifier.replace('/', ':')}"
    url = _endpoint_for(identifier)
    headers = _build_headers()

    for attempt in range(_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
                headers=headers,
            ) as client:
                resp = await client.get(url)

            if resp.status_code == 200:
                data: dict[str, Any] = resp.json()
                return _parse_response(identifier, program_id, data)

            if resp.status_code == 404:
                raise PlatformError(
                    "intigriti", 404, f"Program {identifier!r} not found"
                )

            if resp.status_code in {401, 403}:
                raise PlatformError(
                    "intigriti",
                    resp.status_code,
                    f"Program {identifier!r} requires authentication "
                    "(set INTIGRITI_TOKEN)",
                )

            if resp.status_code == 429:
                if attempt < _MAX_RETRIES - 1:
                    await asyncio.sleep(_RETRY_DELAY * (attempt + 1))
                    continue
                raise PlatformError("intigriti", 429, "Rate limited")

            raise PlatformError(
                "intigriti",
                resp.status_code,
                f"Unexpected HTTP {resp.status_code} for {identifier!r}",
            )

        except PlatformError:
            raise
        except httpx.TimeoutException as exc:
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(_RETRY_DELAY)
                continue
            raise PlatformError("intigriti", 0, f"Timeout: {exc}") from exc
        except Exception as exc:
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(_RETRY_DELAY)
                continue
            raise PlatformError("intigriti", 0, str(exc)) from exc

    raise PlatformError(
        "intigriti", 0, f"Failed after {_MAX_RETRIES} retries for {identifier!r}"
    )


def _parse_response(
    identifier: str,
    program_id: str,
    data: dict[str, Any],
) -> tuple[Program, list[Target]]:
    """Parse Intigriti API response into Program and Target objects.

    Args:
        identifier: Original identifier string.
        program_id: Constructed program ID.
        data: Parsed JSON from the API.

    Returns:
        ``(Program, list[Target])`` tuple.
    """
    name = str(data.get("name", identifier))
    handle = str(data.get("handle", identifier))
    company_handle = str(data.get("companyHandle", ""))
    program_handle = str(data.get("programHandle", handle))

    program_url = (
        f"https://app.intigriti.com/programs/{company_handle}/{program_handle}"
        if company_handle
        else f"https://app.intigriti.com/programs/{program_handle}"
    )

    program = Program(
        id=program_id,
        platform="intigriti",
        handle=handle,
        name=name,
        url=program_url,
        policy_url=program_url,
    )

    targets: list[Target] = []

    # In-scope domains
    for entry in data.get("domains", []):
        if isinstance(entry, dict):
            t = _parse_domain_entry(entry, program_id, "in_scope")
            if t:
                targets.append(t)
        elif isinstance(entry, str):
            targets.append(
                Target(
                    program_id=program_id,
                    scope_type="in_scope",
                    asset_type="wildcard" if entry.startswith("*.") else "url",
                    value=entry,
                )
            )

    # Out-of-scope domains
    for entry in data.get("outOfScope", []):
        if isinstance(entry, dict):
            t = _parse_domain_entry(entry, program_id, "out_of_scope")
            if t:
                targets.append(t)
        elif isinstance(entry, str):
            targets.append(
                Target(
                    program_id=program_id,
                    scope_type="out_of_scope",
                    asset_type="url",
                    value=entry,
                )
            )

    # Also handle "inScope" key variant
    for entry in data.get("inScope", []):
        if isinstance(entry, dict):
            t = _parse_domain_entry(entry, program_id, "in_scope")
            if t:
                targets.append(t)

    log.info(
        "intigriti_scope_fetched",
        identifier=identifier,
        targets=len(targets),
    )
    return program, targets

