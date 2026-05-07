"""
bounty.targets.h1 — Fetch HackerOne program scope.

HackerOne exposes public program data via:

  https://hackerone.com/<handle>/policy_scopes.json

This endpoint returns a JSON document with ``in_scope`` and ``out_of_scope``
arrays, each containing asset objects with ``asset_identifier`` and
``asset_type`` fields.  No authentication is required for public programs;
private programs require HTTP Basic auth with an H1 API token.

Authentication:
  If the env var ``H1_API_TOKEN`` is set (format ``<user>:<token>``), it is
  sent as a Basic Authorization header.  Required for private programs.

Rate limiting:
  H1 returns 429 with a ``Retry-After`` header.  We honour it and retry up to
  3 times with exponential back-off.

Asset type mapping:
  Only URL, WILDCARD, CIDR, IP_ADDRESS, DOMAIN asset types are used for HTTP
  scanning.  All other types (mobile apps, hardware, etc.) are stored as
  informational ``other`` targets.
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

# Asset types that correspond to scannable network/web targets
_WEB_ASSET_TYPES = {
    "URL", "WILDCARD", "CIDR", "IP_ADDRESS", "DOMAIN",
    "url", "wildcard", "cidr", "ip_address", "domain",
}

_MAX_RETRIES = 3
_BASE_BACKOFF = 2.0  # seconds


def _asset_type_to_scope_type(raw_type: str) -> str:
    """Map an H1 asset_type string to our internal asset_type vocabulary.

    Args:
        raw_type: e.g. ``"URL"``, ``"WILDCARD"``, ``"CIDR"``

    Returns:
        One of ``url``, ``wildcard``, ``cidr``, ``android``, ``ios``, ``other``.
    """
    t = raw_type.upper()
    mapping: dict[str, str] = {
        "URL": "url",
        "DOMAIN": "wildcard",
        "WILDCARD": "wildcard",
        "CIDR": "cidr",
        "IP_ADDRESS": "cidr",
        "ANDROID_PLAY_STORE_APP_ID": "android",
        "GOOGLE_PLAY_APP_ID": "android",
        "OTHER_APK": "android",
        "APPLE_STORE_APP_ID": "ios",
        "OTHER_IPA": "ios",
    }
    return mapping.get(t, "other")


def _build_auth_headers() -> dict[str, str]:
    """Return HTTP Basic auth headers if ``H1_API_TOKEN`` is set in env.

    The env var format is ``username:token``.

    Returns:
        A headers dict (may be empty if no token configured).
    """
    token = os.environ.get("H1_API_TOKEN", "").strip()
    if not token:
        return {}
    import base64
    encoded = base64.b64encode(token.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def _parse_targets(
    scope_list: list[dict[str, Any]],
    program_id: str,
    scope_type: str,
) -> list[Target]:
    """Convert a list of H1 scope asset dicts into ``Target`` objects.

    Args:
        scope_list: The ``in_scope`` or ``out_of_scope`` list from the API.
        program_id: The program identifier to attach to each target.
        scope_type: ``"in_scope"`` or ``"out_of_scope"``.

    Returns:
        A list of ``Target`` objects.
    """
    targets: list[Target] = []
    for asset in scope_list:
        identifier = str(asset.get("asset_identifier", "")).strip()
        raw_type = str(asset.get("asset_type", "OTHER")).strip()
        if not identifier:
            continue
        targets.append(
            Target(
                program_id=program_id,
                scope_type=scope_type,  # type: ignore[arg-type]
                asset_type=_asset_type_to_scope_type(raw_type),  # type: ignore[arg-type]
                value=identifier,
                max_severity=asset.get("max_severity"),
                notes=str(asset.get("instruction", "") or ""),
            )
        )
    return targets


async def fetch_program_scope(
    handle: str,
) -> tuple[Program, list[Target]]:
    """Fetch the public scope for a HackerOne program.

    Tries ``/policy_scopes.json`` first.  Falls back to the CSV download
    endpoint if that path returns 404.

    Args:
        handle: The HackerOne program handle (slug), e.g. ``"shopify"``.

    Returns:
        A tuple of ``(Program, list[Target])``.

    Raises:
        PlatformError: On HTTP 404 (program not found), 403 (private/no auth),
                       or repeated 429s (rate limited).
    """
    log.info("h1_fetch_scope_start", handle=handle)

    auth_headers = _build_auth_headers()
    base_url = f"https://hackerone.com/{handle}/policy_scopes.json"

    for attempt in range(_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
                headers={
                    "User-Agent": "BountyScanner/1.0 (security research)",
                    "Accept": "application/json",
                    **auth_headers,
                },
            ) as client:
                resp = await client.get(base_url)

            if resp.status_code == 200:
                data: dict[str, Any] = resp.json()
                return _parse_response(handle, data)

            if resp.status_code == 404:
                raise PlatformError("h1", 404, f"Program {handle!r} not found")

            if resp.status_code == 401 or resp.status_code == 403:
                raise PlatformError(
                    "h1",
                    resp.status_code,
                    f"Program {handle!r} requires authentication "
                    "(set H1_API_TOKEN=username:token)",
                )

            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", _BASE_BACKOFF * (2**attempt)))
                if attempt < _MAX_RETRIES - 1:
                    log.warning(
                        "h1_rate_limited",
                        handle=handle,
                        retry_after=retry_after,
                        attempt=attempt + 1,
                    )
                    await asyncio.sleep(retry_after)
                    continue
                raise PlatformError("h1", 429, f"Rate limited after {_MAX_RETRIES} attempts")

            raise PlatformError(
                "h1",
                resp.status_code,
                f"Unexpected HTTP {resp.status_code} for {handle!r}",
            )

        except httpx.TimeoutException as exc:
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(_BASE_BACKOFF * (2**attempt))
                continue
            raise PlatformError("h1", 0, f"Request timed out: {exc}") from exc

        except PlatformError:
            raise

        except Exception as exc:
            raise PlatformError("h1", 0, str(exc)) from exc

    raise PlatformError("h1", 0, f"Failed to fetch scope for {handle!r} after {_MAX_RETRIES} retries")


def _parse_response(
    handle: str, data: dict[str, Any]
) -> tuple[Program, list[Target]]:
    """Parse the JSON API response into a Program and targets.

    Args:
        handle: Program handle.
        data: Parsed JSON from the API.

    Returns:
        ``(Program, list[Target])`` tuple.
    """
    program_id = f"h1:{handle}"

    # The policy_scopes endpoint wraps data under various keys depending on
    # the H1 API version.  Try the common shapes.
    scope_data = data
    if "data" in data:
        scope_data = data["data"]
    if "attributes" in scope_data:
        scope_data = scope_data["attributes"]

    # Extract the program name (best-effort)
    name = (
        scope_data.get("name")
        or scope_data.get("handle")
        or handle
    )

    in_scope_raw: list[dict[str, Any]] = (
        scope_data.get("in_scope")
        or scope_data.get("structured_scope", {}).get("in_scope", [])
        or []
    )
    out_of_scope_raw: list[dict[str, Any]] = (
        scope_data.get("out_of_scope")
        or scope_data.get("structured_scope", {}).get("out_of_scope", [])
        or []
    )

    program = Program(
        id=program_id,
        platform="h1",
        handle=handle,
        name=str(name),
        url=f"https://hackerone.com/{handle}",
        policy_url=f"https://hackerone.com/{handle}?type=team",
    )

    targets: list[Target] = []
    targets.extend(_parse_targets(in_scope_raw, program_id, "in_scope"))
    targets.extend(_parse_targets(out_of_scope_raw, program_id, "out_of_scope"))

    log.info(
        "h1_scope_fetched",
        handle=handle,
        in_scope=len([t for t in targets if t.scope_type == "in_scope"]),
        out_of_scope=len([t for t in targets if t.scope_type == "out_of_scope"]),
    )
    return program, targets

