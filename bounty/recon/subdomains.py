"""
bounty.recon.subdomains — Async subdomain enumeration via subfinder + crt.sh.

Two sources run in parallel:
  1. subfinder — runs as a subprocess, streams results line-by-line
  2. crt.sh    — queries certificate transparency logs via HTTPS, free, no auth

subfinder intensity mapping:
  gentle     — ``-passive`` flag (passive sources only, no active DNS)
  normal     — default subfinder behavior (passive + some active sources)
  aggressive — ``-all`` flag (all sources including brute-force word lists)

Timeouts:
  gentle / normal subfinder = 10 minutes
  aggressive subfinder      = 30 minutes
  crt.sh per-domain         = 30 seconds

On crt.sh failure / timeout: log warning, continue with subfinder-only results.
If subfinder is missing: crt.sh results are still returned.

Deduplication:
  Known subdomains for the domain are loaded from the DB at the start of
  enumeration; any hostname already present is skipped.  The DB query runs
  once (not per result) to keep the hot path fast.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import AsyncIterator
from pathlib import Path

import httpx

from bounty import get_logger
from bounty.config import get_settings
from bounty.exceptions import ToolFailedError, ToolMissingError, ToolTimeoutError

log = get_logger(__name__)

_GENTLE_TIMEOUT = 600       # 10 minutes
_NORMAL_TIMEOUT = 600       # 10 minutes
_AGGRESSIVE_TIMEOUT = 1800  # 30 minutes
_CRTSH_TIMEOUT = 30.0       # crt.sh per-domain timeout in seconds


def _find_tool(name: str) -> str:
    """Locate a tool binary.

    Checks ``settings.tools_dir`` first, then falls back to ``shutil.which``.

    Args:
        name: Binary name, e.g. ``"subfinder"``.

    Returns:
        Absolute path to the binary.

    Raises:
        ToolMissingError: If the binary cannot be found.
    """
    settings = get_settings()
    # Check tools_dir first
    candidate = settings.tools_dir / name
    if candidate.exists() and os.access(str(candidate), os.X_OK):
        return str(candidate)
    # Fall back to PATH
    found = shutil.which(name)
    if found:
        return found
    raise ToolMissingError(
        name,
        install_hint=(
            f"# Download from https://github.com/projectdiscovery/{name}/releases\n"
            f"# Place the binary at {candidate} or add it to PATH"
        ),
    )


async def _crtsh_hostnames(domain: str) -> set[str]:
    """Fetch subdomains from crt.sh certificate transparency search.

    Queries ``https://crt.sh/?q=%25.{domain}&output=json`` and returns a
    deduplicated set of lowercase FQDNs.  Each JSON entry has a
    ``name_value`` field that may contain newline-separated names and
    leading ``*.`` wildcards.

    This function is called concurrently with subfinder so the HTTP round-trip
    happens in parallel with subprocess I/O.

    Args:
        domain: Root domain to query, e.g. ``"example.com"``.

    Returns:
        Set of discovered hostnames (lowercased, wildcards stripped).
        Returns an empty set on any error (errors are logged as warnings).
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    bound_log = log.bind(domain=domain, source="crtsh")
    bound_log.debug("crtsh_start", url=url)
    found: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=_CRTSH_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})
            # crt.sh returns 404 when there are no matching certificates.
            # Treat it as an empty result rather than an error.
            if resp.status_code == 404:
                bound_log.debug("crtsh_empty_result", domain=domain)
                return found
            resp.raise_for_status()
            entries: list[dict[str, object]] = resp.json()

        for entry in entries:
            name_value = str(entry.get("name_value", ""))
            for raw in name_value.splitlines():
                hostname = raw.strip().lower().lstrip("*.").rstrip(".")
                if hostname and "." in hostname and " " not in hostname:
                    found.add(hostname)

        bound_log.info("crtsh_done", found=len(found))
    except httpx.TimeoutException:
        bound_log.warning("crtsh_timeout", timeout_s=_CRTSH_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        bound_log.warning("crtsh_failed", error=str(exc))
    return found


async def enumerate(
    domain: str,
    *,
    intensity: str = "normal",
    known_hosts: set[str] | None = None,
) -> AsyncIterator[str]:
    """Async generator that yields discovered subdomain hostnames.

    Runs subfinder as a subprocess and streams results as they arrive.
    Concurrently queries crt.sh; those results are yielded after subfinder
    completes (or when subfinder is not installed — crt.sh still runs).

    Skips hostnames already in ``known_hosts``.

    Args:
        domain: The root domain to enumerate, e.g. ``"example.com"``.
        intensity: One of ``"gentle"``, ``"normal"``, ``"aggressive"``.
        known_hosts: Set of already-known hostnames to skip.  If ``None``,
                     no deduplication against existing data is performed —
                     the caller must handle dedup.

    Yields:
        Discovered hostnames (FQDN strings, lowercased).

    Raises:
        ToolMissingError: If subfinder is not installed (raised after
                          crt.sh results are yielded so callers still
                          receive passive results).
        ToolTimeoutError: If the subfinder run exceeds the intensity timeout.
        ToolFailedError: If subfinder exits non-zero (stderr captured).
    """
    seen: set[str] = set(known_hosts or [])

    # Start crt.sh concurrently — runs while subfinder is streaming
    crtsh_task: asyncio.Task[set[str]] = asyncio.create_task(_crtsh_hostnames(domain))

    cmd: list[str] = []
    proc: asyncio.subprocess.Process | None = None
    tool_error: BaseException | None = None

    try:
        binary = _find_tool("subfinder")

        cmd = [binary, "-d", domain, "-silent", "-json"]
        if intensity == "gentle":
            cmd.append("-passive")
            timeout = _GENTLE_TIMEOUT
        elif intensity == "aggressive":
            cmd.append("-all")
            timeout = _AGGRESSIVE_TIMEOUT
        else:
            timeout = _NORMAL_TIMEOUT

        bound_log = log.bind(domain=domain, intensity=intensity, tool="subfinder")
        bound_log.info("subfinder_start", cmd=" ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None  # guaranteed by PIPE

        async def _read_stderr() -> str:
            assert proc is not None and proc.stderr is not None
            raw = await proc.stderr.read()
            return raw.decode("utf-8", errors="replace")

        # Start reading stderr concurrently so it doesn't block stdout
        stderr_task = asyncio.create_task(_read_stderr())

        try:
            async with asyncio.timeout(timeout):
                async for raw_line in proc.stdout:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    hostname = _parse_line(line)
                    if hostname and hostname not in seen:
                        seen.add(hostname)
                        bound_log.debug("subfinder_found", hostname=hostname)
                        yield hostname
        except TimeoutError:
            if proc.returncode is None:
                proc.kill()
            raise ToolTimeoutError("subfinder", timeout)

        await proc.wait()
        stderr_text = await stderr_task

        if proc.returncode is not None and proc.returncode not in (0, 1, 2):
            raise ToolFailedError("subfinder", proc.returncode, stderr_text[:500])
        if proc.returncode == 2:
            bound_log.debug(
                "subfinder_exit2_no_api_keys",
                hint="Configure ~/.config/subfinder/provider-config.yaml for more sources",
            )

        bound_log.info("subfinder_done", found=len(seen))

    except ToolMissingError as exc:
        # Store the error; still yield crt.sh results before propagating
        tool_error = exc
        log.warning("subfinder_missing_falling_back_to_crtsh", domain=domain)
    except (ToolTimeoutError, ToolFailedError) as exc:
        tool_error = exc
    except Exception as exc:  # noqa: BLE001
        bound_log = log.bind(domain=domain, intensity=intensity, tool="subfinder")
        bound_log.error("subfinder_unexpected_error", error=str(exc))
        tool_error = ToolFailedError("subfinder", -1, str(exc))
    finally:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    # ── Yield crt.sh results (runs regardless of subfinder outcome) ──────────
    crtsh_new = 0
    try:
        crtsh_found = await asyncio.wait_for(crtsh_task, timeout=_CRTSH_TIMEOUT)
        for hostname in sorted(crtsh_found):
            if hostname not in seen:
                seen.add(hostname)
                crtsh_new += 1
                yield hostname
        log.debug("crtsh_merged", domain=domain, new=crtsh_new, total_crtsh=len(crtsh_found))
    except TimeoutError:
        log.warning("crtsh_await_timeout", domain=domain)
        crtsh_task.cancel()
    except asyncio.CancelledError:
        pass
    except Exception as exc:  # noqa: BLE001
        log.warning("crtsh_merge_failed", domain=domain, error=str(exc))

    # Propagate any subfinder error AFTER crt.sh results have been yielded
    if tool_error is not None:
        raise tool_error


def _parse_line(line: str) -> str | None:
    """Parse one line from subfinder's JSON output.

    subfinder ``-json`` emits objects like::

        {"host": "sub.example.com", "input": "example.com", "source": "crtsh"}

    Falls back to treating the line as a bare hostname string.

    Args:
        line: A single output line.

    Returns:
        Lowercased FQDN, or ``None`` if the line is unparseable / empty.
    """
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            host = str(obj.get("host", "")).strip().lower().rstrip(".")
            return host if host else None
        except json.JSONDecodeError:
            pass
    # Bare hostname fallback
    host = line.lower().rstrip(".")
    if "." in host and " " not in host:
        return host
    return None

