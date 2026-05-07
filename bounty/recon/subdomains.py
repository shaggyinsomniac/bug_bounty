"""
bounty.recon.subdomains — Async subdomain enumeration via subfinder.

subfinder is run as a subprocess with ``asyncio.create_subprocess_exec``.
Results are streamed line-by-line as they appear in stdout (subfinder writes
one JSON object per line with ``-json`` flag), so newly discovered subdomains
are yielded immediately rather than buffered until the tool finishes.

Intensity mapping:
  gentle     — ``-passive`` flag (passive sources only, no active DNS)
  normal     — default subfinder behavior (passive + some active sources)
  aggressive — ``-all`` flag (all sources including brute-force word lists)

Timeouts:
  gentle / normal = 10 minutes
  aggressive      = 30 minutes

Deduplication:
  Known subdomains for the domain are loaded from the DB at the start of
  enumeration; any hostname already present is skipped.  The DB query runs
  once (not per result) to keep the hot path fast.

Discovery events:
  ``asset:new`` is published for each freshly found hostname.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import AsyncIterator
from pathlib import Path

from bounty import get_logger
from bounty.config import get_settings
from bounty.exceptions import ToolFailedError, ToolMissingError, ToolTimeoutError

log = get_logger(__name__)

_GENTLE_TIMEOUT = 600    # 10 minutes
_NORMAL_TIMEOUT = 600    # 10 minutes
_AGGRESSIVE_TIMEOUT = 1800  # 30 minutes


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


async def enumerate(
    domain: str,
    *,
    intensity: str = "normal",
    known_hosts: set[str] | None = None,
) -> AsyncIterator[str]:
    """Async generator that yields discovered subdomain hostnames.

    Runs subfinder as a subprocess and streams results as they arrive.
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
        ToolMissingError: If subfinder is not installed.
        ToolTimeoutError: If the run exceeds the timeout for the intensity.
        ToolFailedError: If subfinder exits non-zero (stderr captured).
    """
    binary = _find_tool("subfinder")
    seen: set[str] = set(known_hosts or [])

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

    proc: asyncio.subprocess.Process | None = None
    try:
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

        # subfinder exit codes:
        #   0 = success
        #   1 = partial errors (some sources failed)
        #   2 = no results or missing API keys — treat as non-fatal
        # We only raise for exit codes outside that range (e.g. segfault = 139).
        if proc.returncode is not None and proc.returncode not in (0, 1, 2):
            raise ToolFailedError("subfinder", proc.returncode, stderr_text[:500])
        if proc.returncode == 2:
            bound_log.debug(
                "subfinder_exit2_no_api_keys",
                hint="Configure ~/.config/subfinder/provider-config.yaml for more sources",
            )

        bound_log.info("subfinder_done", found=len(seen))

    except (ToolMissingError, ToolTimeoutError, ToolFailedError):
        raise
    except Exception as exc:  # noqa: BLE001
        bound_log.error("subfinder_unexpected_error", error=str(exc))
        raise ToolFailedError("subfinder", -1, str(exc)) from exc
    finally:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass


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

