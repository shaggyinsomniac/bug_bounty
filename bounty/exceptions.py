"""
bounty.exceptions — Typed application exceptions.

All custom exceptions live here so they can be imported by any module without
creating circular dependency chains.  Callers catch specific types; generic
``Exception`` catches are only used in subprocess wrappers.
"""

from __future__ import annotations


class BountyError(Exception):
    """Base class for all application exceptions."""


# ---------------------------------------------------------------------------
# Tool / subprocess errors
# ---------------------------------------------------------------------------

class ToolMissingError(BountyError):
    """A required external binary is not installed or not on the PATH.

    Args:
        tool: Name of the tool (e.g. ``"subfinder"``).
        install_hint: Shell commands to install it.
    """

    def __init__(self, tool: str, install_hint: str = "") -> None:
        self.tool = tool
        self.install_hint = install_hint
        msg = f"Tool not found: {tool!r}"
        if install_hint:
            msg += f"\nInstall with:\n  {install_hint}"
        super().__init__(msg)


class ToolTimeoutError(BountyError):
    """A tool subprocess exceeded its allowed runtime.

    Args:
        tool: Name of the tool.
        timeout_sec: Timeout that was exceeded, in seconds.
    """

    def __init__(self, tool: str, timeout_sec: float) -> None:
        self.tool = tool
        self.timeout_sec = timeout_sec
        super().__init__(
            f"Tool {tool!r} timed out after {timeout_sec:.0f}s"
        )


class ToolFailedError(BountyError):
    """A tool subprocess exited with a non-zero return code.

    Args:
        tool: Name of the tool.
        returncode: Exit code of the subprocess.
        stderr_excerpt: First 500 chars of stderr for diagnostics.
    """

    def __init__(self, tool: str, returncode: int, stderr_excerpt: str = "") -> None:
        self.tool = tool
        self.returncode = returncode
        self.stderr_excerpt = stderr_excerpt
        msg = f"Tool {tool!r} failed (exit {returncode})"
        if stderr_excerpt:
            msg += f": {stderr_excerpt[:500]}"
        super().__init__(msg)


# ---------------------------------------------------------------------------
# Scope / target errors
# ---------------------------------------------------------------------------

class ScopeParseError(BountyError):
    """A scope file could not be parsed.

    Args:
        path: Filesystem path of the file that failed.
        detail: Human-readable description of the parse error.
    """

    def __init__(self, path: str, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"Failed to parse scope file {path!r}: {detail}")


class PlatformError(BountyError):
    """An error communicating with a bug bounty platform API.

    Args:
        platform: Platform name (h1, bugcrowd, intigriti).
        status_code: HTTP status code if applicable.
        detail: Human-readable error description.
    """

    def __init__(
        self, platform: str, status_code: int = 0, detail: str = ""
    ) -> None:
        self.platform = platform
        self.status_code = status_code
        self.detail = detail
        msg = f"Platform error ({platform})"
        if status_code:
            msg += f" HTTP {status_code}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


# ---------------------------------------------------------------------------
# Recon errors
# ---------------------------------------------------------------------------

class ResolveError(BountyError):
    """DNS resolution failure for a hostname."""

    def __init__(self, hostname: str, detail: str = "") -> None:
        self.hostname = hostname
        super().__init__(f"DNS resolution failed for {hostname!r}: {detail}")


# ---------------------------------------------------------------------------
# Detection errors
# ---------------------------------------------------------------------------

class DetectionError(BountyError):
    """A detection could not be completed due to a tool or network failure.

    Raised by ``Detection.run()`` when an unexpected error prevents the check
    from completing.  Callers (the runner) log and continue; a ``DetectionError``
    must NOT be raised simply because the target is not vulnerable.

    Args:
        detection_id: The ``Detection.id`` class variable of the failing check.
        reason: Human-readable description of the failure.
    """

    def __init__(self, detection_id: str, reason: str) -> None:
        self.detection_id = detection_id
        self.reason = reason
        super().__init__(f"Detection {detection_id!r} failed: {reason}")


