"""
bounty.targets.manual — Load scope rules from a YAML or JSON file.

The file format is:

.. code-block:: yaml

    in_scope:
      - "*.example.com"
      - "203.0.113.0/24"
    out_of_scope:
      - "staging.example.com"
    wildcards_resolve: true   # optional, default false

Scope matching is INFORMATIONAL ONLY — it is used for tagging and UI
filtering, not as a hard gate on what the scanner will touch.

Design decisions:
- Wildcard ``*.example.com`` matches any immediate *or deeper* subdomain, so
  ``sub.example.com`` and ``deep.sub.example.com`` both match.  This is the
  most common interpretation in bug-bounty scope definitions.
- CIDR ranges are matched with ``ipaddress.ip_address`` / ``ip_network``; any
  non-IP hostname is checked against the text patterns only.
- Matching is case-insensitive throughout.
- ``out_of_scope`` rules take precedence over ``in_scope``.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

import yaml

from bounty.exceptions import ScopeParseError
from bounty import get_logger

log = get_logger(__name__)


class ScopeRules:
    """Parsed scope rules for a single program.

    Args:
        in_scope: List of scope patterns (wildcards, CIDRs, exact hostnames).
        out_of_scope: Same format — matched before in_scope.
        wildcards_resolve: Hint that wildcard targets should be resolved via
                           DNS enumeration (informational only).
    """

    def __init__(
        self,
        in_scope: list[str],
        out_of_scope: list[str],
        wildcards_resolve: bool = False,
    ) -> None:
        self.in_scope: list[str] = [s.lower().strip() for s in in_scope]
        self.out_of_scope: list[str] = [s.lower().strip() for s in out_of_scope]
        self.wildcards_resolve: bool = wildcards_resolve

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def matches(self, target: str) -> bool:
        """Return ``True`` if ``target`` is in scope (after OOS exclusions).

        Args:
            target: A hostname, IP address, or URL.  URLs are stripped to their
                    host component before matching.

        Returns:
            ``True`` if ``target`` is in-scope, ``False`` otherwise.
        """
        host = _normalise_target(target)
        if not host:
            return False
        if any(_pattern_matches(p, host) for p in self.out_of_scope):
            return False
        return any(_pattern_matches(p, host) for p in self.in_scope)

    def is_out_of_scope(self, target: str) -> bool:
        """Return ``True`` if ``target`` matches any out-of-scope rule.

        Args:
            target: Hostname, IP, or URL.
        """
        host = _normalise_target(target)
        if not host:
            return True
        return any(_pattern_matches(p, host) for p in self.out_of_scope)

    def all_domains(self) -> list[str]:
        """Return all in-scope wildcards/domains suitable for subdomain enumeration.

        Filters out CIDRs and returns bare domains with leading ``*.`` stripped.
        """
        domains: list[str] = []
        for pattern in self.in_scope:
            if "/" in pattern:
                # CIDR — skip
                continue
            # Strip wildcard prefix
            domain = pattern.lstrip("*").lstrip(".")
            if domain:
                domains.append(domain)
        return list(dict.fromkeys(domains))  # deduplicated, order-preserving

    def __repr__(self) -> str:
        return (
            f"ScopeRules(in_scope={len(self.in_scope)}, "
            f"out_of_scope={len(self.out_of_scope)})"
        )


# ---------------------------------------------------------------------------
# Pattern matching helpers
# ---------------------------------------------------------------------------

def _normalise_target(target: str) -> str:
    """Extract the host component and lowercase it.

    Args:
        target: Hostname, IP address, or full URL.

    Returns:
        Lowercased host string, or empty string if unparseable.
    """
    t = target.strip().lower()
    # Strip scheme + path if URL-like
    if "://" in t:
        t = t.split("://", 1)[1]
    # Strip path, port, query
    t = t.split("/")[0].split("?")[0].split("#")[0]
    # Strip port
    if ":" in t and not t.startswith("["):
        t = t.rsplit(":", 1)[0]
    # Unwrap IPv6 brackets
    t = t.strip("[]")
    return t


def _pattern_matches(pattern: str, host: str) -> bool:
    """Test whether ``host`` matches a single scope pattern.

    Supports:
    - ``*.example.com`` — any subdomain (one or more levels)
    - ``203.0.113.0/24``  — CIDR range (tested if host is an IP)
    - ``example.com`` — exact match only

    Args:
        pattern: A scope entry (lowercased).
        host: The normalised target string (lowercased).

    Returns:
        ``True`` if the pattern covers the host.
    """
    # CIDR range
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(host)
            return addr in net
        except ValueError:
            return False

    # Wildcard subdomain
    if pattern.startswith("*."):
        suffix = pattern[2:]  # e.g. "example.com"
        # Only match actual subdomains, never the apex domain itself.
        return host.endswith("." + suffix)

    # Exact match
    return host == pattern


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_scope(path: Path) -> ScopeRules:
    """Parse a YAML or JSON scope file and return a ``ScopeRules`` instance.

    The file must be UTF-8 encoded.  YAML is tried first; JSON is used as a
    fallback (YAML is a superset of JSON so this always works).

    Args:
        path: Filesystem path to the scope file.

    Returns:
        A ``ScopeRules`` object.

    Raises:
        ScopeParseError: If the file cannot be read or has an unexpected shape.
        FileNotFoundError: If ``path`` does not exist (standard stdlib error).
    """
    raw = path.read_text(encoding="utf-8")
    try:
        data: Any = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise ScopeParseError(str(path), f"YAML/JSON parse error: {exc}") from exc

    if not isinstance(data, dict):
        raise ScopeParseError(
            str(path), f"Expected a dict at the top level, got {type(data).__name__}"
        )

    def _coerce_list(key: str) -> list[str]:
        val = data.get(key, [])
        if not isinstance(val, list):
            raise ScopeParseError(
                str(path), f"Key {key!r} must be a list, got {type(val).__name__}"
            )
        return [str(v) for v in val]

    in_scope = _coerce_list("in_scope")
    out_of_scope = _coerce_list("out_of_scope")
    wildcards_resolve = bool(data.get("wildcards_resolve", False))

    result = ScopeRules(
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        wildcards_resolve=wildcards_resolve,
    )
    log.info(
        "scope_loaded",
        path=str(path),
        in_scope=len(in_scope),
        out_of_scope=len(out_of_scope),
    )
    return result

