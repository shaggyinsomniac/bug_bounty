"""
bounty.intel — Intel gathering: Shodan integration, caching, lead management.

Re-exports:
  ShodanClient  — async Shodan REST API client
  ShodanError   — raised on API / credit failures
  IntelCache    — file-backed JSON cache for API results
"""

from __future__ import annotations

from bounty.intel.cache import IntelCache
from bounty.intel.shodan import ShodanClient, ShodanError

__all__ = [
    "ShodanClient",
    "ShodanError",
    "IntelCache",
]

