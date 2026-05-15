"""
bounty.detect.cors — CORS misconfiguration detections.
"""

from __future__ import annotations

from bounty.detect.cors.cors_misconfig import (
    CorsNullOrigin,
    CorsPreflightWildcard,
    CorsWildcardWithCredentials,
)

__all__ = [
    "CorsWildcardWithCredentials",
    "CorsNullOrigin",
    "CorsPreflightWildcard",
]

