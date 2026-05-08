"""
bounty.detect._fingerprint_helpers — Fingerprint-gating utilities for detections.

Provides ``has_tech()`` and ``get_tech_version()`` so detection ``applicable_to``
methods can gate against fingerprint data without duplicating tier-ordering logic.
"""

from __future__ import annotations

from bounty.models import ConfidenceTier, FingerprintResult, TIER_ORDER

__all__ = ["has_tech", "get_tech_version"]

_TIER_ORDER = TIER_ORDER  # {"hint": 0, "weak": 1, "strong": 2, "definitive": 3}


def has_tech(
    fingerprints: list[FingerprintResult],
    tech: str,
    min_tier: ConfidenceTier = "weak",
) -> bool:
    """Return True if any fingerprint matches *tech* at *min_tier* or above.

    Args:
        fingerprints: List of FingerprintResult objects for the asset.
        tech: Technology name to look for (case-sensitive).
        min_tier: Minimum confidence tier required.  Defaults to ``"weak"``.

    Returns:
        True if at least one fingerprint matches.
    """
    min_idx = _TIER_ORDER[min_tier]
    return any(
        fp.tech == tech and _TIER_ORDER.get(fp.confidence, 0) >= min_idx
        for fp in fingerprints
    )


def get_tech_version(
    fingerprints: list[FingerprintResult],
    tech: str,
) -> str | None:
    """Return version string if any fingerprint for *tech* captured one.

    Scans all matching fingerprints and returns the first non-None version.

    Args:
        fingerprints: List of FingerprintResult objects for the asset.
        tech: Technology name to look for (case-sensitive).

    Returns:
        Version string or ``None``.
    """
    for fp in fingerprints:
        if fp.tech == tech and fp.version:
            return fp.version
    return None

