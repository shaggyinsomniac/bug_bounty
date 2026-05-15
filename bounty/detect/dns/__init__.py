"""
bounty.detect.dns — DNS misconfiguration detections.
"""

from __future__ import annotations

from bounty.detect.dns.zone_transfer import ZoneTransferAllowed

__all__ = ["ZoneTransferAllowed"]

