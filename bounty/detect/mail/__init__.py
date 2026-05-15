"""
bounty.detect.mail — Mail configuration (SPF/DMARC/DKIM) detections.
"""

from __future__ import annotations

from bounty.detect.mail.mail_config import (
    DkimNotFound,
    DmarcMissing,
    DmarcWeak,
    SpfMissing,
    SpfWeak,
)

__all__ = [
    "SpfMissing",
    "SpfWeak",
    "DmarcMissing",
    "DmarcWeak",
    "DkimNotFound",
]

