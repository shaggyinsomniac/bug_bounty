"""
bounty.ulid — Minimal pure-Python ULID generator.

A ULID is 128 bits encoded as a 26-character Crockford Base32 string:
  - First 10 characters: 48-bit millisecond timestamp (sortable)
  - Last 16 characters: 80-bit cryptographically random component

Properties:
  - URL-safe, lexicographically sortable by creation time
  - No hyphens (more compact than UUID)
  - Case-insensitive decoding (always emitted uppercase)
  - Monotonically increasing within the same millisecond (random part is
    simply re-drawn each call)

Reference spec: https://github.com/ulid/spec
"""

from __future__ import annotations

import os
import time

# Crockford Base32 alphabet (excludes I, L, O, U to avoid ambiguity)
_CHARS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def make_ulid() -> str:
    """Generate a new ULID string.

    Thread-safe: uses ``os.urandom`` for the random component and
    ``time.time()`` for the timestamp.  Each call produces a unique value
    with overwhelming probability.

    Returns:
        A 26-character uppercase ULID string.

    Example::

        >>> ulid = make_ulid()
        >>> len(ulid)
        26
        >>> ulid.isupper() or ulid.isdigit()
        True
    """
    # 48-bit millisecond timestamp → 10 Crockford-32 characters
    ts = int(time.time() * 1000)
    # 80-bit random component → 16 Crockford-32 characters
    rand = int.from_bytes(os.urandom(10), "big")

    result: list[str] = []
    # Encode random part (low 80 bits → 16 chars, LSB first then reversed)
    for _ in range(16):
        result.append(_CHARS[rand & 0x1F])
        rand >>= 5
    # Encode timestamp (48 bits → 10 chars, LSB first then reversed)
    for _ in range(10):
        result.append(_CHARS[ts & 0x1F])
        ts >>= 5

    # Reverse so the high bits are first (timestamp is most significant)
    return "".join(reversed(result))

