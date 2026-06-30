"""UUIDv7 (RFC 9562) for the mandate's required ``tid`` (the tid clause, Reserved fields §8.2): a
48-bit big-endian Unix-millisecond timestamp plus CSPRNG randomness. On the
wire ``tid`` is always the 16-byte binary form (a CBOR byte string), never
the 36-character text; the text form is a display convenience. The timestamp
field doubles as the mandate's issue time.
"""

from __future__ import annotations

import os
import re
import time
import uuid as _uuid

# Anchored start-to-end (\A..\Z, not $, which would also match before a
# trailing newline) so a tid with stray trailing characters is rejected.
_UUID7_RE = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)


def generate_uuid7(now_ms: int | None = None) -> str:
    """Generate a UUIDv7 (canonical text form) with the given Unix-millisecond
    time (default now)."""
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    b = bytearray(16)
    b[0:6] = int(now_ms).to_bytes(6, "big")
    b[6:16] = os.urandom(10)
    b[6] = (b[6] & 0x0F) | 0x70  # version 7
    b[8] = (b[8] & 0x3F) | 0x80  # variant 0b10
    return str(_uuid.UUID(bytes=bytes(b)))


def is_uuid7(value: object) -> bool:
    """Whether ``value`` is a well-formed UUIDv7 *string* (the tid clause, Reserved fields §8.2)."""
    return isinstance(value, str) and _UUID7_RE.match(value) is not None


def is_uuid7_bytes(value: object) -> bool:
    """Whether ``value`` is a well-formed UUIDv7 in 16-byte binary form — the
    wire form (the tid clause, Reserved fields §8.2): exactly 16 bytes, version field ``0x7``, variant
    field ``0b10``."""
    return (
        isinstance(value, (bytes, bytearray))
        and len(value) == 16
        and (value[6] >> 4) == 0x7
        and (value[8] >> 6) == 0b10
    )


def uuid7_time(tid: object) -> int:
    """The issue time (NumericDate seconds) in a UUIDv7's 48-bit ms field,
    floored to whole seconds (the tid clause, Reserved fields §8.2). Accepts the 16-byte binary form or
    the canonical text form.

    >>> from obsigil.uuid7 import generate_uuid7, uuid7_time
    >>> uuid7_time(generate_uuid7(1_700_000_000_000))
    1700000000
    """
    if isinstance(tid, (bytes, bytearray)):
        ms = int.from_bytes(bytes(tid[:6]), "big")
    else:
        ms = int(str(tid).replace("-", "")[:12], 16)
    return ms // 1000


def uuid_to_bytes(value: str) -> bytes:
    """The 16 raw bytes of a UUID string — the binary ``tid`` wire form
    (the tid clause, Reserved fields §8.2)."""
    return _uuid.UUID(value).bytes


def uuid_from_bytes(data: bytes) -> str:
    """The canonical UUID string from its 16 raw bytes."""
    return str(_uuid.UUID(bytes=bytes(data)))
