"""Mandate key handling (the mandate-key rules of Construction, spec §5.1)."""

from __future__ import annotations

import os

from ._constants import MANIFEST_KEY


def generate_key() -> bytes:
    """Generate a fresh 64-byte mandate key from the platform CSPRNG (Construction, §5.1)."""
    return os.urandom(64)


def _assert_mandate_key(key: bytes) -> None:
    """Reject a key that cannot be a mandate key: wrong length, the public
    manifest key (accepting which would let anyone mint mandates, Construction §5.1), or
    all-zero (a misconfiguration, never a CSPRNG output). Raises a
    (non-uniform) configuration error; this is a deployment bug, not a token
    rejection."""
    if not isinstance(key, (bytes, bytearray)):
        raise ValueError("obsigil: mandate key must be bytes")
    if len(key) != 64:
        raise ValueError("obsigil: mandate key must be 64 bytes")
    if key == MANIFEST_KEY:
        raise ValueError("obsigil: mandate key must not be the public manifest key")
    if not any(key):
        raise ValueError("obsigil: mandate key must not be all-zero")
