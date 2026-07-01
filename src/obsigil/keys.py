"""Mandate key handling (the mandate-key rules of Construction, spec §5.1;
the Key format, §6.2)."""

from __future__ import annotations

import os
from typing import Union

from ._constants import MANIFEST_KEY
from .encoding import decode_hex


def generate_key() -> str:
    """Generate a fresh mandate key as its canonical text form: 128 lowercase
    hex digits (the Key format, §6.2). This is the default form — what a key is
    stored and provisioned as (a secret environment variable, a
    secrets-manager value) — so it feeds straight back into ``mint`` /
    ``clauses``. :func:`generate_key_bytes` is the raw-octet alternative."""
    return os.urandom(64).hex()


def generate_key_bytes() -> bytes:
    """Generate a fresh mandate key as 64 raw bytes (the Key format, §6.2) —
    the raw-octet alternative to :func:`generate_key`."""
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


def _coerce_mandate_key(key: Union[str, bytes, bytearray]) -> bytes:
    """Normalize a mandate key to its 64 raw bytes, accepting the canonical hex
    string (the default form, §6.2) or raw bytes (the alternative). A hex key
    MUST be 128 lowercase hexadecimal digits; uppercase is rejected, not
    lowercased, and the key material is the decoded bytes, not the hex
    characters. A malformed key raises a (non-uniform) ``ValueError`` — a
    configuration error, never folded into a token rejection (the Key format,
    §6.2)."""
    if isinstance(key, str):
        raw = decode_hex(key)
        if raw is None:
            raise ValueError("obsigil: mandate key must be 128 lowercase hexadecimal digits")
        key = raw
    _assert_mandate_key(key)
    return bytes(key)
