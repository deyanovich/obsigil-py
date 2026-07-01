"""obsigil — a mandate-token format and shared-secret JWT alternative.

A token split into a public **manifest** and an encrypted **mandate**, each an
authenticated, deterministically-sealed ciphertext (AES-SIV / AES-GCM-SIV) in
compact text. Each half's fields are a canonical CBOR map (RFC 8949 §4.2);
reserved fields take negative integer keys, application data non-negative
integer or text keys. Verification is symmetric — the same mandate key both
mints and verifies — so obsigil fits shared-secret (HS256-style) JWT/JWE use
cases, not public-key verification.

This package is the pure-Python reference implementation, built on
``cryptography`` for the AEAD primitives and ``cbor2`` for CBOR decoding (the
canonical encoder is obsigil's own).

    import obsigil

    key = obsigil.generate_key()                                # 128-char hex
    tok = obsigil.Obsigil.mint(
        clauses={"role": "admin"},
        mandate_key=key,
        exp=4_000_000_000,
        aud=["api"],
        manifest={"iss": "auth.example"},
    )
    obsigil.Obsigil(tok.token()).claims()                       # advisory, front end
    obsigil.Obsigil(tok.token(), keys=key, audience="api",
                    now=1).clauses()                            # authoritative, backend

The free functions ``mint`` / ``clauses`` / ``claims`` / ``mandate`` /
``manifest`` wrap the same core.
"""

from __future__ import annotations

from ._constants import MANIFEST_KEY
from .core import Obsigil, clauses_unchecked, mandate_plaintext
from .errors import ObsigilError, Reason
from .keys import generate_key, generate_key_bytes
from .manifest import authorization_header, claims, mandate, manifest, manifest_plaintext
from .mint import mint
from .uuid7 import generate_uuid7, is_uuid7, is_uuid7_bytes, uuid7_time
from .verify import clauses

__version__ = "0.2.0"

__all__ = [
    "MANIFEST_KEY",
    "Obsigil",
    "ObsigilError",
    "Reason",
    "authorization_header",
    "claims",
    "clauses",
    "clauses_unchecked",
    "generate_key",
    "generate_key_bytes",
    "generate_uuid7",
    "is_uuid7",
    "is_uuid7_bytes",
    "mandate",
    "mandate_plaintext",
    "manifest",
    "manifest_plaintext",
    "mint",
    "uuid7_time",
]
