"""Deterministic AEAD seal/open (Algorithm registry, spec §6), on pyca/cryptography.

No random nonce, no associated data (Sealing parameters and output layout, §6.2):

* Code 0 (AES-SIV, RFC 5297): the full 64-byte master is the AES-256-SIV
  key; sealed with a zero-element associated-data vector. Layout
  ``synthetic-IV(16) || ciphertext``.
* Code 1 (AES-GCM-SIV, RFC 8452): the 32-byte key is
  ``HKDF-Expand(master, "gcmsiv", 32)`` over HMAC-SHA-256 (Expand only);
  sealed with a fixed all-zero 12-byte nonce. Layout
  ``ciphertext || tag(16)``.

All cryptography-library usage is isolated to this module.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

_GCMSIV_NONCE = b"\x00" * 12


def _gcmsiv_key(master: bytes) -> bytes:
    # Expand-only: master IS the PRK; info = "gcmsiv", L = 32 (Key material, §6.1).
    return HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"gcmsiv").derive(master)


def seal(plaintext: bytes, master: bytes, alg: str) -> bytes:
    """Seal a half's plaintext under a 64-byte master with the AEAD named by
    ``alg``. Output layout per the Sealing parameters and output layout section (§6.2)."""
    if alg == "0":
        # Empty AD list => zero-element S2V vector, not one empty component.
        return AESSIV(master).encrypt(plaintext, [])
    if alg == "1":
        return AESGCMSIV(_gcmsiv_key(master)).encrypt(_GCMSIV_NONCE, plaintext, None)
    raise ValueError(f"obsigil: unsupported algorithm code {alg!r}")


def open_(sealed: bytes, master: bytes, alg: str) -> bytes | None:
    """Open a sealed half. Returns the plaintext, or ``None`` on
    authentication failure or an algorithm code this build cannot open."""
    try:
        if alg == "0":
            return AESSIV(master).decrypt(sealed, [])
        if alg == "1":
            return AESGCMSIV(_gcmsiv_key(master)).decrypt(_GCMSIV_NONCE, sealed, None)
        return None
    except (InvalidTag, ValueError):
        return None
