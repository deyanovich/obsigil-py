"""Pinned constants and the reserved-key namespace (the published manifest
key of Construction §5.2, the output layout of Algorithm registry §6.2, the
Limits and robustness rules of the Security Considerations §16.10, the
reserved namespace of Reserved fields §8.1)."""

from __future__ import annotations

# The public 64-byte manifest key (the published manifest key, Construction §5.2). Public by design: it opens
# AND forges manifests. Every conformant implementation MUST use this value.
MANIFEST_KEY: bytes = bytes.fromhex(
    "381284633d02ea5f35df8596b5cc4218310060468e8b465455a415174ea6e966"
    "a9f48eec4ba446ddfc8b78587895356f45a75a1ab7419454dd9f7aa8a95dbdd5"
)

# Lowest legal decoded length of a sealed half (the output layout of
# Sealing parameters and output layout, §6.2): the AEAD's
# 16-byte floor plus at least one byte of CBOR plaintext (the empty map
# 0xa0).
MIN_HALF_BYTES: int = 17

# Reserved field keys: the negative-integer namespace (the reserved
# namespace of Reserved fields, §8.1). The
# sign of a map key is its namespace — negative is obsigil's, non-negative
# integers and text strings are the application's.
TID_KEY: int = -1
EXP_KEY: int = -2
AUD_KEY: int = -3
SUB_KEY: int = -4
ISS_KEY: int = -5

# Reserved wire key -> conventional name, and the inverse. An implementation
# MAY surface reserved fields under their names (Reserved fields §8.1; the
# reserved-field access of API conformance §12.4).
RESERVED_KEYS: dict = {
    TID_KEY: "tid",
    EXP_KEY: "exp",
    AUD_KEY: "aud",
    SUB_KEY: "sub",
    ISS_KEY: "iss",
}
RESERVED_NAMES: dict = {name: key for key, name in RESERVED_KEYS.items()}

# Hard ceiling on clock-skew leeway, seconds (Limits and robustness, §16.10): a configured
# leeway is clamped to this so an over-large value cannot silently extend a
# token past its exp.
MAX_LEEWAY: int = 60

# Default cap on a half's decoded byte length (Limits and robustness, §16.10): admits any
# realistic mandate while refusing an attacker-supplied oversize half before
# any trial decryption.
DEFAULT_MAX_DECODED_LEN: int = 64 * 1024
