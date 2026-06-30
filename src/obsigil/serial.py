"""Canonical CBOR serialization (the Serialization section, spec §7).

A half's fields are a single **canonical CBOR map** — RFC 8949 §4.2 core
deterministic encoding: definite-length items only, integers and lengths
in shortest form, map keys sorted bytewise by their encoded form, and no
duplicate keys. There is no in-band tag; the sealed plaintext of a half
is exactly ``canonical-CBOR(map of fields)``.

Obsigil owns this encoding, so the encoder is hand-rolled: a CBOR library's
"canonical" mode may sort map keys by RFC 7049 length-first order rather
than RFC 8949 §4.2 bytewise, which diverges once keys differ in encoded
length (e.g. application key ``24`` vs reserved key ``-1``). Scalar values
carry no key-order ambiguity, so those are delegated to ``cbor2``; only
map framing and key sorting are done here.

Map keys are CBOR integers or text strings, split by sign (the
sign-as-namespace rule of Serialization, spec §7):
negative integers are obsigil's reserved namespace, non-negative integers
and text strings are opaque application data.
"""

from __future__ import annotations

import math

import cbor2


def _head(major: int, n: int) -> bytes:
    """A CBOR head (initial byte plus any length bytes) for ``major`` with
    argument ``n`` in shortest form."""
    mt = major << 5
    if n < 24:
        return bytes([mt | n])
    if n < 0x100:
        return bytes([mt | 24, n])
    if n < 0x10000:
        return bytes([mt | 25]) + n.to_bytes(2, "big")
    if n < 0x1_0000_0000:
        return bytes([mt | 26]) + n.to_bytes(4, "big")
    return bytes([mt | 27]) + n.to_bytes(8, "big")


def encode_canonical(value: object) -> bytes:
    """Encode ``value`` as canonical CBOR (RFC 8949 §4.2). Maps are framed
    here with bytewise-sorted keys; arrays recurse; scalars (int, float,
    str, bytes, bool, None) are delegated to ``cbor2`` in shortest form."""
    if isinstance(value, dict):
        pairs = [(encode_canonical(k), encode_canonical(v)) for k, v in value.items()]
        pairs.sort(key=lambda kv: kv[0])  # bytewise lexicographic on encoded key
        out = bytearray(_head(5, len(pairs)))
        for ek, ev in pairs:
            out += ek
            out += ev
        return bytes(out)
    if isinstance(value, (list, tuple)):
        out = bytearray(_head(4, len(value)))
        for item in value:
            out += encode_canonical(item)
        return bytes(out)
    # NaN has no single canonical CBOR bit pattern across encoders, so obsigil
    # forbids it (the NaN ban of Serialization, spec §7): mint refuses to emit one.
    if isinstance(value, float) and math.isnan(value):
        raise ValueError("serial: NaN is not permitted")
    # Scalars: cbor2's shortest-form encoding has no key-order ambiguity.
    return cbor2.dumps(value, canonical=True)


_MAX_DEPTH = 64


def _ensure_pure(value: object, _depth: int = 0) -> None:
    """Reject any value that is not pure CBOR data (Serialization, §7): every value
    must be null / bool / int / float / str / bytes / array / map, and every
    map key a CBOR integer or text string. CBOR semantic tags (datetime,
    regexp, set, …) decode into host objects and are rejected here. Nesting is
    bounded so pathological depth raises a clean error rather than recursing."""
    if isinstance(value, float) and math.isnan(value):
        raise ValueError("serial: NaN is not permitted")  # forbidden (Serialization, §7)
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return
    if _depth >= _MAX_DEPTH:
        raise ValueError("serial: value nested too deeply")
    if isinstance(value, list):
        for item in value:
            _ensure_pure(item, _depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, bool) or not isinstance(key, (int, str)):
                raise ValueError("serial: map key must be a CBOR integer or text string")
            if isinstance(key, int) and not -(1 << 64) <= key <= (1 << 64) - 1:
                # An integer outside CBOR major type 0/1 (>= 2**64 or < -2**64)
                # can only be encoded as a tag-2/3 bignum, and a tag is not an
                # allowed map-key type (Serialization, §7). cbor2 decodes the
                # bignum transparently to a Python int, so check the magnitude.
                raise ValueError("serial: map key integer out of CBOR range (bignum)")
            _ensure_pure(item, _depth + 1)
        return
    raise ValueError("serial: non-pure-data value")


def serialize(fields: dict) -> bytes:
    """The sealed plaintext of a half: ``canonical-CBOR(map of fields)``
    (Serialization, §7). No tag."""
    return encode_canonical(fields)


def deserialize(plaintext: bytes):
    """Decode a half's plaintext as a canonical CBOR map. Returns the map,
    or ``None`` if the bytes are not a CBOR map, carry a non-pure value or a
    ``NaN`` (forbidden, Serialization §7), or are **not canonical** (the
    Limits and robustness rules of the Security Considerations, §16.10) — an
    indefinite-length item, a non-shortest integer or length, keys out of
    sorted order, or a duplicate key. Canonicality is enforced by re-encoding
    and comparing: any
    non-canonical input re-encodes to different bytes (a duplicate key
    collapses to one entry, so its re-encoding is strictly shorter)."""
    try:
        value = cbor2.loads(plaintext)
    except Exception:
        return None
    if not isinstance(value, dict):
        return None
    try:
        _ensure_pure(value)
    except ValueError:
        return None
    if encode_canonical(value) != plaintext:
        return None
    return value
