"""Minting — the trusted issuer side (Construction, spec §5). Descriptive errors: minting
is not bearer-facing, so detail here is not an oracle.

A half's fields become a canonical CBOR map (Serialization, §7) keyed by
integer or text: reserved fields take negative keys (`tid` -1 … `iss` -5,
Reserved fields §8.1), application data takes non-negative integer or text
keys. The map is then sealed and text-encoded (Token structure, §4).
"""

from __future__ import annotations

from typing import Optional, Union

from ._constants import (
    AUD_KEY,
    EXP_KEY,
    ISS_KEY,
    MANIFEST_KEY,
    RESERVED_NAMES,
    SUB_KEY,
    TID_KEY,
)
from .aead import seal
from .encoding import encode_b64url, encode_hex
from .keys import _coerce_mandate_key
from .serial import _ensure_pure, serialize
from .uuid7 import generate_uuid7, is_uuid7, is_uuid7_bytes, uuid_to_bytes

_ALGS = ("0", "1")
_ENCODINGS = ("b64", "hex")

Tid = Union[str, bytes, bytearray]


def _encode(data: bytes, encoding: str) -> str:
    return encode_b64url(data) if encoding == "b64" else encode_hex(data)


def _check_exp(exp: object) -> None:
    # NumericDate is a CBOR integer in the i64 range (the exp clause, Reserved fields §8.3; the reference
    # NumericDate type); bool is an int subclass and is excluded.
    if isinstance(exp, bool) or not isinstance(exp, int) or not (-(2**63) <= exp < 2**63):
        raise ValueError("obsigil: exp must be an integer NumericDate")


def _check_str(value: object, name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"obsigil: {name} must be a text string")


def _check_aud(aud: object) -> None:
    if not isinstance(aud, (list, tuple)) or len(aud) == 0:
        raise ValueError("obsigil: aud must be a non-empty array")
    if not all(isinstance(a, str) for a in aud):
        raise ValueError("obsigil: aud must be an array of text strings")


def _resolve_tid(tid: Optional[Tid]) -> bytes:
    """Generate a fresh UUIDv7 (default) or validate a supplied one, returning
    the 16-byte binary wire form (the tid clause, Reserved fields §8.2). A supplied tid — string or
    16 bytes — MUST be a well-formed UUIDv7, else minting fails."""
    if tid is None:
        return uuid_to_bytes(generate_uuid7())
    if isinstance(tid, str):
        if not is_uuid7(tid):
            raise ValueError("obsigil: tid must be a well-formed UUIDv7")
        return uuid_to_bytes(tid)
    if isinstance(tid, (bytes, bytearray)):
        if not is_uuid7_bytes(tid):
            raise ValueError("obsigil: tid must be a well-formed 16-byte UUIDv7")
        return bytes(tid)
    raise ValueError("obsigil: tid must be a UUIDv7 string or 16 bytes")


def _add_app(wire: dict, app: dict) -> None:
    """Place application fields into the wire map under their own keys
    (non-negative integers or text strings, the reserved namespace of Reserved fields §8.1). Negative keys are
    obsigil's reserved namespace and a text key colliding with a reserved
    name is set via its dedicated argument — both are rejected."""
    for key, value in app.items():
        if isinstance(key, bool) or not isinstance(key, (int, str)):
            raise ValueError("obsigil: application key must be a non-negative integer or text string")
        if isinstance(key, int) and key < 0:
            raise ValueError(f"obsigil: application key {key} is in obsigil's reserved (negative) namespace")
        if isinstance(key, str) and key in RESERVED_NAMES:
            raise ValueError(f"obsigil: application key {key!r} collides with a reserved field; use its argument")
        wire[key] = value


def _seal_half(wire: dict, key: bytes, alg: str, encoding: str) -> str:
    _ensure_pure(wire)  # reject any non-CBOR-pure field value before sealing (Serialization, §7)
    return _encode(seal(serialize(wire), key, alg), encoding)


def mint(
    *,
    clauses: dict,
    mandate_key: Union[str, bytes],
    exp: int,
    tid: Optional[Tid] = None,
    aud: Optional[list] = None,
    sub: Optional[str] = None,
    iss: Optional[str] = None,
    alg: str = "0",
    encoding: str = "b64",
    manifest: Optional[dict] = None,
) -> str:
    """Mint a token (Token structure §4, Construction §5).

    ``mandate_key`` is the canonical hex key string by default (128 lowercase
    hex digits, the Key format §6.2) — the form read from a secret environment
    variable — or the 64 raw bytes. ``clauses`` is application data (keys are
    non-negative integers or text strings; reserved fields are set via the
    dedicated keyword arguments). ``tid`` defaults to a fresh generated UUIDv7;
    a supplied one is validated. Defaults are AES-SIV (``alg="0"``) and base64
    (``encoding``). ``manifest``, if given, is a dict with a required ``iss``
    and optional ``claims`` / ``exp`` / ``alg``; it is sealed keyless under the
    public manifest key.

    >>> import obsigil
    >>> key = bytes(range(1, 65)).hex()  # 128-char hex key
    >>> token = obsigil.mint(clauses={"role": "admin"}, mandate_key=key,
    ...                      exp=4_000_000_000, aud=["api"])
    >>> obsigil.clauses(token, keys=key, audience="api", now=1)["role"]
    'admin'
    """
    mandate_key = _coerce_mandate_key(mandate_key)
    if alg not in _ALGS:
        raise ValueError(f"obsigil: unsupported algorithm code {alg!r}")
    if encoding not in _ENCODINGS:
        raise ValueError(f"obsigil: unsupported encoding {encoding!r}")
    _check_exp(exp)
    tid_bytes = _resolve_tid(tid)
    if aud is not None:
        _check_aud(aud)
    if sub is not None:
        _check_str(sub, "sub")
    if iss is not None:
        _check_str(iss, "iss")

    wire: dict = {TID_KEY: tid_bytes, EXP_KEY: exp}
    if aud is not None:
        wire[AUD_KEY] = list(aud)
    if sub is not None:
        wire[SUB_KEY] = sub
    if iss is not None:
        wire[ISS_KEY] = iss
    _add_app(wire, clauses)

    mandate_part = alg + _seal_half(wire, mandate_key, alg, encoding)

    manifest_part = ""
    if manifest is not None:
        if "iss" not in manifest:
            raise ValueError("obsigil: manifest requires an 'iss' claim")
        m_alg = manifest.get("alg", "0")
        if m_alg not in _ALGS:
            raise ValueError(f"obsigil: unsupported manifest algorithm code {m_alg!r}")
        _check_str(manifest["iss"], "iss")
        m_wire: dict = {ISS_KEY: manifest["iss"]}
        if manifest.get("exp") is not None:
            _check_exp(manifest["exp"])
            m_wire[EXP_KEY] = manifest["exp"]
        _add_app(m_wire, manifest.get("claims") or {})
        manifest_part = _seal_half(m_wire, MANIFEST_KEY, m_alg, encoding) + m_alg

    separator = "." if encoding == "b64" else "~"
    return manifest_part + separator + mandate_part
