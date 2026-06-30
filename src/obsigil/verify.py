"""Verifying — the authoritative backend side (the back-end reader of
Audiences §9, Security Considerations §16, Conformance and test vectors §13).
Every rejection collapses to one opaque :class:`ObsigilError`; the granular
cause goes to ``on_reject`` for internal logging only (the uniform-failure
rule, §16.6).
"""

from __future__ import annotations

import hmac
import time
from typing import Callable, Optional, Tuple, Union

from ._constants import (
    AUD_KEY,
    DEFAULT_MAX_DECODED_LEN,
    EXP_KEY,
    ISS_KEY,
    MAX_LEEWAY,
    MIN_HALF_BYTES,
    RESERVED_KEYS,
    RESERVED_NAMES,
    SUB_KEY,
    TID_KEY,
)
from .aead import open_
from .encoding import decode_b64url, decode_hex
from .errors import ObsigilError, Reason
from .keys import _assert_mandate_key
from .serial import deserialize
from .token import MalformedToken, parse
from .uuid7 import is_uuid7_bytes, uuid_from_bytes

Keys = Union[bytes, "list[bytes]", "tuple[bytes, ...]"]


def clauses(
    token: str,
    *,
    keys: Keys,
    audience: Optional[str] = None,
    leeway: int = 0,
    now: Optional[int] = None,
    max_decoded_len: int = DEFAULT_MAX_DECODED_LEN,
    on_reject: Optional[Callable[[Reason], None]] = None,
) -> dict:
    """Verify a token's mandate and return its clauses (Audiences §9, Security Considerations §16, Conformance and test vectors §13).

    Accepts a full token or the forwarded ``.0mandate`` form; the manifest is
    never parsed or trusted. ``keys`` is one mandate key or several, tried in
    order (key selection by trial decryption, §16.5). ``leeway`` is clamped to a fixed maximum
    (Limits and robustness, §16.10). On any failure raises a single :class:`ObsigilError`; the granular
    :class:`Reason` is delivered to ``on_reject`` for internal logging only.

    Reserved clauses are surfaced under their conventional names (``tid`` as
    its UUID text form); application fields keep their wire keys.

    >>> import obsigil
    >>> key = bytes(range(1, 65))
    >>> token = obsigil.mint(clauses={}, mandate_key=key, exp=4_000_000_000,
    ...                      sub="u1")
    >>> obsigil.clauses(token, keys=key, now=1)["sub"]
    'u1'
    """
    ok, payload = _verify_inner(token, keys, audience, leeway, now, max_decoded_len)
    if ok:
        return payload  # type: ignore[return-value]
    if on_reject is not None:
        on_reject(payload)  # type: ignore[arg-type]
    raise ObsigilError()


def _authenticate(token, key_or_keys, max_decoded_len) -> Tuple[bool, object]:
    """Parse, decode, and trial-decrypt the mandate half, returning its
    decrypted plaintext bytes — authentication only, no CBOR decode and no
    policy (authentication vs policy layers, §16.3). Returns ``(True, plaintext)`` or ``(False, Reason)``.

    The candidate keys are validated first: a missing or misconfigured key is a
    deployment error (not bearer-triggerable), surfaced as a ``ValueError``
    consistently regardless of the token."""
    key_list = list(key_or_keys) if isinstance(key_or_keys, (list, tuple)) else [key_or_keys]
    if not key_list:
        raise ValueError("obsigil: at least one mandate key is required")
    for key in key_list:
        _assert_mandate_key(key)
    if not isinstance(token, str):
        return False, Reason.MALFORMED  # a non-string token (e.g. None) rejects uniformly
    # Limits and robustness (§16.10): bound the whole token before parsing so an oversize input cannot
    # even force the O(n) separator scan, let alone trial decryption.
    if len(token) > 4 * max_decoded_len + 16:
        return False, Reason.MALFORMED
    try:
        parsed = parse(token)
    except MalformedToken:
        return False, Reason.MALFORMED
    if parsed.mandate is None:
        return False, Reason.EMPTY_MANDATE
    alg = parsed.mandate.alg_code
    if alg not in ("0", "1"):
        return False, Reason.UNSUPPORTED

    # Limits and robustness (§16.10): bound the half before any decode or trial decryption. Guard the
    # encoded length first (a cheap over-estimate — hex is densest at 2
    # chars/byte), then the decoded length exactly.
    if len(parsed.mandate.text) > max_decoded_len * 2 + 8:
        return False, Reason.MALFORMED
    if parsed.encoding == "b64":
        sealed = decode_b64url(parsed.mandate.text)
    else:
        sealed = decode_hex(parsed.mandate.text)
    if sealed is None or len(sealed) < MIN_HALF_BYTES or len(sealed) > max_decoded_len:
        return False, Reason.MALFORMED

    plain = None
    for key in key_list:
        plain = open_(sealed, key, alg)
        if plain is not None:
            break
    if plain is None:
        return False, Reason.AUTH_FAILED
    return True, plain


def _read_clauses(fields: dict) -> Tuple[bool, object]:
    """Validate reserved-field types and the reserved namespace, and surface
    the map (Reserved fields §8, Limits and robustness §16.10). Reserved fields appear under their names;
    application fields keep their wire keys. No time/audience policy here."""
    surfaced: dict = {}
    app: dict = {}
    for key, value in fields.items():
        if isinstance(key, int) and not isinstance(key, bool) and key < 0:
            name = RESERVED_KEYS.get(key)
            if name is None:
                return False, Reason.MALFORMED  # unknown reserved key: fail closed (the reserved namespace of Reserved fields, §8.1)
            if key == TID_KEY:
                if not is_uuid7_bytes(value):
                    return False, Reason.BAD_TID
                surfaced["tid"] = uuid_from_bytes(bytes(value))
            elif key == EXP_KEY:
                # NumericDate is a CBOR integer in the i64 range (the exp clause, Reserved fields §8.3; the
                # reference NumericDate type): reject bool, a non-integer, and
                # any out-of-i64 / bignum value.
                if isinstance(value, bool) or not isinstance(value, int) or not (-(2**63) <= value < 2**63):
                    return False, Reason.MISSING_CLAUSE
                surfaced["exp"] = value
            elif key == AUD_KEY:
                if not isinstance(value, list) or len(value) == 0 or not all(isinstance(a, str) for a in value):
                    return False, Reason.AUDIENCE_MISMATCH
                surfaced["aud"] = value
            elif key == SUB_KEY:
                if not isinstance(value, str):
                    return False, Reason.MALFORMED
                surfaced["sub"] = value
            elif key == ISS_KEY:
                if not isinstance(value, str):
                    return False, Reason.MALFORMED
                surfaced["iss"] = value
        else:
            app[key] = value  # application data (non-negative int or text key)

    if "tid" not in surfaced:
        return False, Reason.BAD_TID
    if "exp" not in surfaced:
        return False, Reason.MISSING_CLAUSE
    # Application fields fill in around the reserved names; a text key equal to
    # a reserved name (impossible in a token obsigil minted) is shadowed.
    for key, value in app.items():
        if not (isinstance(key, str) and key in RESERVED_NAMES):
            surfaced[key] = value
    return True, surfaced


def _surface_unenforced(fields: dict) -> dict:
    """Surface an authenticated CBOR map with NO policy or type validation
    (authentication vs policy layers §16.3, the decoded reads of API conformance §12.3): recognized reserved keys appear under their names, a
    16-byte ``tid`` is shown in text form for convenience, and everything else
    (application keys, unrecognized reserved keys) is kept under its wire key.
    Reserved clauses are authoritative — an application text key equal to a
    reserved name never shadows the reserved clause (Reserved fields, §8.1)."""
    out: dict = {}
    app: dict = {}
    for key, value in fields.items():
        if isinstance(key, int) and not isinstance(key, bool) and key in RESERVED_KEYS:
            if key == TID_KEY and is_uuid7_bytes(value):
                value = uuid_from_bytes(bytes(value))
            out[RESERVED_KEYS[key]] = value
        else:
            app[key] = value
    for key, value in app.items():
        if not (isinstance(key, str) and key in RESERVED_NAMES):
            out[key] = value
    return out


def _verify_inner(token, key_or_keys, audience, leeway, now, max_decoded_len) -> Tuple[bool, object]:
    ok, plain = _authenticate(token, key_or_keys, max_decoded_len)
    if not ok:
        return False, plain
    fields = deserialize(plain)  # canonical CBOR map, or None
    if fields is None:
        return False, Reason.MALFORMED
    ok, surfaced = _read_clauses(fields)  # type: ignore[arg-type]
    if not ok:
        return False, surfaced

    exp = surfaced["exp"]  # validated int
    leeway = min(max(leeway, 0), MAX_LEEWAY)  # Limits and robustness (§16.10): clamp to the fixed maximum
    now_value = now if now is not None else int(time.time())
    if now_value >= exp + leeway:
        return False, Reason.EXPIRED

    aud = surfaced.get("aud")
    if aud is not None:
        # Constant-time membership, no early exit on a match (the uniform-failure rule, §16.6),
        # mirroring obsigil-rs.
        hit = False
        if isinstance(audience, str):
            want = audience.encode("utf-8")
            for a in aud:
                hit |= hmac.compare_digest(a.encode("utf-8"), want)
        if not hit:
            return False, Reason.AUDIENCE_MISMATCH

    return True, surfaced
