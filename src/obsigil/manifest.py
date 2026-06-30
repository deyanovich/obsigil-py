"""The front-end / advisory side (the front-end reader of Audiences §9,
Conformance and test vectors §13): open the keyless manifest
for display, and forward the mandate to the backend.
"""

from __future__ import annotations

from typing import Optional

from ._constants import (
    DEFAULT_MAX_DECODED_LEN,
    EXP_KEY,
    ISS_KEY,
    MANIFEST_KEY,
    MIN_HALF_BYTES,
    RESERVED_KEYS,
    RESERVED_NAMES,
)
from .aead import open_
from .encoding import decode_b64url, decode_hex
from .serial import deserialize
from .token import MalformedToken, parse


def _read_claims(fields: dict) -> Optional[dict]:
    """Surface manifest claims for display (advisory). Reserved fields appear
    under their names; application fields keep their wire keys.

    The manifest half defines only two reserved keys, ``iss`` and ``exp``
    (the half-confinement rule and the iss claim, Reserved fields §8.1 and §8.6). A manifest carrying any other reserved key — an
    unknown negative key, or a mandate-only reserved key (``tid`` / ``sub`` /
    ``aud``) misplaced in the manifest half — is malformed: ignore ALL claims
    and return ``None``. Also returns ``None`` on a wrong-typed ``iss`` /
    ``exp`` or a manifest missing its required ``iss`` (the iss claim, Reserved fields §8.6)."""
    surfaced: dict = {}
    app: dict = {}
    for key, value in fields.items():
        if isinstance(key, int) and not isinstance(key, bool) and key < 0:
            name = RESERVED_KEYS.get(key)
            if name is None:
                return None  # unknown reserved key: ignore all claims
            if key == ISS_KEY:
                if not isinstance(value, str):
                    return None
                surfaced["iss"] = value
            elif key == EXP_KEY:
                if isinstance(value, bool) or not isinstance(value, int):
                    return None
                surfaced["exp"] = value
            else:
                # a mandate-only reserved key (tid/sub/aud) in the manifest
                # half: malformed — ignore all claims (the half-confinement rule, Reserved fields §8.1)
                return None
        else:
            app[key] = value
    if "iss" not in surfaced:  # the iss claim, Reserved fields §8.6: a manifest lacking iss is ignored
        return None
    for key, value in app.items():
        if not (isinstance(key, str) and key in RESERVED_NAMES):
            surfaced[key] = value
    return surfaced


def _decrypt_manifest(token: str, max_decoded_len: int) -> Optional[bytes]:
    """Keyless decrypt of the manifest half to its plaintext bytes, or
    ``None`` (no manifest, malformed, oversize, bad encoding, or auth fail).
    No CBOR decode, no validation."""
    if len(token) > 4 * max_decoded_len + 16:
        return None
    try:
        parsed = parse(token)
    except MalformedToken:
        return None
    if parsed.manifest is None:
        return None
    alg = parsed.manifest.alg_code
    if alg not in ("0", "1"):
        return None
    if len(parsed.manifest.text) > max_decoded_len * 2 + 8:
        return None
    if parsed.encoding == "b64":
        sealed = decode_b64url(parsed.manifest.text)
    else:
        sealed = decode_hex(parsed.manifest.text)
    if sealed is None or len(sealed) < MIN_HALF_BYTES or len(sealed) > max_decoded_len:
        return None
    return open_(sealed, MANIFEST_KEY, alg)


def manifest_plaintext(token: str, *, max_decoded_len: int = DEFAULT_MAX_DECODED_LEN) -> Optional[bytes]:
    """The decrypted manifest plaintext — the canonical CBOR octets, keyless
    and advisory (the three fidelities of API conformance, §12.2). ``None`` if no manifest, malformed, or auth
    fails. No parsing or validation."""
    return _decrypt_manifest(token, max_decoded_len)


def claims(token: str, *, max_decoded_len: int = DEFAULT_MAX_DECODED_LEN) -> Optional[dict]:
    """Open the manifest's advisory claims for display. Keyless and advisory
    (the manifest is non-authoritative, §16.7).

    Returns the claims dict, or ``None`` when there is nothing trustworthy to
    display: no manifest, malformed token, bad or non-canonical encoding,
    authentication failure, an unsupported algorithm, a manifest missing its
    required ``iss`` (the iss claim, Reserved fields §8.6), or a manifest carrying a mandate-only
    reserved key (the half-confinement rule, Reserved fields §8.1). Never raises, never an oracle.

    >>> import obsigil
    >>> key = bytes(range(1, 65))
    >>> token = obsigil.mint(clauses={}, mandate_key=key, exp=4_000_000_000,
    ...                      manifest={"iss": "auth.example"})
    >>> obsigil.claims(token)["iss"]
    'auth.example'
    """
    plain = _decrypt_manifest(token, max_decoded_len)
    if plain is None:
        return None
    fields = deserialize(plain)
    if fields is None:
        return None
    return _read_claims(fields)


def manifest(token: str) -> Optional[str]:
    """The manifest half as a standalone ``manifest0.`` token (the three fidelities of API conformance, §12.2).
    Pure string work — no key, no decryption (the mirror of :func:`mandate`).
    Returns ``None`` when the token carries no manifest half or is malformed."""
    try:
        parsed = parse(token)
    except MalformedToken:
        return None
    if parsed.manifest is None:
        return None
    return parsed.manifest.text + parsed.manifest.alg_code + parsed.separator


def mandate(token: str) -> Optional[str]:
    """The mandate to send to the backend: the manifest-absent ``.0mandate``
    form (Audiences, §9). Pure string work — no key, no decryption. Returns
    ``None`` when the token carries no mandate half or is malformed."""
    try:
        parsed = parse(token)
    except MalformedToken:
        return None
    if parsed.mandate is None:
        return None
    return parsed.separator + parsed.mandate_part


def authorization_header(token: str, scheme: str = "Bearer") -> Optional[str]:
    """The ``Authorization`` header value carrying the mandate, e.g.
    ``"Bearer .0mandate"``. ``None`` when :func:`mandate` is ``None``. Pass
    ``scheme=""`` for the bare token."""
    m = mandate(token)
    if m is None:
        return None
    return f"{scheme} {m}" if scheme else m
