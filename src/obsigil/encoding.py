"""Strict, canonical text codecs (Token structure, spec §4).

Decoders return ``None`` on any non-canonical input — padding, whitespace,
out-of-alphabet characters, non-zero trailing b64 bits, or a bad length —
so callers can fold the failure into a uniform rejection (the uniform-failure rule of the Security Considerations, spec §16.6). We
hand-roll these because the stdlib decoders do not enforce that strictness.
"""

from __future__ import annotations

_B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64URL_REV = {ord(c): i for i, c in enumerate(_B64URL)}


def decode_b64url(s: str) -> bytes | None:
    """Decode URL-safe base64 with no padding (Token structure, spec §4)."""
    n = len(s)
    if n % 4 == 1:
        return None
    out = bytearray()
    full = n // 4
    i = 0
    for _ in range(full):
        a = _B64URL_REV.get(ord(s[i]))
        b = _B64URL_REV.get(ord(s[i + 1]))
        c = _B64URL_REV.get(ord(s[i + 2]))
        d = _B64URL_REV.get(ord(s[i + 3]))
        if a is None or b is None or c is None or d is None:
            return None
        out.append((a << 2) | (b >> 4))
        out.append(((b & 0x0F) << 4) | (c >> 2))
        out.append(((c & 0x03) << 6) | d)
        i += 4
    rem = n - full * 4
    if rem == 2:
        a = _B64URL_REV.get(ord(s[i]))
        b = _B64URL_REV.get(ord(s[i + 1]))
        if a is None or b is None or (b & 0x0F) != 0:
            return None
        out.append((a << 2) | (b >> 4))
    elif rem == 3:
        a = _B64URL_REV.get(ord(s[i]))
        b = _B64URL_REV.get(ord(s[i + 1]))
        c = _B64URL_REV.get(ord(s[i + 2]))
        if a is None or b is None or c is None or (c & 0x03) != 0:
            return None
        out.append((a << 2) | (b >> 4))
        out.append(((b & 0x0F) << 4) | (c >> 2))
    return bytes(out)


def encode_b64url(data: bytes) -> str:
    """Encode bytes as URL-safe base64 with no padding (Token structure, spec §4)."""
    out = []
    n = len(data)
    i = 0
    while i + 3 <= n:
        x = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
        out.append(_B64URL[(x >> 18) & 63])
        out.append(_B64URL[(x >> 12) & 63])
        out.append(_B64URL[(x >> 6) & 63])
        out.append(_B64URL[x & 63])
        i += 3
    rem = n - i
    if rem == 1:
        x = data[i] << 16
        out.append(_B64URL[(x >> 18) & 63])
        out.append(_B64URL[(x >> 12) & 63])
    elif rem == 2:
        x = (data[i] << 16) | (data[i + 1] << 8)
        out.append(_B64URL[(x >> 18) & 63])
        out.append(_B64URL[(x >> 12) & 63])
        out.append(_B64URL[(x >> 6) & 63])
    return "".join(out)


def decode_hex(s: str) -> bytes | None:
    """Decode lowercase hex of even length (Token structure, spec §4). Uppercase is rejected."""
    if len(s) % 2 != 0:
        return None
    for ch in s:
        o = ord(ch)
        if not (0x30 <= o <= 0x39 or 0x61 <= o <= 0x66):
            return None
    return bytes.fromhex(s)


def encode_hex(data: bytes) -> str:
    """Encode bytes as lowercase hex (Token structure, spec §4)."""
    return data.hex()
