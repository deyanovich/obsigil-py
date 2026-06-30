"""Token grammar (Token structure, spec §4): split a token into halves and read each present
half's algorithm code. Purely structural — no decoding, decryption, or
registry check.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Half:
    """A present half: its algorithm-code char and still-text ciphertext."""

    alg_code: str
    text: str


@dataclass(frozen=True)
class ParsedToken:
    """A structurally well-formed token. Either half may be absent."""

    encoding: str  # "b64" | "hex"
    separator: str  # "." | "~"
    manifest: Half | None
    mandate: Half | None
    mandate_part: str  # "ALG mandate", or "" — `separator + mandate_part` forwards (Audiences, §9)


class MalformedToken(Exception):
    """Structural parse failure. Diagnostic only — bearer-facing callers
    collapse every cause into one uniform failure (the uniform-failure rule of the Security Considerations, spec §16.6)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _is_alg_char(c: str) -> bool:
    # ALG = %x30-39 | %x61-7A : one char 0-9 or a-z (Token structure, spec §4).
    o = ord(c)
    return 0x30 <= o <= 0x39 or 0x61 <= o <= 0x7A


def parse(token: str) -> ParsedToken:
    """Parse a token into its halves (Token structure, spec §4). Raises ``MalformedToken``."""
    if token == "":
        raise MalformedToken("empty-token")

    sep_index = -1
    sep_char = ""
    sep_count = 0
    for i, ch in enumerate(token):
        if ch in (".", "~"):
            sep_count += 1
            sep_index = i
            sep_char = ch
    if sep_count != 1:
        raise MalformedToken("separator-count")

    encoding = "b64" if sep_char == "." else "hex"
    before = token[:sep_index]
    after = token[sep_index + 1 :]

    manifest = None
    if before:
        if len(before) < 2:
            raise MalformedToken("degenerate-half")
        alg_code = before[-1]
        if not _is_alg_char(alg_code):
            raise MalformedToken("bad-alg-char")
        manifest = Half(alg_code, before[:-1])

    mandate = None
    if after:
        if len(after) < 2:
            raise MalformedToken("degenerate-half")
        alg_code = after[0]
        if not _is_alg_char(alg_code):
            raise MalformedToken("bad-alg-char")
        mandate = Half(alg_code, after[1:])

    if manifest is None and mandate is None:
        raise MalformedToken("both-absent")

    return ParsedToken(encoding, sep_char, manifest, mandate, after)
