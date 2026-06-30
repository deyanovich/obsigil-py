"""Error types. Verification failures are uniform and opaque to the bearer
(the uniform-failure rule of the Security Considerations, spec §16.6)."""

from __future__ import annotations

import enum


class Reason(str, enum.Enum):
    """The internal cause of a rejection — for server-side logging via
    ``clauses(..., on_reject=...)`` ONLY. A verifier MUST NOT signal *why* a
    token was rejected to the bearer (the uniform-failure rule of the Security Considerations, spec §16.6)."""

    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    AUTH_FAILED = "auth-failed"
    EMPTY_MANDATE = "empty-mandate"
    BAD_TID = "bad-tid"
    MISSING_CLAUSE = "missing-clause"
    EXPIRED = "expired"
    AUDIENCE_MISMATCH = "audience-mismatch"


class ObsigilError(Exception):
    """The single, opaque failure :func:`obsigil.clauses` raises on any
    rejection. Its message is uniform across every cause (the uniform-failure rule of the Security Considerations, spec §16.6); the
    granular :class:`Reason` is delivered to ``on_reject``, never here."""

    def __init__(self) -> None:
        super().__init__("obsigil: token rejected")
