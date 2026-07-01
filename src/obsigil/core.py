"""The :class:`Obsigil` token view (API conformance, §12): one type, three roles — a
keyless front-end view, a verifying backend view, and a minting issuer — over
an obsigil token. The free functions ``mint`` / ``clauses`` / ``claims`` /
``mandate`` / ``manifest`` remain as thin wrappers around the same core.

Each half is reachable at three fidelities (the three fidelities of API conformance, §12.2): the wire string
(:meth:`Obsigil.mandate` / :meth:`Obsigil.manifest`), the decrypted plaintext
(``*_plaintext``), and the parsed fields (:meth:`Obsigil.clauses` /
:meth:`Obsigil.claims`). The mandate ladder relaxes one layer at a time and
never relaxes authentication (authentication vs policy layers, §16.3).
"""

from __future__ import annotations

from typing import Callable, Optional, Union

from ._constants import DEFAULT_MAX_DECODED_LEN
from .errors import ObsigilError, Reason
from .manifest import authorization_header as _authorization_header
from .manifest import claims as _claims
from .manifest import mandate as _mandate
from .manifest import manifest as _manifest
from .manifest import manifest_plaintext as _manifest_plaintext
from .mint import mint as _mint
from .serial import deserialize
from .uuid7 import uuid7_time
from .verify import _authenticate, _surface_unenforced
from .verify import clauses as _clauses_verify

_UNSET = object()
# One key or several; each the canonical hex string (default) or 64 raw bytes
# (the Key format, §6.2).
Key = Union[str, bytes]
Keys = Union[Key, "list[Key]", "tuple[Key, ...]"]


class Obsigil:
    """A view over an obsigil token (API conformance, §12).

    * ``Obsigil(token)`` — keyless front-end view: read the advisory manifest
      (:meth:`claims`) and forward the mandate (:meth:`mandate`).
    * ``Obsigil(token, keys=…, audience=…, …)`` — verifying backend view:
      :meth:`clauses` authenticates and enforces policy, raising on failure.
    * ``Obsigil.mint(…)`` — issuer: build and seal a fresh token.

    >>> import obsigil
    >>> key = bytes(range(1, 65))
    >>> tok = obsigil.Obsigil.mint(clauses={"role": "admin"}, mandate_key=key,
    ...                            exp=4_000_000_000, aud=["api"])
    >>> obsigil.Obsigil(tok.token(), keys=key, audience="api", now=1).clause("role")
    'admin'
    """

    def __init__(
        self,
        token: str,
        *,
        keys: Optional[Keys] = None,
        audience: Optional[str] = None,
        leeway: int = 0,
        now: Optional[int] = None,
        max_decoded_len: int = DEFAULT_MAX_DECODED_LEN,
        on_reject: Optional[Callable[[Reason], None]] = None,
    ) -> None:
        self._token = token
        self._keys = keys
        self._audience = audience
        self._leeway = leeway
        self._now = now
        self._max = max_decoded_len
        self._on_reject = on_reject
        self._clauses_cache: object = _UNSET

    @classmethod
    def mint(
        cls,
        *,
        clauses: dict,
        mandate_key: Union[str, bytes],
        exp: int,
        tid=None,
        aud: Optional[list] = None,
        sub: Optional[str] = None,
        iss: Optional[str] = None,
        alg: str = "0",
        encoding: str = "b64",
        manifest: Optional[dict] = None,
    ) -> "Obsigil":
        """Mint a token and return it as an :class:`Obsigil` view (Construction, §5).
        ``tid`` is generated unless supplied (the tid clause, Reserved fields §8.2)."""
        return cls(
            _mint(
                clauses=clauses,
                mandate_key=mandate_key,
                exp=exp,
                tid=tid,
                aud=aud,
                sub=sub,
                iss=iss,
                alg=alg,
                encoding=encoding,
                manifest=manifest,
            )
        )

    # --- wire fidelity (the three fidelities of API conformance, §12.2) ---

    def token(self) -> str:
        """The whole token string."""
        return self._token

    def mandate(self) -> Optional[str]:
        """The mandate half as a standalone ``.0mandate`` token — the value
        forwarded to the backend (Audiences, §9). ``None`` if no mandate half."""
        return _mandate(self._token)

    def manifest(self) -> Optional[str]:
        """The manifest half as a standalone ``manifest0.`` token. ``None`` if
        no manifest half."""
        return _manifest(self._token)

    # --- plaintext fidelity (authenticate only; backend-internal, authentication vs policy layers §16.3) ---

    def mandate_plaintext(self) -> bytes:
        """The decrypted mandate plaintext (canonical CBOR octets), with no
        validation (the decoded reads of API conformance, §12.3). Authenticates first; raises on auth failure.
        Backend-internal — keep non-bearer-facing (authentication vs policy layers, §16.3)."""
        return self._decrypt()

    def manifest_plaintext(self) -> Optional[bytes]:
        """The decrypted manifest plaintext (canonical CBOR octets), keyless
        and advisory (the three fidelities of API conformance, §12.2). ``None`` if absent or auth fails."""
        return _manifest_plaintext(self._token, max_decoded_len=self._max)

    # --- parsed fidelity (the three fidelities of API conformance, §12.2) ---

    def claims(self) -> Optional[dict]:
        """The advisory manifest claims, or ``None`` (keyless; the manifest is non-authoritative, §16.7).
        Never raises."""
        return _claims(self._token, max_decoded_len=self._max)

    def clauses(self) -> dict:
        """The verified mandate clauses (the decoded reads of API conformance, §12.3): authenticate and enforce
        policy, raising :class:`ObsigilError` on any failure. The result is
        cached. Requires a verifying view built with ``keys=``."""
        if self._clauses_cache is _UNSET:
            if self._keys is None:
                raise ValueError("obsigil: no mandate key configured; build the view with keys=")
            self._clauses_cache = _clauses_verify(
                self._token,
                keys=self._keys,
                audience=self._audience,
                leeway=self._leeway,
                now=self._now,
                max_decoded_len=self._max,
                on_reject=self._on_reject,
            )
        return self._clauses_cache  # type: ignore[return-value]

    def clauses_unchecked(self) -> dict:
        """The mandate clauses with **no policy** applied (the decoded reads of API conformance, §12.3):
        authenticate and decode the canonical CBOR map, but skip the value
        checks (``exp`` / ``aud`` / ``tid`` well-formedness / reserved types).
        A non-canonical or duplicate-key encoding still fails. Backend-internal
        — keep non-bearer-facing (authentication vs policy layers, §16.3)."""
        fields = deserialize(self._decrypt())
        if fields is None:
            raise ObsigilError()
        return _surface_unenforced(fields)

    # --- reserved-clause accessors (the reserved-field access of API conformance, §12.4) ---

    def exp(self) -> int:
        """Authoritative expiry (the exp clause, Reserved fields §8.3)."""
        return self.clauses()["exp"]

    def tid(self) -> str:
        """The unique token id, UUIDv7 text form (the tid clause, Reserved fields §8.2)."""
        return self.clauses()["tid"]

    def issued_at(self) -> int:
        """Issue time (NumericDate seconds), derived from ``tid`` (the tid clause, Reserved fields §8.2)."""
        return uuid7_time(self.clauses()["tid"])

    def sub(self) -> Optional[str]:
        """Subject authorized, if present (the sub clause, Reserved fields §8.5)."""
        return self.clauses().get("sub")

    def iss(self) -> Optional[str]:
        """Issuer, if present (the iss clause, Reserved fields §8.6)."""
        return self.clauses().get("iss")

    def aud(self) -> Optional[list]:
        """Intended verifiers, if present (the aud clause, Reserved fields §8.4)."""
        return self.clauses().get("aud")

    def clause(self, key):
        """A single clause by reserved name (``"tid"``, ``"exp"``, …) or by
        application key (a non-negative integer or text string)."""
        return self.clauses().get(key)

    def authorization_header(self, scheme: str = "Bearer") -> Optional[str]:
        """The ``Authorization`` value carrying the mandate (Audiences, §9)."""
        return _authorization_header(self._token, scheme)

    # --- internal ---

    def _decrypt(self) -> bytes:
        if self._keys is None:
            raise ValueError("obsigil: no mandate key configured; build the view with keys=")
        ok, payload = _authenticate(self._token, self._keys, self._max)
        if not ok:
            if self._on_reject is not None:
                self._on_reject(payload)  # type: ignore[arg-type]
            raise ObsigilError()
        return payload  # type: ignore[return-value]


# --- free-function wrappers over the backend-internal fidelities (the decoded
# reads of API conformance §12.3, authentication vs policy layers §16.3). Thin
# shims over the Obsigil view, mirroring the keyless free
# functions in manifest.py. ---


def clauses_unchecked(
    token: str,
    *,
    keys: Keys,
    max_decoded_len: int = DEFAULT_MAX_DECODED_LEN,
    on_reject: Optional[Callable[[Reason], None]] = None,
) -> dict:
    """The mandate clauses with **no policy** applied (the decoded reads of API conformance, §12.3): authenticate
    and decode the canonical CBOR map, but skip the value checks (``exp`` /
    ``aud`` / ``tid`` well-formedness / reserved types). A non-canonical or
    duplicate-key encoding still fails. Backend-internal — keep
    non-bearer-facing (authentication vs policy layers, §16.3)."""
    return Obsigil(token, keys=keys, max_decoded_len=max_decoded_len,
                   on_reject=on_reject).clauses_unchecked()


def mandate_plaintext(
    token: str,
    *,
    keys: Keys,
    max_decoded_len: int = DEFAULT_MAX_DECODED_LEN,
    on_reject: Optional[Callable[[Reason], None]] = None,
) -> bytes:
    """The decrypted mandate plaintext — the canonical CBOR octets — with no
    validation (the decoded reads of API conformance, §12.3). Authenticates first; raises on auth failure.
    Backend-internal — keep non-bearer-facing (authentication vs policy layers, §16.3)."""
    return Obsigil(token, keys=keys, max_decoded_len=max_decoded_len,
                   on_reject=on_reject).mandate_plaintext()
