# obsigil

Homepage: <https://obsigil.org>

Pure-Python implementation of **obsigil**, a mandate-token format and
shared-secret **JWT alternative**: a token split into a public,
advisory **manifest** and a secret-sealed, authoritative **mandate**.
Each half is an authenticated, deterministically-sealed ciphertext —
AES-SIV (RFC 5297) or AES-GCM-SIV (RFC 8452) — in compact text.

Each half's fields are a single **canonical CBOR map** (RFC 8949 §4.2):
reserved fields take negative integer keys (`tid`, `exp`, `aud`, `sub`,
`iss`), application data takes non-negative integer or text-string keys.
obsigil owns the canonical encoding, so the same fields under the same
key seal to byte-identical tokens with no shared serializer.

Verification is symmetric: the verifier holds the same key that mints,
so obsigil fits shared-secret (HS256-style) JWT and JWE use cases, not
public-key verification.

The AEAD primitives come from
[`cryptography`](https://cryptography.io) (OpenSSL-backed, audited) and
CBOR decoding from [`cbor2`](https://pypi.org/project/cbor2/); the
canonical CBOR encoder and the obsigil logic are small, readable Python.
No compiled extension to build — it installs as a universal wheel and
you can read the whole format end to end.

```python
import obsigil
from obsigil import Obsigil

key = obsigil.generate_key()                      # 64 CSPRNG bytes

token = Obsigil.mint(
    clauses={"role": "admin"},                    # opaque application data
    mandate_key=key,
    exp=4_000_000_000,
    aud=["api"],
    sub="u42",
    manifest={"iss": "auth.example"},             # optional public half
)

# Front end (advisory — manifest is non-authoritative, §16.7):
front = Obsigil(token.token())
claims = front.claims()                           # dict | None
header = front.authorization_header()             # "Bearer .0…" — send this

# Backend (authoritative):
mandate = Obsigil(token.token(), keys=key, audience="api", now=1)
role = mandate.clause("role")                     # raises ObsigilError if invalid
when = mandate.exp()
```

## API

A single **`Obsigil`** type views a token in three roles (API
conformance, §12):

- **`Obsigil.mint(*, clauses, mandate_key, exp, tid=None, aud=None,
  sub=None, iss=None, alg="0", encoding="b64", manifest=None)`** — the
  issuer: seal a mandate (and an optional keyless manifest) and return
  the view. `tid` is generated (a fresh UUIDv7) unless supplied; a
  supplied one must be a well-formed UUIDv7. Defaults are AES-SIV
  (`alg="0"`) and base64 (`encoding`; also `"hex"`). Application
  `clauses` use non-negative integer or text keys; reserved fields are
  set via their keyword arguments.
- **`Obsigil(token, *, keys=None, audience=None, leeway=0, now=None,
  max_decoded_len=65536, on_reject=None)`** — keyless for the front end,
  or with `keys` for the backend. `keys` may be one key or several
  (key selection by trial decryption, §16.5); `leeway` is clamped to a
  fixed maximum (Limits and robustness, §16.10).

Each half is reachable at three fidelities (the three fidelities of
API conformance, §12.2):

| | manifest | mandate |
|---|---|---|
| wire string | `manifest()` | `mandate()` |
| plaintext (CBOR octets) | `manifest_plaintext()` | `mandate_plaintext()` |
| parsed | `claims()` | `clauses()` |

- **`clauses()`** authenticates *and* enforces policy (`exp`, `aud`,
  `tid`, types), returning a dict or raising one opaque `ObsigilError`.
  Reserved clauses are surfaced under their names (`tid` as text);
  application fields keep their wire keys. Accessors: `exp()`, `tid()`,
  `issued_at()`, `sub()`, `iss()`, `aud()`, `clause(key)`.
- **`clauses_unchecked()`** authenticates and decodes the canonical
  CBOR but skips the value checks; **`mandate_plaintext()`**
  authenticates only and returns the raw CBOR octets. Both are
  backend-internal — keep them non-bearer-facing (authentication vs
  policy layers, §16.3).
- **`claims()`** opens the keyless manifest for display — advisory,
  returns a dict or `None`, never raises (the manifest is
  non-authoritative, §16.7).
- **`mandate()`** / **`manifest()`** — each half as a standalone token;
  **`authorization_header(scheme="Bearer")`** gives the manifest-absent
  `.0mandate` form to forward to the backend (Audiences, §9).

The free functions **`mint`**, **`clauses`**, **`claims`**,
**`mandate`**, **`manifest`**, **`clauses_unchecked`**,
**`mandate_plaintext`**, **`manifest_plaintext`**, and
**`authorization_header`** wrap the same core, plus **`generate_key`**,
**`generate_uuid7`**, **`is_uuid7`**, **`is_uuid7_bytes`**,
**`uuid7_time`**, **`MANIFEST_KEY`**, **`ObsigilError`**, **`Reason`**.
The granular `Reason` is delivered to `on_reject` for **internal logging
only** — never to the bearer (the uniform-failure rule, §16.6).

## Install

```sh
pip install obsigil
```

Requires Python ≥ 3.9. AES-GCM-SIV (algorithm code `1`) needs OpenSSL
3.2+, which modern `cryptography` wheels bundle; AES-SIV (code `0`, the
mandatory default) has no such floor.

## Conformance

obsigil implements canonical CBOR (RFC 8949 §4.2) and the validation
rules of Reserved fields §8 and Limits and robustness §16.10. The
bundled test suite covers round-trip,
the verification ladder, and the negative cases (non-canonical CBOR,
duplicate keys, wrong-typed reserved fields, expiry, audience, size and
leeway bounds):

```sh
pip install -e .[test]
pytest
```

Cross-language byte-for-byte known-answer vectors are tracked
separately in the `obsigil-test-vectors` suite, kept in step with the
canonical-CBOR format.

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
