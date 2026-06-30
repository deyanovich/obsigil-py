"""Cross-implementation conformance against the language-agnostic
obsigil-test-vectors (Conformance and test vectors, §13). For each positive vector this checks both
layers: the OCTET layer (seal the given canonical-CBOR octets, open them
back, and assemble the exact token) and the FIELD/ENCODER layer (encode the
decoded fields and assert the bytes match the pinned octets — i.e. obsigil-py's
canonical CBOR encoder reproduces the reference byte-for-byte). Every negative
vector must be rejected. Vectors live in the sibling repo; override with
OBSIGIL_TEST_VECTORS, else the sibling path is used; the suite skips if absent.
"""

import hashlib
import json
import os
import pathlib

import pytest

import obsigil
from obsigil import MANIFEST_KEY
from obsigil.aead import open_, seal
from obsigil.encoding import decode_b64url, decode_hex, encode_b64url, encode_hex
from obsigil.serial import serialize
from obsigil.uuid7 import uuid_to_bytes

_VECTORS = pathlib.Path(
    os.environ.get("OBSIGIL_TEST_VECTORS")
    or (pathlib.Path(__file__).resolve().parent.parent.parent / "obsigil-test-vectors")
)
_HAVE = (_VECTORS / "test-vectors.jsonl").is_file()
pytestmark = pytest.mark.skipif(not _HAVE, reason="obsigil-test-vectors not found")

# The vectors' published mandate key: SHA-512("obsigil test mandate key v1").
MANDATE_TEST_KEY = hashlib.sha512(b"obsigil test mandate key v1").digest()

# Reserved field name -> negative wire key (the reserved namespace of Reserved fields, §8.1).
_NAME2KEY = {"tid": -1, "exp": -2, "aud": -3, "sub": -4, "iss": -5}


def _key_for(role):
    if role == "manifest":
        return MANIFEST_KEY
    if role == "mandate":
        return MANDATE_TEST_KEY
    return bytes.fromhex(role)


def _decode(text, encoding):
    return decode_b64url(text) if encoding == "b64" else decode_hex(text)


def _encode(data, encoding):
    return encode_b64url(data) if encoding == "b64" else encode_hex(data)


def _wire_from_fields(fields):
    """Reconstruct a half's integer-keyed canonical-CBOR map from the vector's
    non-normative ``fields`` decode: reserved names map to their negative keys
    (``tid`` to 16 raw bytes), application text keys stay as-is."""
    wire = {}
    for name, value in fields.items():
        if name in _NAME2KEY:
            key = _NAME2KEY[name]
            wire[key] = uuid_to_bytes(value) if key == -1 else value
        else:
            wire[name] = value
    return wire


def _lines(name):
    text = (_VECTORS / name).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def test_positives_reproduce_and_verify():
    vectors = _lines("test-vectors.jsonl")
    assert vectors
    for v in vectors:
        encoding = v["encoding"]
        separator = "." if encoding == "b64" else "~"
        left = right = ""
        for role in ("manifest", "mandate"):
            half = v.get(role)
            if not half:
                continue
            alg = half["alg"]
            octets = bytes.fromhex(half["octets"])
            key = _key_for(role)

            # OCTET layer: seal the given octets, open them back.
            text = _encode(seal(octets, key, alg), encoding)
            assert open_(_decode(text, encoding), key, alg) == octets
            # ENCODER layer: our canonical encoder reproduces the pinned octets.
            assert serialize(_wire_from_fields(half["fields"])) == octets

            if role == "manifest":
                left = text + alg
            else:
                right = alg + text
        assert left + separator + right == v["token"]

        if v.get("mandate"):
            fields = v["mandate"]["fields"]
            aud = fields.get("aud")
            clauses = obsigil.clauses(
                v["token"], keys=MANDATE_TEST_KEY, now=1_000_000_000,
                audience=(aud[0] if aud else None),
            )
            assert clauses["exp"] == fields["exp"]
            assert clauses["tid"] == fields["tid"]

        if v.get("manifest"):
            claims = obsigil.claims(v["token"])
            assert claims is not None
            assert claims["iss"] == v["manifest"]["fields"]["iss"]


def test_negatives_rejected():
    vectors = _lines("negative-test-vectors.jsonl")
    assert vectors
    # The suite must actually run (not skip) over the full negative set. Log
    # the per-op tally so a CI run records that every negative was exercised.
    tally: dict = {}
    for v in vectors:
        tally[v["op"]] = tally.get(v["op"], 0) + 1
    print(f"conformance: iterating {len(vectors)} negative vectors {tally}")
    assert len(vectors) >= 56, f"expected >=56 negatives, found {len(vectors)}"

    for v in vectors:
        op = v["op"]
        token = v["token"]
        if op == "open-manifest":  # advisory manifest path
            assert obsigil.claims(token) is None
        else:  # "verify" or "parse" — both fail through clauses()
            key = _key_for(v.get("key", "mandate"))
            with pytest.raises(obsigil.ObsigilError):
                obsigil.clauses(
                    token, keys=key, audience=v.get("audience"),
                    now=v.get("now", 1_000_000_000), leeway=v.get("leeway", 0),
                )
