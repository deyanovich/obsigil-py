"""Key format: hex-string keys by default, raw bytes as the alternative,
and malformed keys as distinct configuration errors (the Key format, §6.2)."""

import re

import pytest

import obsigil
from obsigil import MANIFEST_KEY, ObsigilError

KEY_BYTES = bytes(range(1, 65))
KEY_HEX = KEY_BYTES.hex()


def _mint(mandate_key, **kw):
    return obsigil.mint(clauses=kw.pop("clauses", {}), mandate_key=mandate_key,
                        exp=4_000_000_000, **kw)


def test_generate_key_is_128_lowercase_hex():
    hexkey = obsigil.generate_key()
    assert isinstance(hexkey, str)
    assert re.fullmatch(r"[0-9a-f]{128}", hexkey)


def test_generate_key_bytes_is_64_raw_bytes():
    raw = obsigil.generate_key_bytes()
    assert isinstance(raw, bytes)
    assert len(raw) == 64


def test_generated_hex_key_round_trips():
    hexkey = obsigil.generate_key()
    token = _mint(hexkey, clauses={"role": "admin"}, aud=["api"])
    assert obsigil.clauses(token, keys=hexkey, audience="api", now=1)["role"] == "admin"


def test_hex_and_bytes_keys_are_equivalent():
    # The same key as hex or bytes seals identically: with the tid pinned (so
    # the plaintext is fixed), a token minted under the hex form is byte-equal
    # to one minted under the bytes form, and each verifies the other.
    tid = "019ed29a-378d-72f0-b462-4929cd2bfcad"
    tok_hex = _mint(KEY_HEX, tid=tid)
    tok_bytes = _mint(KEY_BYTES, tid=tid)
    assert tok_hex == tok_bytes
    assert obsigil.clauses(tok_hex, keys=KEY_BYTES, now=1) is not None
    assert obsigil.clauses(tok_bytes, keys=KEY_HEX, now=1) is not None


def test_uppercase_hex_key_is_a_config_error_not_uniform_failure():
    # Uppercase is not canonical (§6.2): a distinct ValueError, never the
    # opaque ObsigilError a bearer sees.
    with pytest.raises(ValueError) as exc:
        _mint(KEY_HEX.upper())
    assert not isinstance(exc.value, ObsigilError)

    token = _mint(KEY_HEX)
    with pytest.raises(ValueError) as exc:
        obsigil.clauses(token, keys=KEY_HEX.upper(), now=1)
    assert not isinstance(exc.value, ObsigilError)


def test_wrong_length_and_non_hex_keys_rejected():
    for bad in ("2a" * 10, "zz" * 64, "abc", "2a" * 65):
        with pytest.raises(ValueError):
            _mint(bad)


def test_manifest_key_as_hex_is_rejected():
    with pytest.raises(ValueError):
        _mint(MANIFEST_KEY.hex())


def test_key_list_mixes_hex_and_bytes():
    token = _mint(KEY_HEX)
    wrong = bytes([7]) * 64
    # Trial decryption over a candidate list mixing a wrong raw key and the
    # right hex key still authenticates.
    assert obsigil.clauses(token, keys=[wrong, KEY_HEX], now=1) is not None
