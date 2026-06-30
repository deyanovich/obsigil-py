"""Validation and uniform-failure rules (Reserved fields §8, the uniform-failure rule §16.6, Limits and robustness §16.10)."""

import os

import cbor2
import pytest

import obsigil
from obsigil import MANIFEST_KEY, ObsigilError, Reason
from obsigil.aead import seal
from obsigil.encoding import encode_b64url
from obsigil.serial import serialize

KEY = bytes(range(1, 65))


def _craft(wire):
    """Seal an arbitrary wire map (or raw bytes) as a `.0mandate` token — what
    a holder of the key could mint, used to probe verifier validation."""
    plain = serialize(wire) if isinstance(wire, dict) else wire
    return ".0" + encode_b64url(seal(plain, KEY, "0"))


def _tid16():
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x70
    b[8] = (b[8] & 0x3F) | 0x80
    return bytes(b)


def _reason(**kwargs):
    reasons = []
    with pytest.raises(ObsigilError):
        obsigil.clauses(on_reject=reasons.append, **kwargs)
    return reasons[0]


def test_exp_must_be_integer():
    # Infinity / float / bool are not CBOR integers (the exp clause, Reserved fields §8.3) — the
    # never-expires hole. All collapse to uniform rejection.
    for bad in (float("inf"), 1.5, True):
        assert _reason(token=_craft({-1: _tid16(), -2: bad}), keys=KEY, now=1) == Reason.MISSING_CLAUSE


def test_nan_is_forbidden():
    # NaN has no canonical CBOR bit pattern across encoders, so it is rejected
    # at the canonical-CBOR layer (Serialization, §7), before reserved-field typing. The
    # encoder refuses to emit one, so a malicious NaN token is hand-built (a
    # map {-1: tid, -2: float16 NaN 0xf9 0x7e00}).
    raw = bytes([0xA2, 0x20, 0x50]) + _tid16() + bytes([0x21, 0xF9, 0x7E, 0x00])
    assert _reason(token=_craft(raw), keys=KEY, now=1) == Reason.MALFORMED
    # An application NaN is refused at mint, too.
    with pytest.raises(Exception):
        serialize({-1: _tid16(), -2: 1, "score": float("nan")})


def test_tid_must_be_16_byte_uuidv7():
    assert _reason(token=_craft({-1: b"\x00" * 15, -2: 1}), keys=KEY, now=1) == Reason.BAD_TID  # short
    assert _reason(token=_craft({-2: 1}), keys=KEY, now=1) == Reason.BAD_TID                     # absent
    bad = bytearray(_tid16()); bad[6] = (bad[6] & 0x0F) | 0x40                                   # version 4
    assert _reason(token=_craft({-1: bytes(bad), -2: 1}), keys=KEY, now=1) == Reason.BAD_TID


def test_missing_exp():
    assert _reason(token=_craft({-1: _tid16()}), keys=KEY, now=1) == Reason.MISSING_CLAUSE


def test_aud_shape_and_membership():
    assert _reason(token=_craft({-1: _tid16(), -2: 4_000_000_000, -3: "api"}),
                   keys=KEY, audience="api", now=1) == Reason.AUDIENCE_MISMATCH       # bare string
    assert _reason(token=_craft({-1: _tid16(), -2: 4_000_000_000, -3: []}),
                   keys=KEY, audience="api", now=1) == Reason.AUDIENCE_MISMATCH       # empty
    assert _reason(token=_craft({-1: _tid16(), -2: 4_000_000_000, -3: ["other"]}),
                   keys=KEY, audience="api", now=1) == Reason.AUDIENCE_MISMATCH       # not a member


def test_unknown_negative_key_fails_closed():
    assert _reason(token=_craft({-1: _tid16(), -2: 4_000_000_000, -9: "x"}),
                   keys=KEY, now=1) == Reason.MALFORMED


def test_non_canonical_rejected():
    indef = bytes([0xBF]) + cbor2.dumps(-1) + cbor2.dumps(_tid16()) + cbor2.dumps(-2) + cbor2.dumps(1) + bytes([0xFF])
    assert _reason(token=_craft(indef), keys=KEY, now=1) == Reason.MALFORMED


def test_expired_and_leeway_clamp():
    token = obsigil.mint(clauses={}, mandate_key=KEY, exp=1_000)
    assert _reason(token=token, keys=KEY, now=1_050) == Reason.EXPIRED          # 50s past, no leeway
    obsigil.clauses(token, keys=KEY, now=1_030, leeway=60)                       # within clamp
    # excessive leeway must NOT revive a long-expired token (Limits and robustness, §16.10)
    assert _reason(token=token, keys=KEY, now=1_001_000, leeway=10**9) == Reason.EXPIRED


def test_size_cap_before_decrypt():
    big = ".0" + "A" * 5_000_000
    assert _reason(token=big, keys=[bytes([i]) * 64 for i in range(1, 9)], now=1) == Reason.MALFORMED


def test_uniform_rejection_reasons():
    token = obsigil.mint(clauses={}, mandate_key=KEY, exp=4_000_000_000, aud=["api"])
    assert _reason(token=token, keys=KEY, audience="api", now=5_000_000_000) == Reason.EXPIRED
    assert _reason(token=token, keys=KEY, audience="other", now=1) == Reason.AUDIENCE_MISMATCH
    assert _reason(token=token, keys=bytes([7] * 64), now=1) == Reason.AUTH_FAILED
    assert _reason(token="garbage", keys=KEY, now=1) == Reason.MALFORMED
    # empty mandate (manifest-only forwarded)
    mo = obsigil.mint(clauses={}, mandate_key=KEY, exp=1, manifest={"iss": "x"})
    manifest_only = obsigil.Obsigil(mo).manifest()
    assert _reason(token=manifest_only, keys=KEY, now=1) == Reason.EMPTY_MANDATE


def test_mint_rejects_bad_inputs():
    with pytest.raises(ValueError):  # manifest key as mandate key
        obsigil.mint(clauses={}, mandate_key=MANIFEST_KEY, exp=1)
    with pytest.raises(ValueError):  # all-zero key
        obsigil.mint(clauses={}, mandate_key=bytes(64), exp=1)
    with pytest.raises(ValueError):  # bad supplied tid
        obsigil.mint(clauses={}, mandate_key=KEY, exp=1, tid="not-a-uuid")
    with pytest.raises(ValueError):  # exp not an integer
        obsigil.mint(clauses={}, mandate_key=KEY, exp=1.5)
    with pytest.raises(ValueError):  # negative app key (reserved namespace)
        obsigil.mint(clauses={-7: "x"}, mandate_key=KEY, exp=1)
    with pytest.raises(ValueError):  # app key colliding with a reserved name
        obsigil.mint(clauses={"exp": "shadow"}, mandate_key=KEY, exp=1)
    with pytest.raises(ValueError):  # manifest without iss
        obsigil.mint(clauses={}, mandate_key=KEY, exp=1, manifest={})


def test_keyless_view_cannot_read_clauses():
    token = obsigil.mint(clauses={}, mandate_key=KEY, exp=4_000_000_000)
    with pytest.raises(ValueError):
        obsigil.Obsigil(token).clauses()  # no key configured


# --- regression tests for verification-pass fixes ---

def test_mint_rejects_non_pure_value():
    import datetime
    with pytest.raises(ValueError):
        obsigil.mint(clauses={"when": datetime.datetime(2020, 1, 1)}, mandate_key=KEY, exp=1)
    with pytest.raises(ValueError):
        obsigil.mint(clauses={"s": {1, 2, 3}}, mandate_key=KEY, exp=1)


def test_non_string_token_rejects_uniformly():
    assert _reason(token=None, keys=KEY, now=1) == Reason.MALFORMED


def test_keys_none_is_a_clean_error():
    with pytest.raises(ValueError):
        obsigil.clauses("anything", keys=None, now=1)


def test_exp_bounded_to_i64_matching_reference():
    # out-of-i64 (incl. bignum) rejected, matching obsigil-rs's i64 NumericDate
    assert _reason(token=_craft({-1: _tid16(), -2: 2**63}), keys=KEY, now=1) == Reason.MISSING_CLAUSE
    assert _reason(token=_craft({-1: _tid16(), -2: 2**64}), keys=KEY, now=1) == Reason.MISSING_CLAUSE
    obsigil.clauses(_craft({-1: _tid16(), -2: 2**63 - 1}), keys=KEY, now=1)  # i64 max accepted


def test_clauses_unchecked_reserved_takes_precedence():
    # a forged token carrying BOTH reserved exp (-2) and an app text key "exp"
    tok = _craft({-1: _tid16(), -2: 4_000_000_000, "exp": "FORGED"})
    unenforced = obsigil.Obsigil(tok, keys=KEY, now=1).clauses_unchecked()
    assert unenforced["exp"] == 4_000_000_000  # authoritative reserved wins, not "FORGED"


def test_mint_rejects_deeply_nested_value():
    deep = cur = {}
    for _ in range(100):
        cur["n"] = {}
        cur = cur["n"]
    with pytest.raises(ValueError):
        obsigil.mint(clauses={"d": deep}, mandate_key=KEY, exp=1)
