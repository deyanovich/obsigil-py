"""Round-trip and the Obsigil API (Token structure §4, Construction §5, Audiences §9, API conformance §12)."""

import obsigil
from obsigil import Obsigil

KEY = bytes(range(1, 65))


def test_full_round_trip_free_functions():
    token = obsigil.mint(
        clauses={"role": "admin", 5: "x"},
        mandate_key=KEY,
        exp=4_000_000_000,
        aud=["api"],
        sub="u42",
        iss="auth",
        manifest={"iss": "auth.example", "claims": {"theme": "dark"}},
    )
    claims = obsigil.claims(token)
    assert claims["iss"] == "auth.example" and claims["theme"] == "dark"

    clauses = obsigil.clauses(token, keys=KEY, audience="api", now=1_000_000_000)
    assert clauses["role"] == "admin"          # app text key
    assert clauses[5] == "x"                    # app integer key
    assert clauses["sub"] == "u42"              # reserved surfaced by name
    assert clauses["iss"] == "auth"
    assert clauses["exp"] == 4_000_000_000
    assert obsigil.is_uuid7(clauses["tid"])     # surfaced as text form


def test_obsigil_object_three_roles():
    issued = Obsigil.mint(clauses={"role": "admin"}, mandate_key=KEY, exp=4_000_000_000,
                          aud=["api"], manifest={"iss": "auth.example"})
    token = issued.token()

    # keyless front end: claims advisory, clauses unavailable
    front = Obsigil(token)
    assert front.claims()["iss"] == "auth.example"
    assert front.mandate().startswith(".")          # forwardable
    assert front.manifest().endswith(".")            # standalone manifest token

    # backend: clauses verify and accessors work
    back = Obsigil(token, keys=KEY, audience="api", now=1)
    assert back.clause("role") == "admin"
    assert back.exp() == 4_000_000_000
    assert obsigil.is_uuid7(back.tid())
    assert back.issued_at() <= back.exp()


def test_verification_ladder():
    token = obsigil.mint(clauses={"role": "admin"}, mandate_key=KEY, exp=1_000)
    obs = Obsigil(token, keys=KEY, now=5_000)  # past exp

    # clauses() enforces policy -> rejects (expired)
    import pytest
    with pytest.raises(obsigil.ObsigilError):
        obs.clauses()
    # clauses_unchecked() authenticates + decodes, skips policy -> returns
    unenforced = obs.clauses_unchecked()
    assert unenforced["role"] == "admin" and unenforced["exp"] == 1_000
    # mandate_plaintext() authenticates only -> raw canonical CBOR bytes
    raw = obs.mandate_plaintext()
    assert isinstance(raw, bytes) and raw[0] >> 5 == 5  # CBOR map major type


def test_three_fidelities_per_half():
    issued = Obsigil.mint(clauses={}, mandate_key=KEY, exp=4_000_000_000,
                          manifest={"iss": "auth.example"})
    obs = Obsigil(issued.token(), keys=KEY, now=1)
    # wire -> plaintext -> parsed, both halves
    assert obs.manifest_plaintext()[0] >> 5 == 5  # manifest CBOR map
    assert obs.mandate_plaintext()[0] >> 5 == 5   # mandate CBOR map
    assert obs.claims()["iss"] == "auth.example"
    assert "tid" in obs.clauses()
    # each half accessor is itself a well-formed token
    assert Obsigil(obs.mandate(), keys=KEY, now=1).exp() == 4_000_000_000


def test_forward_and_header():
    token = obsigil.mint(clauses={}, mandate_key=KEY, exp=4_000_000_000, aud=["api"],
                         manifest={"iss": "auth.example"})
    forwarded = obsigil.mandate(token)
    assert forwarded.startswith(".")
    obsigil.clauses(forwarded, keys=KEY, audience="api", now=1_000_000_000)
    assert obsigil.authorization_header(token).startswith("Bearer .")


def test_trial_decryption():
    token = obsigil.mint(clauses={}, mandate_key=KEY, exp=4_000_000_000)
    wrong = bytes([7] * 64)
    obsigil.clauses(token, keys=[wrong, KEY], now=1_000_000_000)  # second key authenticates


def test_supplied_tid_round_trips():
    tid = "019ed29a-378d-72f0-b462-4929cd2bfcad"
    token = obsigil.mint(clauses={}, mandate_key=KEY, exp=4_000_000_000, tid=tid)
    assert obsigil.clauses(token, keys=KEY, now=1)["tid"] == tid


def test_each_algorithm():
    for alg in ("0", "1"):
        token = obsigil.mint(clauses={"role": "v"}, mandate_key=KEY, exp=4_000_000_000, alg=alg)
        assert obsigil.clauses(token, keys=KEY, now=1)["role"] == "v"


def test_each_encoding():
    for enc, sep in (("b64", "."), ("hex", "~")):
        token = obsigil.mint(clauses={"role": "v"}, mandate_key=KEY, exp=4_000_000_000, encoding=enc)
        assert sep in token
        assert obsigil.clauses(token, keys=KEY, now=1)["role"] == "v"
