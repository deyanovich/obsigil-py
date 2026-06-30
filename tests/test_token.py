import pytest

from obsigil.token import Half, MalformedToken, parse


def test_parses_the_three_shapes():
    full = parse("abc0.0def")
    assert full.encoding == "b64"
    assert full.manifest == Half("0", "abc")
    assert full.mandate == Half("0", "def")
    assert full.mandate_part == "0def"

    manifest_only = parse("abc0.")
    assert manifest_only.mandate is None
    assert manifest_only.mandate_part == ""

    mandate_only = parse(".0def")
    assert mandate_only.manifest is None
    assert mandate_only.mandate == Half("0", "def")


def test_reads_hex_encoding():
    t = parse("abc0~1def")
    assert t.encoding == "hex"
    assert t.mandate == Half("1", "def")


@pytest.mark.parametrize(
    "token,reason",
    [
        ("", "empty-token"),
        ("abc", "separator-count"),
        ("a.b.c", "separator-count"),
        (".", "both-absent"),
        ("0.", "degenerate-half"),
        (".0", "degenerate-half"),
        ("ab-.", "bad-alg-char"),
        ("abZ.", "bad-alg-char"),
    ],
)
def test_rejects_malformed(token, reason):
    with pytest.raises(MalformedToken) as exc:
        parse(token)
    assert exc.value.reason == reason
