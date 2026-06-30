from obsigil.encoding import decode_b64url, decode_hex, encode_b64url, encode_hex


def test_b64_round_trips_all_lengths():
    for n in range(9):
        data = bytes((i * 37 + 11) & 0xFF for i in range(n))
        text = encode_b64url(data)
        assert not any(c in text for c in "=.~")
        assert decode_b64url(text) == data


def test_b64_rejects_non_canonical():
    assert decode_b64url("AAAAA") is None  # length 1 mod 4
    assert decode_b64url("AA==") is None  # padding
    assert decode_b64url("AB") is None  # non-zero trailing bits
    assert decode_b64url("AAB") is None  # non-zero trailing bits
    assert decode_b64url("A*BC") is None  # out of alphabet
    assert decode_b64url("AA AA") is None  # whitespace
    assert decode_b64url("AA") == b"\x00"  # canonical


def test_hex_round_trips_and_rejects():
    data = bytes([0x00, 0x0F, 0xA9, 0xFF, 0x10])
    assert encode_hex(data) == "000fa9ff10"
    assert decode_hex("000fa9ff10") == data
    assert decode_hex("abc") is None  # odd length
    assert decode_hex("AB") is None  # uppercase
    assert decode_hex("zz") is None  # out of alphabet
