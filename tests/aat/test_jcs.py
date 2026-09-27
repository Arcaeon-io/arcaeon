r"""K062: RFC 8785 JCS, checked on the RFC's own examples.

Every vector below is copied from RFC 8785 (read 9/27 from
https://www.rfc-editor.org/rfc/rfc8785.txt; no network at test time):
section 3.2.2 / 3.2.3 (the primitives sample and its canonical form),
section 3.2.4 (the same as UTF-8 hex bytes), section 3.2.3 (the UTF-16
sorting sample) and Appendix B, Table 1 (number serialization samples).
"""
import json
import math
import struct

import pytest

from arcaeon.prove.jcs import JcsError, canonicalize, number, sha256_hex

BS = chr(92)

# Appendix B, Table 1: IEEE 754 hex -> JSON representation.
APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]
# Appendix B rows marked (3): NaN and Infinity have no JSON representation.
APPENDIX_B_REFUSED = ["7fffffffffffffff", "7ff0000000000000"]


def _double(hex16):
    return struct.unpack(">d", bytes.fromhex(hex16))[0]


@pytest.mark.parametrize("hex16,expected", APPENDIX_B)
def test_appendix_b_numbers(hex16, expected):
    assert number(_double(hex16)) == expected
    assert canonicalize(_double(hex16)) == expected.encode("ascii")


@pytest.mark.parametrize("hex16", APPENDIX_B_REFUSED)
def test_appendix_b_nan_infinity_refused(hex16):
    x = _double(hex16)
    assert math.isnan(x) or math.isinf(x)
    with pytest.raises(JcsError):
        canonicalize(x)
    with pytest.raises(JcsError):
        canonicalize({"n": [1, x]})


# Section 3.2.2: the input, as JSON text.
SECTION_322_INPUT = (
    '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
    ' "string": "' + BS + 'u20ac$' + BS + 'u000F' + BS + 'u000aA\'' + BS + 'u0042'
    + BS + 'u0022' + BS + 'u005c' + BS + BS + BS + '"' + BS + '/",'
    ' "literals": [null, true, false]}'
)
# Section 3.2.4: the canonical form as UTF-8 bytes, hex.
SECTION_324_HEX = """
7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72
75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31
65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30
30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d
"""


def test_section_3_2_4_bytes():
    got = canonicalize(json.loads(SECTION_322_INPUT))
    assert got == bytes.fromhex("".join(SECTION_324_HEX.split()))


def test_section_3_2_3_text():
    # Section 3.2.3's canonical form, as text (the display line wrap removed).
    expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,'
                '1e+30,4.5,0.002,1e-27],"string":"' + chr(0x20AC) + '$' + BS + 'u000f'
                + BS + "nA'B" + BS + '"' + BS + BS + BS + BS + BS + '"/"}')
    assert canonicalize(json.loads(SECTION_322_INPUT)).decode("utf-8") == expected


def test_section_3_2_3_utf16_sort_order():
    sample = json.loads(
        '{"' + BS + 'u20ac": "Euro Sign", "' + BS + 'r": "Carriage Return",'
        ' "' + BS + 'ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One",'
        ' "' + BS + 'ud83d' + BS + 'ude00": "Emoji: Grinning Face",'
        ' "' + BS + 'u0080": "Control",'
        ' "' + BS + 'u00f6": "Latin Small Letter O With Diaeresis"}')
    order = list(json.loads(canonicalize(sample)).values())
    assert order == ["Carriage Return", "One", "Control",
                     "Latin Small Letter O With Diaeresis", "Euro Sign",
                     "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"]


def test_no_whitespace_and_nested_sorting():
    assert canonicalize({"b": [{"z": 1, "a": None}], "a": {"y": True, "x": False}}) == \
        b'{"a":{"x":false,"y":true},"b":[{"a":null,"z":1}]}'


def test_refused_not_rounded():
    with pytest.raises(JcsError) as e:
        canonicalize({"seq": 2 ** 53 + 1})
    assert e.value.path == "$.seq"
    assert canonicalize(2 ** 53) == b"9007199254740992"
    with pytest.raises(JcsError) as e:
        canonicalize({"a": ["ok", chr(0xD800)]})
    assert e.value.path == "$.a[1]"
    with pytest.raises(JcsError):
        canonicalize({1: "x"})
    with pytest.raises(JcsError):
        canonicalize({"s": {1, 2}})


def test_sha256_hex_is_64_hex():
    h = sha256_hex({"a": 1})
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
