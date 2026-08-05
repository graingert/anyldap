"""python-ldap's tests for ldap.schema.tokenizer, run against anyldap's.

Ported from python-ldap 3.4.7, ``Tests/t_ldap_schema_tokenizer.py``. Copyright
the python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT
in this directory, and README.rst for what was changed.
"""

import pytest

from anyldap.ldap.schema import split_tokens

# basic test cases
TESTCASES_BASIC = (
    (" BLUBBER DI BLUBB ", ["BLUBBER", "DI", "BLUBB"]),
    ("BLUBBER DI BLUBB", ["BLUBBER", "DI", "BLUBB"]),
    ("BL-UB-BER DI BL-UBB", ["BL-UB-BER", "DI", "BL-UBB"]),
    ("BLUBBER  DI   BLUBB  ", ["BLUBBER", "DI", "BLUBB"]),
    ("BLUBBER  DI  'BLUBB'   ", ["BLUBBER", "DI", "BLUBB"]),
    ("BLUBBER ( DI ) 'BLUBB'   ", ["BLUBBER", "(", "DI", ")", "BLUBB"]),
    ("BLUBBER(DI)", ["BLUBBER", "(", "DI", ")"]),
    ("BLUBBER ( DI)", ["BLUBBER", "(", "DI", ")"]),
    ("BLUBBER ''", ["BLUBBER", ""]),
    ("( BLUBBER (DI 'BLUBB'))", ["(", "BLUBBER", "(", "DI", "BLUBB", ")", ")"]),
    ("BLUBB (DA$BLAH)", ["BLUBB", "(", "DA", "BLAH", ")"]),
    ("BLUBB ( DA $  BLAH )", ["BLUBB", "(", "DA", "BLAH", ")"]),
    ("BLUBB (DA$ BLAH)", ["BLUBB", "(", "DA", "BLAH", ")"]),
    ("BLUBB (DA $BLAH)", ["BLUBB", "(", "DA", "BLAH", ")"]),
    ("BLUBB 'DA$BLAH'", ["BLUBB", "DA$BLAH"]),
    ("BLUBB DI 'BLU B B ER' DA 'BLAH' ", ["BLUBB", "DI", "BLU B B ER", "DA", "BLAH"]),
    (
        "BLUBB DI 'BLU B B ER' DA 'BLAH' LABER",
        ["BLUBB", "DI", "BLU B B ER", "DA", "BLAH", "LABER"],
    ),
    ("BLUBB\t'DA\tBLUB'", ["BLUBB", "DA\tBLUB"]),
)

# UTF-8 raw strings
TESTCASES_UTF8 = (
    (
        " BL\xc3\x9cBBER D\xc3\x84 BL\xc3\x9cBB ",
        ["BL\xc3\x9cBBER", "D\xc3\x84", "BL\xc3\x9cBB"],
    ),
    (
        "BL\xc3\x9cBBER D\xc3\x84 BL\xc3\x9cBB",
        ["BL\xc3\x9cBBER", "D\xc3\x84", "BL\xc3\x9cBB"],
    ),
    (
        "BL\xc3\x9cBBER  D\xc3\x84   BL\xc3\x9cBB  ",
        ["BL\xc3\x9cBBER", "D\xc3\x84", "BL\xc3\x9cBB"],
    ),
)

# broken schema of Oracle Internet Directory
TESTCASES_BROKEN_OID = (
    "BLUBB DI 'BLU B B ER'MUST 'BLAH' ",
    "BLUBBER DI 'BLU'BB ER' DA 'BLAH' ",
)

# for quoted single quotes inside string values
TESTCASES_ESCAPED_QUOTES = (
    ("BLUBBER '\\''", ["BLUBBER", "'"]),
    ("BLUBBER DI 'BLU\\'BB ER' DA 'BLAH' ", ["BLUBBER", "DI", "BLU'BB ER", "DA", "BLAH"]),
    (
        "BLUBBER DI 'BLU\\' BB ER' DA 'BLAH' ",
        ["BLUBBER", "DI", "BLU' BB ER", "DA", "BLAH"],
    ),
)

# test cases which should result in ValueError raised
TESTCASES_BROKEN = (
    "( BLUB",
    "BLUB )",
    "BLUB 'DA",
    "BLUB $ DA",
)


@pytest.mark.parametrize(
    ("value", "tokens"),
    [*TESTCASES_BASIC, *TESTCASES_UTF8, *TESTCASES_ESCAPED_QUOTES],
)
def test_split_tokens(value: str, tokens: list[str]) -> None:
    assert split_tokens(value) == tokens


@pytest.mark.parametrize("value", [*TESTCASES_BROKEN_OID, *TESTCASES_BROKEN])
def test_split_tokens_refuses(value: str) -> None:
    with pytest.raises(ValueError):
        split_tokens(value)
