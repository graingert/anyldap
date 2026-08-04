"""python-ldap's tests for ldap.dn, run against anyldap.ldap.dn.

Ported from python-ldap 3.4.7, ``Tests/t_ldap_dn.py``. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed.
"""

import pytest

from anyldap.ldap import dn


def test_is_dn() -> None:
    assert dn.is_dn("foobar,ou=ae-dir") is False
    assert dn.is_dn("-cn=foobar,ou=ae-dir") is False
    assert dn.is_dn(";cn=foobar,ou=ae-dir") is False
    assert dn.is_dn(",cn=foobar,ou=ae-dir") is False
    assert dn.is_dn("cn=foobar,ou=ae-dir,") is False
    assert dn.is_dn("uid=xkcd,cn=foobar,ou=ae-dir") is True
    assert dn.is_dn("cn=äöüÄÖÜß,o=äöüÄÖÜß") is True
    assert (
        dn.is_dn(
            r"cn=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f"
            r",o=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f"
        )
        is True
    )


def test_escape_dn_chars() -> None:
    assert dn.escape_dn_chars("foobar") == "foobar"
    assert dn.escape_dn_chars("foo,bar") == "foo\\,bar"
    assert dn.escape_dn_chars("foo=bar") == "foo\\=bar"
    assert dn.escape_dn_chars("foo#bar") == "foo#bar"
    assert dn.escape_dn_chars("#foobar") == "\\#foobar"
    assert dn.escape_dn_chars("foo bar") == "foo bar"
    assert dn.escape_dn_chars(" foobar") == "\\ foobar"
    assert dn.escape_dn_chars(" ") == "\\ "
    assert dn.escape_dn_chars("  ") == "\\ \\ "
    assert dn.escape_dn_chars("foobar ") == "foobar\\ "
    assert (
        dn.escape_dn_chars('f+o>o,b<a;r="\00"')
        == 'f\\+o\\>o\\,b\\<a\\;r\\=\\"\\00\\"'
    )
    assert dn.escape_dn_chars("foo\\,bar") == "foo\\\\\\,bar"


def test_str2dn() -> None:
    assert dn.str2dn("") == []
    assert dn.str2dn("uid=test42,ou=Testing,dc=example,dc=com") == [
        [("uid", "test42", 1)],
        [("ou", "Testing", 1)],
        [("dc", "example", 1)],
        [("dc", "com", 1)],
    ]
    assert dn.str2dn("uid=test42+uidNumber=42,ou=Testing,dc=example,dc=com") == [
        [("uid", "test42", 1), ("uidNumber", "42", 1)],
        [("ou", "Testing", 1)],
        [("dc", "example", 1)],
        [("dc", "com", 1)],
    ]
    assert dn.str2dn("uid=test42,ou=Testing,dc=example,dc=com", flags=0) == [
        [("uid", "test42", 1)],
        [("ou", "Testing", 1)],
        [("dc", "example", 1)],
        [("dc", "com", 1)],
    ]
    assert dn.str2dn("uid=test\\, 42,ou=Testing,dc=example,dc=com", flags=0) == [
        [("uid", "test, 42", 1)],
        [("ou", "Testing", 1)],
        [("dc", "example", 1)],
        [("dc", "com", 1)],
    ]
    assert dn.str2dn("cn=äöüÄÖÜß,dc=example,dc=com", flags=0) == [
        [("cn", "äöüÄÖÜß", 4)],
        [("dc", "example", 1)],
        [("dc", "com", 1)],
    ]
    assert dn.str2dn(
        r"cn=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f,dc=example,dc=com",
        flags=0,
    ) == [
        [("cn", "äöüÄÖÜß", 4)],
        [("dc", "example", 1)],
        [("dc", "com", 1)],
    ]


def test_dn2str() -> None:
    assert dn.str2dn("") == []
    assert (
        dn.dn2str(
            [
                [("uid", "test42", 1)],
                [("ou", "Testing", 1)],
                [("dc", "example", 1)],
                [("dc", "com", 1)],
            ]
        )
        == "uid=test42,ou=Testing,dc=example,dc=com"
    )
    assert (
        dn.dn2str(
            [
                [("uid", "test42", 1), ("uidNumber", "42", 1)],
                [("ou", "Testing", 1)],
                [("dc", "example", 1)],
                [("dc", "com", 1)],
            ]
        )
        == "uid=test42+uidNumber=42,ou=Testing,dc=example,dc=com"
    )
    assert (
        dn.dn2str(
            [
                [("uid", "test, 42", 1)],
                [("ou", "Testing", 1)],
                [("dc", "example", 1)],
                [("dc", "com", 1)],
            ]
        )
        == "uid=test\\, 42,ou=Testing,dc=example,dc=com"
    )
    assert (
        dn.dn2str(
            [[("cn", "äöüÄÖÜß", 4)], [("dc", "example", 1)], [("dc", "com", 1)]]
        )
        == "cn=äöüÄÖÜß,dc=example,dc=com"
    )


def test_explode_dn() -> None:
    assert dn.explode_dn("") == []
    assert dn.explode_dn("uid=test42,ou=Testing,dc=example,dc=com") == [
        "uid=test42",
        "ou=Testing",
        "dc=example",
        "dc=com",
    ]
    assert dn.explode_dn("uid=test42,ou=Testing,dc=example,dc=com", flags=0) == [
        "uid=test42",
        "ou=Testing",
        "dc=example",
        "dc=com",
    ]
    assert dn.explode_dn(
        "uid=test42,ou=Testing,dc=example,dc=com", notypes=True
    ) == ["test42", "Testing", "example", "com"]
    assert dn.explode_dn("uid=test\\, 42,ou=Testing,dc=example,dc=com", flags=0) == [
        "uid=test\\, 42",
        "ou=Testing",
        "dc=example",
        "dc=com",
    ]
    assert dn.explode_dn("cn=äöüÄÖÜß,dc=example,dc=com", flags=0) == [
        "cn=äöüÄÖÜß",
        "dc=example",
        "dc=com",
    ]
    assert dn.explode_dn(
        r"cn=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f,dc=example,dc=com",
        flags=0,
    ) == ["cn=äöüÄÖÜß", "dc=example", "dc=com"]


def test_explode_rdn() -> None:
    assert dn.explode_rdn("") == []
    assert dn.explode_rdn("uid=test42") == ["uid=test42"]
    assert dn.explode_rdn("uid=test42", notypes=False, flags=0) == ["uid=test42"]
    assert dn.explode_rdn("uid=test42", notypes=0, flags=0) == ["uid=test42"]
    assert dn.explode_rdn("uid=test42+uidNumber=42", flags=0) == [
        "uid=test42",
        "uidNumber=42",
    ]
    assert dn.explode_rdn("uid=test42", notypes=True) == ["test42"]
    assert dn.explode_rdn("uid=test42", notypes=1) == ["test42"]
    assert dn.explode_rdn("uid=test\\+ 42", flags=0) == ["uid=test\\+ 42"]
    assert dn.explode_rdn("cn=äöüÄÖÜß", flags=0) == ["cn=äöüÄÖÜß"]
    assert dn.explode_rdn(
        r"cn=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f", flags=0
    ) == ["cn=äöüÄÖÜß"]


# Not in python-ldap's own tests: it raises DECODING_ERROR from the C
# library for the names is_dn() answers False for, and so does this.
def test_a_name_that_is_not_a_dn_is_a_decoding_error() -> None:
    from anyldap.ldap import errors

    for value in ["foobar,ou=ae-dir", "-cn=foobar", ",cn=foobar", "cn=foobar,"]:
        with pytest.raises(errors.DECODING_ERROR):
            dn.str2dn(value)
