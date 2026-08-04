"""python-ldap's tests for ldap.filter, run against anyldap.ldap.filter.

Ported from python-ldap 3.4.7, ``Tests/t_ldap_filter.py``. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed.
"""

import pytest

from anyldap.ldap.filter import escape_filter_chars


def test_escape_filter_chars_mode0() -> None:
    assert escape_filter_chars(r"foobar") == "foobar"
    assert escape_filter_chars(r"foo\bar") == r"foo\5cbar"
    assert escape_filter_chars(r"foo\bar", escape_mode=0) == r"foo\5cbar"


def test_escape_filter_chars_mode1() -> None:
    assert (
        escape_filter_chars(
            "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f",
            escape_mode=1,
        )
        == r"\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f"
    )
    with pytest.raises(TypeError):
        escape_filter_chars(["abc@*()/xyz"], escape_mode=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        escape_filter_chars({"abc@*()/xyz": 1}, escape_mode=1)  # type: ignore[arg-type]


def test_escape_filter_chars_mode2() -> None:
    assert escape_filter_chars("foobar", escape_mode=2) == r"\66\6f\6f\62\61\72"
