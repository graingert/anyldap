"""python-ldap's tests for ldap.functions, run against anyldap.ldap.

Ported from python-ldap 3.4.7, ``Tests/t_ldap_functions.py``. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed.
"""

from anyldap import ldap
from anyldap.ldap.dn import escape_dn_chars
from anyldap.ldap.filter import escape_filter_chars


def test_ldap_strf_secs() -> None:
    assert ldap.strf_secs(0) == "19700101000000Z"
    assert ldap.strf_secs(1466947067) == "20160626131747Z"


def test_ldap_strp_secs() -> None:
    assert ldap.strp_secs("19700101000000Z") == 0
    assert ldap.strp_secs("20160626131747Z") == 1466947067


def test_escape_str() -> None:
    assert (
        ldap.escape_str(
            escape_filter_chars, "(&(objectClass=aeUser)(uid=%s))", "foo"
        )
        == "(&(objectClass=aeUser)(uid=foo))"
    )
    assert (
        ldap.escape_str(
            escape_filter_chars, "(&(objectClass=aeUser)(uid=%s))", "foo)bar"
        )
        == "(&(objectClass=aeUser)(uid=foo\\29bar))"
    )
    assert ldap.escape_str(escape_dn_chars, "uid=%s", "foo=bar") == "uid=foo\\=bar"
    assert (
        ldap.escape_str(
            escape_dn_chars,
            "uid=%s,cn=%s,cn=%s,dc=example,dc=com",
            "foo=bar",
            "foo+",
            "+bar",
        )
        == "uid=foo\\=bar,cn=foo\\+,cn=\\+bar,dc=example,dc=com"
    )
