"""python-ldap's tests for ldapurl, run against anyldap.ldap.ldapurl.

Ported from python-ldap 3.4.7, ``Tests/t_ldapurl.py``. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed.
"""

from urllib.parse import quote

import pytest

from anyldap.ldap import ldapurl
from anyldap.ldap.ldapurl import LDAPUrl


class MyLDAPUrl(LDAPUrl):
    attr2extype = {
        "who": "bindname",
        "cred": "X-BINDPW",
        "start_tls": "startTLS",
        "trace_level": "trace",
    }


IS_LDAP_URL_TESTS = {
    # Examples from RFC2255
    "ldap:///o=University%20of%20Michigan,c=US": 1,
    "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US": 1,
    "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,": 1,
    "ldap://host.com:6666/o=University%20of%20Michigan,": 1,
    "ldap://ldap.itd.umich.edu/c=GB?objectClass?one": 1,
    "ldap://ldap.question.com/o=Question%3f,c=US?mail": 1,
    "ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5c00%5c00%5c00%5c04)": 1,
    "ldap:///??sub??bindname=cn=Manager%2co=Foo": 1,
    "ldap:///??sub??!bindname=cn=Manager%2co=Foo": 1,
    # More examples from various sources
    "ldap://ldap.nameflow.net:1389/c%3dDE": 1,
    "ldap://root.openldap.org/dc=openldap,dc=org": 1,
    "ldaps://root.openldap.org/dc=openldap,dc=org": 1,
    "ldap://x500.mh.se/o=Mitthogskolan,c=se????1.2.752.58.10.2=T.61": 1,
    "ldp://root.openldap.org/dc=openldap,dc=org": 0,
    "ldap://localhost:1389/ou%3DUnstructured%20testing%20tree%2Cdc%3Dstroeder%2Cdc%3Dcom??one": 1,
    "ldaps://ldap.example.com/c%3dDE": 1,
    "ldapi:///dc=stroeder,dc=de????x-saslmech=EXTERNAL": 1,
    "LDAP://localhost": True,
    "LDAPS://localhost": True,
    "LDAPI://%2Frun%2Fldap.sock": True,
    " ldap://space.example": False,
    "ldap ://space.example": False,
}


@pytest.mark.parametrize(("ldap_url", "expected"), IS_LDAP_URL_TESTS.items())
def test_isLDAPUrl(ldap_url: str, expected: bool | int) -> None:
    assert ldapurl.isLDAPUrl(ldap_url) == expected
    if expected:
        LDAPUrl(ldapUrl=ldap_url)
    else:
        with pytest.raises(ValueError):
            LDAPUrl(ldapUrl=ldap_url)


PARSE_LDAP_URL_TESTS = [
    (
        "ldap://root.openldap.org/dc=openldap,dc=org",
        LDAPUrl(hostport="root.openldap.org", dn="dc=openldap,dc=org"),
    ),
    (
        "ldap://root.openldap.org/dc%3dboolean%2cdc%3dnet???%28objectClass%3d%2a%29",
        LDAPUrl(
            hostport="root.openldap.org",
            dn="dc=boolean,dc=net",
            filterstr="(objectClass=*)",
        ),
    ),
    (
        "ldap://root.openldap.org/dc=openldap,dc=org??sub?",
        LDAPUrl(
            hostport="root.openldap.org",
            dn="dc=openldap,dc=org",
            scope=ldapurl.LDAP_SCOPE_SUBTREE,
        ),
    ),
    (
        "ldap://root.openldap.org/dc=openldap,dc=org??one?",
        LDAPUrl(
            hostport="root.openldap.org",
            dn="dc=openldap,dc=org",
            scope=ldapurl.LDAP_SCOPE_ONELEVEL,
        ),
    ),
    (
        "ldap://root.openldap.org/dc=openldap,dc=org??base?",
        LDAPUrl(
            hostport="root.openldap.org",
            dn="dc=openldap,dc=org",
            scope=ldapurl.LDAP_SCOPE_BASE,
        ),
    ),
    (
        "ldap://x500.mh.se/o=Mitthogskolan,c=se????1.2.752.58.10.2=T.61",
        LDAPUrl(
            hostport="x500.mh.se",
            dn="o=Mitthogskolan,c=se",
            extensions=ldapurl.LDAPUrlExtensions(
                {
                    "1.2.752.58.10.2": ldapurl.LDAPUrlExtension(
                        critical=0, extype="1.2.752.58.10.2", exvalue="T.61"
                    )
                }
            ),
        ),
    ),
    (
        "ldap://localhost:12345/dc=stroeder,dc=com????"
        "!bindname=cn=Michael%2Cdc=stroeder%2Cdc=com,!X-BINDPW=secretpassword",
        LDAPUrl(
            hostport="localhost:12345",
            dn="dc=stroeder,dc=com",
            extensions=ldapurl.LDAPUrlExtensions(
                {
                    "bindname": ldapurl.LDAPUrlExtension(
                        critical=1,
                        extype="bindname",
                        exvalue="cn=Michael,dc=stroeder,dc=com",
                    ),
                    "X-BINDPW": ldapurl.LDAPUrlExtension(
                        critical=1, extype="X-BINDPW", exvalue="secretpassword"
                    ),
                }
            ),
        ),
    ),
    (
        "ldap://localhost:54321/dc=stroeder,dc=com????"
        "bindname=cn=Michael%2Cdc=stroeder%2Cdc=com,X-BINDPW=secretpassword",
        LDAPUrl(
            hostport="localhost:54321",
            dn="dc=stroeder,dc=com",
            who="cn=Michael,dc=stroeder,dc=com",
            cred="secretpassword",
        ),
    ),
    (
        "ldaps://localhost:12345/dc=stroeder,dc=com",
        LDAPUrl(
            urlscheme="ldaps", hostport="localhost:12345", dn="dc=stroeder,dc=com"
        ),
    ),
    (
        "LDAPS://localhost:12345/dc=stroeder,dc=com",
        LDAPUrl(
            urlscheme="ldaps", hostport="localhost:12345", dn="dc=stroeder,dc=com"
        ),
    ),
    (
        "ldaps://localhost:12345/dc=stroeder,dc=com",
        LDAPUrl(
            urlscheme="LDAPS", hostport="localhost:12345", dn="dc=stroeder,dc=com"
        ),
    ),
    (
        "ldapi://%2ftmp%2fopenldap2-1389/dc=stroeder,dc=com",
        LDAPUrl(
            urlscheme="ldapi",
            hostport="/tmp/openldap2-1389",
            dn="dc=stroeder,dc=com",
        ),
    ),
]


@pytest.mark.parametrize(("ldap_url_str", "expected"), PARSE_LDAP_URL_TESTS)
def test_ldapurl(ldap_url_str: str, expected: LDAPUrl) -> None:
    assert LDAPUrl(ldapUrl=ldap_url_str) == expected
    # And what it writes back out says the same thing again.
    assert LDAPUrl(ldapUrl=expected.unparse()) == expected


def test_combo() -> None:
    u = MyLDAPUrl(
        "ldap://127.0.0.1:1234/dc=example,dc=com"
        + "?attr1,attr2,attr3"
        + "?sub"
        + "?"
        + quote("(objectClass=*)")
        + "?bindname="
        + quote("cn=d,c=au")
        + ",X-BINDPW="
        + quote("???")
        + ",trace=8"
    )
    assert u.urlscheme == "ldap"
    assert u.hostport == "127.0.0.1:1234"
    assert u.dn == "dc=example,dc=com"
    assert u.attrs == ["attr1", "attr2", "attr3"]
    assert u.scope == ldapurl.LDAP_SCOPE_SUBTREE
    assert u.filterstr == "(objectClass=*)"
    assert u.extensions is not None
    assert len(u.extensions) == 3
    assert u.who == "cn=d,c=au"
    assert u.cred == "???"
    assert u.trace_level == "8"


def test_parse_default_hostport() -> None:
    u = LDAPUrl("ldap://")
    assert u.urlscheme == "ldap"
    assert u.hostport == ""


def test_parse_empty_dn() -> None:
    assert LDAPUrl("ldap://").dn == ""
    assert LDAPUrl("ldap:///").dn == ""
    assert LDAPUrl("ldap:///?").dn == ""


def test_parse_default_attrs() -> None:
    assert LDAPUrl("ldap://").attrs is None


def test_parse_default_scope() -> None:
    assert LDAPUrl("ldap://").scope is None  # RFC4516 s3


def test_parse_default_filter() -> None:
    assert LDAPUrl("ldap://").filterstr is None  # RFC4516 s3


def test_parse_default_extensions() -> None:
    extensions = LDAPUrl("ldap://").extensions
    assert extensions is not None
    assert len(extensions) == 0


def test_parse_schemes() -> None:
    assert LDAPUrl("ldap://").urlscheme == "ldap"
    assert LDAPUrl("ldapi://").urlscheme == "ldapi"
    assert LDAPUrl("ldaps://").urlscheme == "ldaps"


@pytest.mark.parametrize(
    ("url", "hostport"),
    [
        ("ldap://a", "a"),
        ("ldap://a.b", "a.b"),
        ("ldap://a.", "a."),
        ("ldap://%61%62:%32/", "ab:2"),
        ("ldap://[::1]/", "[::1]"),
        ("ldap://[::1]", "[::1]"),
        ("ldap://[::1]:123/", "[::1]:123"),
        ("ldap://[::1]:123", "[::1]:123"),
    ],
)
def test_parse_hostport(url: str, hostport: str) -> None:
    assert LDAPUrl(url).hostport == hostport


@pytest.mark.parametrize(
    ("url", "dn"),
    [
        ("ldap:///", ""),
        ("ldap:///dn=foo", "dn=foo"),
        ("ldap:///dn=foo%2cdc=bar", "dn=foo,dc=bar"),
        ("ldap:///dn=foo%20bar", "dn=foo bar"),
        ("ldap:///dn=foo%2fbar", "dn=foo/bar"),
        ("ldap:///dn=foo%2fbar?", "dn=foo/bar"),
        ("ldap:///dn=foo%3f?", "dn=foo?"),
        ("ldap:///dn=foo%3f", "dn=foo?"),
        ("ldap:///dn=str%c3%b6der.com", "dn=str\xf6der.com"),
    ],
)
def test_parse_dn(url: str, dn: str) -> None:
    assert LDAPUrl(url).dn == dn


@pytest.mark.parametrize(
    ("url", "attrs"),
    [
        ("ldap:///?", None),
        ("ldap:///??", None),
        ("ldap:///?*?", ["*"]),
        ("ldap:///?*,*?", ["*", "*"]),
        ("ldap:///?a", ["a"]),
        ("ldap:///?%61", ["a"]),
        ("ldap:///?a,b", ["a", "b"]),
        ("ldap:///?a%3fb", ["a?b"]),
    ],
)
def test_parse_attrs(url: str, attrs: list[str] | None) -> None:
    assert LDAPUrl(url).attrs == attrs


def test_parse_scope_default() -> None:
    # on opposite to RFC4516 s3 for referral chasing
    assert LDAPUrl("ldap:///??").scope is None
    assert LDAPUrl("ldap:///???").scope is None


@pytest.mark.parametrize(
    ("url", "scope"),
    [
        ("ldap:///??sub", ldapurl.LDAP_SCOPE_SUBTREE),
        ("ldap:///??sub?", ldapurl.LDAP_SCOPE_SUBTREE),
        ("ldap:///??base", ldapurl.LDAP_SCOPE_BASE),
        ("ldap:///??base?", ldapurl.LDAP_SCOPE_BASE),
        ("ldap:///??one", ldapurl.LDAP_SCOPE_ONELEVEL),
        ("ldap:///??one?", ldapurl.LDAP_SCOPE_ONELEVEL),
        ("ldap:///??subordinates", ldapurl.LDAP_SCOPE_SUBORDINATES),
        ("ldap:///??subordinates?", ldapurl.LDAP_SCOPE_SUBORDINATES),
    ],
)
def test_parse_scope(url: str, scope: int) -> None:
    assert LDAPUrl(url).scope == scope


@pytest.mark.parametrize(
    ("url", "filterstr"),
    [
        ("ldap:///???(cn=Bob)", "(cn=Bob)"),
        ("ldap:///???(cn=Bob)?", "(cn=Bob)"),
        ("ldap:///???(cn=Bob%20Smith)?", "(cn=Bob Smith)"),
        ("ldap:///???(cn=Bob/Smith)?", "(cn=Bob/Smith)"),
        ("ldap:///???(cn=Bob:Smith)?", "(cn=Bob:Smith)"),
        ("ldap:///???&(cn=Bob)(objectClass=user)?", "&(cn=Bob)(objectClass=user)"),
        ("ldap:///???|(cn=Bob)(objectClass=user)?", "|(cn=Bob)(objectClass=user)"),
        ("ldap:///???(cn=Q%3f)?", "(cn=Q?)"),
        ("ldap:///???(cn=Q%3f)", "(cn=Q?)"),
        # (possibly bad?)
        ("ldap:///???(sn=Str%c3%b6der)", "(sn=Str\xf6der)"),
        # (recommended)
        ("ldap:///???(sn=Str\\c3\\b6der)", "(sn=Str\\c3\\b6der)"),
        ("ldap:///???(cn=*\\2a*)", "(cn=*\\2a*)"),
        ("ldap:///???(cn=*%5c2a*)", "(cn=*\\2a*)"),
    ],
)
def test_parse_filter(url: str, filterstr: str) -> None:
    assert LDAPUrl(url).filterstr == filterstr


def test_parse_extensions() -> None:
    u = LDAPUrl("ldap:///????")
    assert u.extensions is None
    assert u.who is None

    u = LDAPUrl("ldap:///????bindname=cn=root")
    assert u.extensions is not None
    assert len(u.extensions) == 1
    assert u.who == "cn=root"

    u = LDAPUrl("ldap:///????!bindname=cn=root")
    assert u.extensions is not None
    assert len(u.extensions) == 1
    assert u.who == "cn=root"

    u = LDAPUrl("ldap:///????bindname=%3f,X-BINDPW=%2c")
    assert u.extensions is not None
    assert len(u.extensions) == 2
    assert u.who == "?"
    assert u.cred == ","


def test_parse_extensions_nulls() -> None:
    assert LDAPUrl("ldap:///????bindname=%00name").who == "\0name"


def test_parse_extensions_5questions() -> None:
    u = LDAPUrl("ldap:///????bindname=?")
    assert u.extensions is not None
    assert len(u.extensions) == 1
    assert u.who == "?"


def test_parse_extensions_novalue() -> None:
    u = LDAPUrl("ldap:///????bindname")
    assert u.extensions is not None
    assert len(u.extensions) == 1
    assert u.who is None


BAD_URLS = [
    "",
    "ldap:",
    "ldap:/",
    ":///",
    "://",
    "///",
    "//",
    "/",
    "ldap:///?????",  # extension can't start with '?'
    "LDAP://",
    "invalid://",
    "ldap:///??invalid",
    # XXX-- the following should raise exceptions!
    "ldap://:389/",  # [host [COLON port]]
    "ldap://a:/",  # [host [COLON port]]
    r"ldap://%%%/",  # invalid URL encoding
    "ldap:///?,",  # attrdesc *(COMMA attrdesc)
    "ldap:///?a,",  # attrdesc *(COMMA attrdesc)
    "ldap:///?,a",  # attrdesc *(COMMA attrdesc)
    "ldap:///?a,,b",  # attrdesc *(COMMA attrdesc)
    r"ldap://%00/",  # RFC4516 2.1
    r"ldap:///%00",  # RFC4516 2.1
    r"ldap:///?%00",  # RFC4516 2.1
    r"ldap:///??%00",  # RFC4516 2.1
    "ldap:///????0=0",  # extype must start with Alpha
    "ldap:///????a_b=0",  # extype contains only [-a-zA-Z0-9]
    "ldap:///????!!a=0",  # only one exclamation allowed
]


@pytest.mark.xfail(reason="python-ldap does not reject these either", strict=False)
@pytest.mark.parametrize("bad", BAD_URLS)
def test_bad_urls(bad: str) -> None:
    with pytest.raises(ValueError):
        LDAPUrl(bad)
