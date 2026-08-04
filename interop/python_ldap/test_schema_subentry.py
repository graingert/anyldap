"""python-ldap's tests for ldap.schema.SubSchema, run against anyldap.ldap.

Ported from python-ldap 3.4.7, ``Tests/t_ldap_schema_subentry.py``. Copyright
the python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT
in this directory, and README.rst for what was changed.

Upstream reads its schema out of two LDIF files of about half a megabyte
each. Those are not vendored here; the definitions each test needs are
inline instead, taken from those files, and the tests that read a whole
schema read it from slapd.
"""

import os
from collections.abc import Iterator
from typing import Any

import pytest

from anyldap import ldap
from anyldap.ldap.schema.models import AttributeType, ObjectClass

python_ldap_slapdtest = pytest.importorskip(
    "slapdtest", reason="python-ldap's slapdtest is not installed"
)

if not any(
    os.path.exists(os.path.join(path, "slapd"))
    for path in ("/usr/sbin", "/usr/local/sbin", "/usr/lib/openldap", "/sbin")
):  # pragma: no cover - depends on what is installed
    pytest.skip("slapd is not installed", allow_module_level=True)

pytestmark = pytest.mark.anyio

# From subschema-ipa.demo1.freeipa.org.ldif, which upstream reads these out of.
KRB_HOST_SERVER = (
    "( 2.16.840.1.113719.1.301.4.24.1 NAME 'krbHostServer' "
    "EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )"
)
NSSLAPD_SUFFIX = (
    "( 2.16.840.1.113730.3.1.2091 NAME 'nsslapd-suffix' "
    "DESC 'Netscape defined attribute type' "
    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 X-ORIGIN 'Netscape' )"
)
SEARCH_TIME_LIMIT = (
    "( 1.3.6.1.4.1.11.1.3.1.1.3 NAME 'searchTimeLimit' "
    "DESC 'Maximum time an agent or service allows for a search to complete' "
    "EQUALITY integerMatch ORDERING integerOrderingMatch "
    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE "
    "X-ORIGIN ( 'RFC4876' 'user defined' ) )"
)
GROUP_OF_NAMES = (
    "( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST cn "
    "MAY ( member $ businessCategory $ seeAlso $ owner $ ou $ o "
    "$ description ) X-ORIGIN 'RFC 4519' )"
)


@pytest.fixture(scope="module")
def slapd() -> Iterator[Any]:
    server = python_ldap_slapdtest.SlapdObject()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def test_origin_none() -> None:
    assert AttributeType(KRB_HOST_SERVER).x_origin == ()


def test_origin_string() -> None:
    assert AttributeType(NSSLAPD_SUFFIX).x_origin == ("Netscape",)


def test_origin_multi_valued() -> None:
    assert AttributeType(SEARCH_TIME_LIMIT).x_origin == ("RFC4876", "user defined")


def test_origin_none_str() -> None:
    """Check string representation of an attribute without X-ORIGIN"""
    # This should check that the representation:
    # - does not contain X-ORIGIN, and
    # - is still syntactically valid.
    assert str(AttributeType(KRB_HOST_SERVER)) == (
        "( 2.16.840.1.113719.1.301.4.24.1 "
        "NAME 'krbHostServer' "
        "EQUALITY caseExactIA5Match "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )"
    )


def test_origin_string_str() -> None:
    """Check string representation of an attr with single-value X-ORIGIN"""
    assert str(AttributeType(NSSLAPD_SUFFIX)) == (
        "( 2.16.840.1.113730.3.1.2091 "
        "NAME 'nsslapd-suffix' "
        "DESC 'Netscape defined attribute type' "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
        "X-ORIGIN 'Netscape' )"
    )


def test_origin_multi_valued_str() -> None:
    """Check string representation of an attr with multi-value X-ORIGIN"""
    assert str(AttributeType(SEARCH_TIME_LIMIT)) == (
        "( 1.3.6.1.4.1.11.1.3.1.1.3 NAME 'searchTimeLimit' "
        "DESC 'Maximum time an agent or service allows for a search "
        "to complete' "
        "EQUALITY integerMatch "
        "ORDERING integerOrderingMatch "
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
        "SINGLE-VALUE "
        "X-ORIGIN ( 'RFC4876' 'user defined' ) )"
    )


def test_set_origin_str() -> None:
    """Check that setting X-ORIGIN to a string makes entry unusable"""
    attr = AttributeType(KRB_HOST_SERVER)
    attr.x_origin = "Netscape"  # type: ignore[assignment]
    with pytest.raises(AssertionError):
        str(attr)


def test_set_origin_list() -> None:
    """Check that setting X-ORIGIN to a list makes entry unusable"""
    attr = AttributeType(KRB_HOST_SERVER)
    attr.x_origin = []  # type: ignore[assignment]
    with pytest.raises(AssertionError):
        str(attr)


def test_set_origin_tuple() -> None:
    """Check that setting X-ORIGIN to a tuple works"""
    attr = AttributeType(KRB_HOST_SERVER)
    attr.x_origin = ("user defined",)
    assert " X-ORIGIN 'user defined' " in str(attr)


def test_empty_attributetype_attrs() -> None:
    """Check types and values of attributes of a minimal AttributeType"""
    # (OID 2.999 is actually "/Example", for use in documentation)
    attr = AttributeType("( 2.999 )")
    assert attr.oid == "2.999"
    assert attr.names == ()
    assert attr.desc is None
    assert attr.obsolete == 0
    assert attr.single_value == 0
    assert attr.syntax is None
    assert attr.no_user_mod == 0
    assert attr.equality is None
    assert attr.substr is None
    assert attr.ordering is None
    assert attr.usage == 0
    assert attr.sup == ()
    assert attr.x_origin == ()


def test_empty_objectclass_attrs() -> None:
    """Check types and values of attributes of a minimal ObjectClass"""
    cls = ObjectClass("( 2.999 )")
    assert cls.oid == "2.999"
    assert cls.names == ()
    assert cls.desc is None
    assert cls.obsolete == 0
    assert cls.must == ()
    assert cls.may == ()
    assert cls.kind == 0
    assert cls.sup == ("top",)
    assert cls.x_origin == ()


def test_attributetype_attrs() -> None:
    """Check types and values of an AttributeType object's attributes"""
    attr = AttributeType(SEARCH_TIME_LIMIT)
    expected_desc = (
        "Maximum time an agent or service allows for a search to complete"
    )
    assert attr.oid == "1.3.6.1.4.1.11.1.3.1.1.3"
    assert attr.names == ("searchTimeLimit",)
    assert attr.desc == expected_desc
    assert attr.obsolete == 0
    assert attr.single_value == 1
    assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.27"
    assert attr.no_user_mod == 0
    assert attr.equality == "integerMatch"
    assert attr.ordering == "integerOrderingMatch"
    assert attr.sup == ()
    assert attr.x_origin == ("RFC4876", "user defined")


def test_objectclass_attrs() -> None:
    """Check types and values of an ObjectClass object's attributes"""
    cls = ObjectClass(GROUP_OF_NAMES)
    expected_may = (
        "member",
        "businessCategory",
        "seeAlso",
        "owner",
        "ou",
        "o",
        "description",
    )
    assert cls.oid == "2.5.6.9"
    assert cls.names == ("groupOfNames",)
    assert cls.desc is None
    assert cls.obsolete == 0
    assert cls.must == ("cn",)
    assert cls.may == expected_may
    assert cls.kind == 0
    assert cls.sup == ("top",)
    assert cls.x_origin == ("RFC 4519",)


def assert_slapd_schema(dn: str | None, schema: ldap.schema.SubSchema | None) -> None:
    assert dn == "cn=Subschema"
    assert isinstance(schema, ldap.schema.SubSchema)
    obj = schema.get_obj(ObjectClass, "1.3.6.1.1.3.1")
    assert str(obj) == (
        "( 1.3.6.1.1.3.1 NAME 'uidObject' DESC 'RFC2377: uid object' "
        "SUP top AUXILIARY MUST uid )"
    )
    entries = schema.ldap_entry()
    assert isinstance(entries, dict)
    assert sorted(entries) == [
        "attributeTypes",
        "ldapSyntaxes",
        "matchingRuleUse",
        "matchingRules",
        "objectClasses",
    ]


async def test_urlfetch_ldap(slapd: Any) -> None:
    dn, schema = await ldap.schema.urlfetch(slapd.ldap_uri)
    assert_slapd_schema(dn, schema)


async def test_urlfetch_ldapi(slapd: Any) -> None:
    dn, schema = await ldap.schema.urlfetch(slapd.ldapi_uri)
    assert_slapd_schema(dn, schema)


async def test_subschema_from_a_server(slapd: Any) -> None:
    """From TestSubschemaLDIF, over the schema slapd publishes.

    Upstream reads two LDIF files here; the smoke check is the same either
    way -- every object class, and what an entry of it must and may have.

    ``raise_keyerror=0`` because slapd names attributes in its own object
    classes that it does not publish definitions for, which python-ldap
    raises on too when it is pointed at the same server rather than at the
    LDIF files upstream uses.
    """
    _, schema = await ldap.schema.urlfetch(slapd.ldap_uri)
    assert schema is not None
    for objclass in schema.listall(ObjectClass):
        must, may = schema.attribute_types([objclass], raise_keyerror=0)
        for oid, attributetype in must.items():
            assert attributetype.oid == oid
        for oid, attributetype in may.items():
            assert attributetype.oid == oid
