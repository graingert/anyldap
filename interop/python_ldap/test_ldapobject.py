"""python-ldap's tests for ldap.ldapobject, run against anyldap.ldap.

Ported from python-ldap 3.4.7: ``Tests/t_ldapobject.py``, with the two tests
of ``Tests/t_bind.py`` and ``Tests/t_edit.py`` that apply. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed and what was left out.

python-ldap's ``SlapdTestCase`` is a fixture here: one slapd for the module,
holding the entries its ``LDIF_TEMPLATE`` describes.
"""

import os
from collections.abc import AsyncGenerator, Iterator
from typing import Any

import pytest

from anyldap import ldap

python_ldap_slapdtest = pytest.importorskip(
    "slapdtest", reason="python-ldap's slapdtest is not installed"
)

if not any(
    os.path.exists(os.path.join(path, "slapd"))
    for path in ("/usr/sbin", "/usr/local/sbin", "/usr/lib/openldap", "/sbin")
):  # pragma: no cover - depends on what is installed
    pytest.skip("slapd is not installed", allow_module_level=True)

pytestmark = pytest.mark.anyio

LDIF_TEMPLATE = """dn: %(suffix)s
objectClass: dcObject
objectClass: organization
dc: %(dc)s
o: %(dc)s

dn: %(rootdn)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: %(rootcn)s
userPassword: %(rootpw)s

dn: cn=user1,%(suffix)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: user1
userPassword: user1_pw

dn: cn=Foo1,%(suffix)s
objectClass: organizationalRole
cn: Foo1

dn: cn=Foo2,%(suffix)s
objectClass: organizationalRole
cn: Foo2

dn: cn=Foo3,%(suffix)s
objectClass: organizationalRole
cn: Foo3

dn: ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: Container

dn: cn=Foo4,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo4

"""


@pytest.fixture(scope="module")
def slapd() -> Iterator[Any]:
    """One OpenLDAP server holding python-ldap's own test entries."""
    server = python_ldap_slapdtest.SlapdObject()
    server.start()
    try:
        server.ldapadd(
            LDIF_TEMPLATE
            % {
                "suffix": server.suffix,
                "rootdn": server.root_dn,
                "rootcn": server.root_cn,
                "rootpw": server.root_pw,
                "dc": server.suffix.split(",")[0][3:],
            }
        )
        yield server
    finally:
        server.stop()


@pytest.fixture
async def conn(slapd: Any) -> AsyncGenerator[ldap.SimpleLDAPObject, None]:
    """A connection bound as the root user, as _open_ldap_conn() opens."""
    async with ldap.initialize(slapd.ldap_uri) as connection:
        connection.protocol_version = 3
        connection.set_option(ldap.OPT_REFERRALS, 0)
        await connection.simple_bind_s(slapd.root_dn, slapd.root_pw)
        yield connection


def role(cn: str, suffix: str) -> tuple[str, dict[str, list[bytes]]]:
    return (
        f"cn={cn},{suffix}",
        {"cn": [cn.encode("ascii")], "objectClass": [b"organizationalRole"]},
    )


# Searching.


async def test_search_keys_are_text(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    base = slapd.suffix
    result = await conn.search_s(base, ldap.SCOPE_SUBTREE, "(cn=Foo*)", ["*"])
    result.sort()
    dn, fields = result[0]
    assert dn == "cn=Foo1,%s" % base
    assert type(dn) is str
    assert isinstance(fields, dict)
    for key, values in fields.items():
        assert type(key) is str
        for value in values:
            assert type(value) is bytes


async def test_search_accepts_unicode_dn(conn: ldap.SimpleLDAPObject) -> None:
    with pytest.raises(ldap.NO_SUCH_OBJECT):
        await conn.search_s("CN=abc\U0001f498def", ldap.SCOPE_SUBTREE)


async def test_filterstr_accepts_unicode(
    conn: ldap.SimpleLDAPObject, slapd: Any
) -> None:
    result = await conn.search_s(
        slapd.suffix, ldap.SCOPE_SUBTREE, "(cn=abc\U0001f498def)", ["*"]
    )
    assert result == []


async def test_attrlist_accepts_unicode(
    conn: ldap.SimpleLDAPObject, slapd: Any
) -> None:
    result = await conn.search_s(
        slapd.suffix, ldap.SCOPE_SUBTREE, "(cn=Foo*)", ["abc", "abc\U0001f498def"]
    )
    result.sort()
    for dn, attrs in result:
        assert isinstance(dn, str)
        assert attrs == {}


async def test001_search_subtree(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    result = await conn.search_s(
        slapd.suffix, ldap.SCOPE_SUBTREE, "(cn=Foo*)", attrlist=["*"]
    )
    result.sort()
    assert result == [
        role("Foo1", slapd.suffix),
        role("Foo2", slapd.suffix),
        role("Foo3", slapd.suffix),
        role("Foo4", "ou=Container," + slapd.suffix),
    ]


async def test002_search_onelevel(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    result = await conn.search_s(slapd.suffix, ldap.SCOPE_ONELEVEL, "(cn=Foo*)", ["*"])
    result.sort()
    assert result == [
        role("Foo1", slapd.suffix),
        role("Foo2", slapd.suffix),
        role("Foo3", slapd.suffix),
    ]


async def test003_search_oneattr(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    result = await conn.search_s(slapd.suffix, ldap.SCOPE_SUBTREE, "(cn=Foo4)", ["cn"])
    result.sort()
    assert result == [
        ("cn=Foo4,ou=Container," + slapd.suffix, {"cn": [b"Foo4"]})
    ]


async def test_find_unique_entry(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    result = await conn.find_unique_entry(
        slapd.suffix, ldap.SCOPE_SUBTREE, "(cn=Foo4)", ["cn"]
    )
    assert result == ("cn=Foo4,ou=Container," + slapd.suffix, {"cn": [b"Foo4"]})

    with pytest.raises(ldap.SIZELIMIT_EXCEEDED):
        # > 2 entries returned
        await conn.find_unique_entry(
            slapd.suffix, ldap.SCOPE_ONELEVEL, "(cn=Foo*)", ["*"]
        )
    with pytest.raises(ldap.NO_UNIQUE_ENTRY):
        # 0 entries returned
        await conn.find_unique_entry(
            slapd.suffix, ldap.SCOPE_ONELEVEL, "(cn=Bar*)", ["*"]
        )


async def test_valid_attrlist_parameter_types(
    conn: ldap.SimpleLDAPObject, slapd: Any
) -> None:
    """Any iterable which only contains strings should not raise any errors."""
    valid = [{"a": "2"}, ["a", "b"], {}, set(), {"a", "b"}]
    for attrlist in valid:
        await conn.search_ext(slapd.suffix, ldap.SCOPE_SUBTREE, attrlist=attrlist)


async def test_invalid_attrlist_parameter_types(
    conn: ldap.SimpleLDAPObject, slapd: Any
) -> None:
    """Anything that is not an iterable of strings should raise TypeError."""
    invalid = [{1: 2}, 0, object(), "string"]
    for attrlist in invalid:
        with pytest.raises(TypeError):
            await conn.search_ext(slapd.suffix, ldap.SCOPE_SUBTREE, attrlist=attrlist)


# Binding, and what the server says about itself.


async def test_simple_bind_noarg(slapd: Any) -> None:
    async with ldap.initialize(slapd.ldap_uri) as connection:
        await connection.simple_bind_s()
        assert await connection.whoami_s() == ""
    async with ldap.initialize(slapd.ldap_uri) as connection:
        await connection.simple_bind_s("", "")
        assert await connection.whoami_s() == ""


async def test_simple_bind_wrong_credentials(slapd: Any) -> None:
    """From t_bind.py: a DN that is not there, with a password that is not."""
    unicode_val = "abc\U0001f498def"
    async with ldap.initialize(slapd.ldap_uri) as connection:
        with pytest.raises(ldap.INVALID_CREDENTIALS):
            await connection.simple_bind_s("CN=" + unicode_val, unicode_val)


async def test_dse(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    dse = await conn.read_rootdse_s()
    assert isinstance(dse, dict)
    assert dse["supportedLDAPVersion"] == [b"3"]
    keys = set(dse)
    # SASL info may be missing in restricted build environments
    keys.discard("supportedSASLMechanisms")
    assert keys == {
        "configContext",
        "entryDN",
        "namingContexts",
        "objectClass",
        "structuralObjectClass",
        "subschemaSubentry",
        "supportedControl",
        "supportedExtension",
        "supportedFeatures",
        "supportedLDAPVersion",
    }
    assert await conn.get_naming_contexts() == [slapd.suffix.encode("utf-8")]


async def test_search_subschema(conn: ldap.SimpleLDAPObject) -> None:
    dn = await conn.search_subschemasubentry_s()
    assert isinstance(dn, str)
    assert dn == "cn=Subschema"
    subschema = await conn.read_subschemasubentry_s(dn)
    assert isinstance(subschema, dict)
    # python-ldap asks for the schema attributes it knows; matchingRuleUse
    # is one this does not read, so it is not asked for.
    assert sorted(subschema) == [
        "attributeTypes",
        "ldapSyntaxes",
        "matchingRules",
        "objectClasses",
    ]


async def test005_invalid_credentials(slapd: Any) -> None:
    async with ldap.initialize(slapd.ldap_uri) as connection:
        msgid = await connection.simple_bind(
            slapd.root_dn, slapd.root_pw + "wrong"
        )
        with pytest.raises(ldap.INVALID_CREDENTIALS):
            await connection.result4(msgid, ldap.MSG_ALL)


# Comparing.


async def test_compare_s_true(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    result = await conn.compare_s("cn=Foo1,%s" % slapd.suffix, "cn", b"Foo1")
    assert result is True


async def test_compare_s_false(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    result = await conn.compare_s("cn=Foo1,%s" % slapd.suffix, "cn", b"Foo2")
    assert result is False


async def test_compare_s_notfound(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    with pytest.raises(ldap.NO_SUCH_OBJECT):
        await conn.compare_s("cn=invalid,%s" % slapd.suffix, "cn", b"Foo2")


async def test_compare_s_invalidattr(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    with pytest.raises(ldap.UNDEFINED_TYPE):
        await conn.compare_s("cn=Foo1,%s" % slapd.suffix, "invalidattr", b"invalid")


async def test_compare_true_exception_contains_message_id(
    conn: ldap.SimpleLDAPObject, slapd: Any
) -> None:
    msgid = await conn.compare("cn=Foo1,%s" % slapd.suffix, "cn", b"Foo1")
    with pytest.raises(ldap.COMPARE_TRUE) as caught:
        await conn.result()
    assert caught.value.args[0]["msgid"] == msgid


async def test_async_search_no_such_object_exception_contains_message_id(
    conn: ldap.SimpleLDAPObject,
) -> None:
    msgid = await conn.search("CN=XXX", ldap.SCOPE_SUBTREE)
    with pytest.raises(ldap.NO_SUCH_OBJECT) as caught:
        await conn.result()
    assert caught.value.args[0]["msgid"] == msgid


# Changing entries.


async def test_passwd_s(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    # first, create a user to change password on
    dn = "cn=PasswordTest," + slapd.suffix
    result, pmsg, msgid, ctrls = await conn.add_ext_s(
        dn,
        [
            ("objectClass", b"person"),
            ("sn", b"PasswordTest"),
            ("cn", b"PasswordTest"),
            ("userPassword", b"initial"),
        ],
    )
    assert result == ldap.RES_ADD
    assert isinstance(msgid, int)
    assert pmsg == []
    assert ctrls == []

    # try changing password with a wrong old-pw
    with pytest.raises(ldap.UNWILLING_TO_PERFORM):
        await conn.passwd_s(dn, "bogus", "ignored")

    # change it, and change it back
    respoid, respvalue = await conn.passwd_s(dn, "initial", "changed")
    assert respoid is None
    assert respvalue is None
    respoid, respvalue = await conn.passwd_s(dn, "changed", "initial")
    assert respoid is None
    assert respvalue is None

    await conn.delete_s(dn)


async def test_add_object(conn: ldap.SimpleLDAPObject, slapd: Any) -> None:
    """From t_edit.py: add an entry, find it, and remove it again."""
    base = slapd.suffix
    dn = "cn=Added,ou=Container," + base
    await conn.add_ext_s(
        dn, [("objectClass", [b"organizationalRole"]), ("cn", [b"Added"])]
    )

    # Lookup the object
    result = await conn.search_s(base, ldap.SCOPE_SUBTREE, "(cn=Added)", ["*"])
    assert result == [
        (
            "cn=Added,ou=Container," + base,
            {"cn": [b"Added"], "objectClass": [b"organizationalRole"]},
        )
    ]
    # Delete object
    await conn.delete_s(dn)
    result = await conn.search_s(base, ldap.SCOPE_SUBTREE, "(cn=Added)", ["*"])
    assert result == []


# ReconnectLDAPObject, from Test01_ReconnectLDAPObject: the same tests as
# above hold for it, and these are the ones that are its own.


async def test_reconnect_simple_bind(slapd: Any) -> None:
    connection = ldap.ReconnectLDAPObject(slapd.ldap_uri)
    bind_dn = "cn=user1," + slapd.suffix
    await connection.simple_bind_s(bind_dn, "user1_pw")
    assert await connection.whoami_s() == "dn:" + bind_dn
    slapd.restart()
    assert await connection.whoami_s() == "dn:" + bind_dn
    await connection.unbind_s()


async def test_reconnect_sasl_external(slapd: Any) -> None:
    connection = ldap.ReconnectLDAPObject(slapd.ldapi_uri)
    await connection.sasl_external_bind_s()
    authz_id = await connection.whoami_s()
    assert authz_id == "dn:" + slapd.root_dn.lower()
    slapd.restart()
    assert await connection.whoami_s() == authz_id
    await connection.unbind_s()


async def test_reconnect_get_state(slapd: Any) -> None:
    connection = ldap.ReconnectLDAPObject(slapd.ldap_uri)
    bind_dn = "cn=user1," + slapd.suffix
    await connection.simple_bind_s(bind_dn, "user1_pw")
    assert await connection.whoami_s() == "dn:" + bind_dn
    state = connection.__getstate__()
    # The names and shapes are python-ldap's; what is stored beside them is
    # this client's own, and is left out here.
    assert state["_last_bind"] == ("simple_bind_s", (bind_dn, "user1_pw"), {})
    assert state["_options"] == []
    assert state["_reconnects_done"] == 0
    assert state["_retry_delay"] == 60.0
    assert state["_retry_max"] == 1
    assert state["_start_tls"] == 0
    assert state["_uri"] == slapd.ldap_uri
    assert state["timeout"] is None
    await connection.unbind_s()


async def test_reconnect_restore(slapd: Any) -> None:
    import pickle

    connection = ldap.ReconnectLDAPObject(slapd.ldap_uri)
    bind_dn = "cn=user1," + slapd.suffix
    await connection.simple_bind_s(bind_dn, "user1_pw")
    assert await connection.whoami_s() == "dn:" + bind_dn
    written = pickle.dumps(connection)
    await connection.unbind_s()
    del connection

    read_back = pickle.loads(written)
    assert await read_back.whoami_s() == "dn:" + bind_dn
    await read_back.unbind_s()


async def test_reconnect_after_the_server_goes_away_and_comes_back(
    slapd: Any,
) -> None:
    connection = ldap.ReconnectLDAPObject(
        slapd.ldap_uri, retry_max=2, retry_delay=1
    )
    bind_dn = "cn=user1," + slapd.suffix
    await connection.simple_bind_s(bind_dn, "user1_pw")
    assert await connection.whoami_s() == "dn:" + bind_dn

    slapd.terminate()
    slapd.wait()
    try:
        with pytest.raises(ldap.SERVER_DOWN):
            await connection.whoami_s()
    finally:
        slapd.resume()

    # The connection is used again, and binds again rather than searching
    # as nobody at all: python-ldap's !267.
    assert await connection.whoami_s() == "dn:" + bind_dn
    assert await connection.search_ext_s(bind_dn, ldap.SCOPE_BASE)
    await connection.unbind_s()
