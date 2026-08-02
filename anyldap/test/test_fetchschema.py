"""
Test cases for anyldap.protocols.ldap.fetchschema module.
"""
import pytest

from anyldap import schema
from anyldap._encoder import to_bytes
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import fetchschema
from anyldap.testutil import LDAPClientTestDriver

pytestmark = pytest.mark.anyio


def search_entry(dn, attributes):
    return pureldap.LDAPSearchResultEntry(objectName=dn, attributes=attributes)


search_done = pureldap.LDAPSearchResultDone(resultCode=0)


async def test_fetch_rejects_missing_base_entry():
    client = LDAPClientTestDriver([search_done])
    with pytest.raises(fetchschema.ldaperrors.LDAPOther, match="No such DN"):
        await fetchschema.fetch(client, "dc=example,dc=com")


async def test_fetch_rejects_multiple_base_entries():
    client = LDAPClientTestDriver(
        [search_entry("dc=one", []), search_entry("dc=two", []), search_done]
    )
    with pytest.raises(fetchschema.ldaperrors.LDAPOther, match="multiple entries"):
        await fetchschema.fetch(client, "dc=example,dc=com")


async def test_fetch_rejects_missing_subschema_entry():
    client = LDAPClientTestDriver(
        [search_entry("", [("subschemaSubentry", ["cn=Subschema"])]), search_done],
        [search_done],
    )
    with pytest.raises(fetchschema.ldaperrors.LDAPOther, match="No such DN"):
        await fetchschema.fetch(client, "dc=example,dc=com")


async def test_fetch_rejects_multiple_subschema_entries():
    client = LDAPClientTestDriver(
        [search_entry("", [("subschemaSubentry", ["cn=Subschema"])]), search_done],
        [
            search_entry("cn=Subschema", []),
            search_entry("cn=Subschema", []),
            search_done,
        ],
    )
    with pytest.raises(fetchschema.ldaperrors.LDAPOther, match="multiple entries"):
        await fetchschema.fetch(client, "dc=example,dc=com")


class TestOnWire:
    cn = """( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s) for which the entity is known by' SUP name )"""
    dcObject = """( 1.3.6.1.4.1.1466.344 NAME 'dcObject' DESC 'RFC2247: domain component object' SUP top AUXILIARY MUST dc )"""

    async def testSimple(self):
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="",
                    attributes=(
                        ("subschemaSubentry", ["cn=Subschema"]),
                        ("bar", ["b", "c"]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=Subschema",
                    attributes=(
                        ("attributeTypes", [self.cn]),
                        ("objectClasses", [self.dcObject]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
        )

        val = await fetchschema.fetch(client, "dc=example,dc=com")
        self._cb_testSimple(val, client)

    def _cb_testSimple(self, val, client):
        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_baseObject,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=1,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilter_present("objectClass"),
                attributes=["subschemaSubentry"],
            ),
            pureldap.LDAPSearchRequest(
                baseObject="cn=Subschema",
                scope=pureldap.LDAP_SCOPE_baseObject,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=1,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilter_present("objectClass"),
                attributes=["attributeTypes", "objectClasses"],
            ),
        )
        assert len(val) == 2

        assert [to_bytes(x) for x in val[0]] == [to_bytes(schema.AttributeTypeDescription(self.cn))]
        assert [to_bytes(x) for x in val[1]] == [to_bytes(schema.ObjectClassDescription(self.dcObject))]
