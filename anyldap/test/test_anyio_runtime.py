import anyio
import anyio.lowlevel
import pytest

from anyldap import inmemory, testutil
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldapsyntax

pytestmark = pytest.mark.anyio


async def test_ldap_client_bind_async():
    client = ldapclient.LDAPClient()
    client.makeConnection(testutil.StringTransport())
    creds = (b"cn=foo,dc=example,dc=com", b"secret")
    result = {}

    async with anyio.create_task_group() as task_group:
        async def run_bind():
            result["value"] = await client.bind_async(*creds)

        task_group.start_soon(run_bind)
        while not client.onwire:
            await anyio.lowlevel.checkpoint()
        message_id = next(iter(client.onwire))
        response = pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(resultCode=0, matchedDN=creds[0])
        )
        response.id = message_id
        client.dataReceived(response.toWire())

    assert result["value"] == (creds[0], None)


async def test_ldapsyntax_commit_async():
    client = testutil.LDAPClientTestDriver(
        [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")]
    )
    entry = ldapsyntax.LDAPEntry(
        client=client,
        dn="cn=foo,dc=example,dc=com",
        attributes={"objectClass": ["inetOrgPerson"], "cn": ["foo"]},
        complete=1,
    )

    entry["sn"] = ["bar"]
    result = await entry.commit_async()

    assert result is entry


async def test_ldapsyntax_search_async():
    client = testutil.LDAPClientTestDriver(
        [
            pureldap.LDAPSearchResultEntry(
                "cn=foo,dc=example,dc=com", [("cn", ["foo"])]
            ),
            pureldap.LDAPSearchResultDone(resultCode=0, matchedDN="", errorMessage=""),
        ]
    )
    entry = ldapsyntax.LDAPEntry(client=client, dn="dc=example,dc=com")

    results = await entry.search_async()

    assert [item.dn.getText() for item in results] == ["cn=foo,dc=example,dc=com"]


async def test_inmemory_lookup_async():
    root = inmemory.ReadOnlyInMemoryLDAPEntry(
        dn="dc=example,dc=com", attributes={"dc": ["example"]}
    )
    child = root.addChild("cn=foo", {"cn": ["foo"], "objectClass": ["top"]})

    looked_up = await root.lookup_async("cn=foo,dc=example,dc=com")
    children = await root.children_async()
    committed = await child.commit_async()

    assert looked_up is child
    assert children == [child]
    assert committed is True
