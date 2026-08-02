import anyio
import pytest
from anyio.abc import SocketAttribute

from anyldap import inmemory, testutil
from anyldap._async import await_deferred, await_result
from anyldap.deferred import succeed
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldapserver, ldapsyntax
from anyldap.runtime import Failure, Protocol

pytestmark = pytest.mark.anyio


async def test_await_deferred_accepts_native_deferred_and_awaitable():
    assert await await_deferred(succeed("deferred")) == "deferred"

    async def native():
        return "awaitable"

    assert await await_deferred(native()) == "awaitable"


async def test_await_deferred_rejects_plain_value():
    with pytest.raises(TypeError, match="Unsupported deferred object: 42"):
        await await_deferred(42)


async def test_await_result_accepts_all_result_shapes():
    async def native():
        return "awaitable"

    assert await await_result(succeed("deferred")) == "deferred"
    assert await await_result(native()) == "awaitable"
    assert await await_result("plain") == "plain"


async def test_protocol_default_hooks():
    protocol = Protocol()
    assert protocol.connectionMade() is None
    assert protocol.connectionLost() is None
    assert protocol.dataReceived(b"ignored") is None


async def test_failure_handles_broken_string_and_type_matching():
    class BrokenStringError(Exception):
        def __str__(self):
            raise RuntimeError("cannot stringify")

    error = BrokenStringError("broken")
    failure = Failure(error)
    assert "BrokenStringError" in str(failure)
    assert failure.trap(BrokenStringError) is BrokenStringError
    assert failure.check(ValueError, BrokenStringError) is BrokenStringError
    assert failure.check(ValueError) is None
    with pytest.raises(BrokenStringError):
        failure.trap(ValueError)
    with pytest.raises(BrokenStringError):
        failure.raiseException()


async def test_ldap_client_bind_async():
    client = ldapclient.LDAPClient()
    creds = (b"cn=foo,dc=example,dc=com", b"secret")

    class BindServer(ldapserver.BaseLDAPServer):
        def handle_LDAPBindRequest(self, request, controls, reply):
            return pureldap.LDAPBindResponse(resultCode=0, matchedDN=request.dn)

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve, listener, BindServer)
        client_stream = await anyio.connect_tcp(host, port)
        await client.attach_stream(client_stream, task_group)
        assert await client.bind_async(*creds) == (creds[0], None)
        await client.aclose()
        await listener.aclose()


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
