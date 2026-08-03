import anyio
import pytest
from anyio.abc import SocketAttribute

from anyldap import inmemory, testutil
from anyldap._async import ResultSlot, await_result
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldapserver, ldapsyntax
from anyldap.runtime import Failure, Protocol, unwrap_failure

pytestmark = pytest.mark.anyio


async def test_await_result_accepts_all_result_shapes() -> None:
    async def native():
        return "awaitable"

    assert await await_result(native()) == "awaitable"
    assert await await_result("plain") == "plain"


async def test_result_slot_replays_a_value() -> None:
    slot = ResultSlot()
    assert not slot.is_set
    slot.set_value("done")
    assert slot.is_set
    assert await slot.wait() == "done"


async def test_result_slot_replays_an_exception() -> None:
    slot = ResultSlot()
    slot.set_exception(ValueError("boom"))
    with pytest.raises(ValueError, match="boom"):
        await slot.wait()


async def test_result_slot_waits_for_a_late_producer() -> None:
    slot = ResultSlot()

    async def produce() -> None:
        slot.set_value("late")

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(produce)
        assert await slot.wait() == "late"


async def test_result_slot_rejects_a_second_result() -> None:
    slot = ResultSlot()
    slot.set_value(1)
    with pytest.raises(RuntimeError, match="result already set"):
        slot.set_value(2)


async def test_unwrap_failure_accepts_wrapped_and_bare_reasons() -> None:
    error = ValueError("gone")
    assert unwrap_failure(Failure(error)) is error
    assert unwrap_failure(error) is error


async def test_protocol_default_hooks() -> None:
    protocol = Protocol()
    assert protocol.connectionMade() is None
    assert protocol.connectionLost() is None
    assert protocol.dataReceived(b"ignored") is None


async def test_failure_handles_broken_string_and_type_matching() -> None:
    class BrokenStringError(Exception):
        def __str__(self) -> None:
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


async def test_ldap_client_bind_async() -> None:
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


async def test_ldapsyntax_commit_async() -> None:
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


async def test_ldapsyntax_search_async() -> None:
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


async def test_inmemory_lookup_async() -> None:
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
