import anyio
import anyio.lowlevel
import pytest
import subprocess
import sys

from anyldap import config
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors, proxy
from anyldap.test._anyio_helpers import (
    AsyncLDAPClientDriver,
    MemoryByteStream,
    decode_message,
    patch_client_creator,
)

pytestmark = pytest.mark.anyio


class LegacyClient:
    connected = True

    def __init__(self):
        self.calls = []
        self.transport = MemoryByteStream()

    def send_multiResponse(self, request, callback, reply):
        self.calls.append(("multi", request, callback, reply))

    def send_noResponse(self, request):
        self.calls.append(("none", request))

    def unbind(self):
        self.calls.append(("unbind",))


def _legacy_server(client=None):
    server = proxy.Proxy(config.LDAPConfig(serviceLocationOverrides={}))
    server.client = client
    server.waitingConnect = []
    return server


async def test_legacy_waits_for_connection_and_forwards_result():
    server = _legacy_server()
    deferred = server._whenConnected(lambda value: value + 1, 4)

    assert not deferred.called
    server._cbConnectionMade(LegacyClient())
    assert await deferred == 5


async def test_legacy_waits_for_connection_and_forwards_failure():
    server = _legacy_server()

    def broken():
        raise ValueError("broken")

    deferred = server._whenConnected(broken)
    server._cbConnectionMade(LegacyClient())
    with pytest.raises(ValueError, match="broken"):
        await deferred


async def test_legacy_connected_call_and_request_queues():
    client = LegacyClient()
    server = _legacy_server(client)
    assert await server._whenConnected(lambda value: value, "ready") == "ready"

    replies = []
    bind = pureldap.LDAPBindRequest()
    unbind = pureldap.LDAPUnbindRequest()
    server._clientQueue(bind, None, replies.append)
    server._clientQueue(unbind, None, replies.append)
    assert client.calls[0][0:2] == ("multi", bind)
    assert client.calls[1] == ("none", unbind)

    assert not server._gotResponse(pureldap.LDAPSearchResultEntry("cn=a", []), replies.append)
    assert server._gotResponse(pureldap.LDAPSearchResultDone(resultCode=0), replies.append)
    assert server._gotResponse(pureldap.LDAPBindResponse(resultCode=0), replies.append)
    assert len(replies) == 3


async def test_async_queue_falls_back_to_legacy_client_methods():
    client = LegacyClient()
    server = _legacy_server(client)
    await server._clientQueue_async(pureldap.LDAPBindRequest(), None, lambda response: None)
    await server._clientQueue_async(pureldap.LDAPUnbindRequest(), None, lambda response: None)
    assert [call[0] for call in client.calls] == ["multi", "none"]


async def test_async_queue_uses_async_client_methods():
    class AsyncClient:
        def __init__(self):
            self.calls = []

        async def send_multiResponse_async(self, request, callback, reply):
            self.calls.append(("multi", request, callback, reply))

        async def send_noResponse_async(self, request):
            self.calls.append(("none", request))

    client = AsyncClient()
    server = _legacy_server(client)
    await server._clientQueue_async(pureldap.LDAPBindRequest(), None, lambda response: None)
    await server._clientQueue_async(pureldap.LDAPUnbindRequest(), None, lambda response: None)
    assert [call[0] for call in client.calls] == ["multi", "none"]


async def test_legacy_unknown_and_unbind_handlers():
    client = LegacyClient()
    server = _legacy_server(client)
    bind = pureldap.LDAPBindRequest()
    await server.handleUnknown(bind, None, lambda response: None)
    assert client.calls[0][0:2] == ("multi", bind)

    await server.handle_LDAPUnbindRequest(
        pureldap.LDAPUnbindRequest(), None, lambda response: None
    )
    assert server.unbound
    assert client.calls[1][0] == "none"


async def test_async_unknown_handler_waits_for_connection():
    server = _legacy_server(LegacyClient())
    await server._handleUnknown_async(
        pureldap.LDAPBindRequest(), None, lambda response: None
    )
    assert server.client.calls[0][0] == "multi"


async def test_connection_lost_unbinds_then_closes_legacy_client():
    client = LegacyClient()
    server = _legacy_server(client)
    server.connectionLost(Exception("closed"))
    assert client.calls == [("unbind",)]
    assert server.client is None

    class Transport:
        def __init__(self):
            self.closed = False

        def loseConnection(self):
            self.closed = True

    client = LegacyClient()
    client.transport = Transport()
    server = _legacy_server(client)
    server.unbound = True
    server.connectionLost(Exception("closed"))
    assert client.transport.closed


async def test_connection_lost_ignores_disconnected_client():
    client = LegacyClient()
    client.connected = False
    server = _legacy_server(client)
    server.connectionLost(Exception("closed"))
    assert client.calls == []
    assert server._failConnection(ValueError("no server")).args == ("no server",)


async def test_legacy_connection_made_uses_configured_override():
    client = LegacyClient()
    configured = config.LDAPConfig(serviceLocationOverrides={"": lambda factory: client})
    server = proxy.Proxy(configured)
    server.waitingConnect = []
    server.connectionMade()
    assert server.client is client
    assert server.connected == 1


async def test_async_connection_made_uses_configured_override():
    client = LegacyClient()
    configured = config.LDAPConfig(serviceLocationOverrides={"": lambda factory: client})
    server = proxy.Proxy(configured)
    server.waitingConnect = []
    await server.connectionMade_async()
    assert server.client is client
    assert server.connected == 1


async def test_async_connection_made_handles_override_failure():
    def fail_to_connect(factory):
        raise OSError("unreachable")

    configured = config.LDAPConfig(serviceLocationOverrides={"": fail_to_connect})
    server = proxy.Proxy(configured)
    server.waitingConnect = []
    await server.connectionMade_async()
    assert server.client is None
    assert server.connected == 1


async def test_connection_lost_schedules_async_close_paths():
    class AsyncCloseClient:
        connected = True

        def __init__(self):
            self.closed = False

        async def aclose(self):
            self.closed = True

    first_client = AsyncCloseClient()
    second_client = AsyncCloseClient()
    async with anyio.create_task_group() as task_group:
        server = _legacy_server(first_client)
        server._anyio_task_group = task_group
        server.connectionLost(Exception("closed"))

        server = _legacy_server(second_client)
        server.unbound = True
        server._anyio_task_group = task_group
        server.connectionLost(Exception("closed"))

    assert first_client.closed
    assert second_client.closed


async def test_connection_lost_without_task_group_cannot_schedule_async_close():
    class AsyncCloseClient:
        connected = True
        aclose = anyio.lowlevel.checkpoint

    server = _legacy_server(AsyncCloseClient())
    server.connectionLost(Exception("closed"))
    assert server.client is None

    server = _legacy_server(AsyncCloseClient())
    server.unbound = True
    server.connectionLost(Exception("closed"))
    assert server.client is None


async def test_proxy_module_is_not_a_legacy_entrypoint():
    result = subprocess.run(
        [sys.executable, "-m", proxy.__name__],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "AnyIO server entrypoints" in result.stderr


async def _create_server(monkeypatch, *responses):
    client = AsyncLDAPClientDriver(*responses)
    patch_client_creator(monkeypatch, proxy, client)
    server = proxy.Proxy(config.LDAPConfig(serviceLocationOverrides={}))
    stream = MemoryByteStream()
    return server, stream, client


async def test_bind(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        [pureldap.LDAPBindResponse(resultCode=0)],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == 0
        assert response.id == 4
        client.assert_sent(pureldap.LDAPBindRequest())
        await server.aclose()


async def test_bind_sasl_no_credentials(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        [pureldap.LDAPBindResponse(resultCode=14, serverSaslCreds="test123")],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(auth=("GSS-SPNEGO", None), sasl=True), id=4
            ).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == 14
        assert response.value.serverSaslCreds == b"test123"
        assert response.id == 4
        client.assert_sent(
            pureldap.LDAPBindRequest(auth=("GSS-SPNEGO", None), sasl=True)
        )
        await server.aclose()


async def test_search(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        [pureldap.LDAPBindResponse(resultCode=0)],
        [
            pureldap.LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
            pureldap.LDAPSearchResultEntry("cn=bar,dc=example,dc=com", [("b", ["c"])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=3).toWire()
        )
        bind_response = decode_message(await stream.next_write())
        entry1 = decode_message(await stream.next_write())
        entry2 = decode_message(await stream.next_write())
        done = decode_message(await stream.next_write())

        assert bind_response.value.resultCode == 0
        assert entry1.value.objectName == b"cn=foo,dc=example,dc=com"
        assert entry2.value.objectName == b"cn=bar,dc=example,dc=com"
        assert done.value.resultCode == ldaperrors.Success.resultCode
        client.assert_sent(
            pureldap.LDAPBindRequest(),
            pureldap.LDAPSearchRequest(),
        )
        await server.aclose()


async def test_unbind_client_unbinds(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        [pureldap.LDAPBindResponse(resultCode=0)],
        [],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        await stream.next_write()
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=3).toWire()
        )
        await anyio.sleep(0.01)
        await server.aclose()
        client.assert_sent(pureldap.LDAPBindRequest(), pureldap.LDAPUnbindRequest())


async def test_unbind_client_eof(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        [pureldap.LDAPBindResponse(resultCode=0)],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        await stream.next_write()
        await anyio.lowlevel.checkpoint()
        await server.aclose()
        client.assert_sent(pureldap.LDAPBindRequest(), pureldap.LDAPUnbindRequest())
