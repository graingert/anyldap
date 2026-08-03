import subprocess
import sys

import anyio
import anyio.lowlevel
import pytest

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


class StubClient:
    connected = True

    def __init__(self):
        self.calls = []

    async def send_multiResponse_async(self, request, callback, reply):
        self.calls.append(("multi", request, callback, reply))

    async def send_noResponse_async(self, request):
        self.calls.append(("none", request))

    async def aclose(self):
        self.connected = False


async def test_stub_client_close_uses_async_interface() -> None:
    client = StubClient()
    await client.aclose()
    assert not client.connected


def _legacy_server(client=None):
    server = proxy.Proxy(config.LDAPConfig(serviceLocationOverrides={}))
    server.client = client
    return server


async def _connect_after_checkpoint(server):
    """Let the waiter block first, then complete the connection."""
    await anyio.lowlevel.checkpoint()
    server._cbConnectionMade(StubClient())


async def test_waits_for_connection_and_forwards_result() -> None:
    server = _legacy_server()
    results = []

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(_connect_after_checkpoint, server)
        results.append(await server._whenConnected(lambda value: value + 1, 4))

    assert results == [5]


async def test_waits_for_connection_and_forwards_failure() -> None:
    server = _legacy_server()

    def broken():
        raise ValueError("broken")

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(_connect_after_checkpoint, server)
        with pytest.raises(ValueError, match="broken"):
            await server._whenConnected(broken)


async def test_async_queue_uses_client_async_interface() -> None:
    client = StubClient()
    server = _legacy_server(client)
    await server._clientQueue_async(pureldap.LDAPBindRequest(), None, lambda response: None)
    await server._clientQueue_async(pureldap.LDAPUnbindRequest(), None, lambda response: None)
    assert [call[0] for call in client.calls] == ["multi", "none"]


async def test_async_queue_uses_async_client_methods() -> None:
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


async def test_async_unknown_handler_waits_for_connection() -> None:
    server = _legacy_server(StubClient())
    await server._handleUnknown_async(
        pureldap.LDAPBindRequest(), None, lambda response: None
    )
    assert server.client.calls[0][0] == "multi"


async def test_connection_lost_without_task_group_detaches_client() -> None:
    client = StubClient()
    server = _legacy_server(client)
    server.connectionLost(Exception("closed"))
    assert server.client is None


async def test_connection_lost_ignores_disconnected_client() -> None:
    client = StubClient()
    client.connected = False
    server = _legacy_server(client)
    server.connectionLost(Exception("closed"))
    assert client.calls == []
    assert server._failConnection(ValueError("no server")).args == ("no server",)


async def test_async_connection_made_uses_configured_override() -> None:
    client = StubClient()
    configured = config.LDAPConfig(serviceLocationOverrides={"": lambda factory: client})
    server = proxy.Proxy(configured)
    await server.connectionMade_async()
    assert server.client is client
    assert server.connected == 1


async def test_async_connection_made_handles_override_failure() -> None:
    def fail_to_connect(factory):
        raise OSError("unreachable")

    configured = config.LDAPConfig(serviceLocationOverrides={"": fail_to_connect})
    server = proxy.Proxy(configured)
    await server.connectionMade_async()
    assert server.client is None
    assert server.connected == 1


async def test_connection_lost_schedules_async_close_paths() -> None:
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


async def test_connection_lost_without_task_group_cannot_schedule_async_close() -> None:
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


async def test_proxy_module_is_not_a_legacy_entrypoint() -> None:
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


async def test_bind(monkeypatch: pytest.MonkeyPatch) -> None:
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


async def test_bind_sasl_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
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


async def test_search(monkeypatch: pytest.MonkeyPatch) -> None:
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
        task_group.start_soon(
            stream.feed,
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=3).toWire(),
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


async def test_unbind_client_unbinds(monkeypatch: pytest.MonkeyPatch) -> None:
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


async def test_eof_closes_upstream_client(monkeypatch: pytest.MonkeyPatch) -> None:
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
        await client.closed_event.wait()
        client.assert_sent(pureldap.LDAPBindRequest())
        assert client.closed
