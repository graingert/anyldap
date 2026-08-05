"""
Test cases for anyldap.protocols.ldap.ldapsyntax module.
"""
from collections.abc import Callable, Iterable

import anyio
import pytest
from anyio.abc import ByteStream
from exceptiongroup import suppress

from anyldap import runtime
from anyldap._async import ResultSlot
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldapclient, ldaperrors, ldapserver
from anyldap.runtime import Failure
from ._anyio_helpers import accept_one, local_address

pytestmark = pytest.mark.anyio


def _finish(event: anyio.Event) -> Callable[..., bool]:
    """A response handler that records the response and claims it as final."""

    def handler(*args: object) -> bool:
        event.set()
        return True

    return handler


_finish_ex = _finish


async def test_async_multi_response_and_no_response_paths() -> None:
    client = ldapclient.LDAPClient()

    class SearchServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            return pureldap.LDAPSearchResultDone(resultCode=0)

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await accept_one(listener)
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve_stream, server_stream, SearchServer)
        await client.attach_stream(client_stream, task_group)
        request = pureldap.LDAPSearchRequest()
        response_received = anyio.Event()

        result = await client.send_multiResponse_async(
            request, _finish(response_received)
        )
        assert isinstance(result, pureldap.LDAPSearchResultDone)
        await response_received.wait()

        response_received = anyio.Event()
        result = await client.send_multiResponse_ex_async(
            request,
            controls=[],
            handler=_finish_ex(response_received),
        )
        assert isinstance(result, tuple)
        response, controls = result
        assert isinstance(response, pureldap.LDAPSearchResultDone)
        assert controls is None
        await response_received.wait()

        await client.send_noResponse_async(pureldap.LDAPAbandonRequest(id=1))
        await client.aclose()
    await listener.aclose()


async def test_async_disconnected_and_tls_guards() -> None:
    client = ldapclient.LDAPClient()
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client.bind_async()
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client.startTLS_async()
    await client.aclose()


async def test_send_async_receives_response_from_stream() -> None:
    client = ldapclient.LDAPClient()

    class BindServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPBindRequest(
            self,
            request: pureldap.LDAPBindRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPBindResponse:
            return pureldap.LDAPBindResponse(resultCode=0)

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await accept_one(listener)
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve_stream, server_stream, BindServer)
        await client.attach_stream(client_stream, task_group)
        response = await client.send_async(pureldap.LDAPBindRequest())
        assert isinstance(response, pureldap.LDAPBindResponse)
        await client.aclose()
    await listener.aclose()


async def test_client_methods_use_real_socket_stream() -> None:
    closed = anyio.Event()

    class Client(ldapclient.LDAPClient):
        def connectionLost(
            self, reason: BaseException = runtime.Protocol.connectionDone
        ) -> None:
            super().connectionLost(reason)
            closed.set()

    class Server(ldapserver.BaseLDAPServer):
        async def handle_LDAPBindRequest(
            self,
            request: pureldap.LDAPBindRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPBindResponse:
            return pureldap.LDAPBindResponse(resultCode=0)

        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            reply(pureldap.LDAPSearchResultEntry("cn=entry", []))
            return pureldap.LDAPSearchResultDone(resultCode=0)

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    client = Client()
    client.debug = True
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await accept_one(listener)
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve_stream, server_stream, Server)
        await client.attach_stream(client_stream, task_group)
        assert isinstance(
            await client.send(pureldap.LDAPBindRequest()),
            pureldap.LDAPBindResponse,
        )
        assert await client.bind_async() == (b"", None)
        responses: list[object] = []

        def collect(response: object) -> bool:
            """Gather each response, and say when the search is done."""
            responses.append(response)
            return isinstance(response, pureldap.LDAPSearchResultDone)

        assert isinstance(
            await client.send_multiResponse(
                pureldap.LDAPSearchRequest(), collect
            ),
            pureldap.LDAPSearchResultDone,
        )
        controlled: list[object] = []

        def collect_with_controls(response: object, response_controls: object) -> bool:
            controlled.append(response)
            return isinstance(response, pureldap.LDAPSearchResultDone)

        result = await client.send_multiResponse_ex(
            pureldap.LDAPSearchRequest(),
            controls=[],
            handler=collect_with_controls,
        )
        assert isinstance(result, tuple)
        response, controls = result
        assert isinstance(response, pureldap.LDAPSearchResultDone)
        assert controls is None
        assert len(responses) == len(controlled) == 2
        await client.aclose()
        await closed.wait()
    await listener.aclose()


async def test_prebuffered_stream_delegates_to_real_socket() -> None:
    received: list[bytes] = []
    peer_done = anyio.Event()

    async def peer(stream: ByteStream) -> None:
        received.append(await stream.receive())
        await stream.send(b"pong")
        with suppress(anyio.EndOfStream):
            await stream.receive()
        await stream.aclose()
        peer_done.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await accept_one(listener)
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(peer, server_stream)
        stream = ldapclient._PrebufferedStream(client_stream, b"buffered")
        assert stream.extra_attributes
        assert await stream.receive(3) == b"buf"
        assert await stream.receive() == b"fered"
        await stream.send(b"ping")
        assert await stream.receive() == b"pong"
        await stream.send_eof()
        await peer_done.wait()
        await stream.aclose()
    await listener.aclose()
    assert received == [b"ping"]


async def test_client_response_dispatch_and_disconnect_errors() -> None:
    client = ldapclient.LDAPClient()
    client.debug = True
    client.connectionMade()
    client.handle(
        pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(resultCode=0), id=0)
    )

    controlled: ResultSlot[object] = ResultSlot()
    client.onwire[1] = (controlled, True, None, (), {})
    controls = [(b"1.2.3", False, None)]
    client.handle(
        pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(resultCode=0), id=1, controls=controls
        )
    )
    result = await controlled.wait()
    assert isinstance(result, tuple)
    response, returned_controls = result
    assert isinstance(response, pureldap.LDAPBindResponse)
    assert returned_controls == controls

    pending: ResultSlot[object] = ResultSlot()
    client.onwire[2] = (pending, False, lambda response: False, (), {})
    client.handle(
        pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry("cn=a", []), id=2)
    )
    client.onwire[2] = (pending, False, lambda response: True, (), {})
    client.handle(
        pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(resultCode=0), id=2)
    )
    assert isinstance(await pending.wait(), pureldap.LDAPSearchResultDone)

    disconnected: ResultSlot[object] = ResultSlot()
    client.onwire[3] = (disconnected, False, None, None, None)
    reason = Failure(ConnectionError("closed"))
    client.connectionLost(reason)
    with pytest.raises(ConnectionError, match="closed"):
        await disconnected.wait()


def test_bind_and_starttls_response_validation_errors() -> None:
    client = ldapclient.LDAPClient()
    with pytest.raises(ldaperrors.LDAPInvalidCredentials):
        client._handle_bind_msg(
            pureldap.LDAPBindResponse(
                resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
            )
        )
    with pytest.raises(ldapclient.LDAPStartTLSInvalidResponseName):
        client._validate_start_tls_response(
            pureldap.LDAPExtendedResponse(resultCode=0, responseName=b"wrong")
        )
    with pytest.raises(ldaperrors.LDAPUnavailable):
        client._validate_start_tls_response(
            pureldap.LDAPExtendedResponse(
                resultCode=ldaperrors.LDAPUnavailable.resultCode
            )
        )


async def test_attach_stream_reads_until_end() -> None:
    disconnected = anyio.Event()

    class Client(ldapclient.LDAPClient):
        def connectionLost(
            self, reason: BaseException = runtime.Protocol.connectionDone
        ) -> None:
            super().connectionLost(reason)
            disconnected.set()

    async def send_notification(stream: ByteStream) -> None:
        await stream.send(
            pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(0), id=0).toWire()
        )
        await stream.aclose()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    client = Client()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, send_notification)
        await client.attach_stream(await anyio.connect_tcp(host, port), task_group)
        await disconnected.wait()
        task_group.cancel_scope.cancel()
    await listener.aclose()
    assert not client.connected


async def test_async_close_and_empty_stream_disconnect() -> None:
    peer_closed = anyio.Event()

    async def wait_for_close(stream: ByteStream) -> None:
        async with stream:
            with suppress(anyio.EndOfStream):
                await stream.receive()
        peer_closed.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    client = ldapclient.LDAPClient()
    async with listener, anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, wait_for_close)
        await client.attach_stream(await anyio.connect_tcp(host, port), task_group)
        await client.aclose()
        await peer_closed.wait()
        assert not client.connected
        task_group.cancel_scope.cancel()


async def test_invalid_starttls_response_over_real_socket() -> None:
    async def peer(stream: ByteStream) -> None:
        request, _ = pureber.berDecodeObject(
            ldapclient.LDAPClient.berdecoder, await stream.receive()
        )
        assert isinstance(request, pureldap.LDAPMessage)
        await stream.send(
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(resultCode=0, responseName=b"wrong"),
                id=request.id,
            ).toWire()
        )
        await stream.aclose()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await accept_one(listener)
    client = ldapclient.LDAPClient()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(peer, server_stream)
        await client.attach_stream(client_stream, task_group)
        with pytest.raises(ldapclient.LDAPStartTLSInvalidResponseName):
            await client.startTLS_async()
    await listener.aclose()


async def test_partial_starttls_response_and_failed_upgrade_over_real_socket() -> None:
    async def peer(stream: ByteStream) -> None:
        request, _ = pureber.berDecodeObject(
            ldapclient.LDAPClient.berdecoder, await stream.receive()
        )
        assert isinstance(request, pureldap.LDAPMessage)
        response = pureldap.LDAPMessage(
            pureldap.LDAPStartTLSResponse(resultCode=0), id=request.id
        ).toWire()
        await stream.send(response[:1])
        await anyio.lowlevel.checkpoint()
        await stream.send(response[1:])
        await stream.aclose()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await accept_one(listener)
    client = ldapclient.LDAPClient()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(peer, server_stream)
        await client.attach_stream(client_stream, task_group)
        with pytest.raises(Exception):
            await client.startTLS_async()
    await listener.aclose()


async def test_client_stream_state_guards_and_closed_socket_write() -> None:
    client = ldapclient.LDAPClient()
    client.connectionMade()
    # Anything on the wire is enough to refuse a STARTTLS.
    client.onwire[1] = (ResultSlot(), False, None, None, None)
    with pytest.raises(ldapclient.LDAPStartTLSBusyError):
        await client.startTLS_async()
    client.onwire.clear()

    tls_event = anyio.Event()
    client._tls_upgrade = {
        "context": None,
        "hostname": None,
        "event": tls_event,
        "message_id": 1,
        "response_received": False,
        "error": None,
    }
    client.connectionLost()
    assert tls_event.is_set()

    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client._upgrade_to_tls(None, None)
    client._anyio_write_lock = anyio.Lock()
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client._upgrade_to_tls(None, None)
    client._anyio_write_lock = None
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client._send_anyio_write(b"data")
    client.connectionMade()
    client._anyio_write_lock = anyio.Lock()
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client._send_anyio_write(b"data")

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    stream = await anyio.connect_tcp(host, port)
    peer = await accept_one(listener)
    await stream.aclose()
    client.connectionMade()
    client._anyio_stream = stream
    client._anyio_write_lock = anyio.Lock()
    await client._send_anyio_write(b"data")
    assert not client.connected
    await peer.aclose()
    await listener.aclose()

    disconnected = anyio.Event()

    class NotifyingClient(ldapclient.LDAPClient):
        def connectionLost(
            self, reason: BaseException = runtime.Protocol.connectionDone
        ) -> None:
            super().connectionLost(reason)
            disconnected.set()

    client = NotifyingClient()
    peer_closed = anyio.Event()

    async def close_peer(stream: ByteStream) -> None:
        await stream.aclose()
        peer_closed.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    async with listener, anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, close_peer)
        await client.attach_stream(await anyio.connect_tcp(host, port), task_group)
        await peer_closed.wait()
        await disconnected.wait()
        assert not client.connected
        task_group.cancel_scope.cancel()
        task_group.cancel_scope.cancel()


def test_partial_message_and_starttls_guards() -> None:
    client = ldapclient.LDAPClient()
    client.dataReceived(b"\x30")
    assert client.buffer == b"\x30"


def test_clientConnectionLost_rep() -> None:
    error = ldapclient.LDAPClientConnectionLostException()
    assert b"Connection lost" == error.toWire()


def test_startTLSBusyError_rep() -> None:
    # What is still on the wire is named in the message.
    slot: ResultSlot[object] = ResultSlot()
    error = ldapclient.LDAPStartTLSBusyError({4: (slot, False, None, (), {})})
    message = error.toWire()
    assert message.startswith(b"Cannot STARTTLS while operations on wire: {4: (")
    assert repr(slot).encode() in message


def test_StartTLSInvalidResponseName_rep() -> None:
    error = ldapclient.LDAPStartTLSInvalidResponseName("xyzzy")
    assert b"Invalid responseName in STARTTLS response: 'xyzzy'" == error.toWire()
