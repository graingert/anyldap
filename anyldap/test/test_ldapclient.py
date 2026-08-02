"""
Test cases for anyldap.protocols.ldap.ldapsyntax module.
"""
import anyio
import pytest
from anyio.abc import SocketAttribute
from exceptiongroup import suppress

from anyldap.deferred import DeferredSource
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldapclient, ldaperrors, ldapserver
from anyldap.runtime import Failure
from anyldap.test import unittest


@pytest.mark.anyio
async def test_async_multi_response_and_no_response_paths():
    client = ldapclient.LDAPClient()

    class SearchServer(ldapserver.BaseLDAPServer):
        def handle_LDAPSearchRequest(self, request, controls, reply):
            return pureldap.LDAPSearchResultDone(resultCode=0)

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await listener.listeners[0].accept()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve_stream, server_stream, SearchServer)
        await client.attach_stream(client_stream, task_group)
        request = pureldap.LDAPSearchRequest()
        response_received = anyio.Event()

        result = await client.send_multiResponse_async(
            request, lambda response: response_received.set() or True
        )
        assert isinstance(result, pureldap.LDAPSearchResultDone)
        await response_received.wait()

        response_received = anyio.Event()
        result = await client.send_multiResponse_ex_async(
            request,
            controls=[],
            handler=lambda response, controls: response_received.set() or True,
        )
        response, controls = result
        assert isinstance(response, pureldap.LDAPSearchResultDone)
        assert controls is None
        await response_received.wait()

        await client.send_noResponse_async(pureldap.LDAPAbandonRequest(id=1))
        await client.aclose()
    await listener.aclose()


@pytest.mark.anyio
async def test_async_disconnected_and_tls_guards():
    client = ldapclient.LDAPClient()
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client.bind_async()
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client.startTLS_async()
    await client.aclose()


@pytest.mark.anyio
async def test_send_async_receives_response_from_stream():
    client = ldapclient.LDAPClient()

    class BindServer(ldapserver.BaseLDAPServer):
        def handle_LDAPBindRequest(self, request, controls, reply):
            return pureldap.LDAPBindResponse(resultCode=0)

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await listener.listeners[0].accept()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve_stream, server_stream, BindServer)
        await client.attach_stream(client_stream, task_group)
        response = await client.send_async(pureldap.LDAPBindRequest())
        assert isinstance(response, pureldap.LDAPBindResponse)
        await client.aclose()
    await listener.aclose()


@pytest.mark.anyio
async def test_deferred_client_methods_use_real_socket_stream():
    closed = anyio.Event()

    class Client(ldapclient.LDAPClient):
        def connectionLost(self, reason):
            super().connectionLost(reason)
            closed.set()

    class Server(ldapserver.BaseLDAPServer):
        def handle_LDAPBindRequest(self, request, controls, reply):
            return pureldap.LDAPBindResponse(resultCode=0)

        def handle_LDAPSearchRequest(self, request, controls, reply):
            reply(pureldap.LDAPSearchResultEntry("cn=entry", []))
            return pureldap.LDAPSearchResultDone(resultCode=0)

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    client = Client()
    client.debug = True
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await listener.listeners[0].accept()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve_stream, server_stream, Server)
        await client.attach_stream(client_stream, task_group)
        assert isinstance(
            await client.send(pureldap.LDAPBindRequest()),
            pureldap.LDAPBindResponse,
        )
        assert await client.bind_async() == (b"", None)
        responses = []
        assert isinstance(
            await client.send_multiResponse(
                pureldap.LDAPSearchRequest(),
                lambda response: responses.append(response)
                or isinstance(response, pureldap.LDAPSearchResultDone),
            ),
            pureldap.LDAPSearchResultDone,
        )
        controlled = []
        response, controls = await client.send_multiResponse_ex(
            pureldap.LDAPSearchRequest(),
            controls=[],
            handler=lambda response, response_controls: controlled.append(response)
            or isinstance(response, pureldap.LDAPSearchResultDone),
        )
        assert isinstance(response, pureldap.LDAPSearchResultDone)
        assert controls is None
        assert len(responses) == len(controlled) == 2
        await client.aclose()
        await closed.wait()
    await listener.aclose()


@pytest.mark.anyio
async def test_prebuffered_stream_delegates_to_real_socket():
    received = []
    peer_done = anyio.Event()

    async def peer(stream):
        received.append(await stream.receive())
        await stream.send(b"pong")
        with suppress(anyio.EndOfStream):
            await stream.receive()
        await stream.aclose()
        peer_done.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await listener.listeners[0].accept()
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


@pytest.mark.anyio
async def test_client_response_dispatch_and_disconnect_errors():
    client = ldapclient.LDAPClient()
    client.debug = True
    client.connectionMade()
    client.handle(
        pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(resultCode=0), id=0)
    )

    controlled = DeferredSource()
    client.onwire[1] = (controlled, True, None, (), {})
    controls = [(b"1.2.3", False, None)]
    client.handle(
        pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(resultCode=0), id=1, controls=controls
        )
    )
    response, returned_controls = await controlled.deferred
    assert isinstance(response, pureldap.LDAPBindResponse)
    assert returned_controls == controls

    pending = DeferredSource()
    client.onwire[2] = (pending, False, lambda response: False, (), {})
    client.handle(
        pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry("cn=a", []), id=2)
    )
    client.onwire[2] = (pending, False, lambda response: True, (), {})
    client.handle(
        pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(resultCode=0), id=2)
    )
    assert isinstance(await pending.deferred, pureldap.LDAPSearchResultDone)

    disconnected = DeferredSource()
    client.onwire[3] = (disconnected, False, None, None, None)
    reason = Failure(ConnectionError("closed"))
    client.connectionLost(reason)
    with pytest.raises(ConnectionError, match="closed"):
        await disconnected.deferred


def test_bind_and_starttls_response_validation_errors():
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


@pytest.mark.anyio
async def test_attach_stream_reads_until_end():
    disconnected = anyio.Event()

    class Client(ldapclient.LDAPClient):
        def connectionLost(self, reason):
            super().connectionLost(reason)
            disconnected.set()

    async def send_notification(stream):
        await stream.send(
            pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(0), id=0).toWire()
        )
        await stream.aclose()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    client = Client()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, send_notification)
        await client.attach_stream(await anyio.connect_tcp(host, port), task_group)
        await disconnected.wait()
        task_group.cancel_scope.cancel()
    await listener.aclose()
    assert not client.connected


@pytest.mark.anyio
async def test_async_close_and_empty_stream_disconnect():
    peer_closed = anyio.Event()

    async def wait_for_close(stream):
        with suppress(anyio.EndOfStream):
            await stream.receive()
        peer_closed.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    client = ldapclient.LDAPClient()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, wait_for_close)
        await client.attach_stream(await anyio.connect_tcp(host, port), task_group)
        await client.aclose()
        await peer_closed.wait()
        assert not client.connected
        task_group.cancel_scope.cancel()


@pytest.mark.anyio
async def test_invalid_starttls_response_over_real_socket():
    async def peer(stream):
        request, _ = pureber.berDecodeObject(
            ldapclient.LDAPClient.berdecoder, await stream.receive()
        )
        await stream.send(
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(resultCode=0, responseName=b"wrong"),
                id=request.id,
            ).toWire()
        )
        await stream.aclose()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await listener.listeners[0].accept()
    client = ldapclient.LDAPClient()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(peer, server_stream)
        await client.attach_stream(client_stream, task_group)
        with pytest.raises(ldapclient.LDAPStartTLSInvalidResponseName):
            await client.startTLS_async()
    await listener.aclose()


@pytest.mark.anyio
async def test_partial_starttls_response_and_failed_upgrade_over_real_socket():
    async def peer(stream):
        request, _ = pureber.berDecodeObject(
            ldapclient.LDAPClient.berdecoder, await stream.receive()
        )
        response = pureldap.LDAPMessage(
            pureldap.LDAPStartTLSResponse(resultCode=0), id=request.id
        ).toWire()
        await stream.send(response[:1])
        await anyio.lowlevel.checkpoint()
        await stream.send(response[1:])
        await stream.aclose()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    client_stream = await anyio.connect_tcp(host, port)
    server_stream = await listener.listeners[0].accept()
    client = ldapclient.LDAPClient()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(peer, server_stream)
        await client.attach_stream(client_stream, task_group)
        with pytest.raises(Exception):
            await client.startTLS_async()
    await listener.aclose()


@pytest.mark.anyio
async def test_client_stream_state_guards_and_closed_socket_write():
    client = ldapclient.LDAPClient()
    client.connectionMade()
    client.onwire[1] = object()
    with pytest.raises(ldapclient.LDAPStartTLSBusyError):
        await client.startTLS_async()
    client.onwire.clear()

    tls_event = anyio.Event()
    client._tls_upgrade = {"event": tls_event}
    client.connectionLost()
    assert tls_event.is_set()

    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client._upgrade_to_tls(None, None)
    client._anyio_write_lock = anyio.Lock()
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client._upgrade_to_tls(None, None)
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        client._queue_anyio_write(b"data")

    client._anyio_write_lock = None
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client._send_anyio_write(b"data")
    client.connectionMade()
    client._anyio_write_lock = anyio.Lock()
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client._send_anyio_write(b"data")

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    stream = await anyio.connect_tcp(host, port)
    peer = await listener.listeners[0].accept()
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
        def connectionLost(self, reason):
            super().connectionLost(reason)
            disconnected.set()

    client = NotifyingClient()
    peer_closed = anyio.Event()

    async def close_peer(stream):
        await stream.aclose()
        peer_closed.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    async with listener, anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, close_peer)
        await client.attach_stream(await anyio.connect_tcp(host, port), task_group)
        await peer_closed.wait()
        await disconnected.wait()
        assert not client.connected
        task_group.cancel_scope.cancel()
        task_group.cancel_scope.cancel()


def test_partial_message_and_starttls_guards():
    client = ldapclient.LDAPClient()
    client.dataReceived(b"\x30")
    assert client.buffer == b"\x30"


class RepresentationTests(unittest.TestCase):
    """
    Tests that center on correct representations of objects.
    """

    def test_clientConnectionLost_rep(self):
        error = ldapclient.LDAPClientConnectionLostException()
        self.assertEqual(b"Connection lost", error.toWire())

    def test_startTLSBusyError_rep(self):
        error = ldapclient.LDAPStartTLSBusyError("xyzzy")
        expected_value = b"Cannot STARTTLS while operations on wire: 'xyzzy'"
        self.assertEqual(expected_value, error.toWire())

    def test_StartTLSInvalidResponseName_rep(self):
        error = ldapclient.LDAPStartTLSInvalidResponseName("xyzzy")
        expected_value = b"Invalid responseName in STARTTLS response: 'xyzzy'"
        self.assertEqual(expected_value, error.toWire())
