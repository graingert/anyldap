"""
Test cases for anyldap.protocols.ldap.ldapsyntax module.
"""
import ssl

import anyio
import pytest
import trustme
from anyio.abc import SocketAttribute

from anyldap import testutil
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldaperrors, ldapserver
from anyldap.test import unittest
from anyldap.test._anyio_helpers import MemoryByteStream


def _trusted_client_context():
    authority = trustme.CA()
    authority.issue_cert("ldap.example.com")
    context = ssl.create_default_context()
    authority.configure_trust(context)
    return context


@pytest.mark.anyio
async def test_async_multi_response_and_no_response_paths():
    client = ldapclient.LDAPClient()

    class SearchServer(ldapserver.BaseLDAPServer):
        def handle_LDAPSearchRequest(self, request, controls, reply):
            return pureldap.LDAPSearchResultDone(resultCode=0)

    server_stopped = anyio.Event()

    async def serve(stream):
        await ldapserver.serve_stream(stream, SearchServer)
        server_stopped.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    async with listener, anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, serve)
        await client.attach_stream(await anyio.connect_tcp(host, port), task_group)
        request = pureldap.LDAPSearchRequest()

        result = await client.send_multiResponse_async(request, lambda response: True)
        assert isinstance(result, ldapclient.AnyIODeferred)
        assert isinstance(await result, pureldap.LDAPSearchResultDone)

        result = await client.send_multiResponse_ex_async(
            request, controls=[], handler=lambda response, controls: True
        )
        assert isinstance(result, ldapclient.AnyIODeferred)
        response, controls = await result
        assert isinstance(response, pureldap.LDAPSearchResultDone)
        assert controls is None

        await client.send_noResponse_async(pureldap.LDAPUnbindRequest())
        await server_stopped.wait()
        task_group.cancel_scope.cancel()


@pytest.mark.anyio
async def test_async_disconnected_and_tls_guards():
    client = ldapclient.LDAPClient()
    client._anyio_stream = MemoryByteStream()
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

    server_stopped = anyio.Event()

    async def serve(stream):
        await ldapserver.serve_stream(stream, BindServer)
        server_stopped.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    async with listener, anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, serve)
        await client.attach_stream(await anyio.connect_tcp(host, port), task_group)
        response = await client.send_async(pureldap.LDAPBindRequest())
        assert isinstance(response, pureldap.LDAPBindResponse)
        await client.aclose()
        await server_stopped.wait()
        task_group.cancel_scope.cancel()


@pytest.mark.anyio
async def test_attach_stream_reads_until_end():
    import anyio

    client = ldapclient.LDAPClient()
    stream = MemoryByteStream()
    async with anyio.create_task_group() as task_group:
        await client.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(0), id=0).toWire()
        )
        await stream.close_input()
    assert not client.connected


@pytest.mark.anyio
async def test_async_close_and_empty_stream_disconnect():
    client = ldapclient.LDAPClient()
    stream = MemoryByteStream()
    client._anyio_stream = stream
    client.connectionMade()
    await client.aclose()
    assert stream.closed
    assert not client.connected

    client = ldapclient.LDAPClient()
    stream = MemoryByteStream()
    client._anyio_stream = stream
    client.connectionMade()
    await stream.feed(b"")
    await client._read_from_stream()
    assert not client.connected


def test_partial_message_and_starttls_guards():
    client = ldapclient.LDAPClient()
    client.dataReceived(b"\x30")
    assert client.buffer == b"\x30"

    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        client._startTLS(None)



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
