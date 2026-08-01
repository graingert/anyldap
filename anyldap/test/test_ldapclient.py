"""
Test cases for anyldap.protocols.ldap.ldapsyntax module.
"""
import ssl

import pytest
import trustme

from anyldap import testutil
from anyldap._encoder import WireStrAlias, to_bytes
from anyldap.protocols import (
    pureber,
    pureldap,
)
from anyldap.protocols.ldap import ldapclient, ldaperrors
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
    stream = MemoryByteStream()
    client._anyio_stream = stream
    client.connectionMade()
    request = pureldap.LDAPSearchRequest()

    result = await client.send_multiResponse_async(request, lambda response: True)
    assert isinstance(result, ldapclient.AnyIODeferred)
    assert await stream.next_write()

    result = await client.send_multiResponse_ex_async(
        request, controls=[], handler=lambda response, controls: True
    )
    assert isinstance(result, ldapclient.AnyIODeferred)
    assert await stream.next_write()

    await client.send_noResponse_async(pureldap.LDAPUnbindRequest())
    assert await stream.next_write()


@pytest.mark.anyio
async def test_async_methods_fall_back_to_legacy_transport():
    client = ldapclient.LDAPClient()
    client.makeConnection(testutil.StringTransport())
    request = pureldap.LDAPSearchRequest()
    assert await client.send_multiResponse_async(request, lambda response: True)
    assert await client.send_multiResponse_ex_async(request, handler=lambda response, controls: True)
    await client.send_noResponse_async(pureldap.LDAPUnbindRequest())


@pytest.mark.anyio
async def test_async_disconnected_and_tls_guards():
    client = ldapclient.LDAPClient()
    client._anyio_stream = MemoryByteStream()
    with pytest.raises(ldapclient.LDAPClientConnectionLostException):
        await client.bind_async()
    with pytest.raises(NotImplementedError, match="STARTTLS"):
        await client.startTLS_async()


@pytest.mark.anyio
async def test_send_async_receives_response_from_stream():
    client = ldapclient.LDAPClient()
    stream = MemoryByteStream()
    client._anyio_stream = stream
    client.connectionMade()
    results = []

    async def send():
        results.append(await client.send_async(pureldap.LDAPBindRequest()))

    async with __import__("anyio").create_task_group() as task_group:
        task_group.start_soon(send)
        await stream.next_write()
        message_id = next(iter(client.onwire))
        client.handle(
            pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=message_id)
        )
    assert isinstance(results[0], pureldap.LDAPBindResponse)


@pytest.mark.anyio
async def test_starttls_async_legacy_transport():
    client = ldapclient.LDAPClient()
    client.makeConnection(testutil.StringTransport())
    results = []

    class TLSContextTransport(testutil.StringTransport):
        def startTLS(self, context):
            self.context = context

    client.transport = TLSContextTransport()
    context = _trusted_client_context()
    async with __import__("anyio").create_task_group() as task_group:
        async def start_with_trust():
            results.append(await client.startTLS_async(context))

        task_group.start_soon(start_with_trust)
        await __import__("anyio").lowlevel.checkpoint()
        message_id = next(iter(client.onwire))
        client.handle(
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(resultCode=0), id=message_id
            )
        )
    assert results == [client]
    assert client.transport.context is context


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

    client.makeConnection(testutil.StringTransport())
    client.onwire[1] = object()
    with pytest.raises(ldapclient.LDAPStartTLSBusyError):
        client._startTLS(None)


def test_starttls_response_validation_and_success():
    class TLSTransport(testutil.StringTransport):
        def startTLS(self, context):
            self.context = context

    client = ldapclient.LDAPClient()
    transport = TLSTransport()
    client.makeConnection(transport)
    with pytest.raises(ldapclient.LDAPStartTLSInvalidResponseName):
        client._cbStartTLS(
            pureldap.LDAPExtendedResponse(resultCode=0, responseName=b"wrong"), None
        )
    context = _trusted_client_context()
    assert client._cbStartTLS(pureldap.LDAPExtendedResponse(resultCode=0), context) is client
    assert transport.context is context


def test_multi_response_controls_handler_and_starttls_send():
    client = ldapclient.LDAPClient()
    client.makeConnection(testutil.StringTransport())
    seen = []
    client.send_multiResponse_ex(
        pureldap.LDAPSearchRequest(),
        controls=[],
        handler=lambda response, controls: seen.append((response, controls)) or True,
    )
    message_id = next(iter(client.onwire))
    client.handle(
        pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(0), id=message_id, controls=[]
        )
    )
    assert seen
    assert not client.onwire

    deferred = client._startTLS(None)
    assert deferred is not None


class SillyMessage(WireStrAlias):
    needs_answer = True

    def __init__(self, value):
        self.value = value

    def toWire(self):
        return to_bytes(self.value)


class SillyError(Exception):
    def __str__(self):
        "Exception for test purposes."


class ConnectionLost(unittest.TestCase):
    def test_simple(self):
        c = ldapclient.LDAPClient()
        c.makeConnection(testutil.StringTransport())
        d1 = c.send(SillyMessage("foo"))
        d2 = c.send(SillyMessage("bar"))
        c.connectionLost(SillyError())

        def eb(fail):
            fail.trap(SillyError)

        d1.addCallbacks(testutil.mustRaise, eb)
        d2.addCallbacks(testutil.mustRaise, eb)
        self.successResultOf(d1)
        self.successResultOf(d2)


class SendTests(unittest.TestCase):
    def create_test_client(self):
        """
        Create test client and transport.
        """
        client = ldapclient.LDAPClient()
        transport = testutil.StringTransport()
        client.makeConnection(transport)
        return client, transport

    def create_test_search_req(self):
        """
        Create a test LDAP search request.
        """
        basedn = "ou=people,dc=example,dc=org"
        scope = pureldap.LDAP_SCOPE_wholeSubtree
        op = pureldap.LDAPSearchRequest(basedn, scope)
        return op

    def create_paged_search_controls(self, page_size=10, cookie=b""):
        control_value = pureber.BERSequence(
            [
                pureber.BERInteger(page_size),
                pureber.BEROctetString(cookie),
            ]
        )
        controls = [(b"1.2.840.113556.1.4.319", None, control_value.toWire())]
        return controls

    def test_bind_not_connected(self):
        client = ldapclient.LDAPClient()
        self.assertRaises(
            ldapclient.LDAPClientConnectionLostException,
            client.bind,
            "cn=foo,ou=baz,dc=example,dc=net",
        )

    def test_bind_failure(self):
        client, transport = self.create_test_client()
        d = client.bind()
        error = ldaperrors.LDAPInvalidCredentials()
        op = pureldap.LDAPBindResponse(error.resultCode)
        response = pureldap.LDAPMessage(op)
        response.id -= 1
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)

        def cb_(thing):
            expected = ldaperrors.LDAPInvalidCredentials
            self.assertEqual(expected, type(thing.value))

        d.addErrback(cb_)
        return d

    def test_bind_success(self):
        client, transport = self.create_test_client()
        creds = (b"cn=foo,ou=baz,dc=example,dc=net", b"secret")
        d = client.bind(*creds)
        op = pureldap.LDAPBindResponse(resultCode=0, matchedDN=creds[0])
        response = pureldap.LDAPMessage(op)
        response.id -= 1
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)

        def cb_(thing):
            self.assertEqual((creds[0], None), thing)

        d.addCallback(cb_)
        return d

    def test_unbind(self):
        client, transport = self.create_test_client()
        client.unbind()

    def test_unbind_not_connected(self):
        client = ldapclient.LDAPClient()
        self.assertRaises(Exception, client.unbind)

    def test_TLS_failure(self):
        client, transport = self.create_test_client()
        d = client.startTLS()
        error = ldaperrors.LDAPOperationsError()
        op = pureldap.LDAPStartTLSResponse(error.resultCode)
        response = pureldap.LDAPMessage(op)
        response.id -= 1
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)

        def cb_(thing):
            expected = ldaperrors.LDAPOperationsError
            self.assertEqual(expected, type(thing.value))

        d.addErrback(cb_)
        return d

    def test_unsolicited(self):
        client, transport = self.create_test_client()
        response = pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(0), id=0)
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)

    def test_send_not_connected(self):
        client = ldapclient.LDAPClient()
        op = self.create_test_search_req()
        self.assertRaises(
            ldapclient.LDAPClientConnectionLostException,
            client.send_multiResponse,
            op,
            None,
        )

    def test_send_multiResponse(self):
        client, transport = self.create_test_client()
        op = self.create_test_search_req()
        d = client.send_multiResponse(op, None)
        expected_value = pureldap.LDAPMessage(op)
        expected_value.id -= 1
        expected_bytestring = expected_value.toWire()
        self.assertEqual(transport.value(), expected_bytestring)
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(0), id=expected_value.id
        )
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)
        self.assertEqual(response.value, self.successResultOf(d))

    def test_send_multiResponse_with_handler(self):
        client, transport = self.create_test_client()
        client.debug = True
        op = self.create_test_search_req()
        results = []

        def collect_result_(result):
            results.append(result)
            if isinstance(result, pureldap.LDAPSearchResultDone):
                return True
            return False

        client.send_multiResponse(op, collect_result_)
        expected_value = pureldap.LDAPMessage(op)
        expected_value.id -= 1
        expected_bytestring = expected_value.toWire()
        self.assertEqual(transport.value(), expected_bytestring)
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry("cn=foo,ou=baz,dc=example,dc=net", {}),
            id=expected_value.id,
        )
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(0), id=expected_value.id
        )
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)
        self.assertEqual(response.value, results[1])

    def test_send_multiResponse_ex(self):
        client, transport = self.create_test_client()
        op = self.create_test_search_req()
        controls = self.create_paged_search_controls()
        d = client.send_multiResponse_ex(op, controls)
        expected_value = pureldap.LDAPMessage(op, controls)
        expected_value.id -= 1
        expected_bytestring = expected_value.toWire()
        self.assertEqual(transport.value(), expected_bytestring)
        resp_controls = self.create_paged_search_controls(0, "magic")
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(0),
            id=expected_value.id,
            controls=resp_controls,
        )
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)
        self.assertEqual((response.value, response.controls), self.successResultOf(d))

    def test_send_noResponse(self):
        client, transport = self.create_test_client()
        op = pureldap.LDAPAbandonRequest(id=1)
        client.send_noResponse(op)


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
