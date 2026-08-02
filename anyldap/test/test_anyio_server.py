import ssl

import anyio
import anyio.lowlevel
import pytest
import trustme
from anyio.abc import SocketAttribute

from anyldap import config, inmemory, testutil
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import (
    ldapclient,
    ldaperrors,
    ldapserver,
    merger,
    proxy,
    proxybase,
    svcbindproxy,
)
from anyldap.runtime import ConnectionDone, Failure
from anyldap.test._anyio_helpers import AsyncLDAPClientDriver

pytestmark = pytest.mark.anyio


class MemoryByteStream:
    def __init__(self):
        self._incoming_send, self._incoming_recv = anyio.create_memory_object_stream(0)
        self._outgoing_send, self._outgoing_recv = anyio.create_memory_object_stream(0)
        self.closed = False
        self.closed_event = anyio.Event()

    async def send(self, data):
        await self._outgoing_send.send(data)

    async def receive(self):
        return await self._incoming_recv.receive()

    async def aclose(self):
        self.closed = True
        self.closed_event.set()
        await self._incoming_send.aclose()
        await self._incoming_recv.aclose()
        await self._outgoing_send.aclose()
        await self._outgoing_recv.aclose()

    async def feed(self, data):
        await self._incoming_send.send(data)

    async def next_write(self):
        return await self._outgoing_recv.receive()

    async def close_input(self):
        await self._incoming_send.aclose()

    async def close_output(self):
        await self._outgoing_recv.aclose()


def decode_message(wire_bytes):
    message, _ = pureber.berDecodeObject(ldapserver.BaseLDAPServer.berdecoder, wire_bytes)
    return message


async def test_starttls_upgrades_real_socket_stream():
    authority = trustme.CA()
    certificate = authority.issue_cert("localhost")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server_context)
    client_context = ssl.create_default_context()
    authority.configure_trust(client_context)

    class StartTLSServer(ldapserver.BaseLDAPServer):
        def handle_LDAPExtendedRequest(self, request, controls, reply):
            assert request.requestName == pureldap.LDAPStartTLSRequest.oid
            self.start_tls(server_context)
            reply(pureldap.LDAPStartTLSResponse(resultCode=0))

        def handle_LDAPBindRequest(self, request, controls, reply):
            return pureldap.LDAPBindResponse(resultCode=0)

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve, listener, StartTLSServer)
        client_stream = await anyio.connect_tcp(host, port)
        client = ldapclient.LDAPClient()
        await client.attach_stream(client_stream, task_group)
        with anyio.fail_after(5):
            assert (
                await client.startTLS_async(client_context, hostname="localhost")
                is client
            )
        with anyio.fail_after(5):
            response = await client.send_async(pureldap.LDAPBindRequest())
        assert response.resultCode == 0
        await client.aclose()
        await listener.aclose()


async def test_ldap_server_attach_stream_bind_response():
    root = inmemory.ReadOnlyInMemoryLDAPEntry(
        dn="dc=example,dc=com",
        attributes={"dc": "example"},
    )
    server = ldapserver.LDAPServer()
    server.factory = root
    stream = MemoryByteStream()

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=7).toWire()
        )
        response = decode_message(await stream.next_write())
        assert isinstance(response.value, pureldap.LDAPBindResponse)
        assert response.id == 7
        assert response.value.resultCode == ldaperrors.Success.resultCode
        await server.aclose()


async def test_base_server_real_stream_partial_message_and_close_lifecycle():
    server = ldapserver.BaseLDAPServer()
    server.debug = True
    stream = MemoryByteStream()
    request = pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=12).toWire()

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(request[:1])
        await stream.feed(request[1:])
        response = decode_message(await stream.next_write())
        assert response.id == 12
        assert response.value.resultCode == ldaperrors.LDAPProtocolError.resultCode
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=0).toWire()
        )
        server._start_anyio_close()
        server._start_anyio_close()
        await server.wait_closed()
        await server._send_anyio_write(b"closed")
        await server.aclose()


async def test_unattached_server_stream_workers_and_wait_closed_are_noops():
    server = ldapserver.BaseLDAPServer()

    await server.wait_closed()
    server._start_anyio_close()
    await server._read_from_stream()
    await server._send_anyio_write(b"unattached")


async def test_server_closes_when_the_output_side_breaks():
    server = ldapserver.BaseLDAPServer()
    stream = MemoryByteStream()

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.close_output()
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=15).toWire()
        )
        await server.wait_closed()

    assert stream.closed


async def test_ldap_server_accepts_factory_with_root_attribute():
    root = inmemory.ReadOnlyInMemoryLDAPEntry(
        dn="dc=example,dc=com",
        attributes={"dc": "example"},
    )

    class RootFactory:
        pass

    factory = RootFactory()
    factory.root = root
    server = ldapserver.LDAPServer()
    server.factory = factory
    stream = MemoryByteStream()

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=16).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == ldaperrors.Success.resultCode
        assert server._get_root() is root
        await server.aclose()


async def test_extended_request_handler_without_decoder_receives_raw_value():
    class ExtendedServer(ldapserver.LDAPServer):
        def extendedRequest_echo(self, value, reply):
            return pureldap.LDAPExtendedResponse(
                resultCode=0,
                responseName=self.extendedRequest_echo.oid,
                response=value,
            )

    ExtendedServer.extendedRequest_echo.oid = b"1.2.3.4"
    server = ExtendedServer()
    stream = MemoryByteStream()

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedRequest(
                    requestName=b"1.2.3.4",
                    requestValue=b"raw value",
                ),
                id=18,
            ).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == 0
        assert response.value.response == b"raw value"
        await server.aclose()


async def test_server_async_handler_error_uses_protocol_error_response():
    class FailingServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPBindRequest(self, request, controls, reply):
            raise RuntimeError("real handler failed")

    server = FailingServer()
    stream = MemoryByteStream()
    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=14).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.id == 14
        assert response.value.resultCode == ldaperrors.LDAPProtocolError.resultCode
        assert response.value.errorMessage == b"real handler failed"
        await server.aclose()


async def test_listen_reports_real_tcp_listener_readiness():
    async with anyio.create_task_group() as task_group:
        host, port = await task_group.start(
            ldapserver.BaseLDAPServer.listen,
            "127.0.0.1",
            0,
        )
        assert host == "127.0.0.1"
        assert port > 0
        task_group.cancel_scope.cancel()


async def test_proxybase_attach_stream_forwards_bind():
    expected = pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode)
    client = ldapclient.LDAPClient()
    upstream = MemoryByteStream()
    server = proxybase.ProxyBase()
    server.clientConnector = lambda: client
    downstream = MemoryByteStream()

    async with anyio.create_task_group() as task_group:
        await client.attach_stream(upstream, task_group)
        await server.attach_stream(downstream, task_group)
        await downstream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4).toWire()
        )
        forwarded = decode_message(await upstream.next_write())
        await upstream.feed(
            pureldap.LDAPMessage(expected, id=forwarded.id).toWire()
        )
        response = decode_message(await downstream.next_write())
        assert isinstance(response.value, pureldap.LDAPBindResponse)
        assert response.value.resultCode == ldaperrors.Success.resultCode
        assert isinstance(forwarded.value, pureldap.LDAPBindRequest)
        await downstream.feed(
            pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=5).toWire()
        )
        forwarded_unbind = decode_message(await upstream.next_write())
        assert isinstance(forwarded_unbind.value, pureldap.LDAPUnbindRequest)
        await server.aclose()
        await client.aclose()


async def test_proxy_queues_until_real_upstream_client_is_ready():
    connect = anyio.Event()

    client = ldapclient.LDAPClient()
    upstream = MemoryByteStream()
    downstream = MemoryByteStream()

    async def connector():
        await connect.wait()
        return client

    server = proxybase.ProxyBase()
    server.clientConnector = connector
    async with anyio.create_task_group() as task_group:
        await client.attach_stream(upstream, task_group)
        task_group.start_soon(server.attach_stream, downstream, task_group)
        task_group.start_soon(
            downstream.feed,
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=16).toWire()
        )
        connect.set()
        forwarded = decode_message(await upstream.next_write())
        await upstream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=forwarded.id
            ).toWire()
        )
        response = decode_message(await downstream.next_write())
        assert response.id == 16
        assert response.value.resultCode == 0
        await server.aclose()
        await client.aclose()


async def test_proxy_public_interception_hook_can_answer_without_forwarding():
    class InterceptingProxy(proxybase.ProxyBase):
        def handleBeforeForwardRequest(self, request, controls, reply):
            reply(pureldap.LDAPBindResponse(resultCode=0))
            return None

    client = ldapclient.LDAPClient()
    upstream = MemoryByteStream()
    downstream = MemoryByteStream()
    server = InterceptingProxy()
    server.clientConnector = lambda: client
    async with anyio.create_task_group() as task_group:
        await client.attach_stream(upstream, task_group)
        await server.attach_stream(downstream, task_group)
        await downstream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=17).toWire()
        )
        response = decode_message(await downstream.next_write())
        assert response.id == 17
        assert response.value.resultCode == 0
        assert client.onwire == {}
        await server.aclose()
        await client.aclose()


async def test_proxy_reports_real_connector_failure_and_closes_downstream():
    async def connector():
        raise OSError("connection refused")

    server = proxybase.ProxyBase()
    server.clientConnector = connector
    downstream = MemoryByteStream()
    async with anyio.create_task_group() as task_group:
        await server.attach_stream(downstream, task_group)
        await server.wait_closed()
        assert downstream.closed


async def test_proxy_closes_real_upstream_when_downstream_disconnects_while_connecting():
    release = anyio.Event()
    connector_started = anyio.Event()
    client = ldapclient.LDAPClient()
    upstream = MemoryByteStream()
    downstream = MemoryByteStream()

    async def connector():
        connector_started.set()
        await release.wait()
        return client

    server = proxybase.ProxyBase()
    server.clientConnector = connector
    async with anyio.create_task_group() as task_group:
        await client.attach_stream(upstream, task_group)
        task_group.start_soon(server.attach_stream, downstream, task_group)
        await connector_started.wait()
        await downstream.close_input()
        release.set()
        await server.wait_closed()
        await upstream.closed_event.wait()
        assert client.connected == 0
        assert server.client is None


async def test_merged_server_attach_stream_merges_real_upstream_bind_responses():
    first_client = ldapclient.LDAPClient()
    second_client = ldapclient.LDAPClient()
    first_upstream = MemoryByteStream()
    second_upstream = MemoryByteStream()

    def connect_first(protocol_factory):
        return first_client

    def connect_second(protocol_factory):
        return second_client

    server = merger.MergedLDAPServer(
        [
            config.LDAPConfig(serviceLocationOverrides={"": connect_first}),
            config.LDAPConfig(serviceLocationOverrides={"": connect_second}),
        ],
        [False, False],
    )
    downstream = MemoryByteStream()

    async with anyio.create_task_group() as task_group:
        await first_client.attach_stream(first_upstream, task_group)
        await second_client.attach_stream(second_upstream, task_group)
        await server.attach_stream(downstream, task_group)
        await downstream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=9).toWire()
        )
        first_request = decode_message(await first_upstream.next_write())
        second_request = decode_message(await second_upstream.next_write())
        await first_upstream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=49), id=first_request.id
            ).toWire()
        )
        await second_upstream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=second_request.id
            ).toWire()
        )
        response = decode_message(await downstream.next_write())
        assert isinstance(response.value, pureldap.LDAPBindResponse)
        assert response.value.resultCode == ldaperrors.Success.resultCode
        await server.aclose()


async def test_merged_server_reports_real_async_connector_failure():
    def refuse_connection(protocol_factory):
        raise OSError("connection refused")

    server = merger.MergedLDAPServer(
        [
            config.LDAPConfig(
                serviceLocationOverrides={"": refuse_connection},
            )
        ],
        [False],
    )
    stream = MemoryByteStream()

    async with anyio.create_task_group() as task_group:
        with pytest.raises(ldaperrors.LDAPOther, match="Cannot connect"):
            await server.attach_stream(stream, task_group)


async def test_merged_server_sends_unbind_through_real_async_client():
    client = ldapclient.LDAPClient()
    server = merger.MergedLDAPServer([], [])
    server.clients = [client]
    received = []
    server_stopped = anyio.Event()

    async def receive_unbind(peer):
        received.append(decode_message(await peer.receive()))
        await peer.aclose()
        server_stopped.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    async with listener, anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, receive_unbind)
        upstream = await anyio.connect_tcp(host, port)
        await client.attach_stream(upstream, task_group)
        await server._clientQueue_async(
            pureldap.LDAPUnbindRequest(), None, lambda response: None
        )
        await server_stopped.wait()
        assert isinstance(received[0].value, pureldap.LDAPUnbindRequest)
        await client.aclose()
        task_group.cancel_scope.cancel()


async def test_proxy_attach_stream_forwards_bind():
    client = testutil.LDAPClientTestDriver(
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode)]
    )
    client.connectionMade()

    def connect_client(protocol_factory):
        return client

    server = proxy.Proxy(
        config.LDAPConfig(serviceLocationOverrides={"": connect_client})
    )
    stream = MemoryByteStream()
    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=6).toWire()
        )
        response = decode_message(await stream.next_write())
        assert isinstance(response.value, pureldap.LDAPBindResponse)
        assert response.value.resultCode == ldaperrors.Success.resultCode
        client.assertSent(pureldap.LDAPBindRequest())
        await server.aclose()


async def test_service_binding_proxy_attach_stream_intercepts_bind():
    client = testutil.LDAPClientTestDriver(
        [
            pureldap.LDAPSearchResultEntry(
                r"cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                attributes=[],
            ),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ],
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode)],
    )
    client.connectionMade()

    def connect_client(protocol_factory):
        return client

    server = svcbindproxy.ServiceBindingProxy(
        config=config.LDAPConfig(
            serviceLocationOverrides={"": connect_client},
            identityBaseDN="dc=example,dc=com",
        ),
        services=["svc1"],
        fallback=False,
    )
    server.timestamp = lambda: "20050213140302Z"
    stream = MemoryByteStream()
    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn="cn=jack,dc=example,dc=com",
                    auth="secret",
                ),
                id=4,
            ).toWire()
        )
        response = decode_message(await stream.next_write())
        assert isinstance(response.value, pureldap.LDAPBindResponse)
        assert response.value.resultCode == ldaperrors.Success.resultCode
        assert response.value.matchedDN == b"cn=jack,dc=example,dc=com"
        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="dc=example,dc=com",
                derefAliases=0,
                sizeLimit=0,
                timeLimit=0,
                typesOnly=0,
                filter=svcbindproxy.pureldap.LDAPFilter_and(
                    [
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("objectClass"),
                            assertionValue=pureldap.LDAPAssertionValue(
                                "serviceSecurityObject"
                            ),
                        ),
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("owner"),
                            assertionValue=pureldap.LDAPAssertionValue(
                                "cn=jack,dc=example,dc=com"
                            ),
                        ),
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("cn"),
                            assertionValue=pureldap.LDAPAssertionValue("svc1"),
                        ),
                        pureldap.LDAPFilter_or(
                            [
                                pureldap.LDAPFilter_not(
                                    pureldap.LDAPFilter_present("validFrom")
                                ),
                                pureldap.LDAPFilter_lessOrEqual(
                                    attributeDesc=pureldap.LDAPAttributeDescription(
                                        "validFrom"
                                    ),
                                    assertionValue=pureldap.LDAPAssertionValue(
                                        "20050213140302Z"
                                    ),
                                ),
                            ]
                        ),
                        pureldap.LDAPFilter_or(
                            [
                                pureldap.LDAPFilter_not(
                                    pureldap.LDAPFilter_present("validUntil")
                                ),
                                pureldap.LDAPFilter_greaterOrEqual(
                                    attributeDesc=pureldap.LDAPAttributeDescription(
                                        "validUntil"
                                    ),
                                    assertionValue=pureldap.LDAPAssertionValue(
                                        "20050213140302Z"
                                    ),
                                ),
                            ]
                        ),
                    ]
                ),
                attributes=("1.1",),
            ),
            pureldap.LDAPBindRequest(
                dn=r"cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                auth="secret",
            ),
        )
        await server.aclose()


async def test_serve_stream_runs_until_eof():
    root = inmemory.ReadOnlyInMemoryLDAPEntry(
        dn="dc=example,dc=com",
        attributes={"dc": "example"},
    )
    stream = MemoryByteStream()
    result = {}
    ready = anyio.Event()

    class ObservedServer(ldapserver.LDAPServer):
        async def connectionMade_async(self):
            await super().connectionMade_async()
            ready.set()

    def build_server():
        server = ObservedServer()
        server.factory = root
        return server

    async with anyio.create_task_group() as task_group:
        async def runner():
            result["server"] = await ldapserver.serve_stream(stream, build_server)

        task_group.start_soon(runner)
        await ready.wait()
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.id == 2
        await stream.close_input()
    assert result["server"].connected == 0


async def test_proxybase_failure_and_starttls_response_paths():
    replies = []
    server = proxybase.ProxyBase()
    server.queuedRequests = [
        (pureldap.LDAPBindRequest(), None, replies.append),
        (pureldap.LDAPStartTLSRequest(), None, replies.append),
        (pureldap.LDAPUnbindRequest(), None, replies.append),
    ]
    server._failedToConnectToProxiedServer(Failure(OSError("unreachable")))
    assert [type(response) for response in replies] == [
        pureldap.LDAPBindResponse,
        pureldap.LDAPStartTLSResponse,
    ]
    assert {response.resultCode for response in replies} == {
        ldaperrors.LDAPUnavailable.resultCode
    }

    unavailable = proxybase.ProxyBase()
    unavailable.factory = object()
    assert (
        unavailable.handleStartTLSRequest(
            pureldap.LDAPStartTLSRequest(), None, replies.append
        ).resultCode
        == ldaperrors.LDAPUnavailable.resultCode
    )

    class Factory:
        options = object()

    tls_server = proxybase.ProxyBase()
    tls_server.debug = True
    tls_server.factory = Factory()
    assert await tls_server.handle_LDAPExtendedRequest(
        pureldap.LDAPStartTLSRequest(), None, replies.append
    ) is None
    assert tls_server.startTLS_initiated
    assert (
        tls_server.handleStartTLSRequest(
            pureldap.LDAPStartTLSRequest(), None, replies.append
        ).resultCode
        == ldaperrors.LDAPOperationsError.resultCode
    )


async def test_proxybase_connection_tls_disconnect_and_backlog_paths():
    client = testutil.LDAPClientTestDriver(
        [pureldap.LDAPBindResponse(resultCode=0)], []
    )
    client.connectionMade()

    async def start_tls():
        return client

    client.startTLS_async = start_tls
    server = proxybase.ProxyBase()
    server.use_tls = True
    server.clientConnector = lambda: client
    replies = []
    server.queuedRequests = [
        (pureldap.LDAPBindRequest(), None, replies.append),
        (pureldap.LDAPUnbindRequest(), None, replies.append),
    ]
    await server.connectionMade_async()
    assert replies[0].resultCode == ldaperrors.Success.resultCode
    client.assertSent(pureldap.LDAPBindRequest(), pureldap.LDAPUnbindRequest())

    disconnected_client = testutil.LDAPClientTestDriver()
    disconnected_client.connectionMade()
    disconnected_server = proxybase.ProxyBase()

    async def disconnect_during_connect():
        disconnected_server.connectionLost(ConnectionDone())
        return disconnected_client

    disconnected_server.clientConnector = disconnect_during_connect
    disconnected_server.queuedRequests.append(
        (pureldap.LDAPBindRequest(), None, replies.append)
    )
    await disconnected_server.connectionMade_async()
    assert not disconnected_client.connected
    assert disconnected_server.client is None
    assert disconnected_server.queuedRequests == []


async def test_proxybase_forwarding_and_example_response_paths():
    client = testutil.LDAPClientTestDriver(
        [
            pureldap.LDAPSearchResultEntry("cn=a", []),
            pureldap.LDAPSearchResultDone(resultCode=0),
        ],
        [],
    )
    client.connectionMade()
    server = proxybase.ProxyBase()
    server.client = client
    replies = []
    await server.handleUnknown(pureldap.LDAPSearchRequest(), None, replies.append)
    await server.handle_LDAPExtendedRequest(
        pureldap.LDAPExtendedRequest(requestName=b"1.2.3"), None, replies.append
    )
    assert [type(response) for response in replies] == [
        pureldap.LDAPSearchResultEntry,
        pureldap.LDAPSearchResultDone,
    ]
    assert server._gotResponseFromProxiedServer(
        pureldap.LDAPBindResponse(resultCode=0),
        replies.append,
        pureldap.LDAPBindRequest(),
        None,
    )
    example = proxybase.ExampleProxy()
    response = pureldap.LDAPBindResponse(resultCode=0)
    assert example.handleProxiedResponse(response, None, None) is response


async def test_proxybase_queues_requests_until_connected():
    server = proxybase.ProxyBase()
    request = pureldap.LDAPSearchRequest()
    replies = []
    await server.handleUnknown(request, None, replies.append)
    assert server.queuedRequests == [(request, None, replies.append)]


async def test_proxybase_replies_in_response_order():
    request = pureldap.LDAPSearchRequest()
    replies = []

    class RewritingProxy(proxybase.ProxyBase):
        def handleProxiedResponse(self, response, request, controls):
            return ("rewritten", response)

    server = RewritingProxy()
    entry = pureldap.LDAPSearchResultEntry("cn=entry", [])
    done = pureldap.LDAPSearchResultDone(resultCode=0)
    # Only a search-done or bind response ends the exchange.
    assert not server._gotResponseFromProxiedServer(
        entry, replies.append, request, None
    )
    assert server._gotResponseFromProxiedServer(done, replies.append, request, None)
    assert replies == [("rewritten", entry), ("rewritten", done)]


async def test_proxybase_connection_close_and_quiet_starttls_paths():
    client = AsyncLDAPClientDriver([])
    server = proxybase.ProxyBase()
    server.client = client
    server.connectionLost(ConnectionDone())
    assert server.unbound

    client = AsyncLDAPClientDriver([])
    server = proxybase.ProxyBase()
    server.client = client
    async with anyio.create_task_group() as task_group:
        server._anyio_task_group = task_group
        server.connectionLost(ConnectionDone())
        await client.closed_event.wait()
        assert not client.connected

    class Factory:
        options = object()

    server = proxybase.ProxyBase()
    server.factory = Factory()
    replies = []
    assert (
        server.handleStartTLSRequest(
            pureldap.LDAPStartTLSRequest(), None, replies.append
        )
        is None
    )
    assert replies[0].resultCode == ldaperrors.Success.resultCode


async def test_server_stream_state_guards():
    server = ldapserver.BaseLDAPServer()
    await server._send_anyio_write(b"data")
    with pytest.raises(ldapserver.LDAPServerConnectionLostException):
        await server._upgrade_to_tls(None, b"response")
    server._anyio_write_lock = anyio.Lock()
    await server._send_anyio_write(b"data")
    with pytest.raises(ldapserver.LDAPServerConnectionLostException):
        await server._upgrade_to_tls(None, b"response")
