import anyio
import anyio.lowlevel
import pytest

from anyldap import config, inmemory, testutil
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import (
    ldaperrors,
    ldapserver,
    merger,
    proxy,
    proxybase,
    svcbindproxy,
)

pytestmark = pytest.mark.anyio


class MemoryByteStream:
    def __init__(self):
        self._incoming_send, self._incoming_recv = anyio.create_memory_object_stream(10)
        self._outgoing_send, self._outgoing_recv = anyio.create_memory_object_stream(10)
        self.closed = False

    async def send(self, data):
        await self._outgoing_send.send(data)

    async def receive(self):
        return await self._incoming_recv.receive()

    async def aclose(self):
        self.closed = True
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


def decode_message(wire_bytes):
    message, _ = pureber.berDecodeObject(ldapserver.BaseLDAPServer.berdecoder, wire_bytes)
    return message


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


class FakeAsyncClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []
        self.connected = True
        self.closed = False

    async def send_multiResponse_async(self, op, handler, *args, **kwargs):
        self.sent.append(op)
        responses = self.responses.pop(0)
        for response in responses:
            handler(response, *args, **kwargs)

    async def send_noResponse_async(self, op):
        self.sent.append(op)

    async def aclose(self):
        self.closed = True
        self.connected = False


async def test_fake_async_client_no_response_helper():
    client = FakeAsyncClient([])
    request = pureldap.LDAPUnbindRequest()
    await client.send_noResponse_async(request)
    assert client.sent == [request]


class FakeConfig:
    def getServiceLocationOverrides(self):
        return {}


async def test_proxybase_attach_stream_forwards_bind():
    expected = pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode)
    client = FakeAsyncClient([[expected]])
    server = proxybase.ProxyBase()
    server.clientConnector = lambda: client
    stream = MemoryByteStream()

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4).toWire()
        )
        response = decode_message(await stream.next_write())
        assert isinstance(response.value, pureldap.LDAPBindResponse)
        assert response.value.resultCode == ldaperrors.Success.resultCode
        assert len(client.sent) == 1
        assert isinstance(client.sent[0], pureldap.LDAPBindRequest)
        await server.aclose()


async def test_merged_server_attach_stream_merges_bind_success(monkeypatch):
    clients = [
        FakeAsyncClient([[pureldap.LDAPBindResponse(resultCode=49)]]),
        FakeAsyncClient([[pureldap.LDAPBindResponse(resultCode=0)]]),
    ]

    class FakeCreator:
        def __init__(self, reactor, protocol):
            self.protocol = protocol

        async def connectAsync(self, dn, overrides=None, bindAddress=None, resolver=None, tls=False):
            return clients.pop(0)

    monkeypatch.setattr(merger.ldapconnector, "LDAPClientCreator", FakeCreator)

    server = merger.MergedLDAPServer([FakeConfig(), FakeConfig()], [False, False])
    stream = MemoryByteStream()

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=9).toWire()
        )
        response = decode_message(await stream.next_write())
        assert isinstance(response.value, pureldap.LDAPBindResponse)
        assert response.value.resultCode == ldaperrors.Success.resultCode
        await server.aclose()


async def test_proxy_attach_stream_forwards_bind(monkeypatch):
    client = testutil.LDAPClientTestDriver(
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode)]
    )
    client.connectionMade()

    class FakeCreator:
        def __init__(self, reactor, protocol):
            self.protocol = protocol

        async def connectAsync(self, dn, overrides=None, bindAddress=None, resolver=None, tls=False):
            return client

    monkeypatch.setattr(proxy.ldapconnector, "LDAPClientCreator", FakeCreator)

    server = proxy.Proxy(config.LDAPConfig(serviceLocationOverrides={}))
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


async def test_service_binding_proxy_attach_stream_intercepts_bind(monkeypatch):
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

    class FakeCreator:
        def __init__(self, reactor, protocol):
            self.protocol = protocol

        async def connectAsync(self, dn, overrides=None, bindAddress=None, resolver=None, tls=False):
            return client

    monkeypatch.setattr(proxy.ldapconnector, "LDAPClientCreator", FakeCreator)

    server = svcbindproxy.ServiceBindingProxy(
        config=config.LDAPConfig(
            serviceLocationOverrides={},
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

    def build_server():
        server = ldapserver.LDAPServer()
        server.factory = root
        return server

    async with anyio.create_task_group() as task_group:
        async def runner():
            result["server"] = await ldapserver.serve_stream(stream, build_server)

        task_group.start_soon(runner)
        await anyio.lowlevel.checkpoint()
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.id == 2
        await stream.close_input()
    assert result["server"].connected == 0
