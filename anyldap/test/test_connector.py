import anyio
import pytest
from anyio.abc import SocketAttribute

from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import distinguishedname, ldapclient, ldapconnector

pytestmark = pytest.mark.anyio


class FakeStream:
    def __init__(self, responder):
        self._responder = responder
        self._responses = []
        self._sent = anyio.Event()
        self.sent = []
        self.closed = False

    async def send(self, data):
        self.sent.append(data)
        response = self._responder(data)
        if response is not None:
            self._responses.append(response)
        self._sent.set()

    async def receive(self):
        await self._sent.wait()
        if self._responses:
            return self._responses.pop(0)
        raise anyio.EndOfStream

    async def aclose(self):
        self.closed = True


async def test_fake_stream_without_response():
    stream = FakeStream(lambda data: None)
    await stream.send(b"request")
    assert stream.sent == [b"request"]


async def test_parse_tcp_endpoint():
    assert ldapconnector._parseTCPEndpoint("tcp:host=127.0.0.1:port=10389") == (
        "127.0.0.1",
        10389,
    )


@pytest.mark.parametrize(
    "endpoint",
    ["udp:host=localhost:port=389", "tcp:localhost:port=389", "tcp:host=localhost"],
)
async def test_parse_tcp_endpoint_errors(endpoint):
    with pytest.raises(ValueError):
        ldapconnector._parseTCPEndpoint(endpoint)


async def test_legacy_endpoint_connector_reports_parse_error():
    with pytest.raises(ValueError, match="Unsupported endpoint"):
        await ldapconnector.connectToLDAPEndpoint(None, "udp:host=x:port=1", object)


async def test_find_override_plain_string():
    override = ldapconnector._findOverride(
        distinguishedname.DistinguishedName("cn=foo,dc=example,dc=com"),
        {"dc=example,dc=com": ("server.example.com", 1389)},
    )
    assert override == ("server.example.com", 1389)


async def test_find_override_root():
    override = ldapconnector._findOverride(
        distinguishedname.DistinguishedName("cn=foo,dc=example,dc=com"),
        {"": ("server.example.com", 1389)},
    )
    assert override == ("server.example.com", 1389)


async def test_resolve_service_location_async_callable_override():
    marker = object()

    def override(factory):
        return marker

    resolved = await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com",
        overrides={"dc=example,dc=com": override},
    )

    assert resolved is override
    assert override(None) is marker


async def test_resolve_service_location_async_uses_srv():
    async def resolver(name, record_type):
        assert name == "_ldap._tcp.example.com"
        assert record_type == "SRV"

        class Record:
            priority = 0
            weight = 10
            port = 1389
            target = "ldap.example.net."

        return [Record()]

    host, port = await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com", resolver=resolver
    )

    assert (host, port) == ("ldap.example.net", 1389)


async def test_resolve_service_location_async_override_host_keeps_srv_port():
    async def resolver(name, record_type):
        class Record:
            priority = 0
            weight = 10
            port = 1636
            target = "ldap.example.net."

        return [Record()]

    host, port = await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com",
        overrides={"dc=example,dc=com": ("override.example.net", None)},
        resolver=resolver,
    )

    assert (host, port) == ("override.example.net", 1636)


async def test_resolve_complete_override_and_defaults():
    assert await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com", overrides={"dc=example,dc=com": ("host", 123)}
    ) == ("host", 123)

    async def no_records(name, record_type):
        return []

    assert await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com", resolver=no_records
    ) == ("example.com", 389)
    assert await ldapconnector._resolveServiceLocationAsync("") == ("", 389)
    assert await ldapconnector._resolveServiceLocationAsync(
        distinguishedname.DistinguishedName(""), resolver=no_records
    ) == ("", 389)

    async def one_record(name, record_type):
        return [type("Record", (), {"priority": 0, "weight": 1, "target": "srv.", "port": 999})()]

    assert await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com",
        overrides={"dc=example,dc=com": (None, 123)},
        resolver=one_record,
    ) == ("srv", 123)


async def test_connection_wrapper_and_connector_alias():
    class Stack:
        def __init__(self):
            self.closed = False

        async def aclose(self):
            self.closed = True

    class Client:
        marker = "client"

    stack = Stack()
    connection = ldapconnector.AsyncLDAPClientConnection(stack, Client())
    assert connection.marker == "client"
    assert await connection.__aenter__() is connection.protocol
    await connection.__aexit__(None, None, None)
    assert stack.closed
    assert ldapconnector.LDAPConnector()._findOverRide(
        distinguishedname.DistinguishedName(""), {"": "root"}
    ) == "root"


async def test_creator_connects_to_real_endpoint():
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    port = listener.extra(SocketAttribute.local_port)

    async def hold_open(stream):
        async with stream:
            try:
                await stream.receive()
            except anyio.EndOfStream:
                pass

    creator = ldapconnector.LDAPClientCreator(None, ldapclient.LDAPClient)
    async with listener, anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, hold_open)
        connection = await creator.connectToEndpointAsync(
            f"tcp:host=127.0.0.1:port={port}"
        )
        await connection.aclose()
        task_group.cancel_scope.cancel()


async def test_creator_legacy_and_anonymous_overrides():
    class Client:
        def __init__(self):
            self.bound = False

        async def bind_async(self):
            self.bound = True

    client = Client()
    creator = ldapconnector.LDAPClientCreator(None, Client)
    assert await creator.connect("", overrides={"": lambda factory: client}) is client
    assert await creator.connectAnonymously(
        "", overrides={"": lambda factory: object()}
    ) is not None

    class LegacyBindClient:
        def bind(self):
            return "bound"

    assert await creator.connectAnonymously(
        "", overrides={"": lambda factory: LegacyBindClient()}
    ) == "bound"
    connected = await creator.connectAnonymouslyAsync(
        "", overrides={"": lambda factory: client}
    )
    assert connected is client
    assert client.bound


async def test_creator_non_override_uses_async_implementation():
    class Creator(ldapconnector.LDAPClientCreator):
        async def connectAsync(self, *args, **kwargs):
            return "connected"

    creator = Creator(None, object)
    assert await creator.connect("dc=example,dc=com") == "connected"


async def test_connectToLDAPEndpointAsync_bind(monkeypatch):
    def responder(request_bytes):
        message, _ = pureber.berDecodeObject(
            ldapclient.LDAPClient.berdecoder, request_bytes
        )
        response = pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(
                resultCode=0, matchedDN=b"cn=foo,dc=example,dc=com"
            ),
            id=message.id,
        )
        return response.toWire()

    stream = FakeStream(responder)

    async def fake_connect_tcp(host, port, **kwargs):
        assert (host, port) == ("127.0.0.1", 10389)
        return stream

    monkeypatch.setattr(ldapconnector.anyio, "connect_tcp", fake_connect_tcp)

    async with await ldapconnector.connectToLDAPEndpointAsync(
        "tcp:host=127.0.0.1:port=10389", ldapclient.LDAPClient
    ) as client:
        result = await client.bind_async(b"cn=foo,dc=example,dc=com", b"secret")
        assert result == (b"cn=foo,dc=example,dc=com", None)
    assert stream.sent
    assert stream.closed


async def test_connectAsync_bind_with_srv_resolver(monkeypatch):
    async def resolver(name, record_type):
        return [
            type(
                "Record",
                (),
                {
                    "priority": 0,
                    "weight": 10,
                    "target": "127.0.0.1.",
                    "port": 389,
                },
            )()
        ]

    def responder(request_bytes):
        message, _ = pureber.berDecodeObject(
            ldapclient.LDAPClient.berdecoder, request_bytes
        )
        response = pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(resultCode=0, matchedDN=b""),
            id=message.id,
        )
        return response.toWire()

    stream = FakeStream(responder)

    async def fake_connect_tcp(host, port, **kwargs):
        assert (host, port) == ("127.0.0.1", 389)
        return stream

    creator = ldapconnector.LDAPClientCreator(None, ldapclient.LDAPClient)
    monkeypatch.setattr(ldapconnector.anyio, "connect_tcp", fake_connect_tcp)

    async with await creator.connectAsync("dc=example,dc=com", resolver=resolver) as client:
        result = await client.bind_async()
        assert result == (b"", None)
    assert stream.sent
    assert stream.closed
