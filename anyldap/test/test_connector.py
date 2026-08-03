from collections.abc import Callable
from typing import Any
from unittest import mock

import anyio
import pytest
from anyio.abc import ByteStream, SocketAttribute

from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import distinguishedname, ldapclient, ldapconnector

pytestmark = pytest.mark.anyio


class FakeStream:
    def __init__(self, responder: Callable[[bytes], bytes | None]) -> None:
        self._responder = responder
        self._responses: list[bytes] = []
        self._sent = anyio.Event()
        self.sent: list[bytes] = []
        self.closed = False

    async def send(self, data: bytes) -> None:
        self.sent.append(data)
        response = self._responder(data)
        if response is not None:
            self._responses.append(response)
        self._sent.set()

    async def receive(self, max_bytes: int = 65536) -> bytes:
        await self._sent.wait()
        if self._responses:
            return self._responses.pop(0)
        raise anyio.EndOfStream

    async def aclose(self) -> None:
        self.closed = True


async def test_fake_stream_without_response() -> None:
    stream = FakeStream(lambda data: None)
    await stream.send(b"request")
    assert stream.sent == [b"request"]


async def test_parse_tcp_endpoint() -> None:
    assert ldapconnector._parseTCPEndpoint("tcp:host=127.0.0.1:port=10389") == (
        "127.0.0.1",
        10389,
    )


@pytest.mark.parametrize(
    "endpoint",
    ["udp:host=localhost:port=389", "tcp:localhost:port=389", "tcp:host=localhost"],
)
async def test_parse_tcp_endpoint_errors(endpoint: str) -> None:
    with pytest.raises(ValueError):
        ldapconnector._parseTCPEndpoint(endpoint)


async def test_legacy_endpoint_connector_reports_parse_error() -> None:
    with pytest.raises(ValueError, match="Unsupported endpoint"):
        await ldapconnector.connectToLDAPEndpoint(
            None, "udp:host=x:port=1", ldapclient.LDAPClient
        )


async def test_find_override_plain_string() -> None:
    override = ldapconnector._findOverride(
        distinguishedname.DistinguishedName("cn=foo,dc=example,dc=com"),
        {"dc=example,dc=com": ("server.example.com", 1389)},
    )
    assert override == ("server.example.com", 1389)


async def test_find_override_root() -> None:
    override = ldapconnector._findOverride(
        distinguishedname.DistinguishedName("cn=foo,dc=example,dc=com"),
        {"": ("server.example.com", 1389)},
    )
    assert override == ("server.example.com", 1389)


async def test_resolve_service_location_async_callable_override() -> None:
    marker = object()

    def override(factory: object) -> object:
        return marker

    resolved = await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com",
        overrides={"dc=example,dc=com": override},
    )

    assert resolved is override
    assert override(None) is marker


async def test_resolve_service_location_async_uses_srv() -> None:
    async def resolver(name: str, record_type: str) -> list[Any]:
        assert name == "_ldap._tcp.example.com"
        assert record_type == "SRV"

        class Record:
            priority = 0
            weight = 10
            port = 1389
            target = "ldap.example.net."

        return [Record()]

    resolved = await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com", resolver=resolver
    )

    assert resolved == ("ldap.example.net", 1389)


async def test_resolve_service_location_async_override_host_keeps_srv_port() -> None:
    async def resolver(name: str, record_type: str) -> list[Any]:
        class Record:
            priority = 0
            weight = 10
            port = 1636
            target = "ldap.example.net."

        return [Record()]

    resolved = await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com",
        overrides={"dc=example,dc=com": ("override.example.net", None)},
        resolver=resolver,
    )

    assert resolved == ("override.example.net", 1636)


async def test_resolve_complete_override_and_defaults() -> None:
    assert await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com", overrides={"dc=example,dc=com": ("host", 123)}
    ) == ("host", 123)

    async def no_records(name: str, record_type: str) -> list[Any]:
        return []

    assert await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com", resolver=no_records
    ) == ("example.com", 389)
    assert await ldapconnector._resolveServiceLocationAsync("") == ("", 389)
    assert await ldapconnector._resolveServiceLocationAsync(
        distinguishedname.DistinguishedName(""), resolver=no_records
    ) == ("", 389)

    async def one_record(name: str, record_type: str) -> list[Any]:
        return [type("Record", (), {"priority": 0, "weight": 1, "target": "srv.", "port": 999})()]

    assert await ldapconnector._resolveServiceLocationAsync(
        "dc=example,dc=com",
        overrides={"dc=example,dc=com": (None, 123)},
        resolver=one_record,
    ) == ("srv", 123)


async def test_connection_wrapper_and_connector_alias() -> None:
    class Stack:
        def __init__(self) -> None:
            self.closed = False

        async def aclose(self) -> None:
            self.closed = True

    class Client:
        marker = "client"

        async def attach_stream(self, stream: object, task_group: object) -> None:
            """Never reached: the connection is built directly."""

        async def aclose(self) -> None:
            """Never reached: closing goes through the exit stack."""

    stack = Stack()
    # Only closed, which is all the connection does with it.
    connection = ldapconnector.AsyncLDAPClientConnection(stack, Client())  # type: ignore[arg-type]
    assert connection.marker == "client"
    assert await connection.__aenter__() is connection.protocol
    await connection.__aexit__(None, None, None)
    assert stack.closed
    # An override is a location or a callable; this one only has to come back.
    override: Any = "root"
    assert (
        ldapconnector.LDAPConnector()._findOverRide(
            distinguishedname.DistinguishedName(""), {"": override}
        )
        is override
    )


async def test_creator_connects_to_real_endpoint() -> None:
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    port = listener.extra(SocketAttribute.local_port)

    async def hold_open(stream: ByteStream) -> None:
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


class UnbuiltClient:
    """A client class the connector is given but never gets to build.

    Every connection here comes from an override, which hands back a client
    of its own and ignores the factory it was passed.
    """

    attach_stream = mock.AsyncMock()
    aclose = mock.AsyncMock()

    def __init__(self) -> None:
        self.bound = False

    async def bind_async(self) -> None:
        self.bound = True


async def test_creator_legacy_and_anonymous_overrides() -> None:
    Client = UnbuiltClient
    client = Client()
    creator = ldapconnector.LDAPClientCreator(None, Client)
    assert await creator.connect("", overrides={"": lambda factory: client}) is client
    assert await creator.connectAnonymously(
        "", overrides={"": lambda factory: object()}
    ) is not None

    class LegacyBindClient:
        def bind(self) -> str:
            return "bound"

    assert await creator.connectAnonymously(
        "", overrides={"": lambda factory: LegacyBindClient()}
    ) == "bound"
    connected = await creator.connectAnonymouslyAsync(
        "", overrides={"": lambda factory: client}
    )
    assert connected is client
    assert client.bound
    Client.attach_stream.assert_not_called()
    Client.aclose.assert_not_called()


async def test_creator_non_override_uses_async_implementation() -> None:
    class Creator(ldapconnector.LDAPClientCreator[UnbuiltClient]):
        async def connectAsync(self, *args: object, **kwargs: object) -> str:
            return "connected"

    creator = Creator(None, UnbuiltClient)
    assert await creator.connect("dc=example,dc=com") == "connected"


async def test_connectToLDAPEndpointAsync_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    def responder(request_bytes: bytes) -> bytes:
        message, _ = pureber.berDecodeObject(
            ldapclient.LDAPClient.berdecoder, request_bytes
        )
        assert isinstance(message, pureldap.LDAPMessage)
        response = pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(
                resultCode=0, matchedDN=b"cn=foo,dc=example,dc=com"
            ),
            id=message.id,
        )
        return response.toWire()

    stream = FakeStream(responder)

    async def fake_connect_tcp(host: str, port: int, **kwargs: object) -> FakeStream:
        assert (host, port) == ("127.0.0.1", 10389)
        return stream

    monkeypatch.setattr(anyio, "connect_tcp", fake_connect_tcp)

    async with await ldapconnector.connectToLDAPEndpointAsync(
        "tcp:host=127.0.0.1:port=10389", ldapclient.LDAPClient
    ) as client:
        result = await client.bind_async(b"cn=foo,dc=example,dc=com", b"secret")
        assert result == (b"cn=foo,dc=example,dc=com", None)
    assert stream.sent
    assert stream.closed


async def test_connectAsync_bind_with_srv_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolver(name: str, record_type: str) -> list[Any]:
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

    def responder(request_bytes: bytes) -> bytes:
        message, _ = pureber.berDecodeObject(
            ldapclient.LDAPClient.berdecoder, request_bytes
        )
        assert isinstance(message, pureldap.LDAPMessage)
        response = pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(resultCode=0, matchedDN=b""),
            id=message.id,
        )
        return response.toWire()

    stream = FakeStream(responder)

    async def fake_connect_tcp(host: str, port: int, **kwargs: object) -> FakeStream:
        assert (host, port) == ("127.0.0.1", 389)
        return stream

    creator = ldapconnector.LDAPClientCreator(None, ldapclient.LDAPClient)
    monkeypatch.setattr(anyio, "connect_tcp", fake_connect_tcp)

    async with await creator.connectAsync("dc=example,dc=com", resolver=resolver) as client:
        result = await client.bind_async()
        assert result == (b"", None)
    assert stream.sent
    assert stream.closed
