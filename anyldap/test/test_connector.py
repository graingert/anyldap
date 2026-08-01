import anyio
import pytest

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


async def test_parse_tcp_endpoint():
    assert ldapconnector._parseTCPEndpoint("tcp:host=127.0.0.1:port=10389") == (
        "127.0.0.1",
        10389,
    )


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
