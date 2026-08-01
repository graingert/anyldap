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


async def _create_server(monkeypatch, *responses):
    client = AsyncLDAPClientDriver(*responses)
    patch_client_creator(monkeypatch, proxy, client)
    server = proxy.Proxy(config.LDAPConfig(serviceLocationOverrides={}))
    stream = MemoryByteStream()
    return server, stream, client


async def test_bind(monkeypatch):
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


async def test_bind_sasl_no_credentials(monkeypatch):
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


async def test_search(monkeypatch):
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
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=3).toWire()
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


async def test_unbind_client_unbinds(monkeypatch):
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


async def test_unbind_client_eof(monkeypatch):
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
        client.assert_sent(pureldap.LDAPBindRequest(), pureldap.LDAPUnbindRequest())
