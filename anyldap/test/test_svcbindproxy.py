import anyio
import pytest

from anyldap import config, ldapfilter
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors, proxy, svcbindproxy
from anyldap.test._anyio_helpers import (
    AsyncLDAPClientDriver,
    MemoryByteStream,
    decode_message,
    patch_client_creator,
)

pytestmark = pytest.mark.anyio

NOW = "20050213140302Z"


def _search_request(service_name):
    return pureldap.LDAPSearchRequest(
        baseObject="dc=example,dc=com",
        derefAliases=0,
        sizeLimit=0,
        timeLimit=0,
        typesOnly=0,
        filter=ldapfilter.parseFilter(
            "(&"
            + "(objectClass=serviceSecurityObject)"
            + "(owner=cn=jack,dc=example,dc=com)"
            + f"(cn={service_name})"
            + f"(|(!(validFrom=*))(validFrom<={NOW}))"
            + f"(|(!(validUntil=*))(validUntil>={NOW}))"
            + ")"
        ),
        attributes=("1.1",),
    )


async def _create_server(monkeypatch, services, fallback, *responses):
    client = AsyncLDAPClientDriver(*responses)
    patch_client_creator(monkeypatch, proxy, client)
    server = svcbindproxy.ServiceBindingProxy(
        config=config.LDAPConfig(
            serviceLocationOverrides={},
            identityBaseDN="dc=example,dc=com",
        ),
        services=services,
        fallback=fallback,
    )
    server.timestamp = lambda: NOW
    stream = MemoryByteStream()
    return server, stream, client


async def test_bind_no_matching_services_found_no_fallback(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        ["svc1", "svc2", "svc3"],
        False,
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(dn="cn=jack,dc=example,dc=com", auth="s3krit"),
                id=4,
            ).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == ldaperrors.LDAPInvalidCredentials.resultCode
        client.assert_sent(
            _search_request("svc1"),
            _search_request("svc2"),
            _search_request("svc3"),
        )
        await server.aclose()


async def test_bind_no_matching_services_found_fallback_success(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        ["svc1", "svc2", "svc3"],
        True,
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode)],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(dn="cn=jack,dc=example,dc=com", auth="s3krit"),
                id=4,
            ).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == ldaperrors.Success.resultCode
        client.assert_sent(
            _search_request("svc1"),
            _search_request("svc2"),
            _search_request("svc3"),
            pureldap.LDAPBindRequest(dn="cn=jack,dc=example,dc=com", auth="s3krit"),
        )
        await server.aclose()


async def test_bind_no_matching_services_found_fallback_bad_auth(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        ["svc1", "svc2", "svc3"],
        True,
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode)],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn="cn=jack,dc=example,dc=com", auth="wrong-s3krit"
                ),
                id=4,
            ).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == ldaperrors.LDAPInvalidCredentials.resultCode
        client.assert_sent(
            _search_request("svc1"),
            _search_request("svc2"),
            _search_request("svc3"),
            pureldap.LDAPBindRequest(
                dn="cn=jack,dc=example,dc=com", auth="wrong-s3krit"
            ),
        )
        await server.aclose()


async def test_bind_match_success(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        ["svc1", "svc2", "svc3"],
        True,
        [
            pureldap.LDAPSearchResultEntry(
                r"cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                attributes=[],
            ),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ],
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode)],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(dn="cn=jack,dc=example,dc=com", auth="secret"),
                id=4,
            ).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == ldaperrors.Success.resultCode
        assert response.value.matchedDN == b"cn=jack,dc=example,dc=com"
        client.assert_sent(
            _search_request("svc1"),
            pureldap.LDAPBindRequest(
                dn=r"cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                auth="secret",
            ),
        )
        await server.aclose()


async def test_bind_match_success_later(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        ["svc1", "svc2", "svc3"],
        True,
        [
            pureldap.LDAPSearchResultEntry(
                r"cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                attributes=[],
            ),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ],
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode)],
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [
            pureldap.LDAPSearchResultEntry(
                r"cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                attributes=[],
            ),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ],
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode)],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(dn="cn=jack,dc=example,dc=com", auth="secret"),
                id=4,
            ).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == ldaperrors.Success.resultCode
        assert response.value.matchedDN == b"cn=jack,dc=example,dc=com"
        client.assert_sent(
            _search_request("svc1"),
            pureldap.LDAPBindRequest(
                dn=r"cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                auth="secret",
            ),
            _search_request("svc2"),
            _search_request("svc3"),
            pureldap.LDAPBindRequest(
                dn=r"cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                auth="secret",
            ),
        )
        await server.aclose()


async def test_bind_match_bad_auth(monkeypatch):
    server, stream, client = await _create_server(
        monkeypatch,
        ["svc1", "svc2", "svc3"],
        True,
        [
            pureldap.LDAPSearchResultEntry(
                r"cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                attributes=[],
            ),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ],
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode)],
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)],
        [
            pureldap.LDAPSearchResultEntry(
                r"cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                attributes=[],
            ),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ],
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode)],
        [pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode)],
    )

    async with anyio.create_task_group() as task_group:
        await server.attach_stream(stream, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn="cn=jack,dc=example,dc=com", auth="wrong-s3krit"
                ),
                id=4,
            ).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.value.resultCode == ldaperrors.LDAPInvalidCredentials.resultCode
        client.assert_sent(
            _search_request("svc1"),
            pureldap.LDAPBindRequest(
                dn=r"cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                auth="wrong-s3krit",
            ),
            _search_request("svc2"),
            _search_request("svc3"),
            pureldap.LDAPBindRequest(
                dn=r"cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com",
                auth="wrong-s3krit",
            ),
            pureldap.LDAPBindRequest(
                version=3, dn="cn=jack,dc=example,dc=com", auth="wrong-s3krit"
            ),
        )
        await server.aclose()
