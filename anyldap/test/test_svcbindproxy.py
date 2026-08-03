import anyio
import pytest

from anyldap import config, ldapfilter, testutil
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


async def test_bind_no_matching_services_found_no_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
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


async def test_bind_no_matching_services_found_fallback_success(monkeypatch: pytest.MonkeyPatch) -> None:
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


async def test_bind_no_matching_services_found_fallback_bad_auth(monkeypatch: pytest.MonkeyPatch) -> None:
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


async def test_bind_match_success(monkeypatch: pytest.MonkeyPatch) -> None:
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


def _legacy_proxy(services=None, fallback=False):
    server = svcbindproxy.ServiceBindingProxy(
        config=config.LDAPConfig(identityBaseDN="dc=example,dc=com"),
        services=services,
        fallback=fallback,
    )
    server.timestamp = lambda: NOW
    server.client = object()
    return server


async def test_maybe_fallback_results() -> None:
    request = pureldap.LDAPBindRequest(dn="cn=alice", auth="secret")
    server = _legacy_proxy()
    success = await server._maybeFallback_async(
        object(), request, None, lambda value: None
    )
    assert success.resultCode == ldaperrors.Success.resultCode
    assert success.matchedDN == "cn=alice"

    denied = await server._maybeFallback_async(
        None, request, None, lambda value: None
    )
    assert denied.resultCode == ldaperrors.LDAPInvalidCredentials.resultCode

    class FallbackProxy(svcbindproxy.ServiceBindingProxy):
        forwarded = None

        async def handleUnknown(self, request, controls, reply):
            self.forwarded = (request, controls, reply)

    fallback = FallbackProxy(
        config=config.LDAPConfig(identityBaseDN="dc=example"), fallback=True
    )
    assert (
        await fallback._maybeFallback_async(None, request, "controls", "reply") is None
    )
    assert fallback.forwarded == (request, "controls", "reply")


class ServiceEntry:
    def __init__(self, bind_result=None):
        self.bind_result = bind_result

    async def bind_async(self, password):
        if isinstance(self.bind_result, BaseException):
            raise self.bind_result
        return self.bind_result or self


class SearchBase:
    def __init__(self, results):
        self.results = list(results)
        self.filters = []

    async def search_async(self, **kwargs):
        self.filters.append(kwargs)
        return self.results.pop(0)


async def test_try_service_success_and_exhaustion() -> None:
    request = pureldap.LDAPBindRequest(dn="cn=alice", auth="secret")
    server = _legacy_proxy()
    base = SearchBase([[], [ServiceEntry()]])
    result = await server._tryService_async(["missing", "present"], base, request)
    assert isinstance(result, ServiceEntry)
    assert len(base.filters) == 2
    assert base.filters[0]["attributes"] == ("1.1",)
    assert await server._tryService_async([], base, request) is None


async def test_try_service_retries_invalid_credentials() -> None:
    request = pureldap.LDAPBindRequest(dn="cn=alice", auth="bad")
    invalid = ldaperrors.LDAPInvalidCredentials()
    base = SearchBase([[ServiceEntry(invalid)], [ServiceEntry()]])
    server = _legacy_proxy()
    result = await server._tryService_async(
        ["bad-service", "good-service"], base, request
    )
    assert isinstance(result, ServiceEntry)


async def test_bind_handler_validation_and_anonymous_forwarding() -> None:
    server = _legacy_proxy()
    with pytest.raises(ldaperrors.LDAPProtocolError):
        server.handle_LDAPBindRequest(
            pureldap.LDAPBindRequest(version=2), None, lambda value: None
        )

    class AnonymousProxy(svcbindproxy.ServiceBindingProxy):
        async def handleUnknown(self, request, controls, reply):
            return "forwarded"

    anonymous = AnonymousProxy(config=config.LDAPConfig())
    result = anonymous.handle_LDAPBindRequest(
        pureldap.LDAPBindRequest(dn=""), None, lambda value: None
    )
    assert await result == "forwarded"


async def test_legacy_bind_uses_connected_client_search_interface() -> None:
    client = testutil.LDAPClientTestDriver(
        [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)]
    )
    client.connectionMade()
    server = svcbindproxy.ServiceBindingProxy(
        config=config.LDAPConfig(identityBaseDN="dc=example,dc=com"),
        services=["svc"],
        fallback=False,
    )
    server.timestamp = lambda: NOW
    server.client = client

    response = await server.handle_LDAPBindRequest(
        pureldap.LDAPBindRequest(dn="cn=jack,dc=example,dc=com", auth="secret"),
        None,
        lambda value: None,
    )

    assert response.resultCode == ldaperrors.LDAPInvalidCredentials.resultCode
    client.assertSent(_search_request("svc"))


def test_timestamp_shape_and_constructor_defaults() -> None:
    server = svcbindproxy.ServiceBindingProxy(config=config.LDAPConfig())
    assert server.services == []
    assert server.fallback is False
    value = server.timestamp()
    assert len(value) == 15
    assert value.endswith("Z")


async def test_bind_match_success_later(monkeypatch: pytest.MonkeyPatch) -> None:
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


async def test_bind_match_bad_auth(monkeypatch: pytest.MonkeyPatch) -> None:
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
