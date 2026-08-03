from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any

import pytest

from anyldap import checkers, config
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapconnector, ldaperrors, ldapsyntax

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    ("name", "template", "expected"),
    [
        ("(uid=alice)", None, "(uid=alice)"),
        ("uid=alice", None, "(uid=alice)"),
        ("alice", "(uid=%(name)s)", "(uid=alice)"),
        ("alice", "invalid", None),
        ("alice", None, None),
    ],
)
def test_make_filter(name: str, template: str | None, expected: str | None) -> None:
    result = checkers.makeFilter(name, template)
    if result is None:
        assert expected is None
        return
    assert isinstance(result, pureldap.SupportsAsText)
    assert result.asText() == expected


class FakeConfig:
    def getIdentityBaseDN(self) -> str:
        return "dc=example,dc=com"

    def getIdentitySearch(self, name: str) -> str:
        return f"(uid={name})"

    def getServiceLocationOverrides(self) -> dict[Any, Any]:
        return {}


class FakeEntry:
    dn = "uid=alice,dc=example,dc=com"

    def __init__(self, bind_error: BaseException | None = None) -> None:
        async def bind(dn: object, password: object) -> None:
            if bind_error:
                raise bind_error

        self.client = SimpleNamespace(bind_async=bind)


def install_search(
    monkeypatch: pytest.MonkeyPatch, results: Sequence[object]
) -> None:
    class Creator:
        def __init__(self, *args: object) -> None:
            pass

        async def connectAsync(self, *args: object, **kwargs: object) -> object:
            return object()

    class Entry:
        def __init__(self, *args: object) -> None:
            pass

        async def search_async(self, **kwargs: object) -> Sequence[object]:
            return results

    monkeypatch.setattr(ldapconnector, "LDAPClientCreator", Creator)
    monkeypatch.setattr(ldapsyntax, "LDAPEntry", Entry)


async def test_binding_checker_success(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = FakeEntry()
    install_search(monkeypatch, [entry])
    checker = checkers.LDAPBindingChecker(FakeConfig())
    credentials = SimpleNamespace(username=b"alice", password=b"secret")
    assert await checker.requestAvatarId_async(credentials) is entry
    assert checker.credentialInterfaces == ("username-password",)


@pytest.mark.parametrize(
    ("results", "message"),
    [([], "Invalid credentials"), ([FakeEntry(), FakeEntry()], "single identity")],
)
async def test_binding_checker_result_errors(
    monkeypatch: pytest.MonkeyPatch, results: Sequence[object], message: str
) -> None:
    install_search(monkeypatch, results)
    checker = checkers.LDAPBindingChecker(FakeConfig())
    with pytest.raises(checkers.UnauthorizedLogin, match=message):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"alice", password=b"bad"))


@pytest.mark.parametrize(
    "error", [ldaperrors.LDAPInvalidCredentials(), ldaperrors.LDAPUnwillingToPerform()]
)
async def test_binding_checker_bind_errors(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    install_search(monkeypatch, [FakeEntry(error)])
    checker = checkers.LDAPBindingChecker(FakeConfig())
    with pytest.raises(checkers.UnauthorizedLogin):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"alice", password=b"bad"))


async def test_binding_checker_rejects_anonymous() -> None:
    checker = checkers.LDAPBindingChecker(FakeConfig())
    with pytest.raises(checkers.UnauthorizedLogin, match="Anonymous"):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"", password=b""))


async def test_binding_checker_missing_configuration() -> None:
    class NoBaseDN(FakeConfig):
        def getIdentityBaseDN(self) -> str:
            raise config.MissingBaseDNError()

    checker = checkers.LDAPBindingChecker(NoBaseDN())
    with pytest.raises(checkers.UnauthorizedLogin, match="configuration error"):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"alice", password=b""))


async def test_binding_checker_invalid_filter() -> None:
    class UnparseableSearch(FakeConfig):
        def getIdentitySearch(self, name: str) -> str:
            return "invalid"

    checker = checkers.LDAPBindingChecker(UnparseableSearch())
    with pytest.raises(checkers.UnauthorizedLogin, match="create filter"):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"alice", password=b""))


async def test_binding_checker_requestAvatarId_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    """`requestAvatarId` is another spelling of the same async method."""
    async def request(credentials: Any) -> object:
        return credentials.username

    checker = checkers.LDAPBindingChecker(FakeConfig())
    monkeypatch.setattr(checker, "requestAvatarId", request)
    # Patched, so what comes back is whatever the stand-in returned.
    result: object = await checker.requestAvatarId(SimpleNamespace(username=b"alice"))
    assert result == b"alice"
    assert (
        checkers.LDAPBindingChecker.requestAvatarId
        is checkers.LDAPBindingChecker.requestAvatarId_async
    )
