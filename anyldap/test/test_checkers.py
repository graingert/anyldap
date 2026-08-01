from types import SimpleNamespace

import pytest

from anyldap import checkers, config
from anyldap._async import await_result
from anyldap.protocols.ldap import ldaperrors

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
def test_make_filter(name, template, expected):
    result = checkers.makeFilter(name, template)
    assert (result.asText() if result is not None else None) == expected


class FakeConfig:
    def getIdentityBaseDN(self):
        return "dc=example,dc=com"

    def getIdentitySearch(self, username):
        return f"(uid={username.decode()})"

    def getServiceLocationOverrides(self):
        return {}


class FakeEntry:
    dn = "uid=alice,dc=example,dc=com"

    def __init__(self, bind_error=None):
        async def bind(dn, password):
            if bind_error:
                raise bind_error

        self.client = SimpleNamespace(bind_async=bind)


def install_search(monkeypatch, results):
    class Creator:
        def __init__(self, *args):
            pass

        async def connectAsync(self, *args, **kwargs):
            return object()

    class Entry:
        def __init__(self, *args):
            pass

        async def search_async(self, **kwargs):
            return results

    monkeypatch.setattr(checkers.ldapconnector, "LDAPClientCreator", Creator)
    monkeypatch.setattr(checkers.ldapsyntax, "LDAPEntry", Entry)


async def test_binding_checker_success(monkeypatch):
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
async def test_binding_checker_result_errors(monkeypatch, results, message):
    install_search(monkeypatch, results)
    checker = checkers.LDAPBindingChecker(FakeConfig())
    with pytest.raises(checkers.UnauthorizedLogin, match=message):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"alice", password=b"bad"))


@pytest.mark.parametrize(
    "error", [ldaperrors.LDAPInvalidCredentials(), ldaperrors.LDAPUnwillingToPerform()]
)
async def test_binding_checker_bind_errors(monkeypatch, error):
    install_search(monkeypatch, [FakeEntry(error)])
    checker = checkers.LDAPBindingChecker(FakeConfig())
    with pytest.raises(checkers.UnauthorizedLogin):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"alice", password=b"bad"))


async def test_binding_checker_rejects_anonymous():
    checker = checkers.LDAPBindingChecker(FakeConfig())
    with pytest.raises(checkers.UnauthorizedLogin, match="Anonymous"):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"", password=b""))


async def test_binding_checker_missing_configuration():
    cfg = FakeConfig()
    cfg.getIdentityBaseDN = lambda: (_ for _ in ()).throw(config.MissingBaseDNError())
    checker = checkers.LDAPBindingChecker(cfg)
    with pytest.raises(checkers.UnauthorizedLogin, match="configuration error"):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"alice", password=b""))


async def test_binding_checker_invalid_filter():
    cfg = FakeConfig()
    cfg.getIdentitySearch = lambda username: "invalid"
    checker = checkers.LDAPBindingChecker(cfg)
    with pytest.raises(checkers.UnauthorizedLogin, match="create filter"):
        await checker.requestAvatarId_async(SimpleNamespace(username=b"alice", password=b""))


async def test_binding_checker_deferred_api(monkeypatch):
    async def request(credentials):
        return credentials.username

    checker = checkers.LDAPBindingChecker(FakeConfig())
    monkeypatch.setattr(checker, "requestAvatarId_async", request)
    deferred = checker.requestAvatarId(SimpleNamespace(username=b"alice"))
    assert deferred.called is False
    assert await await_result(deferred) == b"alice"
