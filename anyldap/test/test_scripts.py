import getpass
import io
import pathlib
import subprocess
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from types import ModuleType, SimpleNamespace
from typing import ClassVar, Generic, TypeVar

import dns.asyncresolver
import dns.rdatatype
import pytest

from anyldap import config, delta, generate_password, interfaces, numberalloc, usage
from anyldap._scripts import (
    fetchschema,
    find_server,
    getfreenumber,
    ldap2dhcpconf,
    ldap2dnszones,
    ldap2maradns,
    ldap2passwd,
    ldap2pdns,
    ldifdiff,
    ldifpatch,
    namingcontexts,
    passwd,
    rename,
    search,
)
from anyldap.protocols.ldap import fetchschema as protocol_fetchschema
from anyldap.protocols.ldap import ldapconnector, ldapserver, ldapsyntax, merger, proxybase, svcbindproxy

_T = TypeVar("_T")

pytestmark = pytest.mark.anyio


def _returning(value: _T) -> Callable[..., Awaitable[_T]]:
    """Build an async stand-in that ignores its arguments and returns `value`."""

    async def stub(*args: object, **kwargs: object) -> _T:
        return value

    return stub


@pytest.mark.parametrize(
    "module",
    [ldap2dhcpconf, ldap2dnszones, ldap2maradns, ldap2pdns],
)
async def test_unavailable_scripts_explain_status(module: ModuleType) -> None:
    with pytest.raises(SystemExit, match="rewritten for the AnyIO runtime"):
        module.console_script()


@pytest.mark.parametrize(
    "module",
    [ldap2dhcpconf, ldap2dnszones, ldap2maradns, ldap2pdns],
)
async def test_unavailable_script_module_entrypoints(module: ModuleType) -> None:
    result = subprocess.run(
        [sys.executable, "-m", module.__name__],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "rewritten for the AnyIO runtime" in result.stderr


@pytest.mark.parametrize(
    "module",
    [find_server, ldifdiff, ldifpatch, namingcontexts, passwd, rename, search],
)
def test_script_module_entrypoints_report_missing_arguments(module: ModuleType) -> None:
    result = subprocess.run(
        [sys.executable, "-m", module.__name__],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert result.stderr


@pytest.mark.parametrize(
    "module",
    [fetchschema, getfreenumber, ldap2passwd, ldifdiff, ldifpatch, passwd, rename, search],
)
def test_script_module_entrypoints_report_invalid_options(module: ModuleType) -> None:
    result = subprocess.run(
        [sys.executable, "-m", module.__name__, "--definitely-invalid"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "definitely-invalid" in result.stderr


@pytest.mark.parametrize(
    ("module", "arguments", "stdin"),
    [
        (fetchschema, ["--service-location=:127.0.0.1:1"], b""),
        (getfreenumber, ["--service-location=:127.0.0.1:1"], b""),
        (ldap2passwd, ["--service-location=:127.0.0.1:1"], b""),
        (
            passwd,
            [
                "--binddn=cn=user",
                "--bind-auth-fd=0",
                "--service-location=:127.0.0.1:1",
            ],
            b"secret\n",
        ),
        (
            rename,
            [
                "--bind-auth-fd=0",
                "--service-location=:127.0.0.1:1",
                "cn=old",
                "cn=new",
            ],
            b"secret\n",
        ),
        (
            search,
            ["--service-location=:127.0.0.1:1", "(objectClass=*)"],
            b"",
        ),
        (find_server, ["="], b""),
        (namingcontexts, ["127.0.0.1:1"], b""),
    ],
)
def test_valid_script_entrypoints_reach_real_external_interface(
    module: ModuleType, arguments: Sequence[str], stdin: bytes
) -> None:
    result = subprocess.run(
        [sys.executable, "-m", module.__name__, *arguments],
        input=stdin,
        check=False,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode != 0


@pytest.mark.parametrize(
    ("module", "message"),
    [
        (ldapserver, b"packaged AnyIO examples"),
        (merger, b"AnyIO server entrypoints"),
        (proxybase, b"AnyIO server entrypoints"),
        (svcbindproxy, b"packaged AnyIO examples"),
    ],
)
def test_legacy_protocol_module_entrypoints_explain_replacement(
    module: ModuleType, message: bytes
) -> None:
    result = subprocess.run(
        [sys.executable, "-m", module.__name__],
        check=False,
        capture_output=True,
    )
    assert result.returncode == 1
    assert message in result.stderr


def test_ldifdiff_real_cli(tmp_path: pathlib.Path) -> None:
    content = "dn: dc=example,dc=com\ndc: example\nobjectClass: domain\n\n"
    before = tmp_path / "before.ldif"
    after = tmp_path / "after.ldif"
    before.write_text(content)
    after.write_text(content)
    result = subprocess.run(
        [sys.executable, "-m", ldifdiff.__name__, str(before), str(after)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "version: 1\n\n"


def test_ldifpatch_real_cli(tmp_path: pathlib.Path) -> None:
    content = (
        "dn: dc=example,dc=com\ndc: example\nobjectClass: domain\n\n"
        "dn: cn=child,dc=example,dc=com\ncn: child\nobjectClass: person\n\n"
    )
    data = tmp_path / "data.ldif"
    data.write_text(content)
    result = subprocess.run(
        [sys.executable, "-m", ldifpatch.__name__, str(data)],
        input=(
            "version: 1\n\n"
            "dn: cn=child,dc=example,dc=com\n"
            "changetype: delete\n\n"
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "dn: dc=example,dc=com" in result.stdout
    assert "dn: cn=child,dc=example,dc=com" not in result.stdout


@pytest.mark.parametrize(
    ("module", "arguments"),
    [
        (passwd, ["--binddn=cn=user"]),
        (rename, ["cn=old", "cn=new"]),
    ],
)
def test_bind_password_is_read_from_real_inherited_fd(
    module: ModuleType, arguments: Sequence[str], tmp_path: pathlib.Path
) -> None:
    password_file = tmp_path / "password"
    password_file.write_bytes(b"secret\n")
    with password_file.open("rb") as password_stream:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                module.__name__,
                f"--bind-auth-fd={password_stream.fileno()}",
                "--service-location=:127.0.0.1:1",
                *arguments,
            ],
            check=False,
            capture_output=True,
            pass_fds=(password_stream.fileno(),),
            timeout=10,
        )
    assert result.returncode != 0


def test_fetchschema_print_results(capsys: pytest.CaptureFixture[str]) -> None:
    # Printed, not parsed: the descriptions stand in for their own repr.
    fetchschema._printResults(
        (["one", "two"], ["three"])  # type: ignore[list-item]
    )
    assert capsys.readouterr().out == "attributetype one\nattributetype two\n\nobjectclass three\n"
    fetchschema._printResults(([], ["three"]))  # type: ignore[list-item]
    assert capsys.readouterr().out == "objectclass three\n"


async def test_find_server_lookup_and_main(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        SimpleNamespace(rdtype=dns.rdatatype.A, target="ignored"),
        SimpleNamespace(
            rdtype=dns.rdatatype.SRV,
            priority=10,
            weight=20,
            target="ldap.example.com.",
            port=389,
        ),
    ]

    async def resolve(name: str, kind: str) -> list[SimpleNamespace]:
        assert (name, kind) == ("_ldap._tcp.example.com", "SRV")
        return records

    monkeypatch.setattr(dns.asyncresolver, "resolve", resolve)
    await find_server.lookup("dc=example,dc=com")
    assert "pri=10 weight=20" in capsys.readouterr().out

    seen: list[str] = []

    async def lookup(value: str) -> None:
        seen.append(value)

    monkeypatch.setattr(find_server, "lookup", lookup)
    await find_server.main(["one", "two"])
    assert seen == ["one", "two"]


@pytest.mark.parametrize("module", [find_server, namingcontexts])
def test_positional_scripts_require_arguments(
    module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(module.sys, "argv", ["command"])
    with pytest.raises(SystemExit) as exc:
        module.console_script()
    assert exc.value.code == 1
    assert "usage" in capsys.readouterr().err


def test_ldifdiff_output() -> None:
    operation = delta.DeleteOp("dc=example,dc=com")
    stream = io.BytesIO()
    ldifdiff.output([operation], stream)
    assert stream.getvalue().endswith(b"changetype: delete\n\n")


def test_ldap2passwd_callback(capsys: pytest.CaptureFixture[str]) -> None:
    entry = {
        "uid": ["alice"],
        "uidNumber": [1000],
        "gidNumber": [100],
        "cn": ["Alice"],
        "homeDirectory": ["/home/alice"],
    }
    # A mapping of the attributes the script reads, which is all it touches.
    ldap2passwd._cbSearch(entry)  # type: ignore[arg-type]
    assert capsys.readouterr().out == "alice:x:1000:100:Alice:/home/alice:\n"


def test_search_print_results(capsys: pytest.CaptureFixture[str]) -> None:
    search.printResults("result")  # type: ignore[arg-type]
    assert capsys.readouterr().out == "result"


@pytest.mark.parametrize(
    ("options", "args", "expected"),
    [
        (ldap2passwd.MyOptions(), (), {"filter": None}),
        (search.MyOptions(), ("(uid=*)", "uid", "cn"), {"filter": "(uid=*)", "attributes": ("uid", "cn")}),
        (ldifdiff.MyOptions(), ("old.ldif", "new.ldif"), {"file1": "old.ldif", "file2": "new.ldif"}),
        (ldifpatch.MyOptions(), ("data.ldif",), {"data": "data.ldif"}),
        (rename.MyOptions(), ("old", "new"), {"from": "old", "to": "new"}),
    ],
)
def test_option_argument_parsing(
    options: usage.Options, args: Sequence[str], expected: Mapping[str, object]
) -> None:
    # Each script's Options defines its own; the base does not have one.
    options.parseArgs(*args)  # type: ignore[attr-defined]
    for key, value in expected.items():
        assert options.opts[key] == value


def test_passwd_options_default_target() -> None:
    options = passwd.MyOptions()
    options.opts["binddn"] = "cn=admin"
    options.parseArgs()
    assert options.opts["dnlist"] == ("cn=admin",)
    options.parseArgs("cn=one", "cn=two")
    assert options.opts["dnlist"] == ("cn=one", "cn=two")


async def test_password_prompt_and_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "prompted")
    assert await passwd._get_password("cn=user", False) == "prompted"

    async def generate() -> list[str]:
        return ["generated"]

    monkeypatch.setattr(generate_password, "generate_async", generate)
    assert await passwd._get_password("cn=user", True) == "generated"


class FakeConfig:
    def __init__(self, base: str | None = "dc=example,dc=com") -> None:
        self.base = base

    def getBaseDN(self) -> str:
        if self.base is None:
            raise config.MissingBaseDNError()
        return self.base

    def getServiceLocationOverrides(self) -> dict[str, interfaces.ServiceLocation]:
        return {self.getBaseDN(): ("ldap.example.com", 389)}


class BaseFakeCreator(Generic[_T]):
    """Stands in for LDAPClientCreator, handing back one prepared client."""

    def __init__(self, client: _T) -> None:
        self.client = client

    async def connectAnonymouslyAsync(self, **kwargs: object) -> _T:
        return self.client

    async def connectAsync(self, **kwargs: object) -> _T:
        return self.client


def make_fake_creator(client: _T) -> type[BaseFakeCreator[_T]]:
    """A creator class of its own, carrying the client one test prepared.

    The class the script under test constructs is built here, so the client
    it answers with cannot leak into the next test.
    """

    class FakeCreator(BaseFakeCreator[_T]):
        def __init__(self, *args: object) -> None:
            super().__init__(client)

    return FakeCreator


@pytest.mark.parametrize("module", [fetchschema, getfreenumber, ldap2passwd, search])
async def test_base_dependent_scripts_report_missing_base(
    module: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        if module is ldap2passwd:
            await module.main(FakeConfig(None), None)
        elif module is search:
            await module.main(FakeConfig(None), "(uid=*)", ())
        else:
            await module.main(FakeConfig(None))
    assert exc.value.code == 1
    assert "Configuration must specify a base DN" in capsys.readouterr().err


async def test_fetchschema_main(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(ldapconnector, "LDAPClientCreator", make_fake_creator(object()))
    monkeypatch.setattr(
        protocol_fetchschema,
        "fetch",
        _returning((["attribute"], ["object"])),
    )
    await fetchschema.main(FakeConfig())
    assert "attributetype attribute" in capsys.readouterr().out


async def test_getfreenumber_main(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(ldapconnector, "LDAPClientCreator", make_fake_creator(object()))
    monkeypatch.setattr(ldapsyntax, "LDAPEntry", lambda **kwargs: "entry")
    monkeypatch.setattr(
        numberalloc,
        "getFreeNumber",
        _returning(1001),
    )
    await getfreenumber.main(FakeConfig())
    assert capsys.readouterr().out == "1001\n"


class BaseSearchEntry:
    """Stands in for LDAPEntry, recording the searches a script asks for."""

    def __init__(self, calls: list[Mapping[str, object]]) -> None:
        self.calls = calls

    async def search_async(self, **kwargs: object) -> None:
        self.calls.append(kwargs)
        callback = kwargs.get("callback")
        if callback:
            assert callable(callback)
            callback(
                {
                    "uid": ["alice"],
                    "uidNumber": [1000],
                    "gidNumber": [100],
                    "cn": ["Alice"],
                    "homeDirectory": ["/home/alice"],
                }
            )


def make_search_entry(calls: list[Mapping[str, object]]) -> type[BaseSearchEntry]:
    """An entry class of its own, recording into the list one test owns."""

    class SearchEntry(BaseSearchEntry):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(calls)

    return SearchEntry


async def test_search_entry_without_callback() -> None:
    await BaseSearchEntry([]).search_async()


async def test_search_main(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Mapping[str, object]] = []
    monkeypatch.setattr(ldapconnector, "LDAPClientCreator", make_fake_creator(object()))
    monkeypatch.setattr(ldapsyntax, "LDAPEntry", make_search_entry(calls))
    await search.main(FakeConfig(), "(uid=alice)", ("uid",))
    assert calls[-1]["filterText"] == "(uid=alice)"


@pytest.mark.parametrize("filter_text", [None, "(uid=alice)"])
async def test_ldap2passwd_main(
    monkeypatch: pytest.MonkeyPatch,
    filter_text: str | None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[Mapping[str, object]] = []
    monkeypatch.setattr(ldapconnector, "LDAPClientCreator", make_fake_creator(object()))
    monkeypatch.setattr(ldapsyntax, "LDAPEntry", make_search_entry(calls))
    await ldap2passwd.main(FakeConfig(), filter_text)
    attributes = calls[-1]["attributes"]
    assert isinstance(attributes, Sequence)
    assert attributes[0] == "uid"
    assert "alice:x:1000" in capsys.readouterr().out


async def test_namingcontexts_lookup_and_main(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class Client:
        async def bind_async(self) -> None:
            self.bound = True

    client = Client()

    class Connection:
        """What the connector really returns: the protocol, plus its lifetime."""

        protocol = client

    async def connect(*args: object, **kwargs: object) -> Connection:
        return Connection()

    class Entry:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def search_async(self, **kwargs: object) -> list[dict[str, list[str]]]:
            return [{"namingContexts": ["dc=one", "dc=two"]}]

    monkeypatch.setattr(ldapconnector, "connectToLDAPEndpointAsync", connect)
    monkeypatch.setattr(ldapsyntax, "LDAPEntry", Entry)
    await namingcontexts.lookup("ldap.example.com")
    assert capsys.readouterr().out == "ldap.example.com\tdc=one\nldap.example.com\tdc=two\n"

    seen: list[str] = []

    async def lookup(server: str) -> None:
        seen.append(server)

    monkeypatch.setattr(namingcontexts, "lookup", lookup)
    await namingcontexts.main(["one", "two"])
    assert seen == ["one", "two"]


@pytest.mark.parametrize(("binddn", "supplied"), [(None, None), ("cn=admin", "secret"), ("cn=admin", None)])
async def test_rename_main(
    monkeypatch: pytest.MonkeyPatch, binddn: str | None, supplied: str | None
) -> None:
    class Client:
        binds: ClassVar[list[tuple[object, ...]]] = []

        async def bind_async(self, *args: object) -> None:
            self.binds.append(args)

    class Entry:
        destination: object = None

        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def move_async(self, destination: object) -> None:
            self.destination = destination

    client = Client()
    monkeypatch.setattr(ldapconnector, "LDAPClientCreator", make_fake_creator(client))
    monkeypatch.setattr(ldapsyntax, "LDAPEntry", Entry)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "prompted")
    await rename.main(FakeConfig(), "cn=old", "cn=new", binddn, supplied)
    expected = () if binddn is None else (binddn, supplied or "prompted")
    assert client.binds[-1] == expected


@pytest.mark.parametrize("generate", [False, True])
async def test_passwd_main(
    monkeypatch: pytest.MonkeyPatch,
    generate: bool,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Client:
        async def bind_async(self, *args: object) -> None:
            self.bind = args

    changed: list[tuple[object, object]] = []

    class Entry:
        def __init__(self, client: object, dn: object) -> None:
            self.dn = dn

        async def setPassword_async(self, newPasswd: object) -> None:
            changed.append((self.dn, newPasswd))

    client = Client()
    monkeypatch.setattr(ldapconnector, "LDAPClientCreator", make_fake_creator(client))
    monkeypatch.setattr(ldapsyntax, "LDAPEntry", Entry)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "prompted")

    async def get_password(dn: str, generated: bool) -> str:
        return "new-password"

    monkeypatch.setattr(passwd, "_get_password", get_password)
    await passwd.main("cn=admin", None, ["cn=one", "cn=two"], generate, {})
    # A password is octets by the time it reaches an entry, which is what the
    # entry that hashes it locally needs.
    assert changed[-2:] == [("cn=one", b"new-password"), ("cn=two", b"new-password")]
    assert bool(capsys.readouterr().out) is generate
