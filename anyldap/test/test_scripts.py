import io
import subprocess
import sys
from types import SimpleNamespace

import pytest

from anyldap import config
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
from anyldap.deferred import succeed

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    "module",
    [ldap2dhcpconf, ldap2dnszones, ldap2maradns, ldap2pdns],
)
async def test_unavailable_scripts_explain_status(module):
    with pytest.raises(SystemExit, match="rewritten for the AnyIO runtime"):
        module.console_script()


@pytest.mark.parametrize(
    "module",
    [ldap2dhcpconf, ldap2dnszones, ldap2maradns, ldap2pdns],
)
async def test_unavailable_script_module_entrypoints(module):
    result = subprocess.run(
        [sys.executable, "-m", module.__name__],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "rewritten for the AnyIO runtime" in result.stderr


def test_fetchschema_print_results(capsys):
    fetchschema._printResults((["one", "two"], ["three"]))
    assert capsys.readouterr().out == "attributetype one\nattributetype two\n\nobjectclass three\n"
    fetchschema._printResults(([], ["three"]))
    assert capsys.readouterr().out == "objectclass three\n"


async def test_find_server_lookup_and_main(monkeypatch, capsys):
    records = [
        SimpleNamespace(rdtype=find_server.dns.rdatatype.A, target="ignored"),
        SimpleNamespace(
            rdtype=find_server.dns.rdatatype.SRV,
            priority=10,
            weight=20,
            target="ldap.example.com.",
            port=389,
        ),
    ]

    async def resolve(name, kind):
        assert (name, kind) == ("_ldap._tcp.example.com", "SRV")
        return records

    monkeypatch.setattr(find_server.dns.asyncresolver, "resolve", resolve)
    await find_server.lookup("dc=example,dc=com")
    assert "pri=10 weight=20" in capsys.readouterr().out

    seen = []

    async def lookup(value):
        seen.append(value)

    monkeypatch.setattr(find_server, "lookup", lookup)
    await find_server.main(["one", "two"])
    assert seen == ["one", "two"]


@pytest.mark.parametrize("module", [find_server, namingcontexts])
def test_positional_scripts_require_arguments(module, monkeypatch, capsys):
    monkeypatch.setattr(module.sys, "argv", ["command"])
    with pytest.raises(SystemExit) as exc:
        module.console_script()
    assert exc.value.code == 1
    assert "usage" in capsys.readouterr().err


def test_ldifdiff_output():
    operation = SimpleNamespace(asLDIF=lambda: "operation\n")
    stream = io.StringIO()
    ldifdiff.output([operation], stream)
    assert stream.getvalue().endswith("operation\n")


def test_ldifpatch_output():
    class Tree:
        def subtree(self, callback):
            callback("entry\n")

    stream = io.StringIO()
    ldifpatch.output(Tree(), stream)
    assert stream.getvalue().endswith("entry\n")


def test_ldap2passwd_callback(capsys):
    entry = {
        "uid": ["alice"],
        "uidNumber": [1000],
        "gidNumber": [100],
        "cn": ["Alice"],
        "homeDirectory": ["/home/alice"],
    }
    ldap2passwd._cbSearch(entry)
    assert capsys.readouterr().out == "alice:x:1000:100:Alice:/home/alice:\n"


def test_search_print_results(capsys):
    search.printResults("result")
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
def test_option_argument_parsing(options, args, expected):
    options.parseArgs(*args)
    for key, value in expected.items():
        assert options.opts[key] == value


def test_passwd_options_default_target():
    options = passwd.MyOptions()
    options.opts["binddn"] = "cn=admin"
    options.parseArgs()
    assert options.opts["dnlist"] == ("cn=admin",)
    options.parseArgs("cn=one", "cn=two")
    assert options.opts["dnlist"] == ("cn=one", "cn=two")


async def test_password_prompt_and_generation(monkeypatch):
    monkeypatch.setattr(passwd.getpass, "getpass", lambda prompt: "prompted")
    assert await passwd._get_password("cn=user", False) == "prompted"

    async def generate():
        return ["generated"]

    monkeypatch.setattr(passwd.generate_password, "generate_async", generate)
    assert await passwd._get_password("cn=user", True) == "generated"


class FakeConfig:
    def __init__(self, base="dc=example,dc=com"):
        self.base = base

    def getBaseDN(self):
        if self.base is None:
            raise config.MissingBaseDNError()
        return self.base

    def getServiceLocationOverrides(self):
        return {self.base: ("ldap.example.com", 389)}


class FakeCreator:
    client = None

    def __init__(self, *args):
        pass

    async def connectAnonymouslyAsync(self, **kwargs):
        return self.client

    async def connectAsync(self, **kwargs):
        return self.client


@pytest.mark.parametrize("module", [fetchschema, getfreenumber, ldap2passwd, search])
async def test_base_dependent_scripts_report_missing_base(module, capsys):
    with pytest.raises(SystemExit) as exc:
        if module is ldap2passwd:
            await module.main(FakeConfig(None), None)
        elif module is search:
            await module.main(FakeConfig(None), "(uid=*)", ())
        else:
            await module.main(FakeConfig(None))
    assert exc.value.code == 1
    assert "Configuration must specify a base DN" in capsys.readouterr().err


async def test_fetchschema_main(monkeypatch, capsys):
    FakeCreator.client = object()
    monkeypatch.setattr(fetchschema.ldapconnector, "LDAPClientCreator", FakeCreator)
    monkeypatch.setattr(
        fetchschema.fetchschema,
        "fetch",
        lambda client, base: succeed((["attribute"], ["object"])),
    )
    await fetchschema.main(FakeConfig())
    assert "attributetype attribute" in capsys.readouterr().out


async def test_getfreenumber_main(monkeypatch, capsys):
    FakeCreator.client = object()
    monkeypatch.setattr(getfreenumber.ldapconnector, "LDAPClientCreator", FakeCreator)
    monkeypatch.setattr(getfreenumber.ldapsyntax, "LDAPEntry", lambda **kwargs: "entry")
    monkeypatch.setattr(
        getfreenumber.numberalloc,
        "getFreeNumber",
        lambda entry, name, min: succeed(1001),
    )
    await getfreenumber.main(FakeConfig())
    assert capsys.readouterr().out == "1001\n"


class SearchEntry:
    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def search_async(self, **kwargs):
        self.calls.append(kwargs)
        callback = kwargs.get("callback")
        if callback:
            callback(
                {
                    "uid": ["alice"],
                    "uidNumber": [1000],
                    "gidNumber": [100],
                    "cn": ["Alice"],
                    "homeDirectory": ["/home/alice"],
                }
            )


async def test_search_entry_without_callback():
    await SearchEntry().search_async()


async def test_search_main(monkeypatch):
    SearchEntry.calls.clear()
    FakeCreator.client = object()
    monkeypatch.setattr(search.ldapconnector, "LDAPClientCreator", FakeCreator)
    monkeypatch.setattr(search.ldapsyntax, "LDAPEntry", SearchEntry)
    await search.main(FakeConfig(), "(uid=alice)", ("uid",))
    assert SearchEntry.calls[-1]["filterText"] == "(uid=alice)"


@pytest.mark.parametrize("filter_text", [None, "(uid=alice)"])
async def test_ldap2passwd_main(monkeypatch, filter_text, capsys):
    SearchEntry.calls.clear()
    FakeCreator.client = object()
    monkeypatch.setattr(ldap2passwd.ldapconnector, "LDAPClientCreator", FakeCreator)
    monkeypatch.setattr(ldap2passwd.ldapsyntax, "LDAPEntry", SearchEntry)
    await ldap2passwd.main(FakeConfig(), filter_text)
    assert SearchEntry.calls[-1]["attributes"][0] == "uid"
    assert "alice:x:1000" in capsys.readouterr().out


async def test_namingcontexts_lookup_and_main(monkeypatch, capsys):
    class Client:
        async def bind_async(self):
            self.bound = True

    client = Client()

    async def connect(*args, **kwargs):
        return client

    class Entry:
        def __init__(self, *args, **kwargs):
            pass

        async def search_async(self, **kwargs):
            return [{"namingContexts": ["dc=one", "dc=two"]}]

    monkeypatch.setattr(namingcontexts.ldapconnector, "connectToLDAPEndpointAsync", connect)
    monkeypatch.setattr(namingcontexts.ldapsyntax, "LDAPEntry", Entry)
    await namingcontexts.lookup("ldap.example.com")
    assert capsys.readouterr().out == "ldap.example.com\tdc=one\nldap.example.com\tdc=two\n"

    seen = []

    async def lookup(server):
        seen.append(server)

    monkeypatch.setattr(namingcontexts, "lookup", lookup)
    await namingcontexts.main(["one", "two"])
    assert seen == ["one", "two"]


@pytest.mark.parametrize(("binddn", "supplied"), [(None, None), ("cn=admin", "secret"), ("cn=admin", None)])
async def test_rename_main(monkeypatch, binddn, supplied):
    class Client:
        binds = []

        async def bind_async(self, *args):
            self.binds.append(args)

    class Entry:
        destination = None

        def __init__(self, *args, **kwargs):
            pass

        async def move_async(self, destination):
            self.destination = destination

    client = Client()
    FakeCreator.client = client
    monkeypatch.setattr(rename.ldapconnector, "LDAPClientCreator", FakeCreator)
    monkeypatch.setattr(rename.ldapsyntax, "LDAPEntry", Entry)
    monkeypatch.setattr(rename.getpass, "getpass", lambda prompt: "prompted")
    await rename.main(FakeConfig(), "cn=old", "cn=new", binddn, supplied)
    expected = () if binddn is None else (binddn, supplied or "prompted")
    assert client.binds[-1] == expected


@pytest.mark.parametrize("generate", [False, True])
async def test_passwd_main(monkeypatch, generate, capsys):
    class Client:
        async def bind_async(self, *args):
            self.bind = args

    changed = []

    class Entry:
        def __init__(self, client, dn):
            self.dn = dn

        async def setPassword_async(self, newPasswd):
            changed.append((self.dn, newPasswd))

    client = Client()
    FakeCreator.client = client
    monkeypatch.setattr(passwd.ldapconnector, "LDAPClientCreator", FakeCreator)
    monkeypatch.setattr(passwd.ldapsyntax, "LDAPEntry", Entry)
    monkeypatch.setattr(passwd.getpass, "getpass", lambda prompt: "prompted")

    async def get_password(dn, generated):
        return "new-password"

    monkeypatch.setattr(passwd, "_get_password", get_password)
    await passwd.main("cn=admin", None, ["cn=one", "cn=two"], generate, {})
    assert changed[-2:] == [("cn=one", "new-password"), ("cn=two", "new-password")]
    assert bool(capsys.readouterr().out) is generate
