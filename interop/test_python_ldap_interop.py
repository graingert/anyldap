"""Check anyldap.ldap against python-ldap itself, on a real OpenLDAP server.

The same script of operations is run twice against one slapd started by
python-ldap's own ``slapdtest`` helper: once through python-ldap, once
through ``anyldap.ldap``. What the two hand back has to match, which is the
claim this client makes.

These tests need slapd installed and python-ldap built against it, so they
are not part of the suite that runs on every change. CI runs them in their
own job; to run them yourself::

    tox -e interop

or, against what is already installed::

    python -m pytest interop --no-cov

Skipped, rather than failed, when slapd or python-ldap is missing.
"""

import os
import sys
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from anyldap import ldap as aldap

ldap = pytest.importorskip("ldap", reason="python-ldap is not installed")
pytest.importorskip("ldap.dn")
pytest.importorskip("ldap.filter")
pytest.importorskip("ldap.modlist")
slapdtest = pytest.importorskip(
    "slapdtest", reason="python-ldap's slapdtest is not installed"
)

if not any(
    os.path.exists(os.path.join(path, "slapd"))
    for path in ("/usr/sbin", "/usr/local/sbin", "/usr/lib/openldap", "/sbin")
):  # pragma: no cover - depends on what is installed
    pytest.skip("slapd is not installed", allow_module_level=True)

pytestmark = pytest.mark.anyio

# What a step of the script produced, named so a mismatch says which step.
Step = tuple[str, object]


class Slapd(slapdtest.SlapdObject):  # type: ignore[misc, name-defined]
    """slapd, knowing the schema the entries below are written against."""

    openldap_schema_files = ("core.ldif", "cosine.ldif", "inetorgperson.ldif")


@pytest.fixture(scope="module")
def slapd() -> Iterator[Any]:
    """One OpenLDAP server, with its base entry, for the whole module."""
    server = Slapd()
    server.start()
    try:
        base = server.suffix.split(",")[0].split("=")[1]
        server.ldapadd(
            "\n".join(
                [
                    f"dn: {server.suffix}",
                    "objectClass: dcObject",
                    "objectClass: organization",
                    f"dc: {base}",
                    f"o: {base}",
                    "",
                ]
            )
        )
        yield server
    finally:
        server.stop()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def normalise(steps: list[Step], label: str, suffix: str) -> str:
    """The script's answers, with the sub-tree it ran in taken out.

    The two runs work on their own entries so that neither sees the other's
    changes; what they are called is not part of what is being compared.
    """
    return (
        repr(steps)
        .replace(f"ou={label},{suffix}", "ou=RUN")
        .replace(f"b'{label}'", "b'RUN'")
    )


def person(where: str, uid: str) -> str:
    return f"uid={uid},{where}"


def sync_script(uri: str, root_dn: str, root_pw: str, suffix: str, where: str) -> list[Step]:
    """The script, as python-ldap runs it."""
    steps: list[Step] = []
    connection = ldap.initialize(uri)
    try:
        result = connection.simple_bind_s(root_dn, root_pw)
        steps.append(("bind", result[:2]))

        steps.append(
            (
                "add ou",
                connection.add_s(
                    where,
                    [
                        ("objectClass", [b"organizationalUnit"]),
                        ("ou", [where.split("=")[1].split(",")[0].encode()]),
                    ],
                )[:2],
            )
        )
        dn = person(where, "jack")
        steps.append(
            (
                "add person",
                connection.add_s(
                    dn,
                    [
                        ("objectClass", [b"inetOrgPerson"]),
                        ("uid", [b"jack"]),
                        ("cn", [b"Jack"]),
                        ("sn", [b"Smith"]),
                        ("userPassword", [b"secret"]),
                    ],
                )[:2],
            )
        )

        steps.append(
            (
                "search subtree",
                sorted(
                    connection.search_s(where, ldap.SCOPE_SUBTREE, "(objectClass=*)")
                ),
            )
        )
        steps.append(
            (
                "search attrs",
                connection.search_ext_s(
                    where, ldap.SCOPE_SUBTREE, "(uid=jack)", ["cn", "sn"]
                ),
            )
        )
        steps.append(("read", connection.read_s(dn, attrlist=["cn"])))
        steps.append(("compare true", connection.compare_s(dn, "uid", b"jack")))
        steps.append(("compare false", connection.compare_s(dn, "uid", b"jill")))

        steps.append(
            (
                "modify",
                connection.modify_s(dn, [(ldap.MOD_REPLACE, "cn", [b"Jack Smith"])])[
                    :2
                ],
            )
        )
        steps.append(("read after modify", connection.read_s(dn, attrlist=["cn"])))

        steps.append(("rename", connection.rename_s(dn, "uid=jill")[:2]))
        renamed = person(where, "jill")
        steps.append(("read renamed", connection.read_s(renamed, attrlist=["uid"])))

        steps.append(("whoami", connection.whoami_s()))
        steps.append(("passwd", connection.passwd_s(renamed, None, b"newsecret")))

        steps.append(("delete", connection.delete_s(renamed)[:2]))
        steps.append(("delete ou", connection.delete_s(where)[:2]))

        for name, call in failing_calls_sync(connection, where, suffix):
            steps.append((name, describe_error(call)))
    finally:
        connection.unbind_s()
    return steps


def failing_calls_sync(
    connection: Any, where: str, suffix: str
) -> list[tuple[str, Callable[[], object]]]:
    return [
        (
            "search missing",
            lambda: connection.search_s(
                f"ou=nothing,{suffix}", ldap.SCOPE_BASE, "(objectClass=*)"
            ),
        ),
        (
            "add under missing",
            lambda: connection.add_s(
                f"uid=x,ou=nothing,{suffix}",
                [("objectClass", [b"inetOrgPerson"]), ("uid", [b"x"])],
            ),
        ),
        ("delete missing", lambda: connection.delete_s(f"ou=nothing,{suffix}")),
    ]


def describe_error(call: Callable[[], object]) -> object:
    """The exception a call raises, said the same way for either client."""
    try:
        call()
    except Exception as exc:  # noqa: BLE001 - the class is what is compared
        return (type(exc).__name__, exc.args[0].get("desc"))
    return "no error"


async def describe_error_async(call: Callable[[], Any]) -> object:
    try:
        await call()
    except Exception as exc:  # noqa: BLE001 - the class is what is compared
        return (type(exc).__name__, exc.args[0].get("desc"))
    return "no error"


async def async_script(
    uri: str, root_dn: str, root_pw: str, suffix: str, where: str
) -> list[Step]:
    """The same script, as anyldap.ldap runs it."""
    steps: list[Step] = []
    async with aldap.initialize(uri) as connection:
        result = await connection.simple_bind_s(root_dn, root_pw)
        steps.append(("bind", result[:2]))

        steps.append(
            (
                "add ou",
                (
                    await connection.add_s(
                        where,
                        [
                            ("objectClass", [b"organizationalUnit"]),
                            ("ou", [where.split("=")[1].split(",")[0].encode()]),
                        ],
                    )
                )[:2],
            )
        )
        dn = person(where, "jack")
        steps.append(
            (
                "add person",
                (
                    await connection.add_s(
                        dn,
                        [
                            ("objectClass", [b"inetOrgPerson"]),
                            ("uid", [b"jack"]),
                            ("cn", [b"Jack"]),
                            ("sn", [b"Smith"]),
                            ("userPassword", [b"secret"]),
                        ],
                    )
                )[:2],
            )
        )

        steps.append(
            (
                "search subtree",
                sorted(
                    await connection.search_s(
                        where, aldap.SCOPE_SUBTREE, "(objectClass=*)"
                    )
                ),
            )
        )
        steps.append(
            (
                "search attrs",
                await connection.search_ext_s(
                    where, aldap.SCOPE_SUBTREE, "(uid=jack)", ["cn", "sn"]
                ),
            )
        )
        steps.append(("read", await connection.read_s(dn, attrlist=["cn"])))
        steps.append(("compare true", await connection.compare_s(dn, "uid", b"jack")))
        steps.append(("compare false", await connection.compare_s(dn, "uid", b"jill")))

        steps.append(
            (
                "modify",
                (
                    await connection.modify_s(
                        dn, [(aldap.MOD_REPLACE, "cn", [b"Jack Smith"])]
                    )
                )[:2],
            )
        )
        steps.append(
            ("read after modify", await connection.read_s(dn, attrlist=["cn"]))
        )

        steps.append(("rename", (await connection.rename_s(dn, "uid=jill"))[:2]))
        renamed = person(where, "jill")
        steps.append(
            ("read renamed", await connection.read_s(renamed, attrlist=["uid"]))
        )

        steps.append(("whoami", await connection.whoami_s()))
        steps.append(
            ("passwd", await connection.passwd_s(renamed, None, b"newsecret"))
        )

        steps.append(("delete", (await connection.delete_s(renamed))[:2]))
        steps.append(("delete ou", (await connection.delete_s(where))[:2]))

        for name, call in failing_calls_async(connection, where, suffix):
            steps.append((name, await describe_error_async(call)))
    return steps


def failing_calls_async(
    connection: Any, where: str, suffix: str
) -> list[tuple[str, Callable[[], Any]]]:
    return [
        (
            "search missing",
            lambda: connection.search_s(
                f"ou=nothing,{suffix}", aldap.SCOPE_BASE, "(objectClass=*)"
            ),
        ),
        (
            "add under missing",
            lambda: connection.add_s(
                f"uid=x,ou=nothing,{suffix}",
                [("objectClass", [b"inetOrgPerson"]), ("uid", [b"x"])],
            ),
        ),
        ("delete missing", lambda: connection.delete_s(f"ou=nothing,{suffix}")),
    ]


async def test_the_same_script_gives_the_same_answers(slapd: Any) -> None:
    """Everything an application does, through both clients, side by side."""
    uri = slapd.ldap_uri
    root_dn, root_pw, suffix = slapd.root_dn, slapd.root_pw, slapd.suffix

    expected = sync_script(uri, root_dn, root_pw, suffix, f"ou=sync,{suffix}")
    actual = await async_script(uri, root_dn, root_pw, suffix, f"ou=async,{suffix}")

    assert normalise(actual, "async", suffix) == normalise(expected, "sync", suffix)


async def test_binding_as_a_user_matches(slapd: Any) -> None:
    uri = slapd.ldap_uri
    where = f"ou=people,{slapd.suffix}"
    dn = person(where, "babs")

    setup = ldap.initialize(uri)
    setup.simple_bind_s(slapd.root_dn, slapd.root_pw)
    setup.add_s(where, [("objectClass", [b"organizationalUnit"]), ("ou", [b"people"])])
    setup.add_s(
        dn,
        [
            ("objectClass", [b"inetOrgPerson"]),
            ("uid", [b"babs"]),
            ("cn", [b"Babs"]),
            ("sn", [b"Jensen"]),
            ("userPassword", [b"secret"]),
        ],
    )
    setup.unbind_s()

    connection = ldap.initialize(uri)
    expected_ok = connection.simple_bind_s(dn, "secret")[:2]
    expected_bad = describe_error(lambda: connection.simple_bind_s(dn, "wrong"))
    expected_whoami = connection.whoami_s()
    connection.unbind_s()

    async with aldap.initialize(uri) as other:
        actual_ok = (await other.simple_bind_s(dn, b"secret"))[:2]
        actual_bad = await describe_error_async(
            lambda: other.simple_bind_s(dn, b"wrong")
        )
        actual_whoami = await other.whoami_s()

    assert actual_ok == expected_ok
    assert actual_whoami == expected_whoami
    assert actual_bad == expected_bad


def test_the_helpers_agree_with_python_ldaps_own() -> None:
    """The pieces that need no server at all: filters, DNs and modlists."""
    values = [
        "Ba*bs",
        "a(b)c",
        "back\\slash",
        "plain",
        "{braces}",
        "sp ace",
        "\u00e9t\u00e9",
        "\x00null",
    ]
    for value in values:
        assert aldap.escape_filter_chars(value) == ldap.filter.escape_filter_chars(
            value
        )
        assert aldap.escape_filter_chars(value, 1) == ldap.filter.escape_filter_chars(
            value, 1
        )
        assert aldap.escape_filter_chars(value, 2) == ldap.filter.escape_filter_chars(
            value, 2
        )

    assert aldap.filter_format("(&(cn=%s)(uid=%s))", values[:2]) == (
        ldap.filter.filter_format("(&(cn=%s)(uid=%s))", values[:2])
    )

    for dn in ["cn=foo,dc=example,dc=com", "cn=a+sn=b,dc=example", "dc=com"]:
        assert aldap.str2dn(dn) == ldap.dn.str2dn(dn)
        assert aldap.dn2str(aldap.str2dn(dn)) == ldap.dn.dn2str(ldap.dn.str2dn(dn))
        assert aldap.explode_dn(dn) == ldap.dn.explode_dn(dn)
        assert aldap.explode_dn(dn, notypes=1) == ldap.dn.explode_dn(dn, notypes=1)
        assert aldap.is_dn(dn) == ldap.dn.is_dn(dn)

    assert aldap.explode_rdn("cn=a+sn=b") == ldap.dn.explode_rdn("cn=a+sn=b")
    assert not aldap.is_dn("not a dn") and not ldap.dn.is_dn("not a dn")

    entry = {"cn": [b"Jack"], "sn": [b"Smith"], "objectClass": [b"inetOrgPerson"]}
    assert sorted(aldap.addModlist(entry)) == sorted(ldap.modlist.addModlist(entry))

    changed = {"cn": [b"Jack Smith"], "objectClass": [b"inetOrgPerson"]}
    assert sorted(aldap.modifyModlist(entry, changed)) == sorted(
        ldap.modlist.modifyModlist(entry, changed)
    )


# What python-ldap exports that this deliberately does not: the options and
# tags of the C library underneath, the locks it needs because it blocks, and
# the request/URL parsing this has no equivalent for.
NOT_HERE = (
    "OPT_",
    "TAG_",
    "REQ_",
    "URL_ERR_",
    "DN_FORMAT_",
    "DN_PEDANTIC",
    "DN_PRETTY",
    "DN_P_",
    "DN_SKIP",
    "SASL_",
    "API_",
    "LIBLDAP_",
    "AVA_NULL",
    "MSG_RECEIVED",
    "RES_INTERMEDIATE",
    "SYNC_INFO",
    "TLS_AVAIL",
    "INIT_FD_AVAIL",
    "VENDOR_VERSION",
    "DummyLock",
    "LDAPLock",
    "LDAPLockBaseClass",
    "LDAPBytesWarning",
)


def test_the_names_python_ldap_exports_are_all_here() -> None:
    """Every constant and error class an application is likely to name."""
    missing = [
        name
        for name in dir(ldap)
        if not name.startswith("_")
        and not name.islower()
        and not hasattr(aldap, name)
        and not name.startswith(NOT_HERE)
    ]
    assert missing == [], missing

    for name in dir(ldap):
        theirs = getattr(ldap, name)
        if name.isupper() and isinstance(theirs, (int, str)) and hasattr(aldap, name):
            ours = getattr(aldap, name)
            if isinstance(ours, (int, str)):
                assert ours == theirs, name


def test_the_errors_stand_for_the_same_result_codes() -> None:
    for name in dir(ldap):
        theirs = getattr(ldap, name)
        if not isinstance(theirs, type) or not issubclass(theirs, ldap.LDAPError):
            continue
        ours = getattr(aldap, name, None)
        if ours is None:
            continue
        assert issubclass(ours, aldap.LDAPError), name


async def test_an_async_run_alone_leaves_the_directory_as_python_ldap_finds_it(
    slapd: Any,
) -> None:
    """What one client writes, the other reads back the same way."""
    where = f"ou=shared,{slapd.suffix}"
    async with aldap.initialize(slapd.ldap_uri) as connection:
        await connection.simple_bind_s(slapd.root_dn, slapd.root_pw)
        await connection.add_s(
            where,
            [("objectClass", [b"organizationalUnit"]), ("ou", [b"shared"])],
        )
        await connection.add_s(
            person(where, "written"),
            [
                ("objectClass", [b"inetOrgPerson"]),
                ("uid", [b"written"]),
                ("cn", [b"Written"]),
                ("sn", [b"Async"]),
            ],
        )
        written = await connection.search_s(where, aldap.SCOPE_SUBTREE)

    reader = ldap.initialize(slapd.ldap_uri)
    reader.simple_bind_s(slapd.root_dn, slapd.root_pw)
    read = reader.search_s(where, ldap.SCOPE_SUBTREE)
    reader.unbind_s()

    assert sorted(written) == sorted(read)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "--no-cov", "-v"]))
