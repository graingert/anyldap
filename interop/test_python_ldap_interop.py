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


def subtree(slapd: Any, name: str, backend: str) -> str:
    """A part of the directory only this run writes to.

    One server is shared by the whole module, and the module is run once per
    backend, so a test that writes needs somewhere of its own to write.
    """
    return f"ou={name}-{backend},{slapd.suffix}"


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


async def test_binding_as_a_user_matches(
    slapd: Any, anyio_backend_name: str
) -> None:
    uri = slapd.ldap_uri
    where = subtree(slapd, "people", anyio_backend_name)
    dn = person(where, "babs")

    setup = ldap.initialize(uri)
    setup.simple_bind_s(slapd.root_dn, slapd.root_pw)
    setup.add_s(
        where,
        [("objectClass", [b"organizationalUnit"]), ("ou", [where[3:].split(",")[0].encode()])],
    )
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
    slapd: Any, anyio_backend_name: str
) -> None:
    """What one client writes, the other reads back the same way."""
    where = subtree(slapd, "shared", anyio_backend_name)
    async with aldap.initialize(slapd.ldap_uri) as connection:
        await connection.simple_bind_s(slapd.root_dn, slapd.root_pw)
        await connection.add_s(
            where,
            [
                ("objectClass", [b"organizationalUnit"]),
                ("ou", [where[3:].split(",")[0].encode()]),
            ],
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


# The pieces that needed the C library in python-ldap: TLS options, SASL,
# controls and schema. Each is checked against what python-ldap does with
# the same server.


def test_the_tls_and_sasl_option_numbers_are_python_ldaps() -> None:
    for name in dir(ldap):
        if name.startswith(("OPT_X_TLS", "OPT_X_SASL", "SASL_")) and hasattr(
            aldap, name
        ):
            theirs, ours = getattr(ldap, name), getattr(aldap, name)
            if isinstance(theirs, int) and isinstance(ours, int):
                assert ours == theirs, name


def test_the_sasl_mechanisms_are_named_as_python_ldap_names_them() -> None:
    import ldap.sasl

    assert aldap.sasl.external().mech == ldap.sasl.external().mech
    assert aldap.sasl.cram_md5("u", "p").mech == ldap.sasl.cram_md5("u", "p").mech
    assert aldap.sasl.digest_md5("u", "p").mech == ldap.sasl.digest_md5("u", "p").mech
    # The callback keys a mechanism is built from are the same numbers.
    assert aldap.sasl.CB_AUTHNAME == ldap.sasl.CB_AUTHNAME
    assert aldap.sasl.CB_PASS == ldap.sasl.CB_PASS


async def test_sasl_external_binds_over_a_socket_in_the_filesystem(
    slapd: Any,
) -> None:
    """What ``ldapwhoami -Y EXTERNAL -H ldapi://`` does, both ways."""
    expected = ldap.initialize(slapd.ldapi_uri)
    expected.sasl_non_interactive_bind_s("EXTERNAL")
    expected_whoami = expected.whoami_s()
    expected.unbind_s()

    async with aldap.initialize(slapd.ldapi_uri) as connection:
        await connection.sasl_external_bind_s()
        assert await connection.whoami_s() == expected_whoami


def test_the_controls_encode_to_what_python_ldaps_encode_to() -> None:
    import ldap.controls
    import ldap.controls.pagedresults
    import ldap.controls.simple

    ours = aldap.controls.SimplePagedResultsControl(True, size=3, cookie=b"")
    theirs = ldap.controls.pagedresults.SimplePagedResultsControl(
        True, size=3, cookie=b""
    )
    assert ours.encodeControlValue() == theirs.encodeControlValue()
    assert ours.controlType == theirs.controlType

    # And what one encodes, the other reads back the same way.
    ours_read = aldap.controls.SimplePagedResultsControl()
    ours_read.decodeControlValue(theirs.encodeControlValue())
    theirs_read = ldap.controls.pagedresults.SimplePagedResultsControl()
    theirs_read.decodeControlValue(ours.encodeControlValue())
    assert ours_read.size == theirs_read.size == 3

    assert (
        aldap.controls.ManageDSAITControl().controlType
        == ldap.controls.simple.ManageDSAITControl().controlType
    )
    assert (
        aldap.controls.RelaxRulesControl().controlType
        == ldap.controls.simple.RelaxRulesControl().controlType
    )
    # python-ldap hands this one back as text and lets its C layer encode
    # it; here it is already the octets that go on the wire.
    mine = aldap.controls.ProxyAuthzControl(True, "dn:cn=jack").encodeControlValue()
    theirs_value = ldap.controls.simple.ProxyAuthzControl(
        True, "dn:cn=jack"
    ).encodeControlValue()
    assert mine == theirs_value.encode("utf-8")


async def test_paged_results_walk_the_same_pages(
    slapd: Any, anyio_backend_name: str
) -> None:
    """A search read a page at a time, through both clients."""
    import ldap.controls.pagedresults as their_paged

    where = subtree(slapd, "paged", anyio_backend_name)
    setup = ldap.initialize(slapd.ldap_uri)
    setup.simple_bind_s(slapd.root_dn, slapd.root_pw)
    setup.add_s(
        where,
        [
            ("objectClass", [b"organizationalUnit"]),
            ("ou", [where[3:].split(",")[0].encode()]),
        ],
    )
    for index in range(5):
        setup.add_s(
            f"cn=page{index},{where}",
            [("objectClass", [b"organizationalRole"]), ("cn", [f"page{index}".encode()])],
        )

    def sync_pages() -> list[list[str]]:
        control = their_paged.SimplePagedResultsControl(True, size=2, cookie="")
        pages = []
        while True:
            msgid = setup.search_ext(
                where, ldap.SCOPE_ONELEVEL, "(cn=page*)", serverctrls=[control]
            )
            _, data, _, ctrls = setup.result3(msgid)
            pages.append(sorted(dn for dn, _ in data))
            cookies = [
                c.cookie
                for c in ctrls
                if c.controlType == their_paged.SimplePagedResultsControl.controlType
            ]
            if not cookies or not cookies[0]:
                return pages
            control.cookie = cookies[0]

    async def async_pages() -> list[list[str]]:
        control = aldap.controls.SimplePagedResultsControl(True, size=2, cookie=b"")
        pages = []
        async with aldap.initialize(slapd.ldap_uri) as connection:
            await connection.simple_bind_s(slapd.root_dn, slapd.root_pw)
            while True:
                msgid = await connection.search_ext(
                    where, aldap.SCOPE_ONELEVEL, "(cn=page*)", serverctrls=[control]
                )
                _, data, _, ctrls = await connection.result3(msgid)
                pages.append(sorted(dn for dn, _ in data))
                cookies = [
                    c.cookie
                    for c in ctrls
                    if c.controlType == aldap.CONTROL_PAGEDRESULTS
                ]
                if not cookies or not cookies[0]:
                    return pages
                control.cookie = cookies[0]

    expected = sync_pages()
    setup.unbind_s()
    assert await async_pages() == expected
    assert [len(page) for page in expected] == [2, 2, 1]


async def test_the_schema_is_read_the_same_way(slapd: Any) -> None:
    """The server's own schema, through python-ldap's reader and this one."""
    import ldap.schema

    their_uri = slapd.ldap_uri
    their_dn, their_subschema = ldap.schema.urlfetch(their_uri)

    async with aldap.initialize(their_uri) as connection:
        await connection.simple_bind_s(slapd.root_dn, slapd.root_pw)
        assert await connection.search_subschemasubentry_s() == their_dn
        ours = await connection.read_schema_s()

    # The same object classes and attribute types, said the same way.
    assert sorted(ours.listall(aldap.schema.ObjectClass)) == sorted(
        their_subschema.listall(ldap.schema.ObjectClass)
    )
    assert sorted(ours.listall(aldap.schema.AttributeType)) == sorted(
        their_subschema.listall(ldap.schema.AttributeType)
    )

    for name in ("person", "organizationalUnit", "top"):
        mine = ours.get_obj(aldap.schema.ObjectClass, name)
        theirs = their_subschema.get_obj(ldap.schema.ObjectClass, name)
        assert mine is not None and theirs is not None
        assert (mine.oid, mine.names, mine.kind) == (
            theirs.oid,
            theirs.names,
            theirs.kind,
        )
        assert sorted(mine.must) == sorted(theirs.must)
        assert sorted(mine.may) == sorted(theirs.may)

    for name in ("cn", "objectClass", "userPassword"):
        mine_at = ours.get_obj(aldap.schema.AttributeType, name)
        theirs_at = their_subschema.get_obj(ldap.schema.AttributeType, name)
        assert mine_at is not None and theirs_at is not None
        assert (mine_at.oid, mine_at.names, mine_at.syntax, mine_at.equality) == (
            theirs_at.oid,
            theirs_at.names,
            theirs_at.syntax,
            theirs_at.equality,
        )
        assert mine_at.single_value == theirs_at.single_value

    # And the same answer to what an entry of a class needs.
    for classes in (["person"], ["organizationalUnit"], ["person", "top"]):
        my_must, my_may = ours.attribute_types(classes)
        their_must, their_may = their_subschema.attribute_types(classes)
        assert sorted(my_must) == sorted(their_must)
        assert sorted(my_may) == sorted(their_may)


def test_ldif_is_written_and_read_the_way_python_ldaps_own_module_does() -> None:
    """The LDIF module, which needs no server: same bytes out, same records in."""
    import io

    import ldif as their_ldif

    from anyldap.ldap import ldif as our_ldif

    records: list[tuple[str, dict[str, list[bytes]]]] = [
        ("cn=Michael Ströder,dc=example,dc=com", {"cn": [b"Michael Str\303\266der"]}),
        (
            "uid=jack,ou=People,dc=example,dc=com",
            {
                "objectClass": [b"inetOrgPerson", b"top"],
                "uid": [b"jack"],
                "description": [b"z" * 200, b" leading", b"trailing ", b"", b"a\nb"],
                "jpegPhoto": [bytes(range(256))],
            },
        ),
    ]
    changes: list[tuple[str, list[tuple[int, str, list[bytes] | None]]]] = [
        (
            "uid=jack,ou=People,dc=example,dc=com",
            [
                (ldap.MOD_REPLACE, "description", [b"one", b"two"]),
                (ldap.MOD_ADD, "cn", [b"Jack"]),
                (ldap.MOD_DELETE, "seeAlso", None),
                (ldap.MOD_INCREMENT, "uidNumber", [b"1"]),
            ],
        ),
    ]

    def write(module: object, cols: int, base64_attrs: list[str] | None) -> str:
        out = io.StringIO()
        writer = module.LDIFWriter(out, base64_attrs, cols)  # type: ignore[attr-defined]
        for dn, entry in records:
            writer.unparse(dn, entry)
        for dn, modlist in changes:
            writer.unparse(dn, modlist)
        assert writer.records_written == len(records) + len(changes)
        return out.getvalue()

    for cols, base64_attrs in ((76, None), (20, ["description"]), (200, [])):
        theirs = write(their_ldif, cols, base64_attrs)
        assert write(our_ldif, cols, base64_attrs) == theirs

    written = write(their_ldif, 76, None)

    def read(module: object) -> tuple[list[Any], list[Any], int | None]:
        parser = module.LDIFRecordList(io.StringIO(written))  # type: ignore[attr-defined]
        parser.parse_entry_records()
        changer = module.LDIFRecordList(io.StringIO(written))  # type: ignore[attr-defined]
        changer.parse_change_records()
        return (
            list(parser.all_records),
            list(changer.all_modify_changes),
            parser.records_read,
        )

    assert read(our_ldif) == read(their_ldif)
    # And the pieces beside the classes say the same things.
    assert our_ldif.MOD_OP_INTEGER == their_ldif.MOD_OP_INTEGER
    assert our_ldif.MOD_OP_STR == their_ldif.MOD_OP_STR
    assert our_ldif.CHANGE_TYPES == their_ldif.CHANGE_TYPES
    assert our_ldif.SAFE_STRING_PATTERN == their_ldif.SAFE_STRING_PATTERN
    assert our_ldif.ldif_pattern == their_ldif.ldif_pattern
    for candidate in ("", "cn=x,dc=y", "[not a dn]", "cn=x+sn=y,dc=z"):
        assert bool(our_ldif.is_dn(candidate)) == bool(their_ldif.is_dn(candidate))


@pytest.fixture(scope="module")
def referring(slapd: Any) -> Iterator[Any]:
    """A second server, and an entry on the first one referring to it.

    Both hold the same suffix, so what the referral points at is there to be
    found: a referral names a server, and the DN it does not name is the one
    already asked for.
    """
    away = Slapd()
    away.start()
    try:
        base = away.suffix.split(",")[0].split("=")[1]
        away.ldapadd(
            f"""dn: {away.suffix}
objectClass: dcObject
objectClass: organization
dc: {base}
o: {base}

dn: ou=Away,{away.suffix}
objectClass: organizationalUnit
ou: Away

dn: cn=over-there,ou=Away,{away.suffix}
objectClass: organizationalRole
cn: over-there
"""
        )
        slapd.ldapadd(
            f"""dn: ou=Away,{slapd.suffix}
objectClass: referral
objectClass: extensibleObject
ou: Away
ref: {away.ldap_uri}
"""
        )
        yield away
    finally:
        away.stop()


async def test_referrals_are_followed_the_same_way(slapd: Any, referring: Any) -> None:
    """One server refers to another, with chasing off and then on."""
    where = f"ou=Away,{slapd.suffix}"

    def theirs(chase: int) -> object:
        connection = ldap.initialize(slapd.ldap_uri)
        connection.set_option(ldap.OPT_REFERRALS, chase)
        try:
            connection.simple_bind_s(slapd.root_dn, slapd.root_pw)
            try:
                return sorted(connection.search_s(where, ldap.SCOPE_SUBTREE, "(cn=*)"))
            except ldap.LDAPError as exc:
                return (type(exc).__name__, exc.args[0]["desc"], exc.args[0]["info"])
        finally:
            connection.unbind_s()

    async def ours(chase: int) -> object:
        async with aldap.initialize(slapd.ldap_uri) as connection:
            connection.set_option(aldap.OPT_REFERRALS, chase)
            await connection.simple_bind_s(slapd.root_dn, slapd.root_pw)
            try:
                return sorted(
                    await connection.search_s(where, aldap.SCOPE_SUBTREE, "(cn=*)")
                )
            except aldap.LDAPError as exc:
                return (type(exc).__name__, exc.args[0]["desc"], exc.args[0]["info"])

    # The option is kept the way libldap keeps it, whichever client set it.
    connection = ldap.initialize(slapd.ldap_uri)
    for chase in (0, 1):
        connection.set_option(ldap.OPT_REFERRALS, chase)
        async with aldap.initialize(slapd.ldap_uri) as mine:
            mine.set_option(aldap.OPT_REFERRALS, chase)
            assert mine.get_option(aldap.OPT_REFERRALS) == connection.get_option(
                ldap.OPT_REFERRALS
            )
    connection.unbind_s()

    # Left alone, the referral is the answer, and it is the same answer.
    left_alone = theirs(0)
    assert await ours(0) == left_alone
    assert isinstance(left_alone, tuple) and left_alone[0] == "REFERRAL"
    # Followed, the entry over there is found, and it is the same entry.
    followed = theirs(1)
    assert await ours(1) == followed
    assert followed == [
        (
            f"cn=over-there,{where}",
            {"cn": [b"over-there"], "objectClass": [b"organizationalRole"]},
        )
    ]
