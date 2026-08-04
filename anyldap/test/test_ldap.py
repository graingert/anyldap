"""Test cases for the anyldap.ldap package, python-ldap's API awaited.

Every connection here is made over a real socket to a real server, so what
is exercised is the wire behaviour rather than a stand-in for it.
"""

import ssl
from collections.abc import AsyncGenerator, Callable, Iterable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from urllib.parse import quote

import anyio
import anyio.streams.tls
import pytest
import trustme

from anyldap import inmemory, ldap
from anyldap.ldap import ldapobject
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldapserver
from anyldap.test._anyio_helpers import local_address

pytestmark = pytest.mark.anyio

# The password "secret", salted and hashed as the entries below store it.
SECRET_SSHA = b"{SSHA}Wcm1xEisNjqp921ALcHfuQ7avFdzYWx0MTIzNA=="

JACK = "uid=jack,ou=People,dc=example,dc=com"


def make_root() -> inmemory.ReadOnlyInMemoryLDAPEntry:
    """A small tree the tests search, change and put back."""
    root = inmemory.ReadOnlyInMemoryLDAPEntry(
        dn="dc=example,dc=com", attributes={"dc": ["example"]}
    )
    people = root.addChild(
        rdn="ou=People",
        attributes={"objectClass": ["organizationalUnit"], "ou": ["People"]},
    )
    people.addChild(
        rdn="uid=jack",
        attributes={
            "objectClass": ["inetOrgPerson"],
            "uid": ["jack"],
            "cn": ["Jack"],
            "userPassword": [SECRET_SSHA],
        },
    )
    return root


ServerFactory = Callable[[], ldapserver.BaseLDAPServer]


def tree_server(root: inmemory.ReadOnlyInMemoryLDAPEntry) -> ServerFactory:
    def factory() -> ldapserver.BaseLDAPServer:
        server = ldapserver.LDAPServer()
        server.factory = root
        return server

    return factory


class Serving:
    """Where a server that is listening can be reached."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    @property
    def uri(self) -> str:
        return f"ldap://{self.host}:{self.port}"


@asynccontextmanager
async def serving(
    factory: ServerFactory, ssl_context: ssl.SSLContext | None = None
) -> AsyncGenerator[Serving, None]:
    """A server listening for as long as the body of the with statement runs.

    The task group is entered and left in the one task, which is what
    structured concurrency asks of whoever starts a server.
    """
    listener: anyio.abc.Listener[anyio.abc.ByteStream]
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    if ssl_context is not None:
        listener = anyio.streams.tls.TLSListener(listener, ssl_context)
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve, listener, factory)
        try:
            yield Serving(host, port)
        finally:
            # However the body ends, the server stops with it: a test that
            # fails has to fail rather than wait for a server nobody stopped.
            task_group.cancel_scope.cancel()


def serving_tree() -> AbstractAsyncContextManager[Serving]:
    """A server holding the tree these tests read and write."""
    return serving(tree_server(make_root()))


def connected(
    server: Serving, uri: str | None = None, ssl_context: ssl.SSLContext | None = None
) -> ldapobject.SimpleLDAPObject:
    """A connection, closed however the body of the with statement ends."""
    return ldapobject.SimpleLDAPObject(uri or server.uri, ssl_context=ssl_context)


@asynccontextmanager
async def bound(
    server: Serving,
) -> AsyncGenerator[ldapobject.SimpleLDAPObject, None]:
    """A connection that has already bound anonymously."""
    async with connected(server) as connection:
        await connection.simple_bind_s()
        yield connection


def tls_pair() -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """A server context and a client that trusts it."""
    authority = trustme.CA()
    certificate = authority.issue_cert("localhost")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server_context)
    client_context = ssl.create_default_context()
    authority.configure_trust(client_context)
    return server_context, client_context


# Connecting, and the URLs that say where to.


def test_uri_says_where_to_connect_and_whether_to_raise_tls() -> None:
    assert ldapobject._parse_uri("ldap://ldap.example.com") == (
        "ldap.example.com",
        389,
        False,
    )
    assert ldapobject._parse_uri("ldaps://ldap.example.com") == (
        "ldap.example.com",
        636,
        True,
    )
    assert ldapobject._parse_uri("ldap://ldap.example.com:1389") == (
        "ldap.example.com",
        1389,
        False,
    )
    assert ldapobject._parse_uri("ldap://") == ("localhost", 389, False)


def test_uri_that_cannot_be_connected_to_is_refused() -> None:
    with pytest.raises(ValueError, match="scheme"):
        ldap.initialize("http://ldap.example.com")
    with pytest.raises(ValueError, match="bad port"):
        ldap.initialize("ldap://ldap.example.com:not-a-port")


def test_an_ldapi_url_names_a_socket_in_the_filesystem() -> None:
    assert ldapobject._parse_uri("ldapi://%2Frun%2Fslapd%2Fldapi") == (
        "/run/slapd/ldapi",
        0,
        False,
    )
    assert ldapobject._parse_uri("ldapi:///run/slapd/ldapi") == (
        "/run/slapd/ldapi",
        0,
        False,
    )
    assert ldapobject._parse_uri("ldapi://") == ("/var/run/ldapi", 0, False)


def test_open_names_the_same_connection_as_a_url() -> None:
    connection = ldap.open("ldap.example.com", 1389)
    assert connection.uri == "ldap://ldap.example.com:1389"
    assert connection.get_option(ldap.OPT_URI) == "ldap://ldap.example.com:1389"


async def test_connecting_to_nothing_reports_the_server_as_down() -> None:
    # A port nothing is listening on: bound, then closed again.
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    await listener.aclose()

    async with ldap.initialize(f"ldap://{host}:{port}") as connection:
        with pytest.raises(ldap.SERVER_DOWN) as caught:
            await connection.simple_bind_s()
        assert caught.value.info is not None


async def test_operations_after_unbind_are_refused() -> None:
    async with serving_tree() as server, bound(server) as connection:
        await connection.unbind_s()
        # Unbinding twice is what closing an already closed connection does.
        await connection.unbind_s()
        with pytest.raises(ldap.LDAPError, match="unbind"):
            await connection.search_s("dc=example,dc=com", ldap.SCOPE_BASE)


async def test_a_connection_never_opened_closes_without_complaint() -> None:
    connection = ldap.initialize("ldap://127.0.0.1:389")
    await connection.unbind_s()


async def test_used_as_a_context_manager_it_closes_on_the_way_out() -> None:
    async with serving_tree() as server:
        async with ldap.initialize(server.uri) as connection:
            await connection.simple_bind_s()
            assert await connection.search_s("dc=example,dc=com", ldap.SCOPE_ONELEVEL)
        with pytest.raises(ldap.LDAPError, match="unbind"):
            await connection.search_s("dc=example,dc=com", ldap.SCOPE_BASE)


# Binding.


async def test_binding_says_what_the_server_answered() -> None:
    async with serving_tree() as server, connected(server) as connection:
        # Tracing logs both what is sent and what comes back, and changes
        # nothing else about the answer.
        connection.trace_level = 1
        result = await connection.simple_bind_s(JACK, b"secret")
        rtype, data, _, controls = result
        assert (rtype, data, controls) == (ldap.RES_BIND, [], [])


async def test_binding_with_the_wrong_password_raises_invalid_credentials() -> None:
    async with serving_tree() as server, connected(server) as connection:
        with pytest.raises(ldap.INVALID_CREDENTIALS):
            await connection.simple_bind_s(JACK, b"wrong")


async def test_bind_s_takes_the_method_python_ldap_takes() -> None:
    async with serving_tree() as server, connected(server) as connection:
        result = await connection.bind_s(JACK, b"secret", ldap.AUTH_SIMPLE)
        assert result[0] == ldap.RES_BIND
        with pytest.raises(ldap.AUTH_UNKNOWN):
            await connection.bind_s(JACK, b"secret", ldap.AUTH_NONE)


# Searching.


async def test_search_hands_back_dns_and_attributes() -> None:
    async with serving_tree() as server, bound(server) as connection:
        results = await connection.search_s(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=jack)"
        )
        assert results == [
            (
                JACK,
                {
                    "objectClass": [b"inetOrgPerson"],
                    "uid": [b"jack"],
                    "cn": [b"Jack"],
                    "userPassword": [SECRET_SSHA],
                },
            )
        ]


async def test_search_takes_the_attributes_asked_for() -> None:
    async with serving_tree() as server, bound(server) as connection:
        results = await connection.search_s(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=jack)", ["cn"]
        )
        assert results == [(JACK, {"cn": [b"Jack"]})]

        typesonly = await connection.search_s(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=jack)", ["cn"], 1
        )
        assert typesonly[0][0] == JACK


async def test_search_scopes_and_timed_variants_reach_the_same_entries() -> None:
    async with serving_tree() as server, bound(server) as connection:
        one_level = await connection.search_s("dc=example,dc=com", ldap.SCOPE_ONELEVEL)
        assert [dn for dn, _ in one_level] == ["ou=People,dc=example,dc=com"]

        timed = await connection.search_st(
            "dc=example,dc=com", ldap.SCOPE_ONELEVEL, timeout=10
        )
        assert timed == one_level

        limited = await connection.search_ext_s(
            "dc=example,dc=com", ldap.SCOPE_ONELEVEL, sizelimit=10, timeout=10
        )
        assert limited == one_level


async def test_reading_one_entry_answers_none_when_it_is_not_there() -> None:
    async with serving_tree() as server, bound(server) as connection:
        attributes = await connection.read_s(JACK)
        assert attributes is not None
        assert attributes["cn"] == [b"Jack"]

        assert await connection.read_s(JACK, "(uid=nobody)") is None


async def test_searching_what_is_not_there_raises_no_such_object() -> None:
    async with serving_tree() as server, bound(server) as connection:
        with pytest.raises(ldap.NO_SUCH_OBJECT):
            await connection.search_s("dc=nowhere,dc=com", ldap.SCOPE_BASE)


async def test_a_filter_that_cannot_be_parsed_raises_filter_error() -> None:
    async with serving_tree() as server, bound(server) as connection:
        with pytest.raises(ldap.FILTER_ERROR):
            await connection.search_s("dc=example,dc=com", ldap.SCOPE_BASE, "(((")


# Adding, changing and removing entries.


async def test_add_modify_rename_and_delete_change_the_tree() -> None:
    async with serving_tree() as server, bound(server) as connection:
        dn = "uid=new,ou=People,dc=example,dc=com"

        added = await connection.add_s(
            dn, [("objectClass", [b"inetOrgPerson"]), ("uid", [b"new"])]
        )
        assert added[0] == ldap.RES_ADD

        modified = await connection.modify_s(
            dn, [(ldap.MOD_REPLACE, "cn", [b"New Person"])]
        )
        assert modified[0] == ldap.RES_MODIFY
        assert (await connection.read_s(dn) or {})["cn"] == [b"New Person"]

        await connection.modify_s(dn, [(ldap.MOD_ADD, "description", [b"added"])])
        await connection.modify_s(dn, [(ldap.MOD_DELETE, "description", None)])
        assert "description" not in (await connection.read_s(dn) or {})

        assert (await connection.modrdn_s(dn, "uid=renamed"))[0] == ldap.RES_MODRDN
        renamed = "uid=renamed,ou=People,dc=example,dc=com"
        assert await connection.read_s(renamed) is not None

        assert (await connection.delete_s(renamed))[0] == ldap.RES_DELETE
        with pytest.raises(ldap.NO_SUCH_OBJECT):
            await connection.read_s(renamed)


async def test_adding_what_is_already_there_raises_already_exists() -> None:
    async with serving_tree() as server, bound(server) as connection:
        with pytest.raises(ldap.ALREADY_EXISTS):
            await connection.add_s(JACK, [("objectClass", b"inetOrgPerson")])


async def test_the_ext_spellings_take_controls_and_answer_the_same() -> None:
    async with serving_tree() as server, bound(server) as connection:
        dn = "uid=ext,ou=People,dc=example,dc=com"
        added = await connection.add_ext_s(
            dn, [("objectClass", [b"inetOrgPerson"]), ("uid", [b"ext"])], []
        )
        assert added[0] == ldap.RES_ADD

        modified = await connection.modify_ext_s(
            dn, [(ldap.MOD_REPLACE | ldap.MOD_BVALUES, "cn", b"Ext")], []
        )
        assert modified[0] == ldap.RES_MODIFY
        assert (await connection.read_s(dn) or {})["cn"] == [b"Ext"]

        renamed = await connection.rename_s(dn, "uid=ext2", None, 1, [])
        assert renamed[0] == ldap.RES_MODRDN

        deleted = await connection.delete_ext_s(
            "uid=ext2,ou=People,dc=example,dc=com", []
        )
        assert deleted[0] == ldap.RES_DELETE


async def test_renaming_under_a_new_parent_moves_the_entry() -> None:
    async with serving_tree() as server, bound(server) as connection:
        await connection.add_s(
            "ou=Others,dc=example,dc=com",
            [("objectClass", [b"organizationalUnit"]), ("ou", [b"Others"])],
        )
        await connection.rename_s(JACK, "uid=jack", "ou=Others,dc=example,dc=com")
        assert await connection.read_s("uid=jack,ou=Others,dc=example,dc=com")


async def test_compare_answers_true_and_false() -> None:
    async with serving_tree() as server, bound(server) as connection:
        assert await connection.compare_s(JACK, "uid", b"jack") is True
        assert await connection.compare_s(JACK, "uid", "nobody") is False
        assert await connection.compare_ext_s(JACK, "uid", b"jack", []) is True


# Operations started now and collected later.


async def test_operations_can_be_started_and_collected_by_message_id() -> None:
    async with serving_tree() as server, bound(server) as connection:
        first = await connection.search("dc=example,dc=com", ldap.SCOPE_ONELEVEL)
        second = await connection.search(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=jack)"
        )
        assert first != second

        rtype, data, rmsgid, controls = await connection.result3(second)
        assert (rtype, rmsgid, controls) == (ldap.RES_SEARCH_RESULT, second, [])
        assert [dn for dn, _ in data] == [JACK]

        # RES_ANY takes the operation that was started first.
        rtype, data, rmsgid = await connection.result2()
        assert (rtype, rmsgid) == (ldap.RES_SEARCH_RESULT, first)


async def test_result_and_result4_answer_what_python_ldap_answers() -> None:
    async with serving_tree() as server, bound(server) as connection:
        dn = "uid=four,ou=People,dc=example,dc=com"

        msgid = await connection.search("dc=example,dc=com", ldap.SCOPE_ONELEVEL)
        rtype, data = await connection.result(msgid)
        assert rtype == ldap.RES_SEARCH_RESULT
        assert [entry_dn for entry_dn, _ in data] == ["ou=People,dc=example,dc=com"]

        msgid = await connection.add(
            dn, [("objectClass", [b"inetOrgPerson"]), ("uid", [b"four"])]
        )
        four = await connection.result4(msgid, add_ctrls=1, add_intermediates=1)
        assert four[:2] == (ldap.RES_ADD, [])

        msgid = await connection.modify(dn, [(ldap.MOD_REPLACE, "cn", [b"Four"])])
        assert (await connection.result(msgid))[0] == ldap.RES_MODIFY

        msgid = await connection.compare(dn, "uid", b"four")
        with pytest.raises(ldap.COMPARE_TRUE):
            await connection.result3(msgid)

        msgid = await connection.modrdn(dn, "uid=fourth")
        assert (await connection.result(msgid))[0] == ldap.RES_MODRDN

        msgid = await connection.delete("uid=fourth,ou=People,dc=example,dc=com")
        assert (await connection.result(msgid))[0] == ldap.RES_DELETE


async def test_two_tasks_can_each_wait_for_their_own_operation() -> None:
    async with serving_tree() as server, bound(server) as connection:
        first = await connection.search("dc=example,dc=com", ldap.SCOPE_ONELEVEL)
        second = await connection.search(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=jack)"
        )
        collected: dict[int, int] = {}

        async def collect(msgid: int) -> None:
            # Whichever task reads the connection hands the other task its
            # answer, rather than each of them reading for itself.
            rtype, _, _, _ = await connection.result3(msgid)
            collected[msgid] = rtype

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(collect, first)
            task_group.start_soon(collect, second)

        assert collected == {
            first: ldap.RES_SEARCH_RESULT,
            second: ldap.RES_SEARCH_RESULT,
        }


async def test_a_search_can_be_walked_one_entry_at_a_time() -> None:
    async with serving_tree() as server, bound(server) as connection:
        msgid = await connection.search("dc=example,dc=com", ldap.SCOPE_SUBTREE)
        seen = []
        while True:
            rtype, data = await connection.result(msgid, all=ldap.MSG_ONE)
            if rtype == ldap.RES_SEARCH_RESULT:
                assert data == []
                break
            assert rtype == ldap.RES_SEARCH_ENTRY
            assert len(data) == 1
            seen.append(data[0][0])
        assert seen == ["ou=People,dc=example,dc=com", JACK]


async def test_walking_one_entry_at_a_time_waits_for_each() -> None:
    """An entry the server has not sent yet is waited for, not skipped."""

    class SlowServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            for name in ("uid=one", "uid=two"):
                reply(
                    pureldap.LDAPSearchResultEntry(
                        objectName=f"{name},dc=example,dc=com", attributes=[]
                    )
                )
                await anyio.sleep(0)
            return pureldap.LDAPSearchResultDone(resultCode=0)

    async with serving(SlowServer) as server, connected(server) as connection:
        msgid = await connection.search("dc=example,dc=com", ldap.SCOPE_SUBTREE)
        first = await connection.result(msgid, all=ldap.MSG_ONE)
        assert first[0] == ldap.RES_SEARCH_ENTRY
        assert [dn for dn, _ in first[1]] == ["uid=one,dc=example,dc=com"]

        second = await connection.result(msgid, all=ldap.MSG_ONE)
        assert [dn for dn, _ in second[1]] == ["uid=two,dc=example,dc=com"]

        assert (await connection.result(msgid, all=ldap.MSG_ONE))[0] == (
            ldap.RES_SEARCH_RESULT
        )


async def test_entries_already_read_are_handed_over_one_at_a_time() -> None:
    """Waiting for one search reads the answers to another one too."""
    async with serving_tree() as server, bound(server) as connection:
        first = await connection.search("dc=example,dc=com", ldap.SCOPE_SUBTREE)
        second = await connection.search("dc=example,dc=com", ldap.SCOPE_BASE)

        # Collecting the second search reads the first one's entries as well.
        assert (await connection.result3(second))[0] == ldap.RES_SEARCH_RESULT

        rtype, data = await connection.result(first, all=ldap.MSG_ONE)
        assert rtype == ldap.RES_SEARCH_ENTRY
        assert [dn for dn, _ in data] == ["ou=People,dc=example,dc=com"]


async def test_collecting_a_result_nobody_started_is_an_error() -> None:
    async with serving_tree() as server, bound(server) as connection:
        with pytest.raises(ldap.NO_RESULTS_RETURNED):
            await connection.result3()
        with pytest.raises(ldap.PARAM_ERROR):
            await connection.result3(404)


async def test_an_abandoned_operation_is_no_longer_waited_for() -> None:
    async with serving_tree() as server, bound(server) as connection:
        msgid = await connection.search("dc=example,dc=com", ldap.SCOPE_SUBTREE)
        await connection.abandon(msgid)
        with pytest.raises(ldap.PARAM_ERROR):
            await connection.result3(msgid)
        # Abandoning what was never started, or was abandoned already, is quiet.
        await connection.abandon(msgid)

        # Whatever the server had already sent for it arrives with nobody
        # waiting, and is passed over rather than confusing what comes next.
        assert await connection.search_s("dc=example,dc=com", ldap.SCOPE_ONELEVEL)


# Options.


def test_options_are_read_back_as_they_were_set() -> None:
    connection = ldap.initialize("ldap://ldap.example.com")
    connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
    connection.set_option(ldap.OPT_SIZELIMIT, 10)
    connection.set_option(ldap.OPT_TIMELIMIT, 20)
    connection.set_option(ldap.OPT_TIMEOUT, 30)
    connection.set_option(ldap.OPT_NETWORK_TIMEOUT, 40)
    connection.set_option(ldap.OPT_DEREF, ldap.DEREF_ALWAYS)
    connection.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)

    assert connection.get_option(ldap.OPT_PROTOCOL_VERSION) == ldap.VERSION3
    assert connection.get_option(ldap.OPT_SIZELIMIT) == 10
    assert connection.get_option(ldap.OPT_TIMELIMIT) == 20
    assert connection.get_option(ldap.OPT_TIMEOUT) == 30
    assert connection.get_option(ldap.OPT_NETWORK_TIMEOUT) == 40
    assert connection.get_option(ldap.OPT_DEREF) == ldap.DEREF_ALWAYS
    assert connection.get_option(ldap.OPT_REFERRALS) == ldap.OPT_OFF


def test_an_option_this_cannot_act_on_is_refused() -> None:
    connection = ldap.initialize("ldap://ldap.example.com")
    with pytest.raises(ValueError, match="unknown option"):
        connection.set_option(0x6000, 1)
    with pytest.raises(ValueError, match="unknown option"):
        connection.get_option(0x6000)


def test_the_options_that_limit_a_search_are_sent_with_it() -> None:
    connection = ldap.initialize("ldap://ldap.example.com")
    connection.set_option(ldap.OPT_SIZELIMIT, 1)
    connection.set_option(ldap.OPT_TIMELIMIT, 5)
    connection.set_option(ldap.OPT_DEREF, ldap.DEREF_ALWAYS)
    request = connection._search_request(
        "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)", None, 0, -1, 0
    )
    assert request.sizeLimit == 1
    assert request.timeLimit == 5
    assert request.derefAliases == ldap.DEREF_ALWAYS
    # An empty list of attributes is how LDAP asks for all of them.
    assert request.attributes == []


async def test_a_result_that_does_not_arrive_in_time_raises_timeout() -> None:
    async with serving_tree() as server, bound(server) as connection:
        msgid = await connection.search("dc=example,dc=com", ldap.SCOPE_SUBTREE)
        with pytest.raises(ldap.TIMEOUT):
            await connection.result3(msgid, timeout=0)
        # The operation is still there to be collected afterwards.
        assert (await connection.result3(msgid))[0] == ldap.RES_SEARCH_RESULT


async def test_a_connection_can_be_given_a_deadline_to_open_in() -> None:
    async with serving_tree() as server, connected(server) as connection:
        connection.set_option(ldap.OPT_NETWORK_TIMEOUT, 30)
        await connection.simple_bind_s()


# Extended operations.


class WhoAmIServer(ldapserver.LDAPServer):
    """A server that answers the Who am I? request, as OpenLDAP does."""

    async def extendedRequest_whoami(
        self, data: object, reply: ldapserver.Reply
    ) -> pureldap.LDAPExtendedResponse:
        return pureldap.LDAPExtendedResponse(
            resultCode=0,
            responseName=ldap.WHOAMI_OID,
            response=b"dn:" + JACK.encode("ascii"),
        )

    extendedRequest_whoami.oid = ldap.WHOAMI_OID.encode("ascii")  # type: ignore[attr-defined]


async def test_whoami_says_who_the_server_thinks_is_bound() -> None:
    root = make_root()

    def factory() -> ldapserver.BaseLDAPServer:
        server = WhoAmIServer()
        server.factory = root
        return server

    async with serving(factory) as server, bound(server) as connection:
        assert await connection.whoami_s() == "dn:" + JACK


async def test_changing_a_password_uses_the_extended_operation() -> None:
    async with serving_tree() as server:
        async with connected(server) as connection:
            await connection.simple_bind_s(JACK, b"secret")
            name, value = await connection.passwd_s(JACK, None, b"newsecret")
            assert name == ldap.PASSMOD_OID
            assert value is None

        async with connected(server) as changed:
            await changed.simple_bind_s(JACK, b"newsecret")


async def test_a_password_change_the_server_refuses_is_reported() -> None:
    async with serving_tree() as server, bound(server) as connection:
        with pytest.raises(ldap.STRONG_AUTH_REQUIRED):
            await connection.passwd_s(None, None, b"newsecret")


async def test_an_extended_request_can_be_sent_by_message_id() -> None:
    async with serving_tree() as server, connected(server) as connection:
        await connection.simple_bind_s(JACK, b"secret")
        msgid = await connection.passwd(JACK, None, b"another")
        rtype, data, rmsgid, _ = await connection.result3(msgid)
        assert (rtype, data, rmsgid) == (ldap.RES_EXTENDED, [], msgid)


async def test_extop_s_takes_a_request_and_answers_with_the_response() -> None:
    async with serving_tree() as server, connected(server) as connection:
        await connection.simple_bind_s(JACK, b"secret")
        name, value = await connection.extop_s(
            pureldap.LDAPPasswordModifyRequest(userIdentity=JACK, newPasswd=b"third"),
            [],
        )
        assert (name, value) == (ldap.PASSMOD_OID, None)


# Raising TLS.


async def test_starttls_raises_tls_on_the_connection_that_is_already_open() -> None:
    server_context, client_context = tls_pair()
    root = make_root()

    class StartTLSServer(ldapserver.LDAPServer):
        async def handle_LDAPExtendedRequest(
            self,
            request: pureldap.LDAPExtendedRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> None:
            assert request.requestName == pureldap.LDAPStartTLSRequest.oid
            self.start_tls(server_context)
            reply(pureldap.LDAPStartTLSResponse(resultCode=0))

    def factory() -> ldapserver.BaseLDAPServer:
        server = StartTLSServer()
        server.factory = root
        return server

    async with serving(factory) as server:
        async with connected(
            server, f"ldap://localhost:{server.port}", client_context
        ) as connection:
            await connection.start_tls_s()
            await connection.simple_bind_s()
            assert await connection.search_s("dc=example,dc=com", ldap.SCOPE_ONELEVEL)


async def test_starttls_on_a_connection_that_is_gone_reports_the_server_as_down() -> (
    None
):
    async with serving_tree() as server, bound(server) as connection:
        stream = connection._stream
        assert stream is not None
        await stream.aclose()
        with pytest.raises(ldap.SERVER_DOWN):
            await connection.start_tls_s()


async def test_starttls_answered_about_something_else_is_refused() -> None:
    class ImpostorServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPExtendedRequest(
            self,
            request: pureldap.LDAPExtendedRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPExtendedResponse:
            return pureldap.LDAPExtendedResponse(
                resultCode=0, responseName=b"1.2.3.4"
            )

    async with serving(ImpostorServer) as server, connected(server) as connection:
        with pytest.raises(ldap.PROTOCOL_ERROR, match="StartTLS answered to"):
            await connection.start_tls_s()


async def test_a_server_that_writes_past_its_starttls_response_is_refused() -> None:
    async def handle(stream: anyio.abc.ByteStream) -> None:
        async with stream:
            request, _ = pureber.berDecodeObject(
                ldapobject.BERDECODER, await stream.receive()
            )
            assert isinstance(request, pureldap.LDAPMessage)
            answer = pureldap.LDAPMessage(
                pureldap.LDAPStartTLSResponse(resultCode=0), id=request.id
            )
            # The response, and the start of something the client never
            # asked for: the handshake cannot begin behind that.
            await stream.send(answer.toWire() + b"\x30\x84")

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    try:
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(listener.serve, handle)
            async with ldap.initialize(f"ldap://{host}:{port}") as connection:
                with pytest.raises(ldap.PROTOCOL_ERROR, match="past its StartTLS"):
                    await connection.start_tls_s()
            task_group.cancel_scope.cancel()
    finally:
        await anyio.aclose_forcefully(listener)


async def test_an_ldaps_url_connects_with_tls_from_the_start() -> None:
    server_context, client_context = tls_pair()
    async with serving(tree_server(make_root()), server_context) as server:
        async with connected(
            server, f"ldaps://localhost:{server.port}", client_context
        ) as connection:
            await connection.simple_bind_s()
            assert await connection.search_s("dc=example,dc=com", ldap.SCOPE_ONELEVEL)


# What a server can answer that the client has to make sense of.


async def test_a_search_reference_is_handed_back_as_python_ldap_does() -> None:
    class ReferringServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            reply(
                pureldap.LDAPSearchResultReference(
                    uris=[pureber.BEROctetString(b"ldap://elsewhere.example.com/dc=x")]
                )
            )
            return pureldap.LDAPSearchResultDone(resultCode=0)

    async with serving(ReferringServer) as server, connected(server) as connection:
        results = await connection.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE)
        assert results == [(None, ["ldap://elsewhere.example.com/dc=x"])]


async def test_a_search_answered_with_the_wrong_message_is_a_protocol_error() -> None:
    class ConfusedServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPBindResponse:
            return pureldap.LDAPBindResponse(resultCode=0)

    async with serving(ConfusedServer) as server, connected(server) as connection:
        with pytest.raises(ldap.PROTOCOL_ERROR, match="unexpected response"):
            await connection.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE)


async def test_a_compare_that_answers_neither_way_is_a_protocol_error() -> None:
    class AgreeableServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPCompareRequest(
            self,
            request: pureldap.LDAPCompareRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPCompareResponse:
            return pureldap.LDAPCompareResponse(resultCode=0)

    async with serving(AgreeableServer) as server, connected(server) as connection:
        with pytest.raises(ldap.PROTOCOL_ERROR, match="neither true nor false"):
            await connection.compare_s("dc=example,dc=com", "uid", b"jack")


async def test_a_server_that_goes_away_mid_operation_reports_itself_down() -> None:
    class SilentServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> None:
            self._start_anyio_close()

    async with serving(SilentServer) as server, connected(server) as connection:
        # Tracing logs each operation as it is run, which is all it does.
        connection.trace_level = 1
        with pytest.raises(ldap.SERVER_DOWN):
            await connection.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE)


async def test_unbinding_a_connection_the_server_already_dropped_is_quiet() -> None:
    async with serving_tree() as server, bound(server) as connection:
        stream = connection._stream
        assert stream is not None
        # The connection went before the goodbye could be written, which is
        # the one thing that must not turn closing into an error.
        await stream.aclose()


async def test_a_lost_connection_fails_the_operation_waiting_on_it() -> None:
    async with serving_tree() as server, bound(server) as connection:
        msgid = await connection.search("dc=example,dc=com", ldap.SCOPE_SUBTREE)
        stream = connection._stream
        assert stream is not None
        await stream.aclose()
        with pytest.raises(ldap.SERVER_DOWN):
            await connection.result3(msgid)


# Binding with SASL.


class SaslServer(ldapserver.BaseLDAPServer):
    """A server that answers a two-step SASL exchange, as a real one does."""

    challenge = b"<12345.67890@example.com>"

    def __init__(self) -> None:
        super().__init__()
        self.seen: list[tuple[bytes, bytes | None]] = []

    async def handle_LDAPBindRequest(
        self,
        request: pureldap.LDAPBindRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: ldapserver.Reply,
    ) -> pureldap.LDAPBindResponse:
        assert isinstance(request.auth, tuple)
        mechanism, credentials = request.auth
        assert isinstance(mechanism, bytes)
        assert credentials is None or isinstance(credentials, bytes)
        self.seen.append((mechanism, credentials))
        if mechanism == b"EXTERNAL":
            return pureldap.LDAPBindResponse(resultCode=0)
        if credentials is None:
            # Ask for the next step, with the challenge to answer.
            return pureldap.LDAPBindResponse(
                resultCode=14, serverSaslCreds=self.challenge
            )
        if credentials.startswith(b"jack "):
            return pureldap.LDAPBindResponse(resultCode=0)
        return pureldap.LDAPBindResponse(resultCode=49)


async def test_a_sasl_bind_answers_the_server_until_it_is_done() -> None:
    servers: list[SaslServer] = []

    def factory() -> ldapserver.BaseLDAPServer:
        server = SaslServer()
        servers.append(server)
        return server

    async with serving(factory) as server, connected(server) as connection:
        await connection.sasl_interactive_bind_s(
            "", ldap.sasl.cram_md5("jack", "secret")
        )
        # The first request asks for the mechanism, the second answers the
        # challenge the server sent back.
        assert [mechanism for mechanism, _ in servers[0].seen] == [
            b"CRAM-MD5",
            b"CRAM-MD5",
        ]
        assert servers[0].seen[0][1] is None
        answer = servers[0].seen[1][1]
        assert answer is not None and answer.startswith(b"jack ")


async def test_a_sasl_bind_the_server_refuses_is_reported() -> None:
    async with serving(SaslServer) as server, connected(server) as connection:
        with pytest.raises(ldap.INVALID_CREDENTIALS):
            await connection.sasl_interactive_bind_s(
                "", ldap.sasl.cram_md5("jill", "wrong")
            )


async def test_sasl_external_says_the_connection_is_the_identity() -> None:
    servers: list[SaslServer] = []

    def factory() -> ldapserver.BaseLDAPServer:
        server = SaslServer()
        servers.append(server)
        return server

    async with serving(factory) as server, connected(server) as connection:
        await connection.sasl_external_bind_s(authz_id="dn:cn=jack")
        # An empty response is still a response, which is what EXTERNAL
        # sends when it has no name of its own to give.
        assert servers[0].seen == [(b"EXTERNAL", b"dn:cn=jack")]

    async with serving(factory) as server, connected(server) as connection:
        await connection.sasl_non_interactive_bind_s("EXTERNAL")
        assert servers[1].seen == [(b"EXTERNAL", b"")]

    async with serving(factory) as server, connected(server) as connection:
        with pytest.raises(ldap.AUTH_UNKNOWN, match="credentials"):
            await connection.sasl_non_interactive_bind_s("GSSAPI")


async def test_a_sasl_step_by_step_bind_hands_back_the_challenge() -> None:
    async with serving(SaslServer) as server, connected(server) as connection:
        challenge = await connection.sasl_bind_s("", "CRAM-MD5", None)
        assert challenge == SaslServer.challenge
        answer = ldap.sasl.cram_md5("jack", "secret").process(challenge)
        assert await connection.sasl_bind_s("", "CRAM-MD5", answer) is None


async def test_a_step_by_step_bind_the_server_refuses_is_reported() -> None:
    async with serving(SaslServer) as server, connected(server) as connection:
        challenge = await connection.sasl_bind_s("", "CRAM-MD5", None)
        assert challenge is not None
        with pytest.raises(ldap.INVALID_CREDENTIALS):
            await connection.sasl_bind_s("", "CRAM-MD5", b"jill wrong")


async def test_a_mechanism_with_no_answer_to_give_stops_the_bind() -> None:
    async with serving(SaslServer) as server, connected(server) as connection:
        # The base mechanism answers nothing at all, so the exchange the
        # server asks to continue cannot be continued.
        with pytest.raises(ldap.AUTH_UNKNOWN, match="no answer"):
            await connection.sasl_interactive_bind_s(
                "", ldap.sasl.sasl({}, "CRAM-MD5")
            )


def test_the_sasl_mechanisms_answer_as_their_rfcs_say() -> None:
    assert ldap.sasl.plain("jack", "secret", "u:other").process() == (
        b"u:other\x00jack\x00secret"
    )
    # RFC 2195's own worked example.
    digest = ldap.sasl.cram_md5("tim", "tanstaaftanstaaf").process(
        b"<1896.697170952@postoffice.reston.mci.net>"
    )
    assert digest == b"tim b913a602c7eda7a495b4e6e7334d3890"
    assert ldap.sasl.cram_md5("tim", "x").process() is None
    assert ldap.sasl.sasl({}, "MECH").callback(0, "", "", "default") == "default"

    challenge = (
        b'realm="example.com",nonce="OA6MG9tEQGm2hh",qop="auth",'
        b"charset=utf-8,algorithm=md5-sess"
    )
    answer = ldap.sasl.digest_md5("jack", "secret", "u:jack").process(challenge)
    assert answer is not None
    assert b'username="jack"' in answer
    assert b'realm="example.com"' in answer
    assert b'authzid="u:jack"' in answer
    assert b"response=" in answer
    # A mechanism with no name to give of its own, and a challenge with a
    # part that says nothing at all.
    plain_answer = ldap.sasl.digest_md5("jack", "secret").process(
        b'realm="example.com",nonce="OA6MG9tEQGm2hh",nonsense'
    )
    assert plain_answer is not None
    assert b"authzid" not in plain_answer

    # The server proving itself in turn is answered with nothing.
    assert ldap.sasl.digest_md5("jack", "secret").process(b"rspauth=abcdef") == b""
    assert ldap.sasl.digest_md5("jack", "secret").process() is None


# Controls.


async def test_controls_are_sent_as_the_triples_they_encode_to() -> None:
    class ControlServer(ldapserver.BaseLDAPServer):
        """A server that answers with the controls it was sent."""

        seen: list[list[pureldap.Control]] = []

        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            ControlServer.seen.append(list(controls or ()))
            return pureldap.LDAPSearchResultDone(resultCode=0)

    paged = ldap.controls.SimplePagedResultsControl(True, size=2, cookie=b"")
    async with serving(ControlServer) as server, connected(server) as connection:
        await connection.search_ext_s(
            "dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            serverctrls=[paged, ldap.controls.ManageDSAITControl()],
        )
        # A control that was given as a triple already goes as it stands.
        await connection.search_ext_s(
            "dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            serverctrls=[(b"1.2.3", 0, b"raw")],
        )

    # BER writes true as every bit set, which is what the server reads back.
    sent = [
        (oid, bool(criticality), value)
        for oid, criticality, value in ControlServer.seen[0]
    ]
    assert sent == [
        (b"1.2.840.113556.1.4.319", True, paged.encodeControlValue()),
        (b"2.16.840.1.113730.3.4.2", False, None),
    ]
    assert ControlServer.seen[1] == [(b"1.2.3", 0, b"raw")]


async def test_the_controls_a_response_carries_are_read_back() -> None:
    cookie = b"page-2"

    class PagingServer(ldapserver.BaseLDAPServer):
        """A server that answers every request with a control of its own."""

        async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
            # Answer with a paged results control of the server's own.
            answer = ldap.controls.SimplePagedResultsControl(
                False, size=0, cookie=cookie
            )
            await self._send_anyio_write(
                pureldap.LDAPMessage(
                    pureldap.LDAPSearchResultDone(resultCode=0),
                    id=msg.id,
                    controls=[
                        (
                            ldap.CONTROL_PAGEDRESULTS,
                            0,
                            answer.encodeControlValue(),
                        )
                    ],
                ).toWire()
            )

    async with serving(PagingServer) as server, connected(server) as connection:
        msgid = await connection.search_ext(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, serverctrls=[]
        )
        rtype, data, rmsgid, answered = await connection.result3(msgid)
        assert rtype == ldap.RES_SEARCH_RESULT
        assert len(answered) == 1
        control = answered[0]
        assert isinstance(control, ldap.controls.SimplePagedResultsControl)
        assert control.cookie == cookie


def test_a_control_says_how_its_own_value_is_written() -> None:
    from anyldap.ldap.controls import readentry, simple

    # A control with no value at all.
    assert simple.RelaxRulesControl(True).encodeControlValue() is None

    boolean = simple.BooleanControl("1.2.3", True, booleanValue=True)
    read_back = simple.BooleanControl("1.2.3")
    read_back.decodeControlValue(boolean.encodeControlValue())
    assert read_back.booleanValue is True

    number = simple.OctetStringInteger("1.2.3", True, integerValue=42)
    read_number = simple.OctetStringInteger("1.2.3")
    read_number.decodeControlValue(number.encodeControlValue())
    assert read_number.integerValue == 42

    assert simple.ProxyAuthzControl(True, "dn:cn=jack").encodeControlValue() == (
        b"dn:cn=jack"
    )
    identity = simple.AuthorizationIdentityResponseControl()
    identity.decodeControlValue(b"dn:cn=jack")
    assert identity.authzId == "dn:cn=jack"
    assert simple.AuthorizationIdentityRequestControl().controlType == (
        "2.16.840.1.113730.3.4.16"
    )

    # A read-entry control carries the entry the server read for it.
    entry = pureldap.LDAPSearchResultEntry(
        objectName="cn=jack,dc=example,dc=com", attributes=[("cn", ["Jack"])]
    )
    post = readentry.PostReadControl(True, ["cn"])
    assert post.encodeControlValue()
    post.decodeControlValue(entry.toWire())
    assert post.dn == "cn=jack,dc=example,dc=com"
    assert post.entry == {"cn": [b"Jack"]}
    assert readentry.PreReadControl(True, ["cn"]).controlType == ldap.CONTROL_PRE_READ


def test_a_control_that_cannot_be_read_says_which_one_it_was() -> None:
    plain = ldap.controls.LDAPControl("1.2.3", True, controlValue=b"value")
    assert plain.encodeControlValue() == b"value"
    assert (
        ldap.controls.LDAPControl(
            "1.2.3", True, encodedControlValue=b"already"
        ).encodeControlValue()
        == b"already"
    )
    assert ldap.controls.LDAPControl("1.2.3").encodeControlValue() is None
    assert ldap.controls.encode_controls(None) is None
    assert ldap.controls.decode_controls(None) == []
    assert ldap.controls.RequestControlTuples([plain]) == [(b"1.2.3", 1, b"value")]
    assert ldap.controls.ResponseControlTuples([plain]) == [plain]
    assert ldap.controls.RequestControl().encodeControlValue() is None

    # A control nobody registered comes back with the bytes as they were,
    # and one with no value at all is simply there.
    unknown = ldap.controls.decode_controls([(b"1.2.3", 0, b"xyz")])[0]
    assert isinstance(unknown, ldap.controls.LDAPControl)
    assert unknown.controlValue == b"xyz"
    assert ldap.controls.decode_controls([(b"1.2.3", 1, None)])[0].criticality is True
    base = ldap.controls.ResponseControl("1.2.3")
    base.decodeControlValue(b"raw")
    assert base.encodedControlValue == b"raw"

    with pytest.raises(ldap.DECODING_ERROR, match="1.2.840.113556.1.4.319"):
        ldap.controls.decode_controls(
            [(ldap.CONTROL_PAGEDRESULTS, 0, b"not a control value")]
        )


# TLS, as the options describe it.


def test_the_tls_options_describe_the_context_a_connection_is_raised_with(
    tmp_path: object,
) -> None:
    authority = trustme.CA()
    certificate = authority.issue_cert("localhost")
    import pathlib

    assert isinstance(tmp_path, pathlib.Path)
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(authority.cert_pem.bytes())
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(
        certificate.cert_chain_pems[0].bytes() + certificate.private_key_pem.bytes()
    )

    connection = ldap.initialize("ldaps://ldap.example.com")
    assert connection.get_option(ldap.OPT_X_TLS_CTX) is None

    connection.set_option(ldap.OPT_X_TLS_CACERTFILE, str(ca_file))
    connection.set_option(ldap.OPT_X_TLS_CERTFILE, str(cert_file))
    connection.set_option(ldap.OPT_X_TLS_KEYFILE, str(cert_file))
    connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    connection.set_option(ldap.OPT_X_TLS_CIPHER_SUITE, "HIGH")
    connection.set_option(ldap.OPT_X_TLS_PROTOCOL_MIN, ldap.OPT_X_TLS_PROTOCOL_TLS1_2)
    connection.set_option(ldap.OPT_X_TLS_PROTOCOL_MAX, ldap.OPT_X_TLS_PROTOCOL_TLS1_3)
    assert connection.get_option(ldap.OPT_X_TLS_CACERTFILE) == str(ca_file)

    context = connection.get_option(ldap.OPT_X_TLS_CTX)
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == ssl.TLSVersion.TLSv1_3
    # The same context is kept until something says to start again.
    assert connection.get_option(ldap.OPT_X_TLS_CTX) is context
    connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    assert connection.get_option(ldap.OPT_X_TLS_CTX) is not context


def test_asking_for_no_certificate_check_gets_none() -> None:
    connection = ldap.initialize("ldaps://ldap.example.com")
    # Nothing but the check itself is said, so the context is the default
    # one with its checking turned off.
    connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    context = connection.get_option(ldap.OPT_X_TLS_CTX)
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_the_certificates_to_trust_can_be_a_directory() -> None:
    connection = ldap.initialize("ldaps://ldap.example.com")
    connection.set_option(ldap.OPT_X_TLS_CACERTDIR, "/etc/ssl/certs")
    assert isinstance(connection.get_option(ldap.OPT_X_TLS_CTX), ssl.SSLContext)


async def test_a_connection_can_be_made_to_a_socket_in_the_filesystem(
    tmp_path: object,
) -> None:
    import pathlib

    assert isinstance(tmp_path, pathlib.Path)
    path = tmp_path / "ldapi"

    async def handle(stream: anyio.abc.ByteStream) -> None:
        async with stream:
            request, _ = pureber.berDecodeObject(
                ldapobject.BERDECODER, await stream.receive()
            )
            assert isinstance(request, pureldap.LDAPMessage)
            await stream.send(
                pureldap.LDAPMessage(
                    pureldap.LDAPBindResponse(resultCode=0), id=request.id
                ).toWire()
            )

    listener = await anyio.create_unix_listener(path)
    try:
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(listener.serve, handle)
            # The socket is named in the URL the way OpenLDAP writes it.
            uri = f"ldapi://{quote(str(path), safe='')}"
            async with ldap.initialize(uri) as connection:
                assert (await connection.simple_bind_s())[0] == ldap.RES_BIND
            task_group.cancel_scope.cancel()
    finally:
        await anyio.aclose_forcefully(listener)


def test_a_context_that_was_given_is_the_one_that_is_used() -> None:
    given = ssl.create_default_context()
    connection = ldapobject.SimpleLDAPObject(
        "ldaps://ldap.example.com", ssl_context=given
    )
    assert connection.get_option(ldap.OPT_X_TLS_CTX) is given
    other = ssl.create_default_context()
    connection.set_option(ldap.OPT_X_TLS_CTX, other)
    assert connection.get_option(ldap.OPT_X_TLS_CTX) is other


async def test_the_options_raise_tls_on_a_real_connection() -> None:
    server_context, _ = tls_pair()
    import pathlib
    import tempfile

    authority = trustme.CA()
    certificate = authority.issue_cert("localhost")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server_context)

    with tempfile.TemporaryDirectory() as directory:
        ca_file = pathlib.Path(directory) / "ca.pem"
        ca_file.write_bytes(authority.cert_pem.bytes())
        async with serving(tree_server(make_root()), server_context) as server:
            connection = ldap.initialize(f"ldaps://localhost:{server.port}")
            connection.set_option(ldap.OPT_X_TLS_CACERTFILE, str(ca_file))
            async with connection:
                await connection.simple_bind_s()
                assert await connection.search_s(
                    "dc=example,dc=com", ldap.SCOPE_ONELEVEL
                )


# The schema a server publishes.


SUBSCHEMA = {
    "objectClasses": [
        b"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
        b"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn )"
        b" MAY ( userPassword $ description ) )",
        # An object class that names an attribute the schema does not
        # publish, which a server is entitled to do.
        b"( 1.3.6.1.4.1.99999.1 NAME 'partial' SUP top STRUCTURAL"
        b" MAY ( description $ notPublished ) )",
    ],
    "attributeTypes": [
        b"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch"
        b" SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
        b"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
        b"( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name )",
        b"( 2.5.4.13 NAME 'description' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        b"( 2.5.4.35 NAME 'userPassword'"
        b" SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )",
    ],
    "matchingRules": [
        b"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
    ],
    "ldapSyntaxes": [b"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )"],
}


def test_the_schema_says_what_an_entry_must_and_may_have() -> None:
    sub = ldap.schema.SubSchema(SUBSCHEMA)

    person = sub.get_obj(ldap.schema.ObjectClass, "person")
    assert isinstance(person, ldap.schema.ObjectClass)
    assert person.oid == "2.5.6.6"
    assert person.kind == ldap.schema.STRUCTURAL
    assert sorted(person.must) == ["cn", "sn"]
    assert str(person) == "person"
    assert "2.5.6.6" in repr(person)

    top = sub.get_obj(ldap.schema.ObjectClass, "top")
    assert isinstance(top, ldap.schema.ObjectClass)
    assert top.kind == ldap.schema.ABSTRACT

    # An object class is looked up by name, however it is written, or by OID.
    assert sub.get_obj(ldap.schema.ObjectClass, "PERSON") is person
    assert sub.get_obj(ldap.schema.ObjectClass, "2.5.6.6") is person
    assert sub.get_obj(ldap.schema.ObjectClass, "nothing") is None
    with pytest.raises(KeyError):
        sub.get_obj(ldap.schema.ObjectClass, "nothing", raise_keyerror=1)

    # What an entry of a class needs is what the class and its superiors say.
    must, may = sub.attribute_types(["person"])
    assert sorted(a.names[0] for a in must.values()) == ["cn", "objectClass", "sn"]
    assert sorted(a.names[0] for a in may.values()) == ["description", "userPassword"]

    # An object class the schema does not have is passed over, and one that
    # is reached twice is only counted once.
    must, may = sub.attribute_types(["person", "nothing", "top"], raise_keyerror=0)
    assert sorted(a.names[0] for a in must.values()) == ["cn", "objectClass", "sn"]

    assert sub.get_structural_oc(["top", "person"]) == "2.5.6.6"
    assert sub.get_structural_oc(["top"]) is None
    assert len(sub.listall(ldap.schema.ObjectClass)) == 3

    # An attribute the schema does not describe is passed over rather than
    # guessed at.
    must, may = sub.attribute_types(["partial"], raise_keyerror=0)
    assert sorted(a.names[0] for a in may.values()) == ["description"]
    with pytest.raises(KeyError):
        sub.attribute_types(["partial"], raise_keyerror=1)
    assert sub.getoid(ldap.schema.ObjectClass, "unknown") == "unknown"


def test_the_schema_reads_attribute_types_matching_rules_and_syntaxes() -> None:
    sub = ldap.schema.SubSchema(SUBSCHEMA)

    cn = sub.get_obj(ldap.schema.AttributeType, "commonName")
    assert isinstance(cn, ldap.schema.AttributeType)
    assert cn.oid == "2.5.4.3"
    assert cn.names == ("cn", "commonName")
    assert cn.sup == ("name",)
    assert cn.usage == 0

    object_class = sub.get_obj(ldap.schema.AttributeType, "objectClass")
    assert isinstance(object_class, ldap.schema.AttributeType)
    assert object_class.equality == "objectIdentifierMatch"
    assert object_class.syntax == "1.3.6.1.4.1.1466.115.121.1.38"

    # How long a value may be is said next to the syntax, and is not part
    # of the syntax's own name.
    password = sub.get_obj(ldap.schema.AttributeType, "userPassword")
    assert isinstance(password, ldap.schema.AttributeType)
    assert password.syntax == "1.3.6.1.4.1.1466.115.121.1.40"
    assert password.syntax_len == 128
    assert cn.syntax_len is None

    rule = sub.get_obj(ldap.schema.MatchingRule, "caseIgnoreMatch")
    assert isinstance(rule, ldap.schema.MatchingRule)
    assert rule.oid == "2.5.13.2"

    syntax = sub.get_obj(ldap.schema.LDAPSyntax, "1.3.6.1.4.1.1466.115.121.1.15")
    assert isinstance(syntax, ldap.schema.LDAPSyntax)
    assert syntax.desc == "Directory String"
    assert syntax.not_human_readable == 0

    # An attribute of the subentry that is not schema is not read as schema.
    assert ldap.schema.SubSchema({"cn": [b"Subschema"]}).listall(
        ldap.schema.ObjectClass
    ) == []
    # Options on the attribute name do not hide what it is.
    assert (
        len(
            ldap.schema.SubSchema(
                {"objectClasses;binary": SUBSCHEMA["objectClasses"]}
            ).listall(ldap.schema.ObjectClass)
        )
        == 3
    )
    assert ldap.schema.SchemaElement().get_id() is None
    with pytest.raises(NotImplementedError):
        ldap.schema.SchemaElement("( 1.2.3 )")


async def test_the_schema_can_be_read_off_the_connection() -> None:
    class SchemaServer(ldapserver.LDAPServer):
        """A server that publishes a subschema subentry, as a real one does."""

        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            if request.baseObject == b"cn=Subschema":
                reply(
                    pureldap.LDAPSearchResultEntry(
                        objectName="cn=Subschema",
                        attributes=[
                            (key, values) for key, values in SUBSCHEMA.items()
                        ],
                    )
                )
            elif request.baseObject == b"dc=example,dc=com":
                reply(
                    pureldap.LDAPSearchResultEntry(
                        objectName="dc=example,dc=com",
                        attributes=[("subschemaSubentry", [b"cn=Subschema"])],
                    )
                )
            return pureldap.LDAPSearchResultDone(resultCode=0)

    async with serving(SchemaServer) as server, bound(server) as connection:
        assert await connection.search_subschemasubentry_s(
            "dc=example,dc=com"
        ) == "cn=Subschema"
        published = await connection.read_subschemasubentry_s("cn=Subschema")
        assert published is not None
        assert len(published["objectClasses"]) == 3

        sub = await connection.read_schema_s("dc=example,dc=com")
        person = sub.get_obj(ldap.schema.ObjectClass, "person")
        assert isinstance(person, ldap.schema.ObjectClass)
        assert sorted(person.must) == ["cn", "sn"]

        # An entry that names no subschema subentry has no schema to read.
        assert await connection.search_subschemasubentry_s("ou=nothing") is None
        with pytest.raises(ldap.NO_SUCH_OBJECT, match="subschema"):
            await connection.read_schema_s("ou=nothing")


# The pieces that do not need a connection.


def test_values_are_taken_however_they_are_spelled() -> None:
    assert ldapobject._values(None) == []
    assert ldapobject._values("text") == [b"text"]
    assert ldapobject._values(b"bytes") == [b"bytes"]
    assert ldapobject._values(["one", b"two"]) == [b"one", b"two"]


def test_response_controls_are_a_sequence_even_when_there_are_none() -> None:
    assert ldapobject._controls(None) == []
    control: pureldap.Control = (b"1.2.3", None, None)
    assert ldapobject._controls([control]) == [control]


def test_an_error_carries_what_the_server_said() -> None:
    error = ldap.error_for_result(32, b"no such object here")
    assert isinstance(error, ldap.NO_SUCH_OBJECT)
    assert error.args[0] == {
        "desc": "No such object",
        "result": 32,
        "info": "no such object here",
    }
    assert error.info == "no such object here"

    assert ldap.error_for_result(32).info is None

    unknown = ldap.error_for_result(4242, "who knows")
    assert isinstance(unknown, ldap.OTHER)
    assert unknown.args[0]["result"] == 4242

    assert ldap.LDAPError("plain message").info is None
    assert ldap.STRONG_AUTH_NOT_SUPPORTED is ldap.AUTH_METHOD_NOT_SUPPORTED
    assert ldap.ADMIN_LIMIT_EXCEEDED is ldap.ADMINLIMIT_EXCEEDED
    assert issubclass(ldap.NO_UNIQUE_ENTRY, ldap.LDAPError)


def test_filters_escape_what_would_otherwise_be_read_as_syntax() -> None:
    assert ldap.escape_filter_chars("a*b(c)\\d\x00") == r"a\2ab\28c\29\5cd\00"
    assert ldap.escape_filter_chars(b"ab") == "ab"
    assert ldap.escape_filter_chars("a*b", 1) == r"a\2ab"
    assert ldap.escape_filter_chars("a*b", 2) == r"\61\2a\62"
    assert ldap.escape_filter_chars("{}", 1) == r"\7b\7d"
    # Escaped character by character, as python-ldap escapes it.
    assert ldap.escape_filter_chars("é", 1) == r"\e9"
    with pytest.raises(ValueError, match="escape_mode"):
        ldap.escape_filter_chars("a", 3)
    assert (
        ldap.filter_format("(&(cn=%s)(uid=%s))", ["Ba*bs", "jack"])
        == r"(&(cn=Ba\2abs)(uid=jack))"
    )


def test_distinguished_names_come_apart_and_go_back_together() -> None:
    assert ldap.str2dn("cn=foo,dc=example,dc=com") == [
        [("cn", "foo", ldap.AVA_STRING)],
        [("dc", "example", ldap.AVA_STRING)],
        [("dc", "com", ldap.AVA_STRING)],
    ]
    assert ldap.str2dn(b"cn=foo") == [[("cn", "foo", ldap.AVA_STRING)]]
    assert ldap.str2dn(None) == []
    assert ldap.str2dn("") == []

    assert ldap.dn2str(ldap.str2dn("cn=foo,dc=example")) == "cn=foo,dc=example"
    assert ldap.dn2str([[("cn", "a+b", 1), ("sn", "c", 1)]]) == r"cn=a\+b+sn=c"

    assert ldap.explode_dn("cn=foo,dc=example") == ["cn=foo", "dc=example"]
    assert ldap.explode_dn("cn=foo,dc=example", notypes=1) == ["foo", "example"]
    assert ldap.explode_dn("") == []

    assert ldap.explode_rdn("cn=foo+sn=bar") == ["cn=foo", "sn=bar"]
    assert ldap.explode_rdn("cn=foo+sn=bar", notypes=1) == ["foo", "bar"]
    assert ldap.explode_rdn("") == []

    assert ldap.dn.escape_dn_chars("a,b") == r"a\,b"
    assert ldap.is_dn("cn=foo,dc=example") is True
    assert ldap.is_dn("not a dn") is False
    assert ldap.AVA_BINARY != ldap.AVA_NONPRINTABLE


async def test_the_one_entry_a_search_found_is_handed_back() -> None:
    async with serving_tree() as server, bound(server) as connection:
        assert await connection.find_unique_entry(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=jack)", ["cn"]
        ) == (JACK, {"cn": [b"Jack"]})

        with pytest.raises(ldap.NO_UNIQUE_ENTRY):
            await connection.find_unique_entry(
                "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=nobody)"
            )


async def test_the_root_dse_says_what_the_server_holds() -> None:
    class RootDSEServer(ldapserver.LDAPServer):
        """A server that answers for itself, as one holding a tree does."""

        def getRootDSE(
            self, request: pureldap.LDAPSearchRequest, reply: ldapserver.Reply
        ) -> pureldap.LDAPSearchResultDone:
            reply(
                pureldap.LDAPSearchResultEntry(
                    objectName="",
                    attributes=[
                        ("supportedLDAPVersion", ["3"]),
                        ("namingContexts", ["dc=example,dc=com"]),
                    ],
                )
            )
            return pureldap.LDAPSearchResultDone(resultCode=0)

    root = make_root()

    def factory() -> ldapserver.BaseLDAPServer:
        server = RootDSEServer()
        server.factory = root
        return server

    async with serving(factory) as server, bound(server) as connection:
        dse = await connection.read_rootdse_s()
        assert dse["supportedLDAPVersion"] == [b"3"]
        assert await connection.get_naming_contexts() == [b"dc=example,dc=com"]


async def test_a_search_for_attributes_that_are_not_a_list_is_refused() -> None:
    async with serving_tree() as server, bound(server) as connection:
        # Any iterable of names will do, which a mapping of them is.
        names: dict[str, str] = {"ou": "1"}
        assert await connection.search_s(
            "dc=example,dc=com",
            ldap.SCOPE_ONELEVEL,
            attrlist=names,  # type: ignore[arg-type]
        )
        # A bare string is a sequence of characters, and never the list of
        # attributes the caller meant.
        with pytest.raises(TypeError, match="not a string"):
            await connection.search_s(
                "dc=example,dc=com", ldap.SCOPE_ONELEVEL, attrlist="ou"
            )
        with pytest.raises(TypeError, match="expected string in list"):
            await connection.search_s(
                "dc=example,dc=com",
                ldap.SCOPE_ONELEVEL,
                attrlist=[b"ou"],  # type: ignore[list-item]
            )


async def test_what_a_response_said_about_itself_is_on_the_error() -> None:
    async with serving_tree() as server, bound(server) as connection:
        msgid = await connection.search("dc=nowhere,dc=com", ldap.SCOPE_BASE)
        with pytest.raises(ldap.NO_SUCH_OBJECT) as caught:
            await connection.result3(msgid)
        # python-ldap's callers read the message id off the error like this.
        assert caught.value.args[0]["msgid"] == msgid
        assert caught.value.args[0]["msgtype"] == ldap.RES_SEARCH_RESULT
        assert caught.value.args[0]["ctrls"] == []


def test_the_time_and_template_helpers_are_python_ldaps() -> None:
    assert ldap.strf_secs(0) == "19700101000000Z"
    assert ldap.strf_secs(1466947067) == "20160626131747Z"
    assert ldap.strp_secs("19700101000000Z") == 0
    assert ldap.strp_secs("20160626131747Z") == 1466947067
    assert (
        ldap.escape_str(ldap.escape_filter_chars, "(uid=%s)", "foo)bar")
        == "(uid=foo\\29bar)"
    )


def test_names_that_are_not_distinguished_names_are_refused() -> None:
    for value in ["foobar,ou=x", "-cn=foobar", ",cn=foobar", "cn=foobar,", "cn=a,,cn=b"]:
        assert ldap.is_dn(value) is False
        with pytest.raises(ldap.DECODING_ERROR):
            ldap.str2dn(value)
    with pytest.raises(ldap.DECODING_ERROR, match="backslash"):
        ldap.str2dn("cn=foo\\")
    with pytest.raises(ldap.DECODING_ERROR):
        # \ff is not a character, whatever else it is.
        ldap.str2dn(r"cn=\ff")

    # An escape stands for the octets of the value, so the pair that spells
    # a character in UTF-8 is that character, and the value says it is one
    # that had to be written escaped.
    assert ldap.str2dn(r"cn=\c3\a4") == [[("cn", "ä", ldap.AVA_NONPRINTABLE)]]
    assert ldap.str2dn(r"cn=a\, b") == [[("cn", "a, b", ldap.AVA_STRING)]]
    assert ldap.AVA_NULL == 0


def test_a_filter_value_that_is_not_text_is_refused() -> None:
    with pytest.raises(TypeError, match="must be of type str"):
        ldap.escape_filter_chars(["nope"])  # type: ignore[arg-type]


def test_modlists_say_how_an_entry_is_created_and_changed() -> None:
    assert ldap.addModlist({"cn": ["Jack"], "sn": b"Smith", "empty": []}) == [
        ("cn", [b"Jack"]),
        ("sn", [b"Smith"]),
    ]
    assert ldap.addModlist(
        {"cn": ["Jack"], "objectClass": ["top"]}, ["objectclass"]
    ) == [("cn", [b"Jack"])]

    old = {"cn": [b"Jack"], "sn": [b"Smith"], "mail": [b"jack@example.com"], "x": []}
    new = {"cn": [b"Jack"], "sn": [b"Jones"], "title": [b"Boss"], "mail": []}
    # An attribute that changed is deleted and added again, which is how
    # python-ldap says it too.
    assert sorted(ldap.modifyModlist(old, new)) == sorted(
        [
            (ldap.MOD_DELETE, "sn", None),
            (ldap.MOD_ADD, "sn", [b"Jones"]),
            (ldap.MOD_ADD, "title", [b"Boss"]),
            (ldap.MOD_DELETE, "mail", None),
            (ldap.MOD_DELETE, "x", None),
        ]
    )

    ignored = ["sn", "title", "mail", "x"]
    assert ldap.modifyModlist(old, new, ignore_attr_types=ignored) == []
    assert ldap.modifyModlist({"a": [b"one"]}, {}, ignore_oldexistent=1) == []
    assert ldap.modifyModlist({"a": [b"one"]}, {}) == [(ldap.MOD_DELETE, "a", None)]
    assert (
        ldap.modifyModlist(
            {"cn": [b"JACK"]}, {"cn": [b"jack"]}, case_ignore_attr_types=["cn"]
        )
        == []
    )
    assert ldap.modifyModlist({"cn": [b"JACK"]}, {"cn": [b"jack"]}) == [
        (ldap.MOD_DELETE, "cn", None),
        (ldap.MOD_ADD, "cn", [b"jack"]),
    ]
    # A value the caller left out is not a value, and neither is no value.
    assert ldap.modifyModlist({}, {"cn": [None, b"Jack"]}) == [
        (ldap.MOD_ADD, "cn", [b"Jack"])
    ]
    assert ldap.addModlist({"cn": None}) == []
    # An attribute that has no values on either side is nothing to say.
    assert ldap.modifyModlist({}, {"cn": [], "sn": [b"Smith"]}) == [
        (ldap.MOD_ADD, "sn", [b"Smith"])
    ]
    # An attribute that gained a value has changed; one that did not is
    # left out of the modlist, and what follows it is still looked at.
    assert ldap.modifyModlist(
        {"cn": [b"Jack"], "sn": [b"Smith"]},
        {"cn": [b"Jack"], "sn": [b"Smith", b"Jones"]},
    ) == [
        (ldap.MOD_DELETE, "sn", None),
        (ldap.MOD_ADD, "sn", [b"Smith", b"Jones"]),
    ]
    # The attribute is matched however its case is written.
    assert ldap.modifyModlist({"CN": [b"Jack"]}, {"cn": [b"Jack"]}) == []


def test_a_case_insensitive_dict_answers_to_any_spelling() -> None:
    assert len(ldap.cidict.cidict()) == 0

    entry: ldap.cidict.cidict[list[bytes]] = ldap.cidict.cidict(
        {"givenName": [b"Jack"]}
    )
    assert entry["givenname"] == [b"Jack"]
    assert "GIVENNAME" in entry
    assert list(entry) == ["givenName"]
    assert len(entry) == 1

    entry["GIVENNAME"] = [b"Jill"]
    # The spelling it was first written in is the one that is kept.
    assert list(entry.items()) == [("givenName", [b"Jill"])]
    assert repr(entry) == "cidict({'givenName': [b'Jill']})"
    assert entry.has_key("GIVENNAME")
    assert entry.copy() == entry

    entry["sn"] = [b"Smith"]
    del entry["SN"]
    assert list(entry) == ["givenName"]
    with pytest.raises(KeyError):
        entry["missing"]


def test_the_object_python_ldap_hands_back_is_the_one_named_here() -> None:
    assert ldap.LDAPObject is ldapobject.SimpleLDAPObject
    assert ldap.ReconnectLDAPObject is ldapobject.SimpleLDAPObject
    assert isinstance(ldap.initialize("ldap://x"), ldap.SimpleLDAPObject)
