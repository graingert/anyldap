"""Test cases for the anyldap.ldap package, python-ldap's API awaited.

Every connection here is made over a real socket to a real server, so what
is exercised is the wire behaviour rather than a stand-in for it.
"""

import io
import pathlib
import re
import ssl
from collections.abc import AsyncGenerator, Callable, Iterable, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from urllib.parse import quote

import anyio
import anyio.streams.tls
import pytest
import trustme

from anyldap import inmemory, ldap
from anyldap._encoder import to_unicode
from anyldap.ldap import ldapobject
from anyldap.ldap.controls import openldap
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
        connection.referrals = 0
        results = await connection.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE)
        assert results == [(None, ["ldap://elsewhere.example.com/dc=x"])]
        # A continuation is its own kind of message, not an entry, which is
        # what walking a search one message at a time shows.
        msgid = await connection.search("dc=example,dc=com", ldap.SCOPE_SUBTREE)
        rtype, data, _, _ = await connection.result3(msgid, all=0)
        assert rtype == ldap.RES_SEARCH_REFERENCE
        assert data == [(None, ["ldap://elsewhere.example.com/dc=x"])]


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


# Following referrals.


def referring_to(
    uri: str, *, matched: str = "dc=example,dc=com", binds: bool = True
) -> ServerFactory:
    """A server that answers every operation with a referral somewhere else.

    Nothing is looked up: whatever is asked for, the answer is that it is
    over there, which is what a server holding only a referral does. Binds
    are answered rather than referred unless a test asks otherwise, the way
    a real server answers the bind and refers what comes after it.
    """
    referral = [uri]

    class ReferralServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            return pureldap.LDAPSearchResultDone(
                resultCode=10, matchedDN=matched, referral=referral
            )

        async def handle_LDAPCompareRequest(
            self,
            request: pureldap.LDAPCompareRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPCompareResponse:
            return pureldap.LDAPCompareResponse(
                resultCode=10, matchedDN=matched, referral=referral
            )

        async def handle_LDAPBindRequest(
            self,
            request: pureldap.LDAPBindRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPBindResponse:
            if binds:
                return pureldap.LDAPBindResponse(resultCode=0)
            return pureldap.LDAPBindResponse(resultCode=10, referral=referral)

    return ReferralServer


def continuing_to(*uris: str) -> ServerFactory:
    """A server holding one entry, and a continuation for the rest.

    One continuation can name several servers holding the same thing, which
    is why they are all in the one message: whoever follows it takes the
    first that answers.
    """

    class ContinuingServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            reply(
                pureldap.LDAPSearchResultEntry(
                    objectName=b"cn=here,dc=example,dc=com",
                    attributes=[(b"cn", [b"here"])],
                )
            )
            reply(
                pureldap.LDAPSearchResultReference(
                    uris=[pureber.BEROctetString(uri.encode()) for uri in uris]
                )
            )
            return pureldap.LDAPSearchResultDone(resultCode=0)

    return ContinuingServer


async def test_a_search_continuation_is_followed_when_referrals_are_on() -> None:
    """What the other server holds is added to what this search found."""
    async with serving_tree() as away:
        uri = f"{away.uri}/ou=People,dc=example,dc=com??sub"
        async with (
            serving(continuing_to(uri)) as server,
            connected(server) as connection,
        ):
            found = await connection.search_s(
                "dc=example,dc=com", ldap.SCOPE_SUBTREE, attrlist=["cn"]
            )
    names = [dn for dn, _ in found]
    # The entry this server holds, then the continuation itself -- which
    # python-ldap hands back whether or not it followed one -- then what
    # following it found.
    assert names[0] == "cn=here,dc=example,dc=com"
    assert names[1] is None
    assert JACK in names


async def test_a_search_continuation_is_left_alone_when_referrals_are_off() -> None:
    async with serving_tree() as away:
        uri = f"{away.uri}/ou=People,dc=example,dc=com??sub"
        async with (
            serving(continuing_to(uri)) as server,
            connected(server) as connection,
        ):
            connection.referrals = 0
            found = await connection.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE)
    assert [dn for dn, _ in found] == ["cn=here,dc=example,dc=com", None]


async def test_a_result_that_is_only_a_referral_is_made_again_where_it_points() -> None:
    """A search answered with a referral is run at the server it names."""
    async with serving_tree() as away:
        async with (
            serving(referring_to(f"{away.uri}/{JACK}")) as server,
            connected(server) as connection,
        ):
            found = await connection.search_s(
                "dc=nowhere,dc=com", ldap.SCOPE_BASE, attrlist=["uid"]
            )
    assert found == [(JACK, {"uid": [b"jack"]})]


async def test_a_referral_that_names_a_dn_asks_about_that_one() -> None:
    """A referral to another entry moves the operation to it, not just the server."""
    async with serving_tree() as away:
        async with (
            serving(referring_to(f"{away.uri}/{JACK}")) as server,
            connected(server) as connection,
        ):
            assert await connection.compare_s("dc=nowhere,dc=com", "uid", b"jack")


async def test_a_continuation_takes_the_first_server_that_answers() -> None:
    """One continuation can name several, and a dead one is passed over."""
    async with serving_tree() as away:
        dead = "ldap://127.0.0.1:1/dc=example,dc=com??sub"
        alive = f"{away.uri}/ou=People,dc=example,dc=com??sub"
        async with (
            serving(continuing_to(dead, alive)) as server,
            connected(server) as connection,
        ):
            found = await connection.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE)
    assert JACK in [dn for dn, _ in found]


async def test_a_continuation_nobody_answers_leaves_the_search_as_it_was() -> None:
    async with (
        serving(continuing_to("ldap://127.0.0.1:1/dc=example,dc=com??sub")) as server,
        connected(server) as connection,
    ):
        found = await connection.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE)
    assert [dn for dn, _ in found] == ["cn=here,dc=example,dc=com", None]


async def test_a_continuation_that_fails_where_it_points_fails_the_search() -> None:
    """What the other server says about the rest of the search is the answer."""
    async with serving_tree() as away:
        uri = f"{away.uri}/dc=nowhere,dc=com??sub"
        async with (
            serving(continuing_to(uri)) as server,
            connected(server) as connection,
        ):
            with pytest.raises(ldap.NO_SUCH_OBJECT):
                await connection.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE)


async def test_a_followed_search_can_be_walked_one_message_at_a_time() -> None:
    """What following a continuation found is handed out like the rest."""
    async with serving_tree() as away:
        uri = f"{away.uri}/ou=People,dc=example,dc=com??sub"
        async with (
            serving(continuing_to(uri)) as server,
            connected(server) as connection,
        ):
            msgid = await connection.search("dc=example,dc=com", ldap.SCOPE_SUBTREE)
            seen = []
            while True:
                rtype, data, _, _ = await connection.result3(msgid, all=0)
                if rtype == ldap.RES_SEARCH_RESULT:
                    break
                seen.append((rtype, data[0][0]))
    assert seen[0] == (ldap.RES_SEARCH_ENTRY, "cn=here,dc=example,dc=com")
    assert seen[1] == (ldap.RES_SEARCH_REFERENCE, None)
    # The entries from the other server arrive after the continuation that
    # said where they were, which is the order they were asked for in.
    assert JACK in [dn for _, dn in seen[2:]]


async def test_a_referral_that_names_no_dn_asks_about_the_same_entry() -> None:
    """RFC 4511 section 4.1.10: an absent DN means the one already asked for."""
    async with serving_tree() as away:
        async with (
            serving(referring_to(away.uri)) as server,
            connected(server) as connection,
        ):
            assert await connection.compare_s(JACK, "uid", b"jack")
            assert not await connection.compare_s(JACK, "uid", b"jill")


async def test_a_referral_is_handed_to_the_caller_when_it_cannot_be_reached() -> None:
    """Nobody is listening there, so the referral is the answer after all."""
    async with serving_tree() as away:
        uri = away.uri
    async with (
        serving(referring_to(uri, matched="dc=com")) as server,
        connected(server) as connection,
    ):
        with pytest.raises(ldap.REFERRAL) as caught:
            await connection.search_s("dc=example,dc=com", ldap.SCOPE_BASE)
    assert caught.value.args[0]["info"] == f"Referral:\n{uri}"
    assert caught.value.args[0]["matched"] == "dc=com"
    assert caught.value.args[0]["result"] == 10


async def test_a_referral_is_left_alone_when_referrals_are_off() -> None:
    async with (
        serving(referring_to("ldap://elsewhere.example.com")) as server,
        connected(server) as connection,
    ):
        connection.referrals = 0
        with pytest.raises(ldap.REFERRAL):
            await connection.search_s("dc=example,dc=com", ldap.SCOPE_BASE)


async def test_a_referral_that_points_back_at_itself_stops() -> None:
    """A server that refers to itself is followed only so far.

    The listener is made first so that the server can be told where it is,
    which is what lets the referral it answers with point at itself.
    """
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    factory = referring_to(f"ldap://{host}:{port}")
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve, listener, factory)
        try:
            async with connected(Serving(host, port)) as connection:
                with pytest.raises(ldap.REFERRAL_LIMIT_EXCEEDED, match="stopped after"):
                    await connection.search_s("dc=example,dc=com", ldap.SCOPE_BASE)
        finally:
            task_group.cancel_scope.cancel()


async def test_a_bind_is_never_followed_to_where_a_referral_points() -> None:
    """A referral says where to look, not whose password may be sent there."""
    async with serving_tree() as away:
        async with (
            serving(referring_to(away.uri, binds=False)) as server,
            connected(server) as connection,
        ):
            with pytest.raises(ldap.REFERRAL):
                await connection.simple_bind_s(JACK, b"secret")


async def test_the_referrals_option_is_the_boolean_libldap_keeps() -> None:
    connection = ldap.initialize("ldap://x")
    # Chasing is on to begin with, and on reads back as -1 however it was
    # asked for, which is what libldap answers.
    assert connection.referrals == -1
    assert connection.get_option(ldap.OPT_REFERRALS) == -1
    connection.referrals = 0
    assert connection.get_option(ldap.OPT_REFERRALS) == 0
    connection.set_option(ldap.OPT_REFERRALS, 1)
    assert connection.referrals == -1
    # The hop limit is libldap's own and cannot be read or set, here either.
    with pytest.raises(ValueError, match="unknown option"):
        connection.get_option(ldap.OPT_REFHOPLIMIT)
    with pytest.raises(ValueError, match="unknown option"):
        connection.set_option(ldap.OPT_REFHOPLIMIT, 3)


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
        # A mechanism that has to be told a name and a password cannot be
        # bound with by a caller who says nothing.
        with pytest.raises(ldap.AUTH_UNKNOWN, match="credentials"):
            await connection.sasl_non_interactive_bind_s("CRAM-MD5")


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


def test_a_control_that_carries_a_filter_writes_the_filter_out() -> None:
    from anyldap.ldap.controls import libldap

    # RFC 4528: do the operation only if the entry matches.
    assertion = libldap.AssertionControl()
    assert assertion.controlType == ldap.CONTROL_ASSERT
    assert assertion.criticality is True
    assert assertion.encodeControlValue() == b"\x87\x0bobjectClass"

    # RFC 3876: a sequence of the filters whose values to send back.
    matched = libldap.MatchedValuesControl(filterstr="(cn=jack)")
    assert matched.controlType == ldap.CONTROL_VALUESRETURNFILTER
    assert matched.criticality is False
    assert matched.encodeControlValue() == b"0\x0c\xa3\n\x04\x02cn\x04\x04jack"

    # The paged results control is here too, under python-ldap's other name.
    assert libldap.SimplePagedResultsControl is ldap.controls.SimplePagedResultsControl


def test_a_sort_control_says_what_to_sort_by_and_how_it_went() -> None:
    from anyldap.ldap.controls import sss

    # One rule on its own is taken as though it were a list of one.
    assert sss.SSSRequestControl(ordering_rules="cn").ordering_rules == ["cn"]

    control = sss.SSSRequestControl(
        criticality=True, ordering_rules=["-uidNumber", "cn:caseIgnoreMatch"]
    )
    assert control.controlType == ldap.CONTROL_SORTREQUEST
    # The same bytes python-ldap writes, except that BER says true with
    # every bit set where python-ldap writes it as one.
    assert control.encodeControlValue() == (
        b"0'"
        b"0\x0e\x04\tuidNumber\x81\x01\xff"
        b"0\x15\x04\x02cn\x80\x0fcaseIgnoreMatch"
    )
    assert sss.SSSRequestControl().encodeControlValue() == b"0\x00"

    with pytest.raises(ValueError, match="empty attribute"):
        sss.SSSRequestControl(ordering_rules=["-:caseIgnoreMatch"])
    with pytest.raises(ValueError, match="syntax for ordering rule"):
        sss.SSSRequestControl(ordering_rules=["cn:a:b"])

    # The response says how the sort went, and names the attribute that
    # stopped it when one did.
    answer = sss.SSSResponseControl()
    answer.decodeControlValue(pureber.BERSequence([pureber.BEREnumerated(0)]).toWire())
    assert answer.result == 0
    assert answer.result_code == "success"
    assert answer.attribute_type_error is None

    refused = sss.SSSResponseControl()
    refused.decodeControlValue(
        pureber.BERSequence(
            [
                pureber.BEREnumerated(16),
                pureber.BEROctetString("cn", tag=pureber.CLASS_CONTEXT | 0x00),
            ]
        ).toWire()
    )
    assert refused.result_code == "noSuchAttribute"
    assert refused.attribute_type_error == "cn"
    assert ldap.controls.KNOWN_RESPONSE_CONTROLS[ldap.CONTROL_SORTRESPONSE] is (
        sss.SSSResponseControl
    )


def test_the_password_policy_control_reads_what_the_server_warned() -> None:
    from anyldap.ldap.controls import ppolicy

    control = ppolicy.PasswordPolicyControl()
    assert control.controlType == ldap.CONTROL_PASSWORDPOLICYREQUEST
    assert control.encodeControlValue() is None

    # SEQUENCE { warning [0] { graceAuthNsRemaining [1] INTEGER 2 } }
    control.decodeControlValue(b"\x30\x05\xa0\x03\x81\x01\x02")
    assert control.graceAuthNsRemaining == 2
    assert control.timeBeforeExpiration is None

    # SEQUENCE { warning [0] { timeBeforeExpiration [0] INTEGER 50 } }
    control = ppolicy.PasswordPolicyControl()
    control.decodeControlValue(b"\x30\x05\xa0\x03\x80\x01\x32")
    assert control.timeBeforeExpiration == 50
    assert control.graceAuthNsRemaining is None

    # SEQUENCE { error [1] ENUMERATED 0 }, which is passwordExpired.
    control = ppolicy.PasswordPolicyControl()
    control.decodeControlValue(b"\x30\x03\x81\x01\x00")
    assert control.error == 0

    # A server may warn and refuse in the one answer, and anything else it
    # sends alongside is passed over.
    control = ppolicy.PasswordPolicyControl()
    control.decodeControlValue(b"\x30\x0b\xa0\x03\x81\x01\x02\x81\x01\x01\x82\x01\x07")
    assert control.graceAuthNsRemaining == 2
    assert control.error == 1

    assert ldap.controls.KNOWN_RESPONSE_CONTROLS[
        ldap.CONTROL_PASSWORDPOLICYRESPONSE
    ] is (ppolicy.PasswordPolicyControl)


class Counting(openldap.SearchNoOpMixIn, ldapobject.SimpleLDAPObject):
    """A connection that can ask how much a search would have found."""


def noop_answer(controls: list[pureldap.Control] | None) -> ServerFactory:
    """A server that answers a search with these controls and nothing else."""

    class NoOpServer(ldapserver.BaseLDAPServer):
        async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
            code = 0 if controls else 3
            await self._send_anyio_write(
                pureldap.LDAPMessage(
                    pureldap.LDAPSearchResultDone(resultCode=code),
                    id=msg.id,
                    controls=controls,
                ).toWire()
            )

    return NoOpServer


async def test_a_noop_search_counts_what_it_would_have_found() -> None:
    # SEQUENCE { resultCode, numSearchResults, numSearchContinuations }
    counted = pureber.BERSequence(
        [pureber.BEREnumerated(0), pureber.BERInteger(3), pureber.BERInteger(1)]
    ).toWire()
    factory = noop_answer(
        [(openldap.SEARCH_NOOP_OID, 0, counted), (b"1.2.3", 0, b"other")]
    )
    async with serving(factory) as server:
        async with Counting(server.uri) as connection:
            assert await connection.noop_search_st("dc=example,dc=com") == (3, 1)

    # A server that says nothing about it leaves the numbers unknown.
    async with serving(noop_answer([])) as server:
        async with Counting(server.uri) as connection:
            with pytest.raises(ldap.TIMELIMIT_EXCEEDED):
                await connection.noop_search_st("dc=example,dc=com")
            # The search was abandoned on the way out, and is forgotten.
            assert connection._pending == {}

    async with serving(noop_answer([(b"1.2.3", 0, b"other")])) as server:
        async with Counting(server.uri) as connection:
            assert await connection.noop_search_st("dc=example,dc=com") == (None, None)


def test_a_noop_control_reads_the_numbers_the_server_sent() -> None:
    control = openldap.SearchNoOpControl(criticality=True)
    assert control.criticality is True
    assert control.encodeControlValue() is None
    control.decodeControlValue(
        pureber.BERSequence(
            [pureber.BEREnumerated(0), pureber.BERInteger(7), pureber.BERInteger(2)]
        ).toWire()
    )
    assert control.resultCode == 0
    assert control.numSearchResults == 7
    assert control.numSearchContinuations == 2


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
                found = await connection.search_s(
                    "dc=example,dc=com", ldap.SCOPE_ONELEVEL
                )
            assert found


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


# What the server publishes: the schema, and the entry's own name, which
# is not schema and is passed over.
PUBLISHED = dict(SUBSCHEMA, cn=[b"Subschema"])


def test_the_schema_says_what_an_entry_must_and_may_have() -> None:
    sub = ldap.schema.SubSchema(SUBSCHEMA)

    person = sub.get_obj(ldap.schema.ObjectClass, "person")
    assert isinstance(person, ldap.schema.ObjectClass)
    assert person.oid == "2.5.6.6"
    assert person.kind == ldap.schema.STRUCTURAL
    assert sorted(person.must) == ["cn", "sn"]
    # A definition writes itself back out the way python-ldap writes it.
    assert str(person) == (
        "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn )"
        " MAY ( userPassword $ description ) )"
    )
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
    # Sub-types are dropped before looking a name up, and a name the schema
    # does not describe is made something of only when asked.
    assert sub.getoid(ldap.schema.AttributeType, "cn;lang-en") == "2.5.4.3"
    with pytest.raises(KeyError, match="No registered AttributeType-OID"):
        sub.getoid(ldap.schema.AttributeType, "nothing", raise_keyerror=1)


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


def schema_server() -> ServerFactory:
    """A server that publishes a subschema subentry, as a real one does."""

    class SchemaServer(ldapserver.LDAPServer):
        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            if request.baseObject == b"cn=Subschema":
                asked = [to_unicode(name) for name in request.attributes]
                reply(
                    pureldap.LDAPSearchResultEntry(
                        objectName="cn=Subschema",
                        attributes=[
                            (key, values)
                            for key, values in PUBLISHED.items()
                            if key == "cn" or not asked or key in asked
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

    return SchemaServer


async def test_the_schema_can_be_read_off_the_connection() -> None:
    async with serving(schema_server()) as server, bound(server) as connection:
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


def test_every_error_says_which_result_code_it_stands_for() -> None:
    # errnum is the name python-ldap gives it, on the class and on what is
    # raised.
    assert ldap.NO_SUCH_OBJECT.errnum == 32
    assert ldap.LDAPError.errnum is None
    try:
        raise ldap.INVALID_CREDENTIALS({"desc": "x"})
    except ldap.LDAPError as raised:
        assert raised.errnum == 49

    # A read that found no one entry is a kind of "no such object", which
    # is what python-ldap makes it as well.
    assert issubclass(ldap.NO_UNIQUE_ENTRY, ldap.NO_SUCH_OBJECT)
    assert ldap.NO_UNIQUE_ENTRY.errnum == 32
    # The code still belongs to the error that is named for it.
    assert isinstance(ldap.error_for_result(32, ""), ldap.NO_SUCH_OBJECT)
    assert ldapobject.NO_UNIQUE_ENTRY is ldap.NO_UNIQUE_ENTRY

    # An error of your own that stands for no result code takes none.
    class Mine(ldap.LDAPError):
        """Something this caller raises, which no server ever sends."""

    assert Mine.errnum is None
    assert isinstance(ldap.error_for_result(49, ""), ldap.INVALID_CREDENTIALS)


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
    assert issubclass(ldap.ReconnectLDAPObject, ldapobject.SimpleLDAPObject)
    assert isinstance(ldap.initialize("ldap://x"), ldap.SimpleLDAPObject)


# LDAP URLs, as RFC 4516 writes them.


def test_a_url_says_where_a_server_is_and_what_to_ask_it() -> None:
    url = ldap.ldapurl.LDAPUrl(
        "ldap://localhost:1389/dc=example,dc=com?cn,sn?sub?"
        + quote("(objectClass=*)")
        + "?!bindname="
        + quote("cn=admin,dc=example,dc=com")
        + ",X-BINDPW=secret"
    )
    assert url.urlscheme == "ldap"
    assert url.hostport == "localhost:1389"
    assert url.dn == "dc=example,dc=com"
    assert url.attrs == ["cn", "sn"]
    assert url.scope == ldap.ldapurl.LDAP_SCOPE_SUBTREE
    assert url.filterstr == "(objectClass=*)"
    assert url.who == "cn=admin,dc=example,dc=com"
    assert url.cred == "secret"

    # And it writes back out to something that says the same thing again.
    assert ldap.ldapurl.LDAPUrl(url.unparse()) == url
    assert str(url) == url.unparse()
    assert "LDAPUrl" in repr(url)
    assert url != ldap.ldapurl.LDAPUrl("ldap:///")
    assert url != "not a url"
    assert (url == "not a url") is False


def test_what_is_and_is_not_a_url() -> None:
    assert ldap.ldapurl.isLDAPUrl("LDAPI://%2Frun%2Fldap.sock")
    assert not ldap.ldapurl.isLDAPUrl(" ldap://space.example")
    assert ldap.ldapurl.ldapUrlEscape("dc=x,dc=y/z") == "dc%3Dx%2Cdc%3Dy%2Fz"
    with pytest.raises(ValueError, match="does not seem to be a LDAP URL"):
        ldap.ldapurl.LDAPUrl("http://example.com")
    with pytest.raises(ValueError, match="Invalid search scope"):
        ldap.ldapurl.LDAPUrl("ldap:///??nowhere")


def test_a_url_is_read_however_much_of_it_is_written() -> None:
    LDAPUrl = ldap.ldapurl.LDAPUrl

    # Nothing after the host at all.
    bare = LDAPUrl("ldap://localhost")
    assert (bare.hostport, bare.dn, bare.attrs, bare.scope) == (
        "localhost",
        "",
        None,
        None,
    )
    assert bare.filterstr is None
    assert bare.extensions is not None and len(bare.extensions) == 0

    # A question mark before any slash leaves the DN empty.
    assert LDAPUrl("ldap://localhost?cn").attrs == ["cn"]
    # An empty filter field is no filter at all.
    assert LDAPUrl("ldap:///???").filterstr is None
    # An extensions field that is there and says nothing is not the same as
    # a URL that has no extensions field.
    assert LDAPUrl("ldap:///????").extensions is None
    assert LDAPUrl("ldap:///????").who is None


def test_a_url_is_written_out_the_way_python_ldap_writes_it() -> None:
    LDAPUrl = ldap.ldapurl.LDAPUrl

    assert LDAPUrl("ldap://localhost/dc=example,dc=com").unparse() == (
        "ldap://localhost/dc%3Dexample%2Cdc%3Dcom???"
    )
    assert LDAPUrl(
        "ldap://localhost/dc=example,dc=com?cn?one?(cn=jack)?bindname=cn=root"
    ).unparse() == (
        "ldap://localhost/dc%3Dexample%2Cdc%3Dcom?cn?one?%28cn%3Djack%29"
        "?bindname=cn%3Droot"
    )

    # The socket an ldapi URL names has slashes, so it is escaped.
    socket = LDAPUrl(urlscheme="ldapi", hostport="/tmp/ldapi")
    assert socket.initializeUrl() == "ldapi://%2Ftmp%2Fldapi"
    assert socket.unparse() == "ldapi://%2Ftmp%2Fldapi/???"
    assert LDAPUrl("ldap://localhost").initializeUrl() == "ldap://localhost"

    assert LDAPUrl("ldap:///dc=x").htmlHREF() == (
        '<a href="ldap:///dc%3Dx???">ldap:///dc%3Dx???</a>'
    )
    assert LDAPUrl("ldap:///dc=x").htmlHREF(
        urlPrefix="/go?", hrefText="there", hrefTarget="_blank"
    ) == '<a target="_blank" href="/go?ldap:///dc%3Dx???">there</a>'


def test_what_a_url_did_not_say_is_filled_in_from_the_defaults() -> None:
    url = ldap.ldapurl.LDAPUrl("ldap://localhost/dc=example,dc=com")
    url.applyDefaults({"scope": ldap.ldapurl.LDAP_SCOPE_BASE, "hostport": "other"})
    assert url.scope == ldap.ldapurl.LDAP_SCOPE_BASE
    # What the URL did say is left alone.
    assert url.hostport == "localhost"


def test_the_bind_dn_a_url_carries_is_an_extension_underneath() -> None:
    url = ldap.ldapurl.LDAPUrl("ldap:///", who="cn=root", cred="secret")
    assert url.extensions is not None
    assert url.extensions["bindname"].exvalue == "cn=root"
    assert url.who == "cn=root"

    url.who = None
    assert url.who is None
    assert "bindname" not in url.extensions
    # Deleting one that was never there is quiet, as is deleting from a URL
    # whose extensions field was empty.
    del url.who
    empty = ldap.ldapurl.LDAPUrl("ldap:///????")
    del empty.who
    assert empty.who is None
    # Giving one to a URL that said it had none starts the field off.
    empty.who = "cn=root"
    assert empty.who == "cn=root"

    # An extension the URL names with no value at all answers with none.
    assert ldap.ldapurl.LDAPUrl("ldap:///????bindname").who is None
    with pytest.raises(AttributeError, match="no attribute"):
        url.nonesuch

    # Anything that is not one of those is an ordinary attribute.
    url.hostport = "localhost"
    assert url.hostport == "localhost"
    del url.hostport
    assert not hasattr(url, "hostport")


def test_the_extensions_of_a_url_are_a_mapping_of_their_own() -> None:
    LDAPUrlExtension = ldap.ldapurl.LDAPUrlExtension
    LDAPUrlExtensions = ldap.ldapurl.LDAPUrlExtensions

    critical = LDAPUrlExtension("!bindname=cn=root")
    assert (critical.critical, critical.extype, critical.exvalue) == (
        1,
        "bindname",
        "cn=root",
    )
    assert critical.unparse() == "!bindname=cn%3Droot"
    assert str(critical) == critical.unparse()
    assert "LDAPUrlExtension" in repr(critical)

    # An extension with no value at all, and one parsed from nothing.
    assert LDAPUrlExtension("startTLS").unparse() == "startTLS"
    nothing = LDAPUrlExtension("  ")
    assert (nothing.extype, nothing.exvalue) == (None, None)

    assert critical == LDAPUrlExtension("!bindname=cn=root")
    assert critical != LDAPUrlExtension("bindname=cn=root")
    assert critical != "not an extension"
    assert (critical == "not an extension") is False

    extensions = LDAPUrlExtensions({"bindname": critical})
    assert extensions["bindname"] is critical
    assert list(extensions) == ["bindname"]
    assert len(extensions) == 1
    assert str(extensions) == "!bindname=cn%3Droot"
    assert extensions.unparse() == "!bindname=cn%3Droot"
    assert "LDAPUrlExtensions" in repr(extensions)
    assert extensions == LDAPUrlExtensions({"bindname": critical})
    assert extensions != LDAPUrlExtensions()
    assert extensions != {"bindname": critical}
    assert (extensions == {"bindname": critical}) is False

    # It is keyed by the type of what is put in it, and says so otherwise.
    with pytest.raises(TypeError, match="must be LDAPUrlExtension"):
        extensions["bindname"] = "cn=root"  # type: ignore[assignment]
    with pytest.raises(ValueError, match="does not match extension type"):
        extensions["other"] = critical

    del extensions["bindname"]
    assert len(extensions) == 0
    # An empty extension between two commas is passed over.
    extensions.parse("bindname=cn=root,,X-BINDPW=secret")
    assert sorted(extensions) == ["X-BINDPW", "bindname"]


# LDIF, as RFC 2849 writes it.


def written(dn: str, record: object, **kwargs: object) -> str:
    """One record, as ldap.ldif writes it."""
    out = io.StringIO()
    writer = ldap.ldif.LDIFWriter(out, **kwargs)  # type: ignore[arg-type]
    writer.unparse(dn, record)  # type: ignore[arg-type]
    assert writer.records_written == 1
    return out.getvalue()


def parsed(
    text: str, **kwargs: object
) -> list[tuple[str, "ldap.ldif.ParsedEntry"]]:
    """The entry records some LDIF holds."""
    records = ldap.ldif.LDIFRecordList(io.StringIO(text), **kwargs)  # type: ignore[arg-type]
    records.parse()
    return records.all_records


def test_an_entry_is_written_and_read_back_the_way_python_ldap_writes_it() -> None:
    text = written("cn=x,cn=y,cn=z", {"b": [b"two"], "a": [b"one", b"three"]})
    # The attributes come out sorted, and the record ends with a blank line.
    assert text == "dn: cn=x,cn=y,cn=z\na: one\na: three\nb: two\n\n"
    assert parsed(text) == [
        ("cn=x,cn=y,cn=z", {"a": [b"one", b"three"], "b": [b"two"]})
    ]


def test_a_value_that_cannot_be_written_as_it_stands_is_base64() -> None:
    # A leading space, a NUL, a newline and anything above ASCII all have to
    # be encoded; so does any attribute the caller names.
    assert written("dc=x", {"a": [b" lead"]}) == "dn: dc=x\na:: IGxlYWQ=\n\n"
    assert written("dc=x", {"a": [b"tail "]}) == "dn: dc=x\na:: dGFpbCA=\n\n"
    assert written("dc=x", {"a": [b"a\nb"]}) == "dn: dc=x\na:: YQpi\n\n"
    assert written("dc=x", {"a": [b"caf\xc3\xa9"]}) == "dn: dc=x\na:: Y2Fmw6k=\n\n"
    assert written("dc=x", {"a": [b"plain"]}, base64_attrs=["A"]) == (
        "dn: dc=x\na:: cGxhaW4=\n\n"
    )
    # A DN that is not ASCII is written as UTF-8, base64-encoded.
    assert written("cn=Ströder", {}) == "dn:: Y249U3Ryw7ZkZXI=\n\n"
    assert parsed("dn:: Y249U3Ryw7ZkZXI=\n\n") == [("cn=Ströder", {})]


def test_a_long_line_is_folded_and_unfolded_again() -> None:
    text = written("dc=x", {"a": [b"z" * 200]}, cols=20)
    assert all(len(line) <= 20 for line in text.splitlines())
    assert all(line.startswith(" ") for line in text.splitlines()[2:-1])
    assert parsed(text) == [("dc=x", {"a": [b"z" * 200]})]


def test_the_line_separator_is_the_one_that_was_asked_for() -> None:
    text = written("dc=x", {"a": [b"one"]}, line_sep="\r\n")
    assert text == "dn: dc=x\r\na: one\r\n\r\n"
    # Either ending is read back, whichever it was written with.
    assert parsed(text) == [("dc=x", {"a": [b"one"]})]


def test_a_change_record_is_written_the_way_modify_would_be_called() -> None:
    modify = [
        (ldap.MOD_REPLACE, "a", [b"one"]),
        (ldap.MOD_DELETE, "b", None),
    ]
    assert written("dc=x", modify) == (
        "dn: dc=x\nchangetype: modify\nreplace: a\na: one\n-\ndelete: b\n-\n\n"
    )
    add = [("a", [b"one"]), ("b", [b"two"])]
    assert written("dc=x", add) == (
        "dn: dc=x\nchangetype: add\na: one\nb: two\n\n"
    )
    # Anything else is neither, and says so.
    with pytest.raises(ValueError, match="wrong length"):
        written("dc=x", [("a",)])
    with pytest.raises(ValueError, match="must be dictionary or list"):
        written("dc=x", "a: one")


def test_a_change_record_is_read_back_as_the_modifications_it_describes() -> None:
    text = (
        "version: 1\n\n"
        "dn: dc=x\n"
        "control: 1.2.3 true value\n"
        "control: 1.2.4 false\n"
        "changetype: modify\n"
        "replace: a\na: one\na: two\n-\n"
        "increment: n\nn: 1\n-\n"
        "delete: b\n-\n\n"
    )
    changes = ldap.ldif.LDIFRecordList(io.StringIO(text))
    changes.parse_change_records()
    assert changes.version == 1
    assert changes.all_modify_changes == [
        (
            "dc=x",
            [
                (ldap.MOD_REPLACE, "a", [b"one", b"two"]),
                (ldap.MOD_INCREMENT, "n", [b"1"]),
                (ldap.MOD_DELETE, "b", None),
            ],
            None,
        )
    ]
    assert changes.changetype_counter["modify"] == 1


def test_a_change_record_that_is_not_a_modify_is_passed_over() -> None:
    text = "dn: dc=x\nchangetype: add\na: one\n\ndn: dc=y\nchangetype: delete\n\n"
    changes = ldap.ldif.LDIFRecordList(io.StringIO(text))
    changes.parse_change_records()
    assert changes.all_modify_changes == []
    assert changes.changetype_counter["add"] == 1
    assert changes.changetype_counter["delete"] == 1
    # A record with no changetype at all is counted under no changetype.
    changes = ldap.ldif.LDIFRecordList(io.StringIO("dn: dc=x\na: one\n\n"))
    changes.parse_change_records()
    assert changes.changetype_counter[None] == 1


def test_a_record_that_runs_out_mid_change_is_still_read() -> None:
    """LDIF found in the wild ends where the file does, without a blank line."""
    text = (
        "dn: dc=x\n"
        "changetype: modify\n"
        "replace: a\na: one\na: two\n"
        "-\n"
        "-\n"
        "delete: b"
    )
    changes = ldap.ldif.LDIFRecordList(io.StringIO(text))
    changes.parse_change_records()
    assert changes.all_modify_changes == [
        (
            "dc=x",
            [
                (ldap.MOD_REPLACE, "a", [b"one", b"two"]),
                (ldap.MOD_DELETE, "b", None),
            ],
            None,
        )
    ]
    # The same when the file ends on a value rather than on a mod-op line.
    cut = ldap.ldif.LDIFRecordList(
        io.StringIO("dn: dc=x\nchangetype: modify\nadd: a\na: one")
    )
    cut.parse_change_records()
    assert cut.all_modify_changes == [("dc=x", [(ldap.MOD_ADD, "a", [b"one"])], None)]
    # A modify that modifies nothing is read and handed to nobody.
    empty = ldap.ldif.LDIFRecordList(io.StringIO("dn: dc=x\nchangetype: modify\n\n"))
    empty.parse_change_records()
    assert empty.all_modify_changes == []
    assert empty.records_read == 1


def test_a_value_written_without_the_space_after_the_colon_is_read() -> None:
    """RFC 2849 asks for the space; LDIF found in the wild leaves it out."""
    assert parsed("dn:dc=x\na:one\nb::b25l\n\n") == [
        ("dc=x", {"a": [b"one"], "b": [b"one"]})
    ]


def test_change_records_that_do_not_say_what_they_change_are_refused() -> None:
    for text, complaint in (
        ("changetype: modify\nreplace: a\n\n", 'does not start with "dn:"'),
        ("dn: [not a dn]\nchangetype: modify\n\n", "Not a valid string-representation"),
        ("dn: dc=x\nchangetype: rename\n\n", "Invalid changetype"),
        ("dn: dc=x\nchangetype: modify\nmangle: a\n\n", "Invalid mod-op string"),
    ):
        changes = ldap.ldif.LDIFRecordList(io.StringIO(text))
        with pytest.raises(ValueError, match=complaint):
            changes.parse_change_records()


def test_entry_records_that_are_not_entries_are_refused() -> None:
    for text, complaint in (
        ("a: one\n\n", 'does not start with "dn:"'),
        ("dn: [not a dn]\na: one\n\n", "Not a valid string-representation"),
        ("no-colon-here\n\n", "no value-spec"),
    ):
        with pytest.raises(ValueError, match=complaint):
            parsed(text)


def test_what_the_parser_is_told_to_leave_out_it_leaves_out() -> None:
    text = "version: 1\n\ndn: dc=x\na: one\nB: two\n\ndn: dc=y\na: three\n\n"
    assert parsed(text, ignored_attr_types=["b"]) == [
        ("dc=x", {"a": [b"one"]}),
        ("dc=y", {"a": [b"three"]}),
    ]
    # And it stops once it has read as many records as it was asked for.
    assert parsed(text, max_entries=1) == [("dc=x", {"a": [b"one"], "B": [b"two"]})]


def test_comments_and_empty_lines_are_passed_over() -> None:
    text = (
        "\n# a comment\n"
        " that is folded across lines\n"
        "\ndn: dc=x\na: one\n\n\n\n"
        "# another\ndn: dc=y\na: two"
    )
    assert parsed(text) == [("dc=x", {"a": [b"one"]}), ("dc=y", {"a": [b"two"]})]
    # Nothing but a version line is no records at all.
    assert parsed("version: 1\n") == []
    assert parsed("") == []


def test_a_value_can_be_fetched_from_a_url_when_the_scheme_is_allowed(
    tmp_path: pathlib.Path,
) -> None:
    holding = tmp_path / "value.txt"
    holding.write_bytes(b"from a file")
    text = "dn: dc=x\na:< %s\n\n" % holding.as_uri()
    # Only the schemes the caller names are fetched; anything else is left
    # out of the entry altogether.
    assert parsed(text, process_url_schemes=["file"]) == [
        ("dc=x", {"a": [b"from a file"]})
    ]
    assert parsed(text, process_url_schemes=["https"]) == [("dc=x", {"a": [None]})]
    assert parsed(text) == [("dc=x", {"a": [None]})]


def test_ldif_is_read_from_a_file_opened_either_way(tmp_path: pathlib.Path) -> None:
    holding = tmp_path / "people.ldif"
    holding.write_text("dn: dc=x\na: one\n\n")
    with holding.open() as text:
        assert parsed(text.read()) == [("dc=x", {"a": [b"one"]})]
    # A file opened in binary mode is read as UTF-8, which is not what RFC
    # 2849 allows but is what is found in the wild.
    holding.write_bytes("dn: dc=x\na: Ströder\n\n".encode())
    with holding.open("rb") as binary:
        records = ldap.ldif.LDIFRecordList(binary)
        records.parse()
    assert records.all_records == [("dc=x", {"a": ["Ströder".encode()]})]


def test_copying_ldif_writes_out_what_was_read_in() -> None:
    out = io.StringIO()
    copier = ldap.ldif.LDIFCopy(io.StringIO("dn: dc=x\nb: two\na: one\n\n"), out)
    copier.parse()
    assert out.getvalue() == "dn: dc=x\na: one\nb: two\n\n"


def test_the_parser_can_be_asked_to_do_something_with_each_record() -> None:
    """LDIFParser itself does nothing with what it reads, as python-ldap's does."""
    parser = ldap.ldif.LDIFParser(io.StringIO("dn: dc=x\na: one\n\n"))
    parser.parse()
    assert parser.records_read == 1
    changer = ldap.ldif.LDIFParser(
        io.StringIO("dn: dc=x\nchangetype: modify\nreplace: a\na: one\n-\n\n")
    )
    changer.parse_change_records()
    assert changer.records_read == 1


def test_the_pieces_python_ldap_keeps_beside_the_parser() -> None:
    assert ldap.ldif.is_dn("") == 1
    assert ldap.ldif.is_dn("cn=x,dc=example,dc=com")
    assert not ldap.ldif.is_dn("[not a dn]")
    assert ldap.ldif.MOD_OP_INTEGER["increment"] == ldap.MOD_INCREMENT
    assert ldap.ldif.MOD_OP_STR[ldap.MOD_ADD] == "add"
    assert ldap.ldif.CHANGE_TYPES == ["add", "delete", "modify", "modrdn"]
    assert set(ldap.ldif.valid_changetype_dict) == set(ldap.ldif.CHANGE_TYPES)
    assert ldap.ldif.list_dict(["A", "b"]) == {"A": None, "b": None}
    assert re.match(ldap.ldif.ldif_pattern, "dn: cn=x")
    assert re.search(ldap.ldif.SAFE_STRING_PATTERN, b" leads with a space")


# The SASL options, and what they fill in.


async def test_the_sasl_options_say_what_a_bind_was_not_told() -> None:
    connection = ldap.initialize("ldap://x")
    connection.set_option(ldap.OPT_X_SASL_REALM, "example.com")
    connection.set_option(ldap.OPT_X_SASL_AUTHCID, "jack")
    connection.set_option(ldap.OPT_X_SASL_SSF_EXTERNAL, 128)
    connection.set_option(ldap.OPT_X_SASL_NOCANON, 1)
    assert connection.get_option(ldap.OPT_X_SASL_REALM) == "example.com"
    assert connection.get_option(ldap.OPT_X_SASL_NOCANON) == 1
    # Nothing has bound yet, so the mechanism is whatever was asked for.
    assert connection.get_option(ldap.OPT_X_SASL_MECH) is None
    assert connection.get_option(ldap.OPT_X_SASL_USERNAME) is None
    assert connection.get_option(ldap.OPT_X_SASL_SSF) == 128
    assert connection.get_option(ldap.OPT_X_SASL_SSF_MIN) is None
    connection.set_option(ldap.OPT_X_SASL_MECH, "CRAM-MD5")
    assert connection.get_option(ldap.OPT_X_SASL_MECH) == "CRAM-MD5"

    # What the bind ended up with is the server's to say, not the caller's.
    for option in (ldap.OPT_X_SASL_USERNAME, ldap.OPT_X_SASL_SSF):
        with pytest.raises(ValueError, match="cannot be set"):
            connection.set_option(option, "jack")


async def test_a_bind_is_told_what_the_options_say_and_reports_what_it_did() -> None:
    servers: list[SaslServer] = []

    def factory() -> ldapserver.BaseLDAPServer:
        server = SaslServer()
        servers.append(server)
        return server

    async with serving(factory) as server, connected(server) as connection:
        connection.set_option(ldap.OPT_X_SASL_AUTHZID, "u:jack")
        # EXTERNAL was given no identity, so the option's is the one sent.
        await connection.sasl_interactive_bind_s("", ldap.sasl.external())
        assert servers[0].seen == [(b"EXTERNAL", b"u:jack")]
        assert connection.get_option(ldap.OPT_X_SASL_MECH) == "EXTERNAL"
        assert connection.get_option(ldap.OPT_X_SASL_USERNAME) == "u:jack"

    async with serving(factory) as server, connected(server) as connection:
        await connection.sasl_interactive_bind_s(
            "", ldap.sasl.cram_md5("jack", "secret")
        )
        # A mechanism that was told who it is keeps what it was told.
        assert connection.get_option(ldap.OPT_X_SASL_USERNAME) == "jack"


def test_the_gssapi_mechanism_speaks_rfc_4752(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeContext:
        """What the gssapi package hands back, as far as this uses it."""

        def __init__(self) -> None:
            self.complete = False
            self.sent: list[bytes | None] = []

        def step(self, challenge: bytes | None) -> bytes | None:
            self.sent.append(challenge)
            if challenge is None:
                return b"first token"
            self.complete = True
            # A library that has nothing more to send says so with nothing.
            return None

        def unwrap(self, message: bytes) -> object:
            self.unwrapped = message
            return message

        def wrap(self, message: bytes, confidential: bool) -> object:
            self.wrapped = message
            return type("Wrapped", (), {"message": b"wrapped:" + message})

    contexts: list[FakeContext] = []

    class FakeGssapi:
        NameType = type("NameType", (), {"hostbased_service": object()})

        @staticmethod
        def Name(name: str, name_type: object) -> str:
            return name

        @staticmethod
        def SecurityContext(name: str, usage: str) -> FakeContext:
            context = FakeContext()
            contexts.append(context)
            return context

    mechanism = ldap.sasl.gssapi("u:jack", service="ldap@ldap.example.com")
    assert mechanism.mech == b"GSSAPI"
    monkeypatch.setattr(ldap.sasl, "_gssapi", lambda: FakeGssapi)
    assert mechanism.process() == b"first token"
    # Whatever the library says to send goes as it stands, and nothing to
    # send is nothing to send.
    assert mechanism.process(b"server token") == b""
    # The context is up: what is left is to say which security layer.
    answer = mechanism.process(b"wrapped offer")
    assert answer == b"wrapped:\x01\x00\x00\x00u:jack"
    assert contexts[0].unwrapped == b"wrapped offer"

    # It has to know what the ticket is for, which the bind fills in.
    with pytest.raises(ValueError, match="which service"):
        ldap.sasl.gssapi().process()


async def test_a_gssapi_bind_asks_for_a_ticket_for_the_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mechanism = ldap.sasl.gssapi()

    def not_installed() -> object:
        raise ImportError("no Kerberos here")

    monkeypatch.setattr(ldap.sasl, "_gssapi", not_installed)
    async with serving(SaslServer) as server, connected(server) as connection:
        # The exchange itself needs Kerberos; what is checked here is that
        # the bind says which service the ticket should be for.
        with pytest.raises(ImportError, match="no Kerberos here"):
            await connection.sasl_interactive_bind_s("", mechanism)
    assert mechanism.service == f"ldap@{server.host}"


# A search read result by result.


async def test_a_search_is_read_one_result_at_a_time() -> None:
    async with serving_tree() as server, bound(server) as connection:
        collected = ldap.asyncsearch.List(connection)
        await collected.startSearch(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)"
        )
        assert await collected.processResults() == 0
        assert len(collected.allResults) == 2
        assert collected.beginResultsDropped == 0

        # Into a dictionary, keyed by name.
        keyed = ldap.asyncsearch.Dict(connection)
        await keyed.startSearch(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)"
        )
        await keyed.processResults()
        assert JACK in keyed.allEntries

        # And with an index of which names hold which values.
        indexed = ldap.asyncsearch.IndexedDict(connection, ["uid"])
        await indexed.startSearch(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)"
        )
        await indexed.processResults()
        assert indexed.index["uid"][b"jack"] == [JACK]


async def test_a_search_can_be_read_in_part_and_then_abandoned() -> None:
    async with serving_tree() as server, bound(server) as connection:
        # The first is dropped and the rest taken.
        dropping = ldap.asyncsearch.List(connection)
        await dropping.startSearch(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)"
        )
        assert await dropping.processResults(1, 1) == 0
        assert dropping.beginResultsDropped == 1
        assert len(dropping.allResults) == 1

        # Only the first is wanted, and the search is abandoned after it.
        first = ldap.asyncsearch.List(connection)
        await first.startSearch(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(objectClass=*)"
        )
        assert await first.processResults(0, 1) == 1
        assert len(first.allResults) == 1
        assert first.endResultBreak == 1


async def test_a_search_written_out_as_it_arrives() -> None:
    import io

    async with serving_tree() as server, bound(server) as connection:
        out = io.BytesIO()
        writer = ldap.asyncsearch.LDIFWriter(
            connection, out, b"# entries\n", b"# done\n"
        )
        await writer.startSearch(
            "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=jack)"
        )
        await writer.processResults()
    written = out.getvalue()
    assert written.startswith(b"# entries\n")
    assert written.endswith(b"# done\n")
    assert b"dn: " + JACK.encode() in written


async def test_a_result_a_search_cannot_have_answered_with_is_refused() -> None:
    class WrongServer(ldapserver.BaseLDAPServer):
        """A server that answers a search with something else entirely."""

        async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
            await self._send_anyio_write(
                pureldap.LDAPMessage(
                    pureldap.LDAPModifyResponse(resultCode=0), id=msg.id
                ).toWire()
            )

    async with serving(WrongServer) as server, connected(server) as connection:
        collected = ldap.asyncsearch.List(connection)
        await collected.startSearch("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(cn=*)")
        with pytest.raises(ldap.PROTOCOL_ERROR):
            await collected.processResults()

    error = ldap.asyncsearch.WrongResultType(
        ldap.RES_BIND, {ldap.RES_SEARCH_ENTRY}
    )
    assert "Received wrong result type" in str(error)


# A connection that opens itself again.


async def test_a_connection_that_reconnects_replays_what_was_done_to_it() -> None:
    root = make_root()
    factory = tree_server(root)
    async with serving(factory) as server:
        connection = ldap.ReconnectLDAPObject(server.uri)
        connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        await connection.simple_bind_s(JACK, "secret")
        assert len(await connection.search_ext_s(JACK, ldap.SCOPE_BASE)) == 1

        # The server goes away underneath it: the next operation opens the
        # connection again, binds as it was bound, and is answered.
        assert connection._stream is not None
        await anyio.aclose_forcefully(connection._stream)
        assert len(await connection.search_ext_s(JACK, ldap.SCOPE_BASE)) == 1
        assert connection._reconnects_done == 1
        assert connection.get_option(ldap.OPT_PROTOCOL_VERSION) == ldap.VERSION3
        await connection.unbind_s()


async def test_a_reconnect_gives_up_after_being_told_how_many_times_to_try(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slept: list[float] = []

    async def no_waiting(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(anyio, "sleep", no_waiting)
    host, port = "127.0.0.1", 1
    connection = ldap.ReconnectLDAPObject(
        f"ldap://{host}:{port}", retry_max=3, retry_delay=0.5
    )
    with pytest.raises(ldap.SERVER_DOWN):
        await connection.whoami_s()
    # Three tries at opening it, with a wait between each pair.
    assert slept == [0.5, 0.5]


async def test_a_reconnect_that_the_server_refuses_is_reported() -> None:
    class RefusingServer(ldapserver.BaseLDAPServer):
        """A server that will not have anyone bind to it."""

        async def handle_LDAPBindRequest(
            self,
            request: pureldap.LDAPBindRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPBindResponse:
            return pureldap.LDAPBindResponse(resultCode=49)

    async with serving(RefusingServer) as server:
        connection = ldap.ReconnectLDAPObject(server.uri)
        with pytest.raises(ldap.INVALID_CREDENTIALS):
            await connection.reconnect(server.uri)
        await connection.unbind_s()


async def test_a_reconnect_that_is_not_forced_leaves_a_live_connection_alone() -> None:
    async with serving_tree() as server:
        connection = ldap.ReconnectLDAPObject(server.uri)
        await connection.simple_bind_s()
        stream = connection._stream
        await connection.reconnect(server.uri, force=False)
        assert connection._stream is stream
        assert connection._reconnects_done == 0
        await connection.unbind_s()


async def test_a_reconnecting_connection_can_be_written_down_and_read_back() -> None:
    import pickle

    async with serving_tree() as server:
        connection = ldap.ReconnectLDAPObject(server.uri)
        await connection.simple_bind_s(JACK, "secret")
        written = pickle.dumps(connection)
        await connection.unbind_s()

        # What comes back is not open, and opens itself when it is used.
        read_back = pickle.loads(written)
        assert read_back._stream is None
        assert len(await read_back.search_ext_s(JACK, ldap.SCOPE_BASE)) == 1
        await read_back.unbind_s()


class Answering:
    """A connection that answers a search with whatever it was given."""

    def __init__(self, answers: list[tuple[int, list[object]]]) -> None:
        self.answers = answers
        self.abandoned: list[int] = []

    async def search_ext(self, *args: object, **kwargs: object) -> int:
        return 1

    async def result3(
        self, msgid: int, all: int, timeout: float
    ) -> tuple[int, list[object], int, list[object]]:
        rtype, data = self.answers.pop(0)
        return rtype, data, msgid, []

    async def abandon(self, msgid: int) -> None:
        self.abandoned.append(msgid)


async def test_a_reference_a_search_hands_back_is_passed_over() -> None:
    reference = (None, ["ldap://other.example.com/dc=example,dc=com"])
    entry = (JACK, {"uid": [b"jack"]})

    for handler_class in (
        ldap.asyncsearch.Dict,
        ldap.asyncsearch.IndexedDict,
        ldap.asyncsearch.LDIFWriter,
    ):
        answering = Answering(
            [
                (ldap.RES_SEARCH_REFERENCE, [reference]),
                (ldap.RES_SEARCH_ENTRY, [entry]),
                (ldap.RES_SEARCH_RESULT, []),
            ]
        )
        arguments: list[object] = [answering]
        if handler_class is ldap.asyncsearch.IndexedDict:
            arguments.append(["uid"])
        elif handler_class is ldap.asyncsearch.LDIFWriter:
            import io

            arguments.append(io.BytesIO())
        handler = handler_class(*arguments)  # type: ignore[arg-type]
        await handler.startSearch("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(cn=*)")
        await handler.processResults()
        if isinstance(handler, ldap.asyncsearch.Dict):
            # The entry is kept; where to look next is not an entry.
            assert list(handler.allEntries) == [JACK]


async def test_a_result_that_is_not_a_search_result_at_all_is_refused() -> None:
    answering = Answering([(ldap.RES_BIND, [(JACK, {})])])
    collected = ldap.asyncsearch.List(answering)  # type: ignore[arg-type]
    await collected.startSearch("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(cn=*)")
    with pytest.raises(ldap.asyncsearch.WrongResultType) as raised:
        await collected.processResults()
    assert str(raised.value).startswith("Received wrong result type 97")


async def test_every_operation_on_a_reconnecting_connection_is_answered() -> None:
    root = make_root()

    class AnsweringServer(ldapserver.LDAPServer):
        """The tree, and an answer to whatever extended request arrives."""

        async def handle_LDAPExtendedRequest(
            self,
            request: pureldap.LDAPExtendedRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPExtendedResponse:
            return pureldap.LDAPExtendedResponse(
                resultCode=0,
                responseName=request.requestName,
                response=b"dn:" + JACK.encode(),
            )

    def factory() -> ldapserver.BaseLDAPServer:
        server = AnsweringServer()
        server.factory = root
        return server

    async with serving(factory) as server:
        async with ldap.ReconnectLDAPObject(server.uri) as connection:
            await connection.simple_bind_s()
            await connection.bind_s(JACK, "secret")
            assert await connection.whoami_s() == f"dn:{JACK}"
            assert await connection.search_ext_s(JACK, ldap.SCOPE_BASE)
            await connection.add_ext_s(
                "uid=jill,ou=People,dc=example,dc=com",
                [
                    ("objectClass", ["inetOrgPerson"]),
                    ("uid", ["jill"]),
                    ("cn", ["Jill"]),
                ],
            )
            await connection.modify_ext_s(
                "uid=jill,ou=People,dc=example,dc=com",
                [(ldap.MOD_REPLACE, "cn", ["Jillian"])],
            )
            assert await connection.compare_ext_s(
                "uid=jill,ou=People,dc=example,dc=com", "cn", "Jillian"
            )
            await connection.rename_s(
                "uid=jill,ou=People,dc=example,dc=com", "uid=jules"
            )
            await connection.delete_ext_s("uid=jules,ou=People,dc=example,dc=com")
            _, value = await connection.extop_s(
                pureldap.LDAPExtendedRequest(requestName=b"1.2.3")
            )
            assert value == b"dn:" + JACK.encode()
            # Cancelling something that has already answered is answered too.
            assert await connection.cancel_s(1) == (ldap.RES_EXTENDED, [])
            assert await connection.passwd_s(JACK, "secret", "newer")
            with pytest.raises(ldap.AUTH_METHOD_NOT_SUPPORTED):
                await connection.sasl_interactive_bind_s(
                    "", ldap.sasl.sasl({}, "NOTHING")
                )
            with pytest.raises(ldap.AUTH_METHOD_NOT_SUPPORTED):
                await connection.sasl_bind_s("", "NOTHING", None)
            # A bind the server refused leaves the connection fit to use.
            assert await connection.search_ext_s(JACK, ldap.SCOPE_BASE)


async def test_a_forced_reconnect_says_goodbye_to_the_connection_it_replaces() -> None:
    async with serving_tree() as server:
        connection = ldap.ReconnectLDAPObject(server.uri, trace_level=1)
        await connection.simple_bind_s()
        stream = connection._stream
        await connection.reconnect(server.uri, force=True)
        # A different connection, bound the same way.
        assert connection._stream is not stream
        assert connection._reconnects_done == 1
        await connection.unbind_s()


async def test_a_reconnect_raises_tls_again_if_it_had_been_raised() -> None:
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
        connection = ldap.ReconnectLDAPObject(
            f"ldap://localhost:{server.port}", ssl_context=client_context
        )
        await connection.start_tls_s()
        await connection.simple_bind_s()
        assert await connection.search_ext_s("dc=example,dc=com", ldap.SCOPE_ONELEVEL)

        # The connection goes: what comes back has TLS raised on it again.
        assert connection._stream is not None
        await anyio.aclose_forcefully(connection._stream)
        assert await connection.search_ext_s("dc=example,dc=com", ldap.SCOPE_ONELEVEL)
        assert isinstance(connection._stream, anyio.streams.tls.TLSStream)
        await connection.unbind_s()


async def test_a_reconnect_that_is_told_to_trace_says_it_is_waiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no_waiting(seconds: float) -> None:
        pass

    monkeypatch.setattr(anyio, "sleep", no_waiting)
    connection = ldap.ReconnectLDAPObject(
        "ldap://127.0.0.1:1", trace_level=1, retry_max=2
    )
    with pytest.raises(ldap.SERVER_DOWN):
        await connection.whoami_s()


async def test_a_search_that_is_left_unread_is_abandoned() -> None:
    answering = Answering(
        [
            (ldap.RES_SEARCH_ENTRY, [(JACK, {"uid": [b"jack"]})]),
            (ldap.RES_SEARCH_ENTRY, [("uid=jill,dc=example,dc=com", {})]),
        ]
    )
    collected = ldap.asyncsearch.List(answering)  # type: ignore[arg-type]
    await collected.startSearch("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(cn=*)")
    assert await collected.processResults(0, 1) == 1
    assert answering.abandoned == [1]


async def test_a_reconnecting_connection_remembers_the_sasl_bind_it_made() -> None:
    root = make_root()

    class SaslTreeServer(ldapserver.LDAPServer):
        """The tree, bound to with whatever mechanism is offered."""

        async def handle_LDAPBindRequest(
            self,
            request: pureldap.LDAPBindRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPBindResponse:
            return pureldap.LDAPBindResponse(resultCode=0)

    def factory() -> ldapserver.BaseLDAPServer:
        server = SaslTreeServer()
        server.factory = root
        return server

    async with serving(factory) as server:
        async with ldap.ReconnectLDAPObject(server.uri) as connection:
            await connection.sasl_interactive_bind_s("", ldap.sasl.external())
            assert connection._last_bind is not None
            assert connection._last_bind[0] == "sasl_interactive_bind_s"

            # And the step-by-step spelling of the same thing.
            await connection.sasl_bind_s("", "EXTERNAL", b"")
            assert connection._last_bind[0] == "sasl_bind_s"

            # The connection goes: the bind it remembers is made again.
            assert connection._stream is not None
            await anyio.aclose_forcefully(connection._stream)
            assert await connection.search_ext_s(JACK, ldap.SCOPE_BASE)
            assert connection._reconnects_done == 1


# Keeping a copy of what the server holds.


UUIDS = [
    "8dc44601-a936-11ea-8aaf-f248c5fa5780",
    "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
]


def sync_state(state: int, uuid: str, cookie: bytes | None = None) -> bytes:
    """A Sync State control value, as a server writes one."""
    import uuid as uuid_module

    value: list[pureber.BERBase] = [
        pureber.BEREnumerated(state),
        pureber.BEROctetString(uuid_module.UUID(uuid).bytes),
    ]
    if cookie is not None:
        value.append(pureber.BEROctetString(cookie))
    return pureber.BERSequence(value).toWire()


def sync_info(tag: int, *parts: pureber.BERBase) -> bytes:
    """A Sync Info message, written under the tag that says what it is."""
    return pureber.BERSequence(list(parts), tag=tag).toWire()


class Consumer(ldap.syncrepl.SyncreplConsumer, ldapobject.SimpleLDAPObject):
    """A connection that writes down what the server tells it."""

    def __init__(self, uri: str) -> None:
        super().__init__(uri)
        self.entries: dict[str, tuple[str, dict[str, list[bytes]]]] = {}
        self.present: list[str] = []
        self.deleted: list[str] = []
        self.cookies: list[str] = []
        self.reset: list[bool | None] = []
        self.refreshed = False

    def syncrepl_set_cookie(self, cookie: str) -> None:
        self.cookies.append(cookie)

    def syncrepl_get_cookie(self) -> str | None:
        return self.cookies[-1] if self.cookies else None

    def syncrepl_entry(
        self, dn: str, attrs: dict[str, list[bytes]], uuid: str
    ) -> None:
        self.entries[uuid] = (dn, attrs)

    def syncrepl_present(
        self, uuids: Sequence[str] | None, refreshDeletes: bool | None = False
    ) -> None:
        if uuids is None:
            self.reset.append(refreshDeletes)
        else:
            self.present.extend(uuids)

    def syncrepl_delete(self, uuids: Sequence[str]) -> None:
        self.deleted.extend(uuids)

    def syncrepl_refreshdone(self) -> None:
        self.refreshed = True


class SyncServer(ldapserver.BaseLDAPServer):
    """A server that plays a whole syncrepl session, refresh and persist."""

    asked: list[list[pureldap.Control]] = []

    async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
        if not isinstance(msg.value, pureldap.LDAPSearchRequest):
            return
        SyncServer.asked.append(list(msg.controls or ()))
        await self.send_entry(msg.id, "cn=one,dc=example,dc=com", 1, UUIDS[0])
        # The refresh is over, and the cookie says where it got to.
        await self.send_info(
            msg.id,
            sync_info(
                pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x02,
                pureber.BEROctetString(b"csn=refreshed"),
                pureber.BERBoolean(1),
            ),
        )
        # Then what changes: one entry is still there, one has gone.
        await self.send_entry(msg.id, "cn=two,dc=example,dc=com", 0, UUIDS[1])
        await self.send_entry(msg.id, "cn=two,dc=example,dc=com", 3, UUIDS[1])
        # And a set of entries that are all gone, then a cookie on its own.
        await self.send_info(
            msg.id,
            sync_info(
                pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x03,
                pureber.BEROctetString(b"csn=set"),
                pureber.BERBoolean(1),
                pureber.BERSet(
                    [pureber.BEROctetString(__import__("uuid").UUID(UUIDS[0]).bytes)]
                ),
            ),
        )
        await self.send_info(
            msg.id,
            pureber.BEROctetString(
                b"csn=later", tag=pureber.CLASS_CONTEXT | 0x00
            ).toWire(),
        )
        # A message this consumer is not interested in, passed over.
        await self._send_anyio_write(
            pureldap.LDAPMessage(
                pureldap.LDAPIntermediateResponse(
                    responseName=b"1.2.3", responseValue=b"other"
                ),
                id=msg.id,
            ).toWire()
        )
        await self._send_anyio_write(
            pureldap.LDAPMessage(
                pureldap.LDAPSearchResultDone(resultCode=0),
                id=msg.id,
                controls=[
                    (
                        ldap.CONTROL_SYNC_DONE,
                        0,
                        pureber.BERSequence(
                            [
                                pureber.BEROctetString(b"csn=done"),
                                pureber.BERBoolean(1),
                            ]
                        ).toWire(),
                    )
                ],
            ).toWire()
        )

    async def send_entry(self, msgid: int, dn: str, state: int, uuid: str) -> None:
        await self._send_anyio_write(
            pureldap.LDAPMessage(
                pureldap.LDAPSearchResultEntry(
                    objectName=dn, attributes=[("cn", [dn.split(",")[0][3:]])]
                ),
                id=msgid,
                controls=[(ldap.CONTROL_SYNC_STATE, 0, sync_state(state, uuid))],
            ).toWire()
        )

    async def send_info(self, msgid: int, value: bytes) -> None:
        await self._send_anyio_write(
            pureldap.LDAPMessage(
                pureldap.LDAPIntermediateResponse(
                    responseName=ldap.syncrepl.SYNC_INFO, responseValue=value
                ),
                id=msgid,
            ).toWire()
        )


async def test_a_syncrepl_search_is_told_what_the_server_holds() -> None:
    SyncServer.asked = []
    async with serving(SyncServer) as server:
        async with Consumer(server.uri) as connection:
            msgid = await connection.syncrepl_search(
                "dc=example,dc=com", ldap.SCOPE_SUBTREE, mode="refreshAndPersist"
            )
            while await connection.syncrepl_poll(msgid=msgid):
                pass

    # The search asked for syncrepl, in the mode it was told to.
    [(oid, criticality, value)] = SyncServer.asked[0]
    assert oid == ldap.CONTROL_SYNC.encode()
    assert bool(criticality) is True
    request = ldap.syncrepl.SyncRequestControl(mode="refreshAndPersist")
    assert value == request.encodeControlValue()

    # The entry that was added is kept, the one that went is gone, and the
    # one that was there was recorded as present.
    assert connection.entries[UUIDS[0]][0] == "cn=one,dc=example,dc=com"
    assert connection.present[:2] == [UUIDS[0], UUIDS[1]]
    assert connection.deleted == [UUIDS[1], UUIDS[0]]
    assert connection.refreshed is True
    # Every cookie the server sent, in the order it sent them.
    assert connection.cookies == ["csn=refreshed", "csn=set", "csn=later", "csn=done"]
    # The refresh ending resets the record; the Sync Done control does too.
    assert connection.reset == [False, True]


async def test_a_syncrepl_search_starts_from_the_cookie_it_was_left() -> None:
    SyncServer.asked = []
    async with serving(SyncServer) as server:
        async with Consumer(server.uri) as connection:
            connection.cookies.append("csn=earlier")
            msgid = await connection.syncrepl_search(
                "dc=example,dc=com", serverctrls=[ldap.controls.ManageDSAITControl()]
            )
            while await connection.syncrepl_poll(msgid=msgid):
                pass

    # The control it was given is still sent, with the sync request after it.
    oids = [oid for oid, _, _ in SyncServer.asked[0]]
    assert oids == [b"2.16.840.1.113730.3.4.2", ldap.CONTROL_SYNC.encode()]
    asked = ldap.syncrepl.SyncRequestControl(cookie="csn=earlier")
    assert SyncServer.asked[0][1][2] == asked.encodeControlValue()


def test_what_a_syncrepl_message_says_is_read_out_of_it() -> None:
    import binascii

    # A refresh that is not done, with no cookie.
    message = ldap.syncrepl.SyncInfoMessage(
        sync_info(
            pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x01,
            pureber.BERBoolean(0),
        )
    )
    assert message.refreshDelete == {"refreshDone": False}
    assert message.refreshPresent is None

    # A refresh with nothing said at all: it is done, by default.
    empty = ldap.syncrepl.SyncInfoMessage(
        sync_info(pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x02)
    )
    assert empty.refreshPresent == {"refreshDone": True}

    # A set of entries that are present rather than gone, with no cookie.
    import uuid as uuid_module

    present = ldap.syncrepl.SyncInfoMessage(
        sync_info(
            pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x03,
            pureber.BERSet(
                [pureber.BEROctetString(uuid_module.UUID(UUIDS[0]).bytes)]
            ),
        )
    )
    assert present.syncIdSet == {
        "refreshDeletes": False,
        "syncUUIDs": [UUIDS[0]],
    }

    # The message python-ldap keeps as a regression, taken off the wire from
    # 389-ds: a syncIdSet that an earlier reading took for a refresh.
    dumped = (
        "a36b04526c6461706b64632e6578616d706c652e636f6d3a333839303123636e"
        "3d6469726563746f7279206d616e616765723a64633d6578616d706c652c6463"
        "3d636f6d3a286f626a656374436c6173733d2a2923330101ff311204108dc446"
        "01a93611ea8aaff248c5fa5780"
    )
    from_the_wire = ldap.syncrepl.SyncInfoMessage(binascii.unhexlify(dumped))
    assert from_the_wire.refreshDelete is None
    assert from_the_wire.refreshPresent is None
    assert from_the_wire.newcookie is None
    assert from_the_wire.syncIdSet == {
        "cookie": (
            "ldapkdc.example.com:38901#cn=directory manager:"
            "dc=example,dc=com:(objectClass=*)#3"
        ),
        "syncUUIDs": [UUIDS[0]],
        "refreshDeletes": True,
    }

    with pytest.raises(ValueError, match="unknown syncrepl info message"):
        ldap.syncrepl.SyncInfoMessage(
            sync_info(pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x04)
        )


def test_the_syncrepl_controls_say_what_they_are_asked_to() -> None:
    asked = ldap.syncrepl.SyncRequestControl(cookie="csn=1", reloadHint=True)
    assert asked.controlType == ldap.CONTROL_SYNC
    # The same bytes python-ldap writes, except that BER says true with
    # every bit set where python-ldap writes it as one.
    assert asked.encodeControlValue() == b"0\r\n\x01\x01\x04\x05csn=1\x01\x01\xff"
    with pytest.raises(ValueError, match="unknown syncrepl mode"):
        ldap.syncrepl.SyncRequestControl(mode="whenever").encodeControlValue()

    state = ldap.syncrepl.SyncStateControl()
    state.decodeControlValue(sync_state(3, UUIDS[0]))
    assert (state.state, state.entryUUID, state.cookie) == ("delete", UUIDS[0], None)

    done = ldap.syncrepl.SyncDoneControl()
    done.decodeControlValue(pureber.BERSequence([]).toWire())
    assert done.cookie is None and done.refreshDeletes is None

    assert ldap.controls.KNOWN_RESPONSE_CONTROLS[ldap.CONTROL_SYNC_STATE] is (
        ldap.syncrepl.SyncStateControl
    )
    assert ldap.controls.KNOWN_RESPONSE_CONTROLS[ldap.CONTROL_SYNC_DONE] is (
        ldap.syncrepl.SyncDoneControl
    )


async def test_a_cancelled_operation_is_answered_rather_than_forgotten() -> None:
    class CancellingServer(ldapserver.BaseLDAPServer):
        """A server that answers a cancel, and the operation it stops."""

        async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
            if isinstance(msg.value, pureldap.LDAPExtendedRequest):
                assert msg.value.requestName == pureldap.LDAPCancelRequest.oid
                await self._send_anyio_write(
                    pureldap.LDAPMessage(
                        pureldap.LDAPExtendedResponse(resultCode=0), id=msg.id
                    ).toWire()
                )

    async with serving(CancellingServer) as server:
        async with connected(server) as connection:
            # A search nobody will answer, and then the word to stop it.
            msgid = await connection.search_ext("dc=example,dc=com")
            assert await connection.cancel_s(msgid) == (ldap.RES_EXTENDED, [])
            await connection.abandon(msgid)

    request = pureldap.LDAPCancelRequest(cancelID=7)
    assert "cancelID=7" in repr(request)
    assert request.requestValue == pureber.BERSequence(
        [pureber.BERInteger(7)]
    ).toWire()


async def test_a_cancel_the_server_says_it_did_answers_with_nothing() -> None:
    class CancelledServer(ldapserver.BaseLDAPServer):
        """A server that answers the cancel with the code for having done it."""

        async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
            if isinstance(msg.value, pureldap.LDAPExtendedRequest):
                await self._send_anyio_write(
                    pureldap.LDAPMessage(
                        pureldap.LDAPExtendedResponse(resultCode=118), id=msg.id
                    ).toWire()
                )

    async with serving(CancelledServer) as server:
        async with connected(server) as connection:
            msgid = await connection.search_ext("dc=example,dc=com")
            assert await connection.cancel_s(msgid) is None
            await connection.abandon(msgid)


FOREIGN = (b"1.2.3", 0, b"not a sync control")


class PersistServer(ldapserver.BaseLDAPServer):
    """A server that says every other thing a syncrepl search can be told."""

    async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
        if not isinstance(msg.value, pureldap.LDAPSearchRequest):
            return
        # An entry with nothing to say about syncing at all.
        await self.entry(msg.id, "cn=one,dc=example,dc=com", [FOREIGN])
        # One whose sync control comes after a control this passes over,
        # and which carries a cookie of its own.
        await self.entry(
            msg.id,
            "cn=two,dc=example,dc=com",
            [
                FOREIGN,
                (
                    ldap.CONTROL_SYNC_STATE,
                    0,
                    sync_state(1, UUIDS[0], b"csn=entry"),
                ),
            ],
        )
        # A refresh that is not finished, and names nothing.
        await self.info(
            msg.id,
            sync_info(
                pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x01,
                pureber.BERBoolean(0),
            ),
        )
        # Then one that is, after which entries are not counted as present.
        await self.info(
            msg.id,
            sync_info(
                pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x02,
                pureber.BERBoolean(1),
            ),
        )
        await self.entry(
            msg.id,
            "cn=three,dc=example,dc=com",
            [(ldap.CONTROL_SYNC_STATE, 0, sync_state(2, UUIDS[1]))],
        )
        # A set of entries that are all still there, with no cookie.
        await self.info(
            msg.id,
            sync_info(
                pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x03,
                pureber.BERSet(
                    [pureber.BEROctetString(__import__("uuid").UUID(UUIDS[0]).bytes)]
                ),
            ),
        )
        await self._send_anyio_write(
            pureldap.LDAPMessage(
                pureldap.LDAPSearchResultDone(resultCode=0),
                id=msg.id,
                controls=[
                    FOREIGN,
                    (ldap.CONTROL_SYNC_DONE, 0, pureber.BERSequence([]).toWire()),
                ],
            ).toWire()
        )

    async def entry(
        self, msgid: int, dn: str, controls: list[pureldap.Control]
    ) -> None:
        await self._send_anyio_write(
            pureldap.LDAPMessage(
                pureldap.LDAPSearchResultEntry(objectName=dn, attributes=[]),
                id=msgid,
                controls=controls,
            ).toWire()
        )

    async def info(self, msgid: int, value: bytes) -> None:
        await self._send_anyio_write(
            pureldap.LDAPMessage(
                pureldap.LDAPIntermediateResponse(
                    responseName=ldap.syncrepl.SYNC_INFO, responseValue=value
                ),
                id=msgid,
            ).toWire()
        )


async def test_a_consumer_that_keeps_nothing_is_told_all_the_same() -> None:
    class Bare(ldap.syncrepl.SyncreplConsumer, ldapobject.SimpleLDAPObject):
        """The mixin as it comes, whose methods all do nothing."""

    async with serving(PersistServer) as server:
        async with Bare(server.uri) as connection:
            msgid = await connection.syncrepl_search("dc=example,dc=com")
            # Reading until the search finishes rather than message by
            # message, which is what all=1 asks for.
            assert await connection.syncrepl_poll(msgid=msgid, all=1) is False


async def test_a_syncrepl_search_can_be_told_where_to_start_from() -> None:
    SyncServer.asked = []
    async with serving(SyncServer) as server:
        async with Consumer(server.uri) as connection:
            msgid = await connection.syncrepl_search(
                "dc=example,dc=com", cookie="csn=given"
            )
            while await connection.syncrepl_poll(msgid=msgid):
                pass
    asked = ldap.syncrepl.SyncRequestControl(cookie="csn=given")
    assert SyncServer.asked[0][0][2] == asked.encodeControlValue()


async def test_the_controls_a_message_carried_come_with_it_when_asked() -> None:
    async with serving(PersistServer) as server:
        async with connected(server) as connection:
            msgid = await connection.search_ext("dc=example,dc=com")
            rtype, data, _, _, _, _ = await connection.result4(
                msgid, all=1, add_ctrls=1, add_intermediates=1
            )
            assert rtype == ldap.RES_SEARCH_RESULT
            # Each entry with the controls it carried, and no intermediate
            # response among them: those are not what a search found.
            assert len(data) == 3
            dn, attrs, entry_controls = data[1]  # type: ignore[misc]
            assert dn == "cn=two,dc=example,dc=com"
            assert isinstance(attrs, dict)
            assert any(
                isinstance(control, ldap.syncrepl.SyncStateControl)
                for control in entry_controls
            )


async def test_something_said_mid_search_is_passed_over_unless_asked_for() -> None:
    async with serving(PersistServer) as server:
        async with connected(server) as connection:
            msgid = await connection.search_ext("dc=example,dc=com")
            seen = []
            while True:
                rtype, data, _, _ = await connection.result3(msgid, all=0)
                seen.append(rtype)
                if rtype == ldap.RES_SEARCH_RESULT:
                    break
            # The entries and the result, and nothing of what the server
            # said in between, which was not asked for.
            assert seen == [ldap.RES_SEARCH_ENTRY] * 3 + [ldap.RES_SEARCH_RESULT]


def test_an_intermediate_response_says_only_what_it_was_given() -> None:
    empty = pureldap.LDAPIntermediateResponse()
    assert empty.toWire() == b"y\x00"
    assert repr(empty) == (
        "LDAPIntermediateResponse(responseName=None, responseValue=None)"
    )
    named = pureldap.LDAPIntermediateResponse(responseName="1.2.3")
    assert named.toWire() == b"y\x07\x80\x051.2.3"


def test_how_long_an_operation_may_take_is_said_the_way_libldap_says_it() -> None:
    connection = ldap.initialize("ldap://localhost")
    # Nothing is asked for to begin with.
    assert connection.get_option(ldap.OPT_TIMEOUT) is None
    assert connection.get_option(ldap.OPT_NETWORK_TIMEOUT) is None

    connection.set_option(ldap.OPT_TIMEOUT, 10.5)
    assert connection.get_option(ldap.OPT_TIMEOUT) == 10.5
    assert connection.timeout == 10.5
    connection.set_option(ldap.OPT_TIMEOUT, 0)
    assert connection.get_option(ldap.OPT_TIMEOUT) == 0

    # Both spellings of no limit at all.
    connection.set_option(ldap.OPT_TIMEOUT, -1)
    assert connection.get_option(ldap.OPT_TIMEOUT) is None
    connection.set_option(ldap.OPT_TIMEOUT, 5)
    connection.set_option(ldap.OPT_TIMEOUT, None)
    assert connection.get_option(ldap.OPT_TIMEOUT) is None

    with pytest.raises(ValueError, match="not a length of time"):
        connection.set_option(ldap.OPT_NETWORK_TIMEOUT, -5)
    with pytest.raises(TypeError):
        connection.set_option(ldap.OPT_NETWORK_TIMEOUT, object)
    with pytest.raises(OverflowError):
        connection.set_option(ldap.OPT_NETWORK_TIMEOUT, 10**1000)


def test_the_server_to_open_can_be_named_again_before_anything_is_sent() -> None:
    connection = ldap.initialize("ldap://localhost:389")
    connection.set_option(ldap.OPT_URI, "ldapi:///path/to/socket")
    assert connection.get_option(ldap.OPT_URI) == "ldapi:///path/to/socket"
    assert connection.uri == "ldapi:///path/to/socket"
    assert connection._unix is True
    assert connection._host == "/path/to/socket"


def test_a_definition_writes_itself_out_the_way_python_ldap_writes_it() -> None:
    # Every field of an attribute type, and where the definition came from.
    attribute = ldap.schema.AttributeType(
        "( 1.3.6.1.4.1.11.1.3.1.1.3 NAME ( 'searchTimeLimit' 'timeLimit' )"
        " DESC 'How long a search may take' OBSOLETE SUP name"
        " EQUALITY integerMatch ORDERING integerOrderingMatch"
        " SUBSTR caseIgnoreSubstringsMatch"
        " SYNTAX 1.3.6.1.4.1.1466.115.121.1.27{64} SINGLE-VALUE COLLECTIVE"
        " NO-USER-MODIFICATION USAGE directoryOperation"
        " X-ORIGIN ( 'RFC4876' 'user defined' ) )"
    )
    assert attribute.x_origin == ("RFC4876", "user defined")
    assert attribute.syntax_len == 64
    assert str(attribute) == (
        "( 1.3.6.1.4.1.11.1.3.1.1.3 NAME ( 'searchTimeLimit' 'timeLimit' )"
        " DESC 'How long a search may take' SUP name OBSOLETE"
        " EQUALITY integerMatch ORDERING integerOrderingMatch"
        " SUBSTR caseIgnoreSubstringsMatch"
        " SYNTAX 1.3.6.1.4.1.1466.115.121.1.27{64} SINGLE-VALUE COLLECTIVE"
        " NO-USER-MODIFICATION USAGE directoryOperation"
        " X-ORIGIN ( 'RFC4876' 'user defined' ) )"
    )

    # An object class that says nothing is under top and is structural.
    empty = ldap.schema.ObjectClass("( 2.999 )")
    assert (empty.sup, empty.x_origin, empty.names) == (("top",), (), ())
    assert str(empty) == "( 2.999 SUP top STRUCTURAL )"
    assert str(ldap.schema.AttributeType("( 2.999 )")) == "( 2.999 )"

    obsolete = ldap.schema.ObjectClass(
        "( 2.999 NAME 'gone' OBSOLETE SUP top AUXILIARY X-ORIGIN 'nowhere' )"
    )
    assert str(obsolete) == (
        "( 2.999 NAME 'gone' SUP top OBSOLETE AUXILIARY X-ORIGIN 'nowhere' )"
    )

    rule = ldap.schema.MatchingRule(
        "( 2.5.13.0 NAME 'objectIdentifierMatch' DESC 'by OID' OBSOLETE"
        " SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 X-ORIGIN 'RFC 4517' )"
    )
    assert rule.x_origin == ("RFC 4517",)
    assert str(rule) == (
        "( 2.5.13.0 NAME 'objectIdentifierMatch' DESC 'by OID' OBSOLETE"
        " SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )"
    )

    syntax = ldap.schema.LDAPSyntax(
        "( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio'"
        " X-NOT-HUMAN-READABLE 'TRUE' X-SUBST '1.3.6.1.4.1.1466.115.121.1.40' )"
    )
    assert syntax.not_human_readable == 1
    assert syntax.x_subst == "1.3.6.1.4.1.1466.115.121.1.40"
    assert str(syntax) == (
        "( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio'"
        " X-SUBST '1.3.6.1.4.1.1466.115.121.1.40' X-NOT-HUMAN-READABLE 'TRUE' )"
    )

    # A quote inside a value is written escaped, and a name can be set.
    quoted = ldap.schema.AttributeType("( 2.999 )")
    quoted.desc = "it's here"
    assert " DESC 'it\\'s here'" in str(quoted)
    quoted.set_id("2.998")
    assert quoted.get_id() == "2.998"

    # The base class, which a definition of a kind this does not know would
    # be read into, writes out what every definition has.
    base = ldap.schema.SchemaElement()
    base.oid = "2.999"
    base.desc = "whatever it is"
    assert str(base) == "( 2.999 DESC 'whatever it is' )"
    with pytest.raises(AssertionError):
        quoted.key_attr("DESC", 42)  # type: ignore[arg-type]
    with pytest.raises(AssertionError):
        quoted.key_list("NAME", ["a"])  # type: ignore[arg-type]


def test_the_schema_writes_out_the_entry_it_was_read_from() -> None:
    sub = ldap.schema.SubSchema(SUBSCHEMA)
    entry = sub.ldap_entry()
    assert sorted(entry) == [
        "attributeTypes",
        "ldapSyntaxes",
        "matchingRules",
        "objectClasses",
    ]
    assert "( 2.5.6.0 NAME 'top' SUP top ABSTRACT MUST objectClass )" in (
        entry["objectClasses"]
    )
    # And what it wrote reads back as the same schema.
    again = ldap.schema.SubSchema(entry)
    assert again.listall(ldap.schema.ObjectClass) == sub.listall(
        ldap.schema.ObjectClass
    )


async def test_the_schema_can_be_fetched_from_the_url_of_a_server() -> None:
    async with serving(schema_server()) as server:
        dn, sub = await ldap.schema.urlfetch(f"{server.uri}/dc=example,dc=com")
        assert dn == "cn=Subschema"
        assert sub is not None
        person = sub.get_obj(ldap.schema.ObjectClass, "person")
        assert isinstance(person, ldap.schema.ObjectClass)
        assert person.oid == "2.5.6.6"

        # The attributes the URL names are the ones asked for.
        _, only = await ldap.schema.urlfetch(
            f"{server.uri}/dc=example,dc=com?objectClasses"
        )
        assert only is not None
        assert only.listall(ldap.schema.AttributeType) == []


async def test_a_server_that_says_where_its_schema_is_not_answers_with_none() -> None:
    class Bare(ldapserver.BaseLDAPServer):
        """A server whose root DSE names no subschema subentry."""

        async def handle_LDAPBindRequest(
            self,
            request: pureldap.LDAPBindRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPBindResponse:
            return pureldap.LDAPBindResponse(resultCode=0)

        async def handle_LDAPSearchRequest(
            self,
            request: pureldap.LDAPSearchRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPSearchResultDone:
            return pureldap.LDAPSearchResultDone(resultCode=0)

    async with serving(Bare) as server:
        assert await ldap.schema.urlfetch(server.uri) == (None, None)


# The names and numbers python-ldap has, and the pieces that go with them.


def test_every_option_is_named_by_the_number_it_is_known_by() -> None:
    assert ldap.OPT_NAMES_DICT[ldap.OPT_URI] == "OPT_URI"
    assert ldap.OPT_NAMES_DICT[ldap.OPT_X_TLS_CACERTFILE] == "OPT_X_TLS_CACERTFILE"
    # Where several names share a number, it is the one python-ldap answers
    # with: an option and a value an option takes can collide.
    assert ldap.OPT_NAMES_DICT[0] == "OPT_SUCCESS"
    assert ldap.OPT_NAMES_DICT[ldap.OPT_ERROR_NUMBER] == "OPT_ERROR_NUMBER"
    assert ldap.OPT_ERROR_NUMBER == ldap.OPT_RESULT_CODE

    # The request tags, which is what each kind of request goes out under.
    assert ldap.REQ_BIND == 0x60
    assert ldap.REQ_EXTENDED == 0x77
    assert ldap.TAG_MESSAGE == 0x30
    assert ldap.URL_ERR_BADSCOPE == 8
    assert ldap.SYNC_INFO == ldap.syncrepl.SYNC_INFO
    # python-ldap's older name for the class every LDAP error is one of.
    assert ldap.error is ldap.LDAPError


def test_an_option_set_before_a_connection_is_opened_is_on_it() -> None:
    assert ldap.get_option(ldap.OPT_SIZELIMIT) == 0
    ldap.set_option(ldap.OPT_SIZELIMIT, 25)
    try:
        assert ldap.get_option(ldap.OPT_SIZELIMIT) == 25
        assert ldap.initialize("ldap://x").sizelimit == 25
        # A connection made before it was set keeps what it had, and one
        # made without initialize() is not given it either.
        assert ldap.SimpleLDAPObject("ldap://x").sizelimit == 0
        with pytest.raises(ValueError, match="unknown option"):
            ldap.set_option(-1, 1)
    finally:
        del ldap.functions._defaults[ldap.OPT_SIZELIMIT]
    assert ldap.get_option(ldap.OPT_SIZELIMIT) == 0


def test_an_attribute_that_is_an_option_is_set_as_one() -> None:
    connection = ldap.initialize("ldap://x")
    assert set(connection.CLASSATTR_OPTION_MAPPING) == {
        "protocol_version",
        "deref",
        "referrals",
        "timelimit",
        "sizelimit",
        "network_timeout",
    }
    # Assigning goes through set_option, so -1 means what it means there.
    connection.network_timeout = -1
    assert connection.network_timeout is None
    assert connection.get_option(ldap.OPT_NETWORK_TIMEOUT) is None
    connection.network_timeout = 5
    assert connection.get_option(ldap.OPT_NETWORK_TIMEOUT) == 5
    connection.deref = ldap.DEREF_ALWAYS
    assert connection.get_option(ldap.OPT_DEREF) == ldap.DEREF_ALWAYS
    # Anything else is an ordinary attribute.
    connection.timeout = -1
    assert connection.timeout == -1


def test_the_helpers_python_ldap_keeps_beside_the_connection() -> None:
    assert ldap.timegm((2026, 8, 4, 12, 0, 0, 0, 0, 0)) == 1785844800
    assert ldap.functions.explode_dn is ldap.explode_dn
    assert ldap.functions.initialize is ldap.initialize
    assert ldap.functions.LDAPError is ldap.LDAPError

    # A filter narrowed to what changed inside a span of time.
    assert ldap.time_span_filter("(objectClass=*)", 0, 1000) == (
        "(&(objectClass=*)(modifyTimestamp>=19700101000000Z)"
        "(!(modifyTimestamp>=19700101001640Z)))"
    )
    # A negative start is that many seconds before the end of the span.
    recent = ldap.time_span_filter(from_timestamp=-60)
    assert recent.startswith("(&(modifyTimestamp>=")
    assert ldap.time_span_filter(delta_attr="createTimestamp", until_timestamp=1).count(
        "createTimestamp"
    ) == 2
    with pytest.raises(ValueError, match="must not be greater"):
        ldap.time_span_filter(from_timestamp=100, until_timestamp=1)


async def test_an_operation_can_be_stopped_and_collected_by_message_id() -> None:
    root = make_root()
    async with serving(tree_server(root)) as server, bound(server) as connection:
        # Started, then collected: what extop_result() is for.
        msgid = await connection.extop(
            pureldap.LDAPExtendedRequest(requestName=b"1.2.3")
        )
        with pytest.raises(ldap.PROTOCOL_ERROR):
            await connection.extop_result(msgid)

        # abandon_ext is abandon, under the name python-ldap gives it.
        msgid = await connection.search_ext(JACK, ldap.SCOPE_BASE)
        await connection.abandon_ext(msgid)
        assert msgid not in connection._pending

        stream = connection._stream
        assert stream is not None
        assert connection.fileno() == stream.extra(
            anyio.abc.SocketAttribute.raw_socket
        ).fileno()


async def test_a_gssapi_bind_can_be_asked_for_by_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked = []

    def not_installed() -> object:
        asked.append(True)
        raise ImportError("no Kerberos here")

    monkeypatch.setattr(ldap.sasl, "_gssapi", not_installed)
    async with serving(SaslServer) as server, connected(server) as connection:
        with pytest.raises(ImportError, match="no Kerberos here"):
            await connection.sasl_gssapi_bind_s()
    assert asked


def test_an_extended_operation_is_a_name_and_a_value() -> None:
    request = ldap.extop.ExtendedRequest("1.2.3", b"value")
    assert request.encodedRequestValue() == b"value"
    assert repr(request) == "ExtendedRequest(1.2.3,b'value')"

    response = ldap.extop.ExtendedResponse("1.2.3", b"answer")
    assert response.responseValue == b"answer"
    assert repr(response) == "ExtendedResponse(1.2.3,b'answer')"


def test_a_dynamic_entry_is_asked_to_go_on_living() -> None:
    request = ldap.extop.RefreshRequest(
        entryName="cn=dyn,dc=example,dc=com", requestTtl=3600
    )
    assert request.requestName == "1.3.6.1.4.1.1466.101.119.1"
    assert request.encodedRequestValue() == (
        b"0\x1e\x80\x18cn=dyn,dc=example,dc=com\x81\x02\x0e\x10"
    )
    # A request that says nothing else asks for the day the class names.
    assert ldap.extop.RefreshRequest().requestTtl == 86400

    answered = pureber.BERSequence(
        [pureber.BERInteger(1800, tag=pureber.CLASS_CONTEXT | 0x01)]
    ).toWire()
    response = ldap.extop.RefreshResponse("1.3.6.1.4.1.1466.101.119.1", answered)
    assert response.responseTtl == 1800
    assert response.responseValue == 1800


def test_a_password_the_server_made_up_is_read_out_of_the_response() -> None:
    answered = pureber.BERSequence(
        [pureber.BEROctetString(b"s3cret", tag=pureber.CLASS_CONTEXT | 0x00)]
    ).toWire()
    response = ldap.extop.PasswordModifyResponse(None, answered)
    assert response.genPasswd == b"s3cret"
    assert ldap.extop.PasswordModifyResponse.responseName is None


def test_a_control_can_ask_what_an_identity_would_be_allowed_to_do() -> None:
    control = ldap.controls.GetEffectiveRightsControl(True, "dn:cn=jack")
    assert control.controlType == "1.3.6.1.4.1.42.2.27.9.5.2"
    assert control.encodeControlValue() == b"dn:cn=jack"
    assert ldap.controls.GetEffectiveRightsControl().encodeControlValue() is None
    # python-ldap's other spellings of the two that read and write triples.
    assert ldap.controls.DecodeControlTuples is ldap.controls.decode_controls
    assert ldap.controls.EncodeControlTuples is ldap.controls.encode_controls


# The kinds of schema definition that are read word by word.


def test_the_other_kinds_of_definition_say_what_they_say() -> None:
    use = ldap.schema.MatchingRuleUse(
        "( 2.5.13.16 NAME 'bitStringMatch' DESC 'x' OBSOLETE"
        " APPLIES ( givenName $ surname ) )"
    )
    assert use.schema_attribute == "matchingRuleUse"
    assert use.applies == ("givenName", "surname")
    assert use.obsolete == 1
    assert str(use) == (
        "( 2.5.13.16 NAME 'bitStringMatch' DESC 'x' OBSOLETE"
        " APPLIES ( givenName $ surname ) )"
    )
    assert str(ldap.schema.MatchingRuleUse("( 2.5.13.16 )")) == "( 2.5.13.16 )"

    rule = ldap.schema.DITContentRule(
        "( 2.5.6.4 NAME 'org' AUX posixAccount MUST cn MAY ( sn $ l )"
        " NOT description )"
    )
    assert rule.schema_attribute == "dITContentRules"
    assert (rule.aux, rule.must, rule.may, rule.nots) == (
        ("posixAccount",),
        ("cn",),
        ("sn", "l"),
        ("description",),
    )
    assert str(rule) == (
        "( 2.5.6.4 NAME 'org' AUX posixAccount MUST cn MAY ( sn $ l )"
        " NOT description )"
    )

    # A structure rule is numbered rather than named by an OID.
    structure = ldap.schema.DITStructureRule(
        "( 2 NAME 'orgStructure' FORM orgNameForm SUP ( 1 $ 3 ) )"
    )
    assert structure.schema_attribute == "dITStructureRules"
    assert structure.ruleid == "2"
    assert structure.get_id() == "2"
    assert (structure.form, structure.sup) == ("orgNameForm", ("1", "3"))
    assert str(structure) == (
        "( 2 NAME 'orgStructure' FORM orgNameForm SUP ( 1 $ 3 ) )"
    )

    form = ldap.schema.NameForm(
        "( 1.2.3 NAME 'orgNameForm' OC organization MUST o MAY ou )"
    )
    assert form.schema_attribute == "nameForms"
    assert (form.oc, form.must, form.may) == ("organization", ("o",), ("ou",))
    assert str(form) == "( 1.2.3 NAME 'orgNameForm' OC organization MUST o MAY ou )"

    assert ldap.schema.SCHEMA_ATTR_MAPPING[ldap.schema.NameForm] == "nameForms"
    assert ldap.schema.AttributeUsage["dSAOperation"] == 3
    assert "1.3.6.1.4.1.1466.115.121.1.28" in (
        ldap.schema.NOT_HUMAN_READABLE_LDAP_SYNTAXES
    )
    with pytest.raises(NotImplementedError):
        ldap.schema.models._TokenisedElement()._set_attrs([], {})


def test_a_definition_comes_apart_into_the_words_it_is_written_in() -> None:
    split = ldap.schema.split_tokens
    assert split("( 2.5.6.9 NAME 'groupOfNames' )") == [
        "(",
        "2.5.6.9",
        "NAME",
        "groupOfNames",
        ")",
    ]
    # A quote inside a quoted string is escaped, and comes back unescaped.
    assert split(r"( 1.2 DESC 'it\'s here' )")[3] == "it's here"
    # The dollar signs that separate a list are dropped inside parentheses.
    assert split("( 1.2 MUST ( a $ b ) )") == [
        "(", "1.2", "MUST", "(", "a", "b", ")", ")"
    ]
    with pytest.raises(ValueError, match=r"\$' outside parenthesis"):
        split("( 1.2 ) $")
    with pytest.raises(ValueError, match="Unbalanced parenthesis"):
        split("( 1.2 ")

    # What each keyword was given, and what it is worth when unmentioned.
    read = split("( 1.2 NAME 'x' OBSOLETE MUST ( a $ b ) )")
    said = ldap.schema.extract_tokens(
        read, {"NAME": (), "OBSOLETE": None, "MUST": (), "DESC": (None,)}
    )
    assert said == {
        "NAME": ("x",),
        "OBSOLETE": (),
        "MUST": ("a", "b"),
        "DESC": (None,),
    }


def test_an_entry_that_knows_its_schema_is_keyed_by_what_it_holds() -> None:
    sub = ldap.schema.SubSchema(SUBSCHEMA)
    entry = ldap.schema.Entry(
        sub, JACK, {"objectClass": [b"person"], "cn": [b"Jack"]}
    )
    assert entry.dn == JACK
    # However the attribute is spelled, it is the same attribute.
    assert entry["cn"] == entry["commonName"] == entry["2.5.4.3"] == [b"Jack"]
    assert "COMMONNAME" in entry
    assert entry.has_key("cn")
    assert list(entry.keys()) == ["objectClass", "cn"]
    assert entry.items() == [("objectClass", [b"person"]), ("cn", [b"Jack"])]

    # And it can say what an entry of its classes must and may have.
    must, may = entry.attribute_types()
    assert sorted(a.names[0] for a in must.values()) == ["cn", "objectClass", "sn"]
    assert sorted(a.names[0] for a in may.values()) == ["description", "userPassword"]

    entry["sn"] = [b"Smith"]
    assert entry["surname"] == [b"Smith"]
    del entry["sn"]
    assert "sn" not in entry
    # An entry with no object class at all is asked about all the same.
    assert ldap.schema.Entry(sub, JACK, {}).attribute_types() == ({}, {})


def test_a_definition_that_is_not_one_is_refused() -> None:
    with pytest.raises(ValueError):
        ldap.schema.split_tokens("( 1.2 DESC 'unterminated )")


async def test_an_extended_operation_answers_the_message_id_it_was_started_as() -> (
    None
):
    class AnsweringServer(ldapserver.BaseLDAPServer):
        async def handle_LDAPExtendedRequest(
            self,
            request: pureldap.LDAPExtendedRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPExtendedResponse:
            return pureldap.LDAPExtendedResponse(
                resultCode=0, responseName=request.requestName, response=b"answered"
            )

    async with serving(AnsweringServer) as server, connected(server) as connection:
        msgid = await connection.extop(
            pureldap.LDAPExtendedRequest(requestName=b"1.2.3")
        )
        assert await connection.extop_result(msgid) == ("1.2.3", b"answered")
        # Nothing is open until an operation has been awaited, and there is
        # no socket to name before that.
    with pytest.raises(ldap.LDAPError, match="not open"):
        ldap.initialize("ldap://x").fileno()


def test_a_time_span_that_says_nothing_is_the_moment_it_is_asked() -> None:
    assert ldap.time_span_filter().startswith("(&(modifyTimestamp>=")


async def test_the_socket_a_connection_names_is_the_one_under_the_tls() -> None:
    server_context, client_context = tls_pair()
    root = make_root()

    class StartTLSServer(ldapserver.LDAPServer):
        async def handle_LDAPExtendedRequest(
            self,
            request: pureldap.LDAPExtendedRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> None:
            self.start_tls(server_context)
            reply(pureldap.LDAPStartTLSResponse(resultCode=0))

    def factory() -> ldapserver.BaseLDAPServer:
        server = StartTLSServer()
        server.factory = root
        return server

    # Raised after the connection was made: the number does not change.
    async with serving(factory) as server:
        async with connected(
            server, f"ldap://localhost:{server.port}", client_context
        ) as connection:
            await connection.simple_bind_s()
            plain = connection.fileno()
            await connection.start_tls_s()
            assert isinstance(connection._stream, anyio.streams.tls.TLSStream)
            assert connection.fileno() == plain

    # And raised before anything was sent, which is what ldaps:// does.
    async with serving(tree_server(root), server_context) as server:
        async with connected(
            server, f"ldaps://localhost:{server.port}", client_context
        ) as connection:
            await connection.simple_bind_s()
            stream = connection._stream
            assert isinstance(stream, anyio.streams.tls.TLSStream)
            assert connection.fileno() == stream.extra(
                anyio.abc.SocketAttribute.raw_socket
            ).fileno()


async def test_an_extended_response_can_be_read_into_the_class_that_knows_it() -> (
    None
):
    answered = pureber.BERSequence(
        [pureber.BERInteger(1800, tag=pureber.CLASS_CONTEXT | 0x01)]
    ).toWire()

    class RefreshingServer(ldapserver.BaseLDAPServer):
        """A server that answers the refresh request RFC 2589 describes."""

        async def handle_LDAPExtendedRequest(
            self,
            request: pureldap.LDAPExtendedRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPExtendedResponse:
            return pureldap.LDAPExtendedResponse(
                resultCode=0,
                responseName=request.requestName,
                response=answered,
            )

    async with serving(RefreshingServer) as server, connected(server) as connection:
        request = ldap.extop.RefreshRequest(entryName=JACK, requestTtl=3600)
        assert request.requestName is not None
        response = await connection.extop_s(
            pureldap.LDAPExtendedRequest(
                requestName=request.requestName,
                requestValue=request.encodedRequestValue(),
            ),
            None,
            None,
            ldap.extop.RefreshResponse,
        )
        assert response.responseTtl == 1800

        # A server that answered to a different name than the class reads.
        with pytest.raises(ldap.PROTOCOL_ERROR, match="Wrong OID"):
            await connection.extop_s(
                pureldap.LDAPExtendedRequest(requestName=b"1.2.3"),
                None,
                None,
                ldap.extop.RefreshResponse,
            )


async def test_a_control_can_be_read_by_a_class_named_for_the_one_call() -> None:
    class Mine(ldap.controls.ResponseControl):
        """A reading of the paged results control that is not the usual one."""

        def decodeControlValue(self, encodedControlValue: bytes) -> None:
            self.raw = encodedControlValue

    class PagingServer(ldapserver.BaseLDAPServer):
        async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
            await self._send_anyio_write(
                pureldap.LDAPMessage(
                    pureldap.LDAPSearchResultDone(resultCode=0),
                    id=msg.id,
                    controls=[(ldap.CONTROL_PAGEDRESULTS, 0, b"0\x05\x02\x01\x02\x04\x00")],
                ).toWire()
            )

    async with serving(PagingServer) as server, connected(server) as connection:
        msgid = await connection.search_ext("dc=example,dc=com")
        _, _, _, answered = await connection.result3(
            msgid, resp_ctrl_classes={ldap.CONTROL_PAGEDRESULTS: Mine}
        )
        [control] = answered
        assert isinstance(control, Mine)
        assert control.raw == b"0\x05\x02\x01\x02\x04\x00"

        # Without saying so, it is read by the class that is registered.
        msgid = await connection.search_ext("dc=example,dc=com")
        _, _, _, usual = await connection.result3(msgid)
        assert isinstance(usual[0], ldap.controls.SimplePagedResultsControl)


async def test_the_bind_arguments_are_the_ones_python_ldap_takes() -> None:
    servers: list[SaslServer] = []

    def factory() -> ldapserver.BaseLDAPServer:
        server = SaslServer()
        servers.append(server)
        return server

    async with serving(factory) as server, connected(server) as connection:
        # sasl_flags comes before authz_id, as it does in python-ldap: an
        # identity passed positionally lands where it is meant to.
        await connection.sasl_external_bind_s(None, None, ldap.SASL_QUIET, "u:jack")
        assert servers[0].seen == [(b"EXTERNAL", b"u:jack")]

    async with serving(factory) as server, connected(server) as connection:
        # And the mechanism of a step-by-step bind is called mechanism.
        assert await connection.sasl_bind_s(
            "", mechanism="EXTERNAL", cred=b""
        ) is None


async def test_who_the_server_says_we_are_takes_the_controls_it_may() -> None:
    class WhoamiServer(ldapserver.BaseLDAPServer):
        seen: list[list[pureldap.Control]] = []

        async def handle_LDAPExtendedRequest(
            self,
            request: pureldap.LDAPExtendedRequest,
            controls: Iterable[pureldap.Control] | None,
            reply: ldapserver.Reply,
        ) -> pureldap.LDAPExtendedResponse:
            WhoamiServer.seen.append(list(controls or ()))
            return pureldap.LDAPExtendedResponse(
                resultCode=0, responseName=request.requestName, response=b"dn:cn=jack"
            )

    async with serving(WhoamiServer) as server, connected(server) as connection:
        assert await connection.whoami_s(
            [ldap.controls.ManageDSAITControl()]
        ) == "dn:cn=jack"
    assert WhoamiServer.seen[0][0][0] == b"2.16.840.1.113730.3.4.2"


def test_a_schema_that_says_one_thing_twice_is_read_as_python_ldap_reads_it() -> None:
    twice = {
        "objectClasses": [
            b"( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )",
            b"( 2.5.6.6 NAME 'other' STRUCTURAL MUST sn )",
        ]
    }
    # By default both are kept, the second under a name of its own.
    sub = ldap.schema.SubSchema(twice)
    assert sorted(sub.sed[ldap.schema.ObjectClass]) == ["2.5.6.6", "2.5.6.6;1"]
    assert sub.non_unique_oids == ["2.5.6.6"]

    # Asked to be strict about it, the schema is refused.
    with pytest.raises(ldap.schema.OIDNotUnique, match="OID not unique"):
        ldap.schema.SubSchema(twice, check_uniqueness=2)

    # Told not to check, the second simply replaces the first.
    quiet = ldap.schema.SubSchema(twice, check_uniqueness=0)
    assert list(quiet.sed[ldap.schema.ObjectClass]) == ["2.5.6.6"]
    assert quiet.non_unique_oids == []

    # A name claimed twice is refused however it was asked for.
    with pytest.raises(ldap.schema.NameNotUnique, match="NAME not unique"):
        ldap.schema.SubSchema(
            {
                "objectClasses": [
                    b"( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )",
                    b"( 2.5.6.7 NAME 'person' STRUCTURAL MUST sn )",
                ]
            }
        )
    assert issubclass(ldap.schema.OIDNotUnique, ldap.schema.SubschemaError)

    # A name is looked up however it is written, and an empty definition is
    # passed over rather than read.
    sub = ldap.schema.SubSchema({"objectClasses": [b"", SUBSCHEMA["objectClasses"][0]]})
    assert sub.getoid(ldap.schema.ObjectClass, "TOP") == "2.5.6.0"
    assert len(sub.listall(ldap.schema.ObjectClass)) == 1
