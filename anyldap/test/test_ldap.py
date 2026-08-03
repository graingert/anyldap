"""Test cases for the anyldap.ldap package, python-ldap's API awaited.

Every connection here is made over a real socket to a real server, so what
is exercised is the wire behaviour rather than a stand-in for it.
"""

import ssl
from collections.abc import AsyncGenerator, Callable, Iterable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

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
        ldap.initialize("ldapi:///var/run/ldapi")
    with pytest.raises(ValueError, match="bad port"):
        ldap.initialize("ldap://ldap.example.com:not-a-port")


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
    assert len(ldap.cidict()) == 0

    entry: ldap.cidict[list[bytes]] = ldap.cidict({"givenName": [b"Jack"]})
    assert entry["givenname"] == [b"Jack"]
    assert "GIVENNAME" in entry
    assert list(entry) == ["givenName"]
    assert len(entry) == 1

    entry["GIVENNAME"] = [b"Jill"]
    # The spelling it was first written in is the one that is kept.
    assert list(entry.items()) == [("givenName", [b"Jill"])]
    assert repr(entry) == "cidict({'givenName': [b'Jill']})"

    entry["sn"] = [b"Smith"]
    del entry["SN"]
    assert list(entry) == ["givenName"]
    with pytest.raises(KeyError):
        entry["missing"]


def test_the_object_python_ldap_hands_back_is_the_one_named_here() -> None:
    assert ldap.LDAPObject is ldapobject.SimpleLDAPObject
    assert ldap.ReconnectLDAPObject is ldapobject.SimpleLDAPObject
    assert isinstance(ldap.initialize("ldap://x"), ldap.SimpleLDAPObject)
