import ssl

import anyio
import anyio.lowlevel
import anyio.streams.tls
import pytest
import trustme

from anyldap import app
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldaperrors, ldapserver

from ._anyio_helpers import MemoryByteStream, local_address

pytestmark = pytest.mark.anyio


def operation(scope: app.Scope) -> app.OperationScope:
    """The scope, once it is known not to be the lifespan one."""
    assert scope["type"] != "lifespan"
    return scope


def decode_message(wire_bytes: bytes) -> pureldap.LDAPMessage:
    message, _ = pureber.berDecodeObject(
        ldapserver.BaseLDAPServer.berdecoder, wire_bytes
    )
    assert isinstance(message, pureldap.LDAPMessage)
    return message


async def echo_result(
    scope: app.Scope, receive: app.Receive, send: app.Send
) -> None:
    """Answer every operation with a search-done carrying its scope type."""
    if scope["type"] == "lifespan":
        # Nothing to set up, so this application does not take one.
        raise NotImplementedError("no lifespan here")
    await send(
        {
            "type": "ldap.response",
            "response": pureldap.LDAPSearchResultDone(
                resultCode=ldaperrors.Success.resultCode,
                errorMessage=scope["type"],
            ),
        }
    )


async def test_operation_type_names_each_request() -> None:
    named = {
        pureldap.LDAPBindRequest(): "ldap.bind",
        pureldap.LDAPUnbindRequest(): "ldap.unbind",
        pureldap.LDAPSearchRequest(): "ldap.search",
        pureldap.LDAPModifyRequest(object="cn=x", modification=[]): "ldap.modify",
        pureldap.LDAPAddRequest(entry="cn=x", attributes=[]): "ldap.add",
        pureldap.LDAPDelRequest(entry="cn=x"): "ldap.delete",
        pureldap.LDAPModifyDNRequest(
            entry="cn=x", newrdn="cn=y", deleteoldrdn=0
        ): "ldap.modifydn",
        pureldap.LDAPCompareRequest(
            entry="cn=x",
            ava=pureldap.LDAPAttributeValueAssertion(
                pureber.BEROctetString("cn"), pureber.BEROctetString("y")
            ),
        ): "ldap.compare",
        pureldap.LDAPAbandonRequest(value=1): "ldap.abandon",
        pureldap.LDAPStartTLSRequest(): "ldap.starttls",
        pureldap.LDAPCancelRequest(cancelID=3): "ldap.cancel",
        pureldap.LDAPPasswordModifyRequest(userIdentity="cn=x"): "ldap.passwordmodify",
        pureldap.LDAPExtendedRequest(requestName=b"1.2.3"): "ldap.extended",
    }
    for request, name in named.items():
        assert app.operation_type(request) == name

    # A request the module has no name for is still given a scope.
    class Homegrown(pureldap.LDAPProtocolRequest):
        pass

    assert app.operation_type(Homegrown()) == "ldap.unknown"


async def test_failure_response_matches_the_operation() -> None:
    for operation, response_type in (
        ("ldap.bind", pureldap.LDAPBindResponse),
        ("ldap.search", pureldap.LDAPSearchResultDone),
        ("ldap.modify", pureldap.LDAPModifyResponse),
        ("ldap.add", pureldap.LDAPAddResponse),
        ("ldap.delete", pureldap.LDAPDelResponse),
        ("ldap.modifydn", pureldap.LDAPModifyDNResponse),
        ("ldap.compare", pureldap.LDAPCompareResponse),
    ):
        response = app.failure_response(operation, "no")
        assert isinstance(response, response_type)
        assert response.resultCode == ldaperrors.LDAPProtocolError.resultCode

    # Anything else is answered the way an unknown extended request is.
    extended = app.failure_response("ldap.extended", "no")
    assert isinstance(extended, pureldap.LDAPExtendedResponse)
    assert extended.responseName == "1.3.6.1.4.1.1466.20036"


async def _attach(
    application: app.LDAPApp, task_group: anyio.abc.TaskGroup
) -> tuple[app.ApplicationServer, MemoryByteStream]:
    server = app.ApplicationServer(application)
    stream = MemoryByteStream()
    await server.attach_stream(stream, task_group)
    return server, stream


async def test_an_operation_is_answered_with_its_scope() -> None:
    seen: list[app.OperationScope] = []

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        seen.append(operation(scope))
        await echo_result(scope, receive, send)

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=7).toWire()
        )
        response = decode_message(await stream.next_write())
        assert response.id == 7
        assert isinstance(response.value, pureldap.LDAPResult)
        assert response.value.errorMessage == b"ldap.search"
        await server.aclose()

    (scope,) = seen
    assert scope["type"] == "ldap.search"
    assert scope["id"] == 7
    assert scope["spec_version"] == app.SPEC_VERSION
    assert scope["controls"] is None
    assert isinstance(scope["request"], pureldap.LDAPSearchRequest)
    connection = scope["connection"]
    assert connection["type"] == "ldap.connection"
    # A stream in memory is neither a socket nor raised with TLS.
    assert connection["server"] is None
    assert connection["client"] is None
    assert not connection["tls"]


async def test_controls_reach_the_scope() -> None:
    seen: list[app.OperationScope] = []

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        seen.append(operation(scope))
        await echo_result(scope, receive, send)

    controls = [(b"1.2.3", False, None)]
    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(
                pureldap.LDAPSearchRequest(), id=1, controls=controls
            ).toWire()
        )
        decode_message(await stream.next_write())
        await server.aclose()

    assert seen[0]["controls"] == controls


async def test_operations_run_concurrently() -> None:
    """The second request is answered while the first is still running."""
    holding = anyio.Event()

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        if operation(scope)["id"] == 1:
            await holding.wait()
        else:
            holding.set()
        await echo_result(scope, receive, send)

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=2).toWire()
        )
        answered = [decode_message(await stream.next_write()).id for _ in range(2)]
        # The one that had to wait is answered last, which it could not be
        # if the reader had waited for it before reading the next request.
        assert answered == [2, 1]
        await server.aclose()


async def test_abandon_stops_an_operation_and_silences_it() -> None:
    started = anyio.Event()
    reason: list[app.ReceiveEvent] = []
    finished = anyio.Event()

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        if scope["type"] != "ldap.search":
            await echo_result(scope, receive, send)
            return
        try:
            with anyio.CancelScope(shield=True):
                started.set()
                reason.append(await receive())
            await anyio.sleep_forever()
        finally:
            # An abandoned operation has nowhere left to write, which
            # saying so is how it finds out.
            with anyio.CancelScope(shield=True):
                with pytest.raises(app.ClientDisconnected, match="abandoned"):
                    await send(
                        {
                            "type": "ldap.response",
                            "response": pureldap.LDAPSearchResultDone(resultCode=0),
                        }
                    )
            finished.set()

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        await started.wait()
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPAbandonRequest(value=1), id=2).toWire()
        )
        await finished.wait()
        assert reason == [{"type": "ldap.abandon"}]
        assert server._operations == {}

        # Nothing was written for the abandoned search, so the next answer
        # on the wire is the one that follows it.
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=3).toWire()
        )
        assert decode_message(await stream.next_write()).id == 3
        await server.aclose()


async def test_abandoning_an_operation_that_has_finished_does_nothing() -> None:
    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(echo_result, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        assert decode_message(await stream.next_write()).id == 1
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPAbandonRequest(value=1), id=2).toWire()
        )
        # Still answering, which it would not be had the abandon raised.
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=3).toWire()
        )
        assert decode_message(await stream.next_write()).id == 3
        await server.aclose()


async def test_cancel_is_answered_by_abandoning_through_the_connection() -> None:
    """RFC 3909: unlike an abandon, a cancel says that it worked."""
    running = anyio.Event()
    stopped = anyio.Event()

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        if scope["type"] == "ldap.cancel":
            request = operation(scope)["request"]
            assert isinstance(request, pureldap.LDAPExtendedRequest)
            operation(scope)["connection"]["abandon"](app.cancel_id(request))
            await send(
                {
                    "type": "ldap.response",
                    "response": pureldap.LDAPExtendedResponse(
                        # canceled, which RFC 3909 adds for this
                        resultCode=118
                    ),
                }
            )
            return
        try:
            running.set()
            await anyio.sleep_forever()
        finally:
            stopped.set()

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        await running.wait()
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPCancelRequest(cancelID=1), id=2).toWire()
        )
        answer = decode_message(await stream.next_write())
        assert answer.id == 2
        assert isinstance(answer.value, pureldap.LDAPResult)
        assert answer.value.resultCode == 118
        await stopped.wait()
        assert server._operations == {}
        await server.aclose()


async def test_cancel_id_reads_the_operation_out_of_the_request() -> None:
    wire = pureldap.LDAPCancelRequest(cancelID=9).toWire()
    decoded, _ = pureber.berDecodeObject(
        ldapserver.BaseLDAPServer.berdecoder,
        pureldap.LDAPMessage(pureldap.LDAPCancelRequest(cancelID=9), id=1).toWire(),
    )
    assert isinstance(decoded, pureldap.LDAPMessage)
    request = decoded.value
    # It arrives as a plain extended request, so the id has to be decoded.
    assert isinstance(request, pureldap.LDAPExtendedRequest)
    assert not isinstance(request, pureldap.LDAPCancelRequest)
    assert app.cancel_id(request) == 9
    assert wire


async def test_an_application_that_fails_still_answers() -> None:
    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        if scope["type"] == "ldap.bind":
            raise ldaperrors.LDAPInvalidCredentials("no")
        raise ValueError("nope")

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        failed = decode_message(await stream.next_write())
        assert isinstance(failed.value, pureldap.LDAPSearchResultDone)
        assert failed.value.resultCode == ldaperrors.LDAPProtocolError.resultCode
        assert failed.value.errorMessage == b"nope"

        # An LDAP error says what it is rather than being logged as a bug.
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        refused = decode_message(await stream.next_write())
        assert isinstance(refused.value, pureldap.LDAPBindResponse)
        assert refused.value.errorMessage == b"no"
        await server.aclose()


async def test_an_unanswered_operation_that_fails_says_nothing() -> None:
    failed = anyio.Event()

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        if scope["type"] == "ldap.unbind":
            failed.set()
            raise ValueError("nope")
        await echo_result(scope, receive, send)

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=1).toWire()
        )
        await failed.wait()
        # Answered, so nothing was written for the unbind before it.
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=2).toWire()
        )
        assert decode_message(await stream.next_write()).id == 2
        await server.aclose()


async def test_unbind_closes_the_connection() -> None:
    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        assert scope["type"] == "ldap.unbind"
        await send({"type": "ldap.close"})

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=1).toWire()
        )
        await stream.closed_event.wait()
        assert stream.closed
        await server.aclose()


async def test_losing_the_connection_tells_an_operation_so() -> None:
    running = anyio.Event()
    seen: list[app.ReceiveEvent] = []

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        running.set()
        seen.append(await receive())

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        await running.wait()
        # The client went away, which the reader finds out about and the
        # application is told.
        await stream.close_input()
        while not seen:
            await anyio.lowlevel.checkpoint()
        assert seen == [{"type": "ldap.disconnect"}]


async def test_an_event_waits_for_an_application_that_is_not_yet_reading() -> None:
    """Delivery waits rather than dropping, and gives up when nothing will read."""
    running = anyio.Event()
    release = anyio.Event()

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        running.set()
        await release.wait()

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        await running.wait()
        await stream.close_input()
        # The event is still waiting to be taken, so letting the operation
        # end is what releases it.
        release.set()


async def test_an_event_with_no_task_group_to_carry_it_is_not_delivered() -> None:
    server = app.ApplicationServer(echo_result)
    operation = app._Operation()
    server._operations[1] = operation
    # No connection was ever attached, so there is nothing to deliver on.
    server.connectionLost(ConnectionError("gone"))
    operation.close()


async def test_a_request_arriving_without_a_connection_is_refused() -> None:
    server = app.ApplicationServer(echo_result)
    with pytest.raises(ldapserver.LDAPServerConnectionLostException):
        await server.handle_async(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1)
        )


async def test_an_unsolicited_notification_is_logged_not_dispatched() -> None:
    answered: list[int] = []

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        answered.append(operation(scope)["id"])

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        server.debug = True
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=0).toWire()
        )
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        while answered != [1]:
            await anyio.lowlevel.checkpoint()
        await server.aclose()


async def test_starttls_raises_the_connection_behind_its_answer() -> None:
    authority = trustme.CA()
    certificate = authority.issue_cert("localhost")
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    certificate.configure_cert(server_context)
    client_context = ssl.create_default_context()
    authority.configure_trust(client_context)

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        if scope["type"] == "ldap.starttls":
            await send({"type": "ldap.starttls", "ssl_context": server_context})
            await send(
                {
                    "type": "ldap.response",
                    "response": pureldap.LDAPStartTLSResponse(resultCode=0),
                }
            )
            return
        await echo_result(scope, receive, send)

    async with anyio.create_task_group() as task_group:
        host, port = await task_group.start(app.listen, application, "127.0.0.1", 0)
        stream = await anyio.connect_tcp(host, port)
        await stream.send(
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedRequest(
                    requestName=pureldap.LDAPStartTLSRequest.oid
                ),
                id=1,
            ).toWire()
        )
        assert decode_message(await stream.receive()).id == 1
        tls = await anyio.streams.tls.TLSStream.wrap(
            stream,
            hostname="localhost",
            ssl_context=client_context,
            standard_compatible=False,
        )
        await tls.send(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=2).toWire()
        )
        answer = decode_message(await tls.receive())
        assert answer.id == 2
        assert isinstance(answer.value, pureldap.LDAPResult)
        assert answer.value.errorMessage == b"ldap.search"
        await tls.aclose()
        task_group.cancel_scope.cancel()


async def test_a_served_connection_knows_both_its_addresses() -> None:
    seen: list[app.ConnectionScope] = []

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        seen.append(operation(scope)["connection"])
        await echo_result(scope, receive, send)

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = local_address(listener)
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(app.serve, listener, application)
        stream = await anyio.connect_tcp(host, port)
        await stream.send(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        assert decode_message(await stream.receive()).id == 1
        await stream.aclose()
        task_group.cancel_scope.cancel()

    assert seen[0]["server"] == (host, port)
    assert seen[0]["client"] is not None
    assert not seen[0]["tls"]


async def test_send_after_the_connection_is_closed_is_refused() -> None:
    running = anyio.Event()
    refused: list[Exception] = []

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        running.set()
        await gone.wait()
        try:
            await send(
                {
                    "type": "ldap.response",
                    "response": pureldap.LDAPSearchResultDone(resultCode=0),
                }
            )
        except app.ClientDisconnected as exc:
            refused.append(exc)

    gone = anyio.Event()
    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        await running.wait()
        await server.aclose()
        gone.set()

    assert [str(exc) for exc in refused] == ["the connection is closed"]


async def test_an_operation_cannot_send_a_lifespan_event() -> None:
    refused: list[str] = []

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        try:
            await send({"type": "lifespan.startup.complete"})
        except TypeError as exc:
            refused.append(str(exc))
        await echo_result(scope, receive, send)

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        assert decode_message(await stream.next_write()).id == 1
        await server.aclose()

    assert refused == ["lifespan.startup.complete is not something an operation sends"]


async def test_lifespan_state_holds_a_task_group_the_connections_use() -> None:
    """The classic shape: a task group open for as long as the server runs."""
    done: list[str] = []
    shutting_down = anyio.Event()

    async def note(dn: str) -> None:
        # Only finishes as the application shuts down, so the task group
        # having waited for it is what the last assertion shows.
        await shutting_down.wait()
        done.append(dn)

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        if scope["type"] == "lifespan":
            assert await receive() == {"type": "lifespan.startup"}
            async with anyio.create_task_group() as background:
                scope["state"]["background"] = background
                await send({"type": "lifespan.startup.complete"})
                assert await receive() == {"type": "lifespan.shutdown"}
                shutting_down.set()
                await send({"type": "lifespan.shutdown.complete"})
            return
        started = operation(scope)["connection"]["state"]["background"]
        assert isinstance(started, anyio.abc.TaskGroup)
        # Work started from a connection, but owned by the application.
        started.start_soon(note, "cn=jack")
        await echo_result(scope, receive, send)

    async with app.lifespan(application) as state:
        async with anyio.create_task_group() as task_group:
            server = app.ApplicationServer(application, state)
            stream = MemoryByteStream()
            await server.attach_stream(stream, task_group)
            await stream.feed(
                pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
            )
            assert decode_message(await stream.next_write()).id == 1
            await server.aclose()
        # Leaving the lifespan is what shuts the application down, and the
        # task group it opened is waited for as it goes.
        assert done == []

    assert done == ["cn=jack"]


async def test_lifespan_runs_startup_and_shutdown_in_order() -> None:
    seen: list[str] = []

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        assert scope["type"] == "lifespan"
        seen.append((await receive())["type"])
        scope["state"]["opened"] = True
        await send({"type": "lifespan.startup.complete"})
        seen.append((await receive())["type"])
        await send({"type": "lifespan.shutdown.complete"})

    async with app.lifespan(application) as state:
        assert state == {"opened": True}
        seen.append("serving")

    assert seen == ["lifespan.startup", "serving", "lifespan.shutdown"]


async def test_an_application_without_a_lifespan_is_served_anyway() -> None:
    async with app.lifespan(echo_result) as state:
        assert state == {}


async def test_startup_that_fails_is_not_served() -> None:
    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        await receive()
        await send({"type": "lifespan.startup.failed", "message": "no database"})

    # Starting up is what fails, so there is never a body to run.
    with pytest.raises(app.LifespanFailed, match="no database"):
        await app.lifespan(application).__aenter__()


async def test_shutdown_that_fails_is_reported() -> None:
    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        await send({"type": "lifespan.shutdown.failed"})

    with pytest.raises(app.LifespanFailed, match="^$"):
        async with app.lifespan(application):
            pass


async def test_an_answer_to_the_wrong_question_is_an_error() -> None:
    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        await receive()
        await send({"type": "lifespan.shutdown.complete"})

    with pytest.raises(app.LifespanFailed, match="answered lifespan.startup"):
        await app.lifespan(application).__aenter__()


async def test_an_application_may_simply_let_the_refusal_out() -> None:
    """Being refused is an answer, not a bug to be reported."""
    running = anyio.Event()
    gone = anyio.Event()

    async def application(
        scope: app.Scope, receive: app.Receive, send: app.Send
    ) -> None:
        if operation(scope)["id"] == 1:
            running.set()
            await gone.wait()
            # Nothing catches this; the operation ends with it, and the
            # connection carries on.
            await send(
                {
                    "type": "ldap.response",
                    "response": pureldap.LDAPSearchResultDone(resultCode=0),
                }
            )
        else:
            await echo_result(scope, receive, send)

    async with anyio.create_task_group() as task_group:
        server, stream = await _attach(application, task_group)
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        await running.wait()
        await stream.feed(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=2).toWire()
        )
        assert decode_message(await stream.next_write()).id == 2
        await server.aclose()
        gone.set()
