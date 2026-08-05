"""Writing an LDAP server as an application rather than a subclass.

An application is a coroutine function of three arguments -- a scope
saying what is being asked, a ``receive`` handing over events as they
happen, and a ``send`` writing them out::

    async def app(scope, receive, send):
        if scope["type"] == "ldap.search":
            await send({"type": "ldap.response", "response": entry})
        await send({"type": "ldap.response", "response": done})

The shape is borrowed from ASGI, so that anyone who has written a web
application will recognise it, but what a scope describes is an LDAP
*operation* rather than an HTTP request. LDAP multiplexes: a client
numbers its requests and may have several outstanding at once, which is
what abandon is for, so an operation is the unit an application answers.
Each runs in its own task, and the connection they share is in
``scope["connection"]``, which is where per-connection state such as the
bound user belongs.

A request arrives whole, so it is in the scope rather than being
received. ``receive`` hands over what happens *after* it: the client
abandoning this operation, or the connection going away. Once there is
nowhere left to write -- the operation abandoned, or the connection
closed -- ``send`` raises `ClientDisconnected` rather than quietly
throwing the rest of the answer away.

`lifespan` calls the application once more, with a `LifespanScope`, so
that it can open what it needs for as long as it is serving and close it
again afterwards. `listen` and `serve` do that around the listener they
run.
"""

import ssl
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Literal, TypedDict

import anyio
from anyio.abc import ByteStream, Listener, SocketAttribute
from anyio.streams.tls import TLSStream
from typing_extensions import NotRequired

from anyldap._encoder import to_bytes
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldaperrors, ldapserver
from anyldap.runtime import Failure, Protocol, logger

#: Which revision of the scopes and events below a scope was built for.
SPEC_VERSION = "0.1"


class ClientDisconnected(OSError):
    """Raised by ``send`` when there is no longer anywhere to write.

    The client abandoned or cancelled this operation, or the connection
    itself went away. Either way the rest of the answer is not wanted,
    which is what a reset stream means to an HTTP/2 application. It is an
    `OSError`, since a write that cannot happen is what it is.
    """


class LifespanFailed(Exception):
    """The application refused to start up, or failed shutting down."""


#: Every name an operation scope can go by. It is a closed set so that
#: ``scope["type"] == "lifespan"`` tells the two kinds of scope apart.
OperationType = Literal[
    "ldap.bind",
    "ldap.unbind",
    "ldap.search",
    "ldap.modify",
    "ldap.add",
    "ldap.delete",
    "ldap.modifydn",
    "ldap.compare",
    "ldap.abandon",
    "ldap.extended",
    "ldap.starttls",
    "ldap.passwordmodify",
    "ldap.unknown",
]


class ConnectionScope(TypedDict):
    """The connection an operation arrived on, shared by its siblings.

    ``state`` is a plain dict an application may keep whatever it likes
    in; it is what holds the bound user, since a bind on one operation is
    meant to be seen by the next. Every connection starts from a copy of
    what the lifespan scope left behind.
    """

    type: Literal["ldap.connection"]
    spec_version: str
    server: tuple[str, int] | None
    client: tuple[str, int] | None
    tls: bool
    state: dict[str, object]


class OperationScope(TypedDict):
    """One operation: what was asked, and on whose behalf.

    ``type`` names the operation -- ``"ldap.search"``, ``"ldap.bind"`` and
    so on -- so an application can dispatch on it.
    """

    type: OperationType
    spec_version: str
    id: int
    request: pureldap.LDAPProtocolRequest
    controls: Sequence[pureldap.Control] | None
    connection: ConnectionScope


class LifespanScope(TypedDict):
    """The application itself, rather than any one operation.

    It is entered once before the first connection is accepted and left
    once the last one is done with, so it is where an application opens
    whatever it needs for as long as it is serving -- a task group, a
    connection pool -- by keeping it in ``state``. Every connection scope
    starts as a copy of that ``state``.
    """

    type: Literal["lifespan"]
    spec_version: str
    state: dict[str, object]


class StartupEvent(TypedDict):
    """Serving is about to begin."""

    type: Literal["lifespan.startup"]


class ShutdownEvent(TypedDict):
    """Serving has finished."""

    type: Literal["lifespan.shutdown"]


class StartupCompleteEvent(TypedDict):
    """The application is ready to be served."""

    type: Literal["lifespan.startup.complete"]


class StartupFailedEvent(TypedDict):
    """The application cannot start, and says why."""

    type: Literal["lifespan.startup.failed"]
    message: NotRequired[str]


class ShutdownCompleteEvent(TypedDict):
    """The application has finished shutting down."""

    type: Literal["lifespan.shutdown.complete"]


class ShutdownFailedEvent(TypedDict):
    """The application failed to shut down cleanly, and says why."""

    type: Literal["lifespan.shutdown.failed"]
    message: NotRequired[str]


class AbandonEvent(TypedDict):
    """The client abandoned this operation."""

    type: Literal["ldap.abandon"]


class DisconnectEvent(TypedDict):
    """The connection is going away."""

    type: Literal["ldap.disconnect"]


class ResponseEvent(TypedDict):
    """One response, written to the client as it is sent.

    A response may carry controls of its own, which is how a server
    answers a paged search with the cookie for the next page.
    """

    type: Literal["ldap.response"]
    response: pureber.BERBase
    controls: NotRequired[Sequence[pureldap.Control] | None]


class StartTLSEvent(TypedDict):
    """Raise TLS on this connection once the next response is out.

    StartTLS is answered in the clear and the stream raised behind the
    answer, so an application asks for the upgrade and then sends the
    response that goes in front of it.
    """

    type: Literal["ldap.starttls"]
    ssl_context: ssl.SSLContext


class CloseEvent(TypedDict):
    """Close the connection, which is what an unbind asks for."""

    type: Literal["ldap.close"]


Scope = OperationScope | LifespanScope
ReceiveEvent = AbandonEvent | DisconnectEvent | StartupEvent | ShutdownEvent
SendEvent = (
    ResponseEvent
    | StartTLSEvent
    | CloseEvent
    | StartupCompleteEvent
    | StartupFailedEvent
    | ShutdownCompleteEvent
    | ShutdownFailedEvent
)

Receive = Callable[[], Awaitable[ReceiveEvent]]
Send = Callable[[SendEvent], Awaitable[None]]
LDAPApp = Callable[[Scope, Receive, Send], Awaitable[None]]


# An extended request arrives as itself, with an OID naming what it asks
# for, so which one it is is read from the OID and not from its class.
_EXTENDED_TYPES: dict[bytes, OperationType] = {
    pureldap.LDAPStartTLSRequest.oid: "ldap.starttls",
    pureldap.LDAPPasswordModifyRequest.oid: "ldap.passwordmodify",
}

_REQUEST_TYPES: tuple[tuple[type[pureldap.LDAPProtocolRequest], OperationType], ...] = (
    (pureldap.LDAPBindRequest, "ldap.bind"),
    (pureldap.LDAPUnbindRequest, "ldap.unbind"),
    (pureldap.LDAPSearchRequest, "ldap.search"),
    (pureldap.LDAPModifyRequest, "ldap.modify"),
    (pureldap.LDAPAddRequest, "ldap.add"),
    (pureldap.LDAPDelRequest, "ldap.delete"),
    (pureldap.LDAPModifyDNRequest, "ldap.modifydn"),
    (pureldap.LDAPCompareRequest, "ldap.compare"),
    (pureldap.LDAPAbandonRequest, "ldap.abandon"),
)

# What each operation is answered with, so that a client waiting on one is
# answered in the shape it expects.
_RESULT_TYPES: dict[str, type[pureldap.LDAPResult]] = {
    "ldap.bind": pureldap.LDAPBindResponse,
    "ldap.search": pureldap.LDAPSearchResultDone,
    "ldap.modify": pureldap.LDAPModifyResponse,
    "ldap.add": pureldap.LDAPAddResponse,
    "ldap.delete": pureldap.LDAPDelResponse,
    "ldap.modifydn": pureldap.LDAPModifyDNResponse,
    "ldap.compare": pureldap.LDAPCompareResponse,
}

# An unbind is not answered, so a failure in one has nothing to report.
# An abandon is not answered either, but it never reaches an application:
# the connection acts on it itself, as it does on a cancel.
_UNANSWERED = frozenset({"ldap.unbind"})

# What RFC 3909 answers a Cancel with. Unlike an abandon, a cancel says
# whether it worked, and the operation it stopped is told as well.
CANCELED = 118
NO_SUCH_OPERATION = 119


def operation_type(request: pureldap.LDAPProtocolRequest) -> OperationType:
    """What to call this request in a scope.

    Anything with no name of its own is ``"ldap.unknown"``, which an
    application may answer however it sees fit.
    """
    if isinstance(request, pureldap.LDAPExtendedRequest):
        name = request.requestName
        assert name is not None
        return _EXTENDED_TYPES.get(to_bytes(name), "ldap.extended")
    for request_type, operation in _REQUEST_TYPES:
        if isinstance(request, request_type):
            return operation
    return "ldap.unknown"


def _cancel_id(request: pureldap.LDAPExtendedRequest) -> int | None:
    """Which operation a Cancel request names, or nothing if it says.

    RFC 3909 carries the message id in the request value rather than in
    the request itself, so it has to be decoded before it can be used, and
    a client is free to send something that is not one.
    """
    value = request.requestValue
    if value is None:
        return None
    try:
        sequence, _ = pureber.berDecodeObject(
            pureber.BERDecoderContext(), to_bytes(value)
        )
    except (pureber.BERException, pureber.BERExceptionInsufficientData):
        return None
    if not isinstance(sequence, pureber.BERSequence) or len(sequence) != 1:
        return None
    cancelID = sequence[0]
    return cancelID.value if isinstance(cancelID, pureber.BERInteger) else None


def result_response(
    operation: str, resultCode: int, errorMessage: str | bytes | None = None
) -> pureldap.LDAPResult:
    """A result of the type that operation is answered with.

    An application that raises, or an operation that was cancelled, would
    otherwise leave a client waiting, so something final is sent in its
    place -- and it has to be of the right shape, since that is what the
    client is reading for.
    """
    response = _RESULT_TYPES.get(operation)
    if response is None:
        return pureldap.LDAPExtendedResponse(
            resultCode=resultCode,
            responseName="1.3.6.1.4.1.1466.20036",
            errorMessage=errorMessage,
        )
    return response(resultCode=resultCode, errorMessage=errorMessage)


class _Operation:
    """One operation in flight, and the means to stop it."""

    def __init__(self, name: OperationType) -> None:
        self.name = name
        self.abandoned = False
        # Unbuffered: an event is handed straight to an application asking
        # for one, rather than queued to be read after the moment it
        # described has passed. Sending waits for that hand-over, so it is
        # done off the connection's reader.
        self._send, self._receive = anyio.create_memory_object_stream[ReceiveEvent](0)

    async def post(self, event: ReceiveEvent) -> None:
        """Hand an event over, waiting until the application takes it.

        Nothing is queued and nothing is thrown away: the wait is the back
        pressure. It ends early when the operation does, since by then
        there is no one left to read it.
        """
        try:
            await self._send.send(event)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError):
            pass

    async def receive(self) -> ReceiveEvent:
        return await self._receive.receive()

    def close(self) -> None:
        self._send.close()
        self._receive.close()


class ApplicationServer(ldapserver.BaseLDAPServer):
    """A connection that hands each operation to an application.

    Operations run concurrently, as LDAP says they may: reading the next
    request does not wait for the last one to be answered, so an abandon
    can arrive -- and be acted on -- while the search it names is still
    running. StartTLS is the exception, since what follows it is framed
    differently; that one is finished before the next request is read.

    Nothing here cancels an application. Giving up on an operation ends
    the message id, the way resetting an HTTP/2 stream does, and an
    application finds out by being refused when it next sends. When it
    stops is its own business, and a connection is not done until all of
    them have.
    """

    def __init__(self, app: LDAPApp, state: Mapping[str, object] = {}) -> None:
        super().__init__()
        self.app = app
        # What the lifespan scope left behind. Each connection starts from
        # a copy of it, as ASGI has each of its scopes do.
        self.state = state
        self._operations: dict[int, _Operation] = {}
        self._connection_scope: ConnectionScope | None = None

    def connectionLost(self, reason: BaseException = Protocol.connectionDone) -> None:
        # Told before the connection's task group is let go of, since that
        # is what carries the telling.
        for operation in list(self._operations.values()):
            self._notify(operation, {"type": "ldap.disconnect"})
        super().connectionLost(reason)

    def _notify(self, operation: _Operation, event: ReceiveEvent) -> None:
        """Start handing an event to an application.

        Delivery waits for the application to ask for it rather than
        queueing it or dropping it, so it runs in a task of its own and
        the connection's reader is never held up by it.
        """
        task_group = self._anyio_task_group
        if task_group is not None:
            task_group.start_soon(operation.post, event)

    def abandon(self, msgid: int) -> _Operation | None:
        """Give up on the operation with this message id.

        Nothing is cancelled. As with a reset HTTP/2 stream, what ends is
        the message id rather than the work: the operation is no longer
        one this connection will write for, so its ``send`` refuses from
        here on -- which is what RFC 4511 section 4.11 asks of an abandon
        -- and an application waiting on ``receive`` is told why. When it
        stops is the application's own business.

        Answers with the operation that was given up on, if there was one.
        """
        operation = self._operations.pop(msgid, None)
        if operation is None:
            return None
        operation.abandoned = True
        self._notify(operation, {"type": "ldap.abandon"})
        return operation

    async def cancel(self, msgid: int) -> int:
        """Stop an operation the way RFC 3909 says a Cancel does.

        Unlike an abandon, the operation that was stopped is answered --
        with ``canceled``, in whatever shape it was going to be answered
        in -- and so is the Cancel itself. What comes back is the result
        code to answer the Cancel with.
        """
        operation = self.abandon(msgid)
        if operation is None:
            return NO_SUCH_OPERATION
        await self._respond(msgid, result_response(operation.name, CANCELED))
        return CANCELED

    @staticmethod
    def _address(address: tuple[str, int] | str | None) -> tuple[str, int] | None:
        """One end of the connection, when it is one that has an address.

        A socket in the filesystem answers with its path instead, and a
        stream that is not a socket at all answers with nothing.
        """
        return address if isinstance(address, tuple) else None

    async def connectionMade_async(self) -> None:
        """The connection is up, so build the scope its operations share.

        It is built once and handed to each of them, so state an
        application keeps in it outlives the operation that put it there.
        """
        await super().connectionMade_async()
        stream = self._anyio_stream
        assert stream is not None
        self._connection_scope = ConnectionScope(
            type="ldap.connection",
            spec_version=SPEC_VERSION,
            server=self._address(stream.extra(SocketAttribute.local_address, None)),
            client=self._address(stream.extra(SocketAttribute.remote_address, None)),
            tls=isinstance(stream, TLSStream),
            state=dict(self.state),
        )

    async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
        assert isinstance(msg.value, pureldap.LDAPProtocolRequest)
        if self.debug:
            logger.debug("S<-C %s", repr(msg))
        if msg.id == 0:
            self.unsolicitedNotification(msg.value)
            return

        if isinstance(msg.value, pureldap.LDAPAbandonRequest):
            # What it carries is the id of the operation to stop. It is
            # not itself answered, and gets no scope of its own.
            self.abandon(msg.value.value)
            return

        task_group = self._anyio_task_group
        if task_group is None:
            raise ldapserver.LDAPServerConnectionLostException()

        if (
            isinstance(msg.value, pureldap.LDAPExtendedRequest)
            and to_bytes(msg.value.requestName or b"") == pureldap.LDAPCancelRequest.oid
        ):
            # Stopping an operation is the connection's business, not an
            # application's, so a Cancel gets no scope of its own either.
            target = _cancel_id(msg.value)
            code = (
                ldaperrors.LDAPProtocolError.resultCode
                if target is None
                else await self.cancel(target)
            )
            await self._respond(
                msg.id, pureldap.LDAPExtendedResponse(resultCode=code)
            )
            return

        name = operation_type(msg.value)
        operation = _Operation(name)
        # Registered before the task runs, so an abandon that arrives
        # first still finds it.
        self._operations[msg.id] = operation
        if name == "ldap.starttls":
            # Everything after the answer is framed by TLS, so this one is
            # finished before the reader goes back for more.
            await self._run_operation(msg, operation)
        else:
            task_group.start_soon(self._run_operation, msg, operation)

    async def _run_operation(
        self, msg: pureldap.LDAPMessage, operation: _Operation
    ) -> None:
        assert isinstance(msg.value, pureldap.LDAPProtocolRequest)
        connection = self._connection_scope
        assert connection is not None
        name = operation.name
        scope = OperationScope(
            type=name,
            spec_version=SPEC_VERSION,
            id=msg.id,
            request=msg.value,
            controls=None if msg.controls is None else list(msg.controls),
            connection=connection,
        )

        async def send(event: SendEvent) -> None:
            await self._send_event(operation, msg.id, event)

        try:
            await self.app(scope, operation.receive, send)
        except ClientDisconnected:
            # Answered by going away; there is nothing left to say.
            pass
        except ldaperrors.LDAPException as exc:
            await self._fail(operation, msg.id, name, exc.message)
        except Exception as exc:
            logger.exception("Application failed handling %s", name)
            await self._fail(operation, msg.id, name, Failure(exc).getErrorMessage())
        finally:
            operation.close()
            self._operations.pop(msg.id, None)

    async def _fail(
        self,
        operation: _Operation,
        msgid: int,
        name: str,
        errorMessage: str | bytes | None,
    ) -> None:
        if name in _UNANSWERED or operation.abandoned or self._anyio_stream is None:
            # Nothing is owed, or there is nowhere left to say it.
            return
        await self._send_event(
            operation,
            msgid,
            {
                "type": "ldap.response",
                "response": result_response(
                    name, ldaperrors.LDAPProtocolError.resultCode, errorMessage
                ),
            },
        )

    async def _send_event(
        self, operation: _Operation, msgid: int, event: SendEvent
    ) -> None:
        if operation.abandoned:
            raise ClientDisconnected(f"operation {msgid} was abandoned")
        if self._anyio_stream is None:
            raise ClientDisconnected("the connection is closed")
        if event["type"] == "ldap.response":
            await self._respond(msgid, event["response"], event.get("controls"))
        elif event["type"] == "ldap.starttls":
            self.start_tls(event["ssl_context"])
        elif event["type"] == "ldap.close":
            self._start_anyio_close()
        else:
            raise TypeError(f"{event['type']} is not something an operation sends")


def app_factory(
    app: LDAPApp, state: Mapping[str, object] = {}
) -> Callable[[], ApplicationServer]:
    """A protocol factory serving ``app``, for `listen` and `serve`."""

    def factory() -> ApplicationServer:
        return ApplicationServer(app, state)

    return factory


@asynccontextmanager
async def lifespan(app: LDAPApp) -> AsyncIterator[Mapping[str, object]]:
    """Run the application's lifespan scope around whatever is inside.

    The application is called once with a `LifespanScope` and told that
    startup is happening; what it puts in ``scope["state"]`` before
    answering is what every connection then starts from. It is told about
    shutdown when the block ends, which is where an application closes
    what it opened -- and, since it may hold the scope open across the
    whole of it, where a task group it started is waited for.

    An application that will not take a lifespan scope is served without
    one, as the ASGI specification says to do.
    """
    state: dict[str, object] = {}
    scope = LifespanScope(type="lifespan", spec_version=SPEC_VERSION, state=state)
    events_send, events_receive = anyio.create_memory_object_stream[ReceiveEvent](0)
    replies_send, replies_receive = anyio.create_memory_object_stream[SendEvent](0)
    failed: LifespanFailed | None = None

    async def run() -> None:
        try:
            await app(scope, events_receive.receive, replies_send.send)
        except Exception:
            logger.info("Application has no lifespan scope", exc_info=True)
        finally:
            # Closing these is what lets a wait for an answer end when the
            # application is not going to give one.
            events_receive.close()
            replies_send.close()

    async def tell(event: ReceiveEvent, answer: str) -> bool:
        """Say what is happening, and wait for the application to answer.

        Answers ``False`` when there was no lifespan scope to tell, which
        is not an error: an application need not have one. A wrong answer
        is recorded rather than raised, so that it is not raised from
        inside a task group and delivered as a group of one.
        """
        nonlocal failed
        try:
            await events_send.send(event)
            reply = await replies_receive.receive()
        except (
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ):
            return False
        if reply["type"] == "lifespan.startup.failed" or (
            reply["type"] == "lifespan.shutdown.failed"
        ):
            failed = LifespanFailed(reply.get("message", ""))
        elif reply["type"] != answer:
            failed = LifespanFailed(f"{reply['type']} answered {event['type']}")
        return True

    async with (
        events_send,
        replies_receive,
        anyio.create_task_group() as task_group,
    ):
        task_group.start_soon(run)
        told = await tell({"type": "lifespan.startup"}, "lifespan.startup.complete")
        if failed is None:
            try:
                yield state
            finally:
                if told:
                    await tell(
                        {"type": "lifespan.shutdown"}, "lifespan.shutdown.complete"
                    )
    if failed is not None:
        raise failed


async def serve(listener: Listener[ByteStream], app: LDAPApp) -> None:
    """Answer everything that connects to ``listener`` with ``app``."""
    async with lifespan(app) as state:
        await ldapserver.serve(listener, app_factory(app, state))


async def listen(
    app: LDAPApp,
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    backlog: int = 65536,
    task_status: anyio.abc.TaskStatus[object] = anyio.TASK_STATUS_IGNORED,
) -> None:
    """Listen for TCP clients and answer them with ``app``.

    Startup finishes before the socket is bound, so the bound address
    reported through ``task_status`` says that the application is ready as
    well as that the listener is.
    """
    async with lifespan(app) as state:
        await ldapserver.listen(
            host,
            port,
            app_factory(app, state),
            backlog=backlog,
            task_status=task_status,
        )
