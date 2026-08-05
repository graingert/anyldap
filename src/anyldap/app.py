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
Each runs in its own task and its own cancel scope, and the connection
they share is in ``scope["connection"]``, which is where per-connection
state such as the bound user belongs.

A request arrives whole, so it is in the scope rather than being
received. ``receive`` hands over what happens *after* it: the client
abandoning this operation, or the connection going away.
"""

import ssl
from collections.abc import Awaitable, Callable, Sequence
from typing import Literal, TypedDict

import anyio
from anyio.abc import ByteStream, Listener, SocketAttribute
from anyio.streams.tls import TLSStream

from anyldap._encoder import to_bytes
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldaperrors, ldapserver
from anyldap.runtime import Failure, Protocol, logger

#: Which revision of the scopes and events below a scope was built for.
SPEC_VERSION = "0.1"


class ConnectionScope(TypedDict):
    """The connection an operation arrived on, shared by its siblings.

    ``state`` is a plain dict an application may keep whatever it likes
    in; it is what holds the bound user, since a bind on one operation is
    meant to be seen by the next. ``abandon`` stops another operation on
    this connection, which is what answering a Cancel request (RFC 3909)
    needs.
    """

    type: Literal["ldap.connection"]
    spec_version: str
    server: tuple[str, int] | None
    client: tuple[str, int] | None
    tls: bool
    state: dict[str, object]
    abandon: Callable[[int], None]


class OperationScope(TypedDict):
    """One operation: what was asked, and on whose behalf.

    ``type`` names the operation -- ``"ldap.search"``, ``"ldap.bind"`` and
    so on -- so an application can dispatch on it.
    """

    type: str
    spec_version: str
    id: int
    request: pureldap.LDAPProtocolRequest
    controls: Sequence[pureldap.Control] | None
    connection: ConnectionScope


class AbandonEvent(TypedDict):
    """The client abandoned this operation."""

    type: Literal["ldap.abandon"]


class DisconnectEvent(TypedDict):
    """The connection is going away."""

    type: Literal["ldap.disconnect"]


class ResponseEvent(TypedDict):
    """One response, written to the client as it is sent."""

    type: Literal["ldap.response"]
    response: pureber.BERBase


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


ReceiveEvent = AbandonEvent | DisconnectEvent
SendEvent = ResponseEvent | StartTLSEvent | CloseEvent

Receive = Callable[[], Awaitable[ReceiveEvent]]
Send = Callable[[SendEvent], Awaitable[None]]
LDAPApp = Callable[[OperationScope, Receive, Send], Awaitable[None]]


# An extended request arrives as itself, with an OID naming what it asks
# for, so which one it is is read from the OID and not from its class.
_EXTENDED_TYPES: dict[bytes, str] = {
    pureldap.LDAPStartTLSRequest.oid: "ldap.starttls",
    pureldap.LDAPCancelRequest.oid: "ldap.cancel",
    pureldap.LDAPPasswordModifyRequest.oid: "ldap.passwordmodify",
}

_REQUEST_TYPES: tuple[tuple[type[pureldap.LDAPProtocolRequest], str], ...] = (
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

# What to answer with when an application fails, chosen so that a client
# waiting on the operation is answered in the shape it expects.
_FAILURE_RESPONSES: dict[str, type[pureldap.LDAPResult]] = {
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
# the connection acts on it itself.
_UNANSWERED = frozenset({"ldap.unbind"})


def operation_type(request: pureldap.LDAPProtocolRequest) -> str:
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


def cancel_id(request: pureldap.LDAPExtendedRequest) -> int:
    """Which operation a Cancel request names.

    RFC 3909 carries the message id in the request value rather than in
    the request itself, so it has to be decoded before it can be used.
    """
    assert request.requestValue is not None
    sequence, _ = pureber.berDecodeObject(
        pureber.BERDecoderContext(), to_bytes(request.requestValue)
    )
    assert isinstance(sequence, pureber.BERSequence)
    (cancelID,) = sequence
    assert isinstance(cancelID, pureber.BERInteger)
    return cancelID.value


def failure_response(
    operation: str, errorMessage: str | bytes | None
) -> pureldap.LDAPResult:
    """The result to answer a failed operation with.

    An application that raises would otherwise leave a client waiting, so
    something final is sent in its place, of the type that operation is
    answered with.
    """
    response = _FAILURE_RESPONSES.get(operation)
    if response is None:
        return pureldap.LDAPExtendedResponse(
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            responseName="1.3.6.1.4.1.1466.20036",
            errorMessage=errorMessage,
        )
    return response(
        resultCode=ldaperrors.LDAPProtocolError.resultCode,
        errorMessage=errorMessage,
    )


class _Operation:
    """One operation in flight, and the means to stop it."""

    def __init__(self) -> None:
        self.cancel_scope = anyio.CancelScope()
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
    """

    def __init__(self, app: LDAPApp) -> None:
        super().__init__()
        self.app = app
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

    def abandon(self, msgid: int) -> None:
        """Stop the operation with this message id, if it is still running.

        RFC 4511 section 4.11 says an abandoned operation is not answered,
        so its ``send`` stops writing before the task is cancelled. What
        stops the work is the cancellation; the event says why, for an
        application waiting on one.
        """
        operation = self._operations.get(msgid)
        if operation is None:
            return
        operation.abandoned = True
        self._notify(operation, {"type": "ldap.abandon"})
        operation.cancel_scope.cancel()

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
            state={},
            abandon=self.abandon,
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

        operation = _Operation()
        # Registered before the task runs, so an abandon that arrives
        # first still finds it.
        self._operations[msg.id] = operation
        if operation_type(msg.value) == "ldap.starttls":
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
        name = operation_type(msg.value)
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
            with operation.cancel_scope:
                try:
                    await self.app(scope, operation.receive, send)
                except ldaperrors.LDAPException as exc:
                    await self._fail(operation, msg.id, name, exc.message)
                except Exception as exc:
                    logger.exception("Application failed handling %s", name)
                    await self._fail(
                        operation, msg.id, name, Failure(exc).getErrorMessage()
                    )
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
        if name in _UNANSWERED:
            return
        await self._send_event(
            operation,
            msgid,
            {"type": "ldap.response", "response": failure_response(name, errorMessage)},
        )

    async def _send_event(
        self, operation: _Operation, msgid: int, event: SendEvent
    ) -> None:
        if operation.abandoned:
            # An abandoned operation is never answered, so whatever the
            # application had left to say is dropped rather than written.
            return
        if event["type"] == "ldap.response":
            await self._respond(msgid, event["response"])
        elif event["type"] == "ldap.starttls":
            self.start_tls(event["ssl_context"])
        else:
            self._start_anyio_close()


def app_factory(app: LDAPApp) -> Callable[[], ApplicationServer]:
    """A protocol factory serving ``app``, for `listen` and `serve`."""

    def factory() -> ApplicationServer:
        return ApplicationServer(app)

    return factory


async def serve(listener: Listener[ByteStream], app: LDAPApp) -> None:
    """Answer everything that connects to ``listener`` with ``app``."""
    await ldapserver.serve(listener, app_factory(app))


async def listen(
    app: LDAPApp,
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    backlog: int = 65536,
    task_status: anyio.abc.TaskStatus[object] = anyio.TASK_STATUS_IGNORED,
) -> None:
    """Listen for TCP clients and answer them with ``app``.

    The bound address is reported through ``task_status``, so a caller
    that asked for port 0 learns which port it was given.
    """
    await ldapserver.listen(
        host,
        port,
        app_factory(app),
        backlog=backlog,
        task_status=task_status,
    )
