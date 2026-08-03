"""LDAP protocol server"""

import ssl
from collections.abc import Callable, Iterable, Sequence
from contextlib import AsyncExitStack

import anyio
from anyio.abc import ByteStream, Listener, SocketAttribute, TaskGroup
from anyio.streams.tls import TLSStream
from exceptiongroup import suppress

from anyldap import delta, interfaces
from anyldap._async import await_result
from anyldap._encoder import to_bytes, to_unicode
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import distinguishedname, ldaperrors
from anyldap.runtime import ConnectionDone, Failure, Protocol, logger

# A handler is given the response objects to send back one at a time.
Reply = Callable[[pureber.BERBase], object]


class LDAPServerConnectionLostException(ldaperrors.LDAPException):
    pass


class BaseLDAPServer(Protocol):
    debug = False

    def __init__(self) -> None:
        self.buffer = b""
        self.connected: int | None = None
        self._anyio_stream: ByteStream | None = None
        self._anyio_task_group: TaskGroup | None = None
        self._anyio_write_lock: anyio.Lock | None = None
        self._anyio_reader_scope: object = None
        self._anyio_closing = False
        self._anyio_closed_event: anyio.Event | None = None
        # The context to raise TLS with, once the response saying so is out.
        self._tls_upgrade: ssl.SSLContext | None = None

    berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
            fallback=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext()
            ),
            inherit=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext()
            ),
        )
    )

    def connectionMade(self) -> None:
        """TCP connection has opened"""
        self.connected = 1

    async def connectionMade_async(self) -> None:
        self.connectionMade()

    @classmethod
    async def listen(
        cls,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        backlog: int = 65536,
        task_status: anyio.abc.TaskStatus[object] = anyio.TASK_STATUS_IGNORED,
    ) -> None:
        """Listen for TCP clients and report the bound address when ready."""
        await listen(
            host,
            port,
            cls,
            backlog=backlog,
            task_status=task_status,
        )

    def connectionLost(self, reason: BaseException = Protocol.connectionDone) -> None:
        """Called when TCP connection has been lost"""
        self.connected = 0
        self._anyio_stream = None
        self._anyio_task_group = None
        self._anyio_write_lock = None
        self._anyio_reader_scope = None
        self._anyio_closing = False
        self._tls_upgrade = None
        if self._anyio_closed_event is not None:
            self._anyio_closed_event.set()

    async def attach_stream(
        self, stream: ByteStream, task_group: TaskGroup
    ) -> "BaseLDAPServer":
        self._anyio_stream = stream
        self._anyio_task_group = task_group
        self._anyio_closed_event = anyio.Event()
        self._anyio_write_lock = anyio.Lock()
        await self.connectionMade_async()
        task_group.start_soon(self._run_reader)
        return self

    async def aclose(self) -> None:
        stream = self._anyio_stream
        self._anyio_stream = None
        self._anyio_closing = True
        if self.connected:
            self.connectionLost(Failure(ConnectionDone()))
        if stream is not None:
            await stream.aclose()

    async def wait_closed(self) -> None:
        if self._anyio_closed_event is not None:
            await self._anyio_closed_event.wait()

    async def _send_anyio_write(self, data: bytes) -> None:
        lock = self._anyio_write_lock
        if lock is None:
            return
        async with lock:
            stream = self._anyio_stream
            if stream is None:
                return
            try:
                await stream.send(data)
            except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                await self.aclose()

    def start_tls(self, ssl_context: ssl.SSLContext) -> None:
        self._tls_upgrade = ssl_context

    async def _upgrade_to_tls(
        self, ssl_context: ssl.SSLContext, response: bytes
    ) -> None:
        lock = self._anyio_write_lock
        if lock is None:
            raise LDAPServerConnectionLostException()
        async with lock:
            stream = self._anyio_stream
            if stream is None:
                raise LDAPServerConnectionLostException()
            assert response is not None
            await stream.send(response)
            self._anyio_stream = await TLSStream.wrap(
                stream,
                server_side=True,
                ssl_context=ssl_context,
                standard_compatible=False,
            )

    def _start_anyio_close(self) -> None:
        if self._anyio_closing:
            return
        self._anyio_closing = True
        if self._anyio_task_group is not None:
            self._anyio_task_group.start_soon(self.aclose)

    async def _read_from_stream(self) -> None:
        stream = self._anyio_stream
        if stream is None:
            return
        try:
            while True:
                data = await stream.receive()
                await self.data_received_async(data)
                current_stream = self._anyio_stream
                if current_stream is not None:
                    stream = current_stream
        except (anyio.EndOfStream, anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass
        finally:
            if self.connected:
                closing = self._anyio_stream
                self._anyio_stream = None
                assert closing is not None
                await closing.aclose()
                self.connectionLost(Failure(ConnectionDone()))

    async def data_received_async(self, recd: bytes) -> None:
        self.buffer += recd
        while True:
            try:
                message, used = pureber.berDecodeObject(self.berdecoder, self.buffer)
            except pureber.BERExceptionInsufficientData:
                message, used = None, 0
            self.buffer = self.buffer[used:]
            if message is None:
                return
            assert isinstance(message, pureldap.LDAPMessage)
            await self.handle_async(message)

    async def handle_async(self, msg: pureldap.LDAPMessage) -> None:
        assert isinstance(msg.value, pureldap.LDAPProtocolRequest)
        if self.debug:
            logger.debug("S<-C %s", repr(msg))
        if msg.id == 0:
            self.unsolicitedNotification(msg.value)
            return

        name = msg.value.__class__.__name__
        handler = getattr(self, "handle_" + name, self.handleUnknown)
        responses: list[pureber.BERBase] = []
        try:
            result = await await_result(
                handler(msg.value, msg.controls, responses.append)
            )
        except ldaperrors.LDAPException as exc:
            result = self._callErrorHandler(
                name=name,
                resultCode=exc.resultCode,
                errorMessage=exc.message,
            )
        except Exception as exc:
            result = self._cbOtherError(Failure(exc), name)
        if result is not None:
            assert isinstance(result, pureber.BERBase)
            responses.append(result)

        for response in responses:
            message = pureldap.LDAPMessage(response, id=msg.id)
            if self.debug:
                logger.debug("S->C %s", repr(message))
            tls_upgrade = self._tls_upgrade
            if tls_upgrade is None:
                await self._send_anyio_write(message.toWire())
            else:
                self._tls_upgrade = None
                await self._upgrade_to_tls(tls_upgrade, message.toWire())
    async def _run_reader(self) -> None:
        await self._read_from_stream()

    def unsolicitedNotification(self, msg: object) -> None:
        logger.info("Got unsolicited notification: %s", repr(msg))

    def checkControls(self, controls: Iterable[pureldap.Control] | None) -> None:
        if controls is not None:
            for controlType, criticality, controlValue in controls:
                if criticality:
                    raise ldaperrors.LDAPUnavailableCriticalExtension(
                        b"Unknown control %s" % to_bytes(controlType)
                    )

    # Set by whatever is serving this protocol; it holds the tree, or is it.
    factory: object

    def _get_root(self) -> interfaces.IConnectedLDAPEntry:
        if hasattr(self.factory, "root"):
            root = self.factory.root
            assert interfaces.IConnectedLDAPEntry.providedBy(root)
            return root
        return interfaces.IConnectedLDAPEntry(self.factory)

    def handleUnknown(
        self,
        request: pureldap.LDAPProtocolRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> object:
        """What to answer a request with no handler of its own.

        A proxying server overrides this to forward instead, which it does by
        handing back the awaitable that forwards it; the dispatcher awaits
        whatever a handler returns.
        """
        logger.info("Unknown request: %r", request)
        msg = pureldap.LDAPExtendedResponse(
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            responseName="1.3.6.1.4.1.1466.20036",
            errorMessage="Unknown request",
        )
        return msg

    def failDefault(
        self, resultCode: int | None, errorMessage: str | bytes | None
    ) -> pureldap.LDAPExtendedResponse:
        return pureldap.LDAPExtendedResponse(
            resultCode=resultCode,
            responseName="1.3.6.1.4.1.1466.20036",
            errorMessage=errorMessage,
        )

    def _callErrorHandler(
        self, name: str, resultCode: int | None, errorMessage: str | bytes | None
    ) -> object:
        errh = getattr(self, "fail_" + name, self.failDefault)
        return errh(resultCode=resultCode, errorMessage=errorMessage)

    def _cbOtherError(self, reason: Failure, name: str) -> object:
        return self._callErrorHandler(
            name=name,
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            errorMessage=reason.getErrorMessage(),
        )

async def serve_stream(
    stream: ByteStream, protocol_factory: Callable[[], BaseLDAPServer]
) -> BaseLDAPServer:
    server = protocol_factory()
    async with AsyncExitStack() as exit_stack:
        task_group = await exit_stack.enter_async_context(anyio.create_task_group())
        await server.attach_stream(stream, task_group)
        exit_stack.push_async_callback(server.aclose)
        await server.wait_closed()
    return server


async def serve(
    listener: Listener[ByteStream], protocol_factory: Callable[[], BaseLDAPServer]
) -> None:
    async with listener:
        with suppress(anyio.ClosedResourceError):
            await listener.serve(
                lambda stream: serve_stream(stream, protocol_factory)
            )


async def listen(
    host: str,
    port: int,
    protocol_factory: Callable[[], BaseLDAPServer],
    *,
    backlog: int = 65536,
    task_status: anyio.abc.TaskStatus[object] = anyio.TASK_STATUS_IGNORED,
) -> None:
    listener = await anyio.create_tcp_listener(
        local_host=host,
        local_port=port,
        backlog=backlog,
    )
    task_status.started(listener.extra(SocketAttribute.local_address))
    await serve(listener, protocol_factory)


class LDAPServer(BaseLDAPServer):
    """An LDAP server"""

    boundUser: interfaces.ILDAPEntry | None = None

    fail_LDAPBindRequest = pureldap.LDAPBindResponse

    async def handle_LDAPBindRequest(
        self,
        request: pureldap.LDAPBindRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> pureldap.LDAPBindResponse:
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError(
                "Version %u not supported" % request.version
            )

        self.checkControls(controls)

        if request.sasl:
            # The credentials are a (mechanism, credentials) pair, which
            # nothing here knows how to check.
            raise ldaperrors.LDAPAuthMethodNotSupported(
                "SASL authentication is not supported"
            )

        if request.dn == b"":
            # anonymous bind
            self.boundUser = None
            return pureldap.LDAPBindResponse(resultCode=0)

        dn = distinguishedname.DistinguishedName(request.dn)
        root = self._get_root()
        try:
            entry = await root.lookup(dn)
        except ldaperrors.LDAPNoSuchObject:
            raise ldaperrors.LDAPInvalidCredentials()

        assert not isinstance(request.auth, tuple)
        bound = await entry.bind(request.auth)
        self.boundUser = bound
        return pureldap.LDAPBindResponse(
            resultCode=ldaperrors.Success.resultCode,
            matchedDN=bound.dn.getText(),
        )

    def handle_LDAPUnbindRequest(
        self,
        request: pureldap.LDAPUnbindRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> None:
        # explicitly do not check unsupported critical controls -- we
        # have no way to return an error, anyway.
        self._start_anyio_close()

    def getRootDSE(
        self, request: pureldap.LDAPSearchRequest, reply: Reply
    ) -> pureldap.LDAPSearchResultDone:
        root = self._get_root()
        reply(
            pureldap.LDAPSearchResultEntry(
                objectName="",
                attributes=[
                    ("supportedLDAPVersion", ["3"]),
                    ("namingContexts", [root.dn.getText()]),
                    (
                        "supportedExtension",
                        [
                            pureldap.LDAPPasswordModifyRequest.oid,
                        ],
                    ),
                ],
            )
        )
        return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode)

    fail_LDAPCompareRequest = pureldap.LDAPCompareResponse

    async def handle_LDAPCompareRequest(
        self,
        request: pureldap.LDAPCompareRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> pureldap.LDAPCompareResponse:
        self.checkControls(controls)
        dn = distinguishedname.DistinguishedName(request.entry)
        root = self._get_root()

        try:
            base = await root.lookup(dn)
            # base.search only works with Filter Objects, and not with
            # AttributeValueAssertion objects. Here we convert the AVA to an
            # equivalent Filter so we can re-use the existing search
            # functionality we require.
            search_filter = pureldap.LDAPFilter_equalityMatch(
                attributeDesc=request.ava.attributeDesc,
                assertionValue=request.ava.assertionValue,
            )
            result_list = await base.search(
                filterObject=search_filter,
                scope=pureldap.LDAP_SCOPE_baseObject,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
            )
        except ldaperrors.LDAPException as exc:
            return pureldap.LDAPCompareResponse(resultCode=exc.resultCode)
        except Exception as exc:
            logger.exception("Compare request failed")
            return pureldap.LDAPCompareResponse(
                resultCode=ldaperrors.other, errorMessage=Failure(exc).getErrorMessage()
            )

        if result_list:
            resultCode = ldaperrors.LDAPCompareTrue.resultCode
        else:
            resultCode = ldaperrors.LDAPCompareFalse.resultCode
        return pureldap.LDAPCompareResponse(resultCode)

    async def _cbSearchGotBase(
        self,
        base: interfaces.IConnectedLDAPEntry,
        dn: distinguishedname.DistinguishedName,
        request: pureldap.LDAPSearchRequest,
        reply: Reply,
    ) -> pureldap.LDAPSearchResultDone:
        def _sendEntryToClient(entry: interfaces.IConnectedLDAPEntry) -> None:
            requested_attribs = request.attributes or ()
            filtered_attribs: list[tuple[str | bytes, Sequence[str | bytes]]]
            if len(requested_attribs) > 0 and b"*" not in requested_attribs:
                filtered_attribs = [
                    (k, list(entry[k])) for k in requested_attribs if k in entry
                ]
            else:
                filtered_attribs = list(entry.items())
            reply(
                pureldap.LDAPSearchResultEntry(
                    objectName=entry.dn.getText(),
                    attributes=filtered_attribs,
                )
            )

        await base.search(
            filterObject=request.filter,
            attributes=request.attributes,
            scope=request.scope,
            derefAliases=request.derefAliases,
            sizeLimit=request.sizeLimit,
            timeLimit=request.timeLimit,
            typesOnly=request.typesOnly,
            callback=_sendEntryToClient,
        )
        return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode)

    fail_LDAPSearchRequest = pureldap.LDAPSearchResultDone

    async def handle_LDAPSearchRequest(
        self,
        request: pureldap.LDAPSearchRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> pureldap.LDAPSearchResultDone:
        self.checkControls(controls)

        if (
            request.baseObject == b""
            and request.scope == pureldap.LDAP_SCOPE_baseObject
            and request.filter == pureldap.LDAPFilter_present("objectClass")
        ):
            return self.getRootDSE(request, reply)
        dn = distinguishedname.DistinguishedName(request.baseObject)
        root = self._get_root()
        try:
            base = await root.lookup(dn)
            return await self._cbSearchGotBase(base, dn, request, reply)
        except ldaperrors.LDAPException as exc:
            return pureldap.LDAPSearchResultDone(resultCode=exc.resultCode)
        except Exception as exc:
            logger.exception("Search request failed")
            return pureldap.LDAPSearchResultDone(
                resultCode=ldaperrors.other, errorMessage=Failure(exc).getErrorMessage()
            )

    fail_LDAPDelRequest = pureldap.LDAPDelResponse

    async def handle_LDAPDelRequest(
        self,
        request: pureldap.LDAPDelRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> pureldap.LDAPDelResponse:
        self.checkControls(controls)

        dn = distinguishedname.DistinguishedName(request.value)
        root = self._get_root()
        entry = await root.lookup(dn)
        assert interfaces.IEditableLDAPEntry.providedBy(entry)
        await entry.delete()
        return pureldap.LDAPDelResponse(resultCode=0)

    fail_LDAPAddRequest = pureldap.LDAPAddResponse

    async def handle_LDAPAddRequest(
        self,
        request: pureldap.LDAPAddRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> pureldap.LDAPAddResponse:
        self.checkControls(controls)

        attributes: dict[str | bytes, set[str | bytes]] = {}
        assert request.attributes is not None
        for pair in request.attributes:
            name, vals = pair
            assert isinstance(name, pureber.BEROctetString)
            assert isinstance(vals, pureber.BERSequence)
            attributes.setdefault(name.value, set())
            attributes[name.value].update(
                x.value for x in vals if isinstance(x, pureber.BEROctetString)
            )
        dn = distinguishedname.DistinguishedName(request.entry)
        rdn = dn.split()[0].getText()
        root = self._get_root()
        parent = await root.lookup(dn.up())
        await await_result(parent.addChild(rdn, attributes))
        return pureldap.LDAPAddResponse(resultCode=0)

    fail_LDAPModifyDNRequest = pureldap.LDAPModifyDNResponse

    async def handle_LDAPModifyDNRequest(
        self,
        request: pureldap.LDAPModifyDNRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> pureldap.LDAPModifyDNResponse:
        self.checkControls(controls)
        dn = distinguishedname.DistinguishedName(request.entry)
        newrdn = distinguishedname.RelativeDistinguishedName(request.newrdn)
        deleteoldrdn = bool(request.deleteoldrdn)
        if not deleteoldrdn:
            raise ldaperrors.LDAPUnwillingToPerform(
                "Cannot handle preserving old RDN yet."
            )
        if request.newSuperior is None:
            newSuperior = dn.up()
        else:
            newSuperior = distinguishedname.DistinguishedName(request.newSuperior)
        newdn = distinguishedname.DistinguishedName(
            listOfRDNs=(newrdn,) + newSuperior.split()
        )
        root = self._get_root()
        entry = await root.lookup(dn)
        assert interfaces.IEditableLDAPEntry.providedBy(entry)
        await entry.move(newdn)
        return pureldap.LDAPModifyDNResponse(resultCode=0)

    fail_LDAPModifyRequest = pureldap.LDAPModifyResponse

    async def handle_LDAPModifyRequest(
        self,
        request: pureldap.LDAPModifyRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> pureldap.LDAPModifyResponse:
        self.checkControls(controls)

        root = self._get_root()
        mod = delta.ModifyOp.fromLDAP(request)
        entry = await mod.patch(root)
        assert interfaces.IEditableLDAPEntry.providedBy(entry)
        await entry.commit()
        return pureldap.LDAPModifyResponse(resultCode=0)

    fail_LDAPExtendedRequest = pureldap.LDAPExtendedResponse

    async def handle_LDAPExtendedRequest(
        self,
        request: pureldap.LDAPExtendedRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> object:
        self.checkControls(controls)

        for handler in [
            getattr(self, attr)
            for attr in dir(self)
            if attr.startswith("extendedRequest_")
        ]:
            if getattr(handler, "oid", None) == request.requestName:
                berdecoder = getattr(handler, "berdecoder", None)

                values: list[object]
                if berdecoder is None:
                    values = [request.requestValue]
                else:
                    assert isinstance(request.requestValue, bytes)
                    values = list(
                        pureber.berDecodeMultiple(request.requestValue, berdecoder)
                    )

                try:
                    return await await_result(handler(*values, reply=reply))
                except ldaperrors.LDAPException as exc:
                    return pureldap.LDAPExtendedResponse(
                        resultCode=exc.resultCode,
                        errorMessage=exc.message,
                        responseName=request.requestName,
                    )

        raise ldaperrors.LDAPProtocolError(
            b"Unknown extended request: %s" % to_bytes(request.requestName)
        )

    async def extendedRequest_LDAPPasswordModifyRequest(
        self, data: object, reply: Reply
    ) -> pureldap.LDAPExtendedResponse:
        if not isinstance(data, pureber.BERSequence):
            raise ldaperrors.LDAPProtocolError(
                "Extended request PasswordModify expected a BERSequence."
            )

        userIdentity = None
        oldPasswd = None
        newPasswd = None

        for value in data:
            if isinstance(value, pureldap.LDAPPasswordModifyRequest_userIdentity):
                if userIdentity is not None:
                    raise ldaperrors.LDAPProtocolError(
                        "Extended request "
                        "PasswordModify received userIdentity twice."
                    )
                userIdentity = value.value
            elif isinstance(value, pureldap.LDAPPasswordModifyRequest_oldPasswd):
                if oldPasswd is not None:
                    raise ldaperrors.LDAPProtocolError(
                        "Extended request PasswordModify " "received oldPasswd twice."
                    )
                oldPasswd = value.value
            elif isinstance(value, pureldap.LDAPPasswordModifyRequest_newPasswd):
                if newPasswd is not None:
                    raise ldaperrors.LDAPProtocolError(
                        "Extended request PasswordModify " "received newPasswd twice."
                    )
                newPasswd = value.value
            else:
                raise ldaperrors.LDAPProtocolError(
                    "Extended request PasswordModify " "received unexpected item."
                )

        if self.boundUser is None:
            raise ldaperrors.LDAPStrongAuthRequired()

        if userIdentity is not None and userIdentity != self.boundUser.dn:
            logger.info(
                "User %s tried to change password of %s",
                self.boundUser.dn.getText(),
                to_unicode(userIdentity),
            )
            raise ldaperrors.LDAPInsufficientAccessRights()
        if oldPasswd is not None or newPasswd is None:
            raise ldaperrors.LDAPOperationsError("Password does not support this case.")
        assert interfaces.IEditableLDAPEntry.providedBy(self.boundUser)
        self.boundUser.setPassword(to_bytes(newPasswd))
        await self.boundUser.commit()
        return pureldap.LDAPExtendedResponse(
            resultCode=ldaperrors.Success.resultCode,
            responseName=pureldap.LDAPPasswordModifyRequest.oid,
        )

    # An extended request handler carries the oid it answers to, and how to
    # decode the request value, so that handle_LDAPExtendedRequest can find it
    # by looking over its own attributes.
    extendedRequest_LDAPPasswordModifyRequest.oid = (  # type: ignore[attr-defined]
        pureldap.LDAPPasswordModifyRequest.oid
    )
    extendedRequest_LDAPPasswordModifyRequest.berdecoder = (  # type: ignore[attr-defined]
        pureber.BERDecoderContext(
            inherit=pureldap.LDAPBERDecoderContext_LDAPPasswordModifyRequest(
                inherit=pureber.BERDecoderContext()
            )
        )
    )


if __name__ == "__main__":
    raise SystemExit("Run the packaged AnyIO examples instead of this legacy demo.")
