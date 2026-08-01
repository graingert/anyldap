"""LDAP protocol server"""

import inspect
from contextlib import AsyncExitStack

import anyio
from anyio.abc import SocketAttribute

from anyldap import delta, interfaces
from anyldap.deferred import (
    Deferred,
    DeferredSource,
    fail,
    logError,
    maybeDeferred,
    succeed,
)
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import distinguishedname, ldaperrors
from anyldap.runtime import ConnectionDone, Failure, Protocol, logger


class LDAPServerConnectionLostException(ldaperrors.LDAPException):
    pass


class _AnyIOTransport:
    def __init__(self, server):
        self.server = server

    def write(self, data):
        self.server._queue_anyio_write(data)

    def loseConnection(self):
        self.server._start_anyio_close()

    def startTLS(self, ctx):
        raise NotImplementedError("STARTTLS is not yet implemented for AnyIO servers")


class BaseLDAPServer(Protocol):
    debug = False

    def __init__(self):
        self.buffer = b""
        self.connected = None
        self._anyio_stream = None
        self._anyio_task_group = None
        self._anyio_send_stream = None
        self._anyio_recv_stream = None
        self._anyio_closing = False
        self._anyio_closed_event = None

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

    def dataReceived(self, recd):
        self.buffer += recd
        while 1:
            try:
                o, bytes = pureber.berDecodeObject(self.berdecoder, self.buffer)
            except pureber.BERExceptionInsufficientData:
                o, bytes = None, 0
            self.buffer = self.buffer[bytes:]
            if o is None:
                break
            self.handle(o)

    def connectionMade(self):
        """TCP connection has opened"""
        self.connected = 1

    def connectionLost(self, reason=Protocol.connectionDone):
        """Called when TCP connection has been lost"""
        self.connected = 0
        self._anyio_stream = None
        self._anyio_task_group = None
        self._anyio_send_stream = None
        self._anyio_recv_stream = None
        self._anyio_closing = False
        if self._anyio_closed_event is not None:
            self._anyio_closed_event.set()

    async def attach_stream(self, stream, task_group):
        self._anyio_stream = stream
        self._anyio_task_group = task_group
        self._anyio_closed_event = anyio.Event()
        self._anyio_send_stream, self._anyio_recv_stream = anyio.create_memory_object_stream(
            100
        )
        self.transport = _AnyIOTransport(self)
        task_group.start_soon(self._write_to_stream)
        task_group.start_soon(self._read_from_stream)
        connection_made_async = getattr(self, "connectionMade_async", None)
        if connection_made_async is None:
            self.connectionMade()
        else:
            await connection_made_async()
        return self

    async def aclose(self):
        send_stream = self._anyio_send_stream
        recv_stream = self._anyio_recv_stream
        stream = self._anyio_stream
        self._anyio_send_stream = None
        self._anyio_recv_stream = None
        self._anyio_stream = None
        self._anyio_closing = True
        if send_stream is not None:
            await send_stream.aclose()
        if recv_stream is not None:
            await recv_stream.aclose()
        if stream is not None:
            await stream.aclose()
        if self.connected:
            self.connectionLost(Failure(ConnectionDone()))

    async def wait_closed(self):
        if self._anyio_closed_event is not None:
            await self._anyio_closed_event.wait()

    def _queue_anyio_write(self, data):
        if not self.connected or self._anyio_send_stream is None:
            raise LDAPServerConnectionLostException()
        self._anyio_send_stream.send_nowait(data)

    def _start_anyio_close(self):
        if self._anyio_closing:
            return
        self._anyio_closing = True
        if self._anyio_task_group is not None:
            self._anyio_task_group.start_soon(self.aclose)

    async def _write_to_stream(self):
        recv_stream = self._anyio_recv_stream
        stream = self._anyio_stream
        if recv_stream is None or stream is None:
            return
        try:
            async with recv_stream:
                async for data in recv_stream:
                    await stream.send(data)
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass
        finally:
            if self.connected:
                await self.aclose()

    async def _read_from_stream(self):
        stream = self._anyio_stream
        if stream is None:
            return
        try:
            while True:
                data = await stream.receive()
                if not data:
                    break
                self.dataReceived(data)
        except (anyio.EndOfStream, anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass
        finally:
            if self.connected:
                await self.aclose()

    async def _resolve_awaitable(self, awaitable, deferred):
        try:
            result = await awaitable
        except Exception as exc:
            deferred.errback(exc)
        else:
            deferred.callback(result)

    def queue(self, id, op):
        if not self.connected:
            raise LDAPServerConnectionLostException()
        msg = pureldap.LDAPMessage(op, id=id)
        if self.debug:
            logger.debug("S->C %s", repr(msg))
        self.transport.write(msg.toWire())

    def unsolicitedNotification(self, msg):
        logger.info("Got unsolicited notification: %s", repr(msg))

    def checkControls(self, controls):
        if controls is not None:
            for controlType, criticality, controlValue in controls:
                if criticality:
                    raise ldaperrors.LDAPUnavailableCriticalExtension(
                        b"Unknown control %s" % controlType
                    )

    def _get_root(self):
        if hasattr(self.factory, "root"):
            return self.factory.root
        return interfaces.IConnectedLDAPEntry(self.factory)

    def handleUnknown(self, request, controls, callback):
        logger.info("Unknown request: %r", request)
        msg = pureldap.LDAPExtendedResponse(
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            responseName="1.3.6.1.4.1.1466.20036",
            errorMessage="Unknown request",
        )
        return msg

    def _cbLDAPError(self, reason, name):
        reason.trap(ldaperrors.LDAPException)
        return self._callErrorHandler(
            name=name,
            resultCode=reason.value.resultCode,
            errorMessage=reason.value.message,
        )

    def _cbHandle(self, response, id):
        if response is not None:
            self.queue(id, response)

    def failDefault(self, resultCode, errorMessage):
        return pureldap.LDAPExtendedResponse(
            resultCode=resultCode,
            responseName="1.3.6.1.4.1.1466.20036",
            errorMessage=errorMessage,
        )

    def _callErrorHandler(self, name, resultCode, errorMessage):
        errh = getattr(self, "fail_" + name, self.failDefault)
        return errh(resultCode=resultCode, errorMessage=errorMessage)

    def _cbOtherError(self, reason, name):
        return self._callErrorHandler(
            name=name,
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            errorMessage=reason.getErrorMessage(),
        )

    def handle(self, msg):
        assert isinstance(msg.value, pureldap.LDAPProtocolRequest)
        if self.debug:
            logger.debug("S<-C %s", repr(msg))

        if msg.id == 0:
            self.unsolicitedNotification(msg.value)
        else:
            name = msg.value.__class__.__name__
            handler = getattr(self, "handle_" + name, self.handleUnknown)
            try:
                result = handler(
                    msg.value,
                    msg.controls,
                    lambda response: self._cbHandle(response, msg.id),
                )
            except Exception as exc:
                d = fail(exc)
            else:
                if isinstance(result, Deferred):
                    d = result
                elif inspect.isawaitable(result):
                    if self._anyio_task_group is None:
                        result.close()
                        d = fail(RuntimeError("async handlers require an AnyIO stream"))
                    else:
                        d = DeferredSource()
                        self._anyio_task_group.start_soon(
                            self._resolve_awaitable, result, d
                        )
                        d = d.deferred
                else:
                    d = succeed(result)
            d.addErrback(self._cbLDAPError, name)
            d.addErrback(logError)
            d.addErrback(self._cbOtherError, name)
            d.addCallback(self._cbHandle, msg.id)


async def serve_stream(stream, protocol_factory):
    server = protocol_factory()
    async with AsyncExitStack() as exit_stack:
        task_group = await exit_stack.enter_async_context(anyio.create_task_group())
        await server.attach_stream(stream, task_group)
        exit_stack.push_async_callback(server.aclose)
        await server.wait_closed()
    return server


async def listen(
    host,
    port,
    protocol_factory,
    *,
    backlog=65536,
    task_status=anyio.TASK_STATUS_IGNORED,
):
    listener = await anyio.create_tcp_listener(
        local_host=host,
        local_port=port,
        backlog=backlog,
    )
    async with listener:
        task_status.started(listener.extra(SocketAttribute.local_address))
        await listener.serve(lambda stream: serve_stream(stream, protocol_factory))


class LDAPServer(BaseLDAPServer):
    """An LDAP server"""

    boundUser = None

    fail_LDAPBindRequest = pureldap.LDAPBindResponse

    def handle_LDAPBindRequest(self, request, controls, reply):
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError(
                "Version %u not supported" % request.version
            )

        self.checkControls(controls)

        if request.dn == b"":
            # anonymous bind
            self.boundUser = None
            return pureldap.LDAPBindResponse(resultCode=0)
        else:
            dn = distinguishedname.DistinguishedName(request.dn)
            root = self._get_root()
            d = root.lookup(dn)

            def _noEntry(fail):
                fail.trap(ldaperrors.LDAPNoSuchObject)

            d.addErrback(_noEntry)

            def _gotEntry(entry, auth):
                if entry is None:
                    raise ldaperrors.LDAPInvalidCredentials()

                d = entry.bind(auth)

                def _cb(entry):
                    self.boundUser = entry
                    msg = pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.Success.resultCode,
                        matchedDN=entry.dn.getText(),
                    )
                    return msg

                d.addCallback(_cb)
                return d

            d.addCallback(_gotEntry, request.auth)

            return d

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        # explicitly do not check unsupported critical controls -- we
        # have no way to return an error, anyway.
        self.transport.loseConnection()

    def getRootDSE(self, request, reply):
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

    def handle_LDAPCompareRequest(self, request, controls, reply):
        def _cbCompareGotBase(base, ava, reply):
            def _done(result_list):
                if result_list:
                    resultCode = ldaperrors.LDAPCompareTrue.resultCode
                else:
                    resultCode = ldaperrors.LDAPCompareFalse.resultCode
                return pureldap.LDAPCompareResponse(resultCode)

            # base.search only works with Filter Objects, and not with
            # AttributeValueAssertion objects. Here we convert the AVA to an
            # equivalent Filter so we can re-use the existing search
            # functionality we require.
            search_filter = pureldap.LDAPFilter_equalityMatch(
                attributeDesc=ava.attributeDesc, assertionValue=ava.assertionValue
            )

            d = base.search(
                filterObject=search_filter,
                scope=pureldap.LDAP_SCOPE_baseObject,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
            )

            d.addCallback(_done)

            return d

        def _cbCompareLDAPError(reason):
            reason.trap(ldaperrors.LDAPException)
            return pureldap.LDAPCompareResponse(resultCode=reason.value.resultCode)

        def _cbCompareOtherError(reason):
            return pureldap.LDAPCompareResponse(
                resultCode=ldaperrors.other, errorMessage=reason.getErrorMessage()
            )

        self.checkControls(controls)
        dn = distinguishedname.DistinguishedName(request.entry)
        root = self._get_root()

        d = root.lookup(dn)
        d.addCallback(_cbCompareGotBase, request.ava, reply)
        d.addErrback(_cbCompareLDAPError)
        d.addErrback(logError)
        d.addErrback(_cbCompareOtherError)
        return d

    def _cbSearchGotBase(self, base, dn, request, reply):
        def _sendEntryToClient(entry):
            requested_attribs = request.attributes
            if len(requested_attribs) > 0 and b"*" not in requested_attribs:
                filtered_attribs = [
                    (k, entry.get(k)) for k in requested_attribs if k in entry
                ]
            else:
                filtered_attribs = entry.items()
            reply(
                pureldap.LDAPSearchResultEntry(
                    objectName=entry.dn.getText(),
                    attributes=filtered_attribs,
                )
            )

        d = base.search(
            filterObject=request.filter,
            attributes=request.attributes,
            scope=request.scope,
            derefAliases=request.derefAliases,
            sizeLimit=request.sizeLimit,
            timeLimit=request.timeLimit,
            typesOnly=request.typesOnly,
            callback=_sendEntryToClient,
        )

        def _done(_):
            return pureldap.LDAPSearchResultDone(
                resultCode=ldaperrors.Success.resultCode
            )

        d.addCallback(_done)
        return d

    def _cbSearchLDAPError(self, reason):
        reason.trap(ldaperrors.LDAPException)
        return pureldap.LDAPSearchResultDone(resultCode=reason.value.resultCode)

    def _cbSearchOtherError(self, reason):
        return pureldap.LDAPSearchResultDone(
            resultCode=ldaperrors.other, errorMessage=reason.getErrorMessage()
        )

    fail_LDAPSearchRequest = pureldap.LDAPSearchResultDone

    def handle_LDAPSearchRequest(self, request, controls, reply):
        self.checkControls(controls)

        if (
            request.baseObject == b""
            and request.scope == pureldap.LDAP_SCOPE_baseObject
            and request.filter == pureldap.LDAPFilter_present("objectClass")
        ):
            return self.getRootDSE(request, reply)
        dn = distinguishedname.DistinguishedName(request.baseObject)
        root = self._get_root()
        d = root.lookup(dn)
        d.addCallback(self._cbSearchGotBase, dn, request, reply)
        d.addErrback(self._cbSearchLDAPError)
        d.addErrback(logError)
        d.addErrback(self._cbSearchOtherError)
        return d

    fail_LDAPDelRequest = pureldap.LDAPDelResponse

    def handle_LDAPDelRequest(self, request, controls, reply):
        self.checkControls(controls)

        dn = distinguishedname.DistinguishedName(request.value)
        root = self._get_root()
        d = root.lookup(dn)

        def _gotEntry(entry):
            d = entry.delete()
            return d

        def _report(entry):
            return pureldap.LDAPDelResponse(resultCode=0)

        d.addCallback(_gotEntry)
        d.addCallback(_report)
        return d

    fail_LDAPAddRequest = pureldap.LDAPAddResponse

    def handle_LDAPAddRequest(self, request, controls, reply):
        self.checkControls(controls)

        attributes = {}
        for name, vals in request.attributes:
            attributes.setdefault(name.value, set())
            attributes[name.value].update([x.value for x in vals])
        dn = distinguishedname.DistinguishedName(request.entry)
        rdn = dn.split()[0].getText()
        parent = dn.up()
        root = self._get_root()
        d = root.lookup(parent)

        def _gotEntry(parent):
            d = parent.addChild(rdn, attributes)
            return d

        def _report(entry):
            return pureldap.LDAPAddResponse(resultCode=0)

        d.addCallback(_gotEntry)
        d.addCallback(_report)
        return d

    fail_LDAPModifyDNRequest = pureldap.LDAPModifyDNResponse

    def handle_LDAPModifyDNRequest(self, request, controls, reply):
        self.checkControls(controls)
        dn = distinguishedname.DistinguishedName(request.entry)
        newrdn = distinguishedname.RelativeDistinguishedName(request.newrdn)
        deleteoldrdn = bool(request.deleteoldrdn)
        if not deleteoldrdn:
            raise ldaperrors.LDAPUnwillingToPerform(
                "Cannot handle preserving old RDN yet."
            )
        newSuperior = request.newSuperior
        if newSuperior is None:
            newSuperior = dn.up()
        else:
            newSuperior = distinguishedname.DistinguishedName(newSuperior)
        newdn = distinguishedname.DistinguishedName(
            listOfRDNs=(newrdn,) + newSuperior.split()
        )
        root = self._get_root()
        d = root.lookup(dn)

        def _gotEntry(entry):
            d = entry.move(newdn)
            return d

        def _report(entry):
            return pureldap.LDAPModifyDNResponse(resultCode=0)

        d.addCallback(_gotEntry)
        d.addCallback(_report)
        return d

    fail_LDAPModifyRequest = pureldap.LDAPModifyResponse

    def handle_LDAPModifyRequest(self, request, controls, reply):
        self.checkControls(controls)

        root = self._get_root()
        mod = delta.ModifyOp.fromLDAP(request)
        d = mod.patch(root)

        def _patched(entry):
            return entry.commit()

        def _report(entry):
            return pureldap.LDAPModifyResponse(resultCode=0)

        d.addCallback(_patched)
        d.addCallback(_report)
        return d

    fail_LDAPExtendedRequest = pureldap.LDAPExtendedResponse

    def handle_LDAPExtendedRequest(self, request, controls, reply):
        self.checkControls(controls)

        for handler in [
            getattr(self, attr)
            for attr in dir(self)
            if attr.startswith("extendedRequest_")
        ]:
            if getattr(handler, "oid", None) == request.requestName:
                berdecoder = getattr(handler, "berdecoder", None)

                if berdecoder is None:
                    values = [request.requestValue]
                else:
                    values = pureber.berDecodeMultiple(request.requestValue, berdecoder)

                d = maybeDeferred(handler, *values, reply=reply)

                def eb(fail, oid):
                    fail.trap(ldaperrors.LDAPException)
                    return pureldap.LDAPExtendedResponse(
                        resultCode=fail.value.resultCode,
                        errorMessage=fail.value.message,
                        responseName=oid,
                    )

                d.addErrback(eb, request.requestName)
                return d

        raise ldaperrors.LDAPProtocolError(
            b"Unknown extended request: %s" % request.requestName
        )

    def extendedRequest_LDAPPasswordModifyRequest(self, data, reply):
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
                f"User {self.boundUser.dn.getText()} tried to change password of {userIdentity}"
            )
            raise ldaperrors.LDAPInsufficientAccessRights()
        if oldPasswd is not None or newPasswd is None:
            raise ldaperrors.LDAPOperationsError("Password does not support this case.")
        self.boundUser.setPassword(newPasswd)
        d = self.boundUser.commit()

        def cb_(result):
            return pureldap.LDAPExtendedResponse(
                resultCode=ldaperrors.Success.resultCode,
                responseName=self.extendedRequest_LDAPPasswordModifyRequest.oid,
            )

        d.addCallback(cb_)
        return d

    extendedRequest_LDAPPasswordModifyRequest.oid = (
        pureldap.LDAPPasswordModifyRequest.oid
    )
    extendedRequest_LDAPPasswordModifyRequest.berdecoder = pureber.BERDecoderContext(
        inherit=pureldap.LDAPBERDecoderContext_LDAPPasswordModifyRequest(
            inherit=pureber.BERDecoderContext()
        )
    )


if __name__ == "__main__":
    raise SystemExit("Run the packaged AnyIO examples instead of this legacy demo.")
