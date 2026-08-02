"""LDAP protocol server"""

from contextlib import AsyncExitStack

import anyio
from anyio.abc import SocketAttribute
from anyio.streams.tls import TLSStream
from exceptiongroup import suppress

from anyldap import delta, interfaces
from anyldap._async import await_result
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import distinguishedname, ldaperrors
from anyldap.runtime import ConnectionDone, Failure, Protocol, logger


class LDAPServerConnectionLostException(ldaperrors.LDAPException):
    pass


class BaseLDAPServer(Protocol):
    debug = False

    def __init__(self):
        self.buffer = b""
        self.connected = None
        self._anyio_stream = None
        self._anyio_task_group = None
        self._anyio_write_lock = None
        self._anyio_reader_scope = None
        self._anyio_closing = False
        self._anyio_closed_event = None
        self._tls_upgrade = None

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

    def connectionMade(self):
        """TCP connection has opened"""
        self.connected = 1

    async def connectionMade_async(self):
        self.connectionMade()

    @classmethod
    async def listen(
        cls,
        host="127.0.0.1",
        port=0,
        *,
        backlog=65536,
        task_status=anyio.TASK_STATUS_IGNORED,
    ):
        """Listen for TCP clients and report the bound address when ready."""
        await listen(
            host,
            port,
            cls,
            backlog=backlog,
            task_status=task_status,
        )

    def connectionLost(self, reason=Protocol.connectionDone):
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

    async def attach_stream(self, stream, task_group):
        self._anyio_stream = stream
        self._anyio_task_group = task_group
        self._anyio_closed_event = anyio.Event()
        self._anyio_write_lock = anyio.Lock()
        await self.connectionMade_async()
        task_group.start_soon(self._run_reader)
        return self

    async def aclose(self):
        stream = self._anyio_stream
        self._anyio_stream = None
        self._anyio_closing = True
        if self.connected:
            self.connectionLost(Failure(ConnectionDone()))
        if stream is not None:
            await stream.aclose()

    async def wait_closed(self):
        if self._anyio_closed_event is not None:
            await self._anyio_closed_event.wait()

    async def _send_anyio_write(self, data):
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

    def start_tls(self, ssl_context):
        self._tls_upgrade = [ssl_context, None]

    async def _upgrade_to_tls(self, ssl_context, response):
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

    def _start_anyio_close(self):
        if self._anyio_closing:
            return
        self._anyio_closing = True
        if self._anyio_task_group is not None:
            self._anyio_task_group.start_soon(self.aclose)

    async def _read_from_stream(self):
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
                stream = self._anyio_stream
                self._anyio_stream = None
                assert stream is not None
                await stream.aclose()
                self.connectionLost(Failure(ConnectionDone()))

    async def data_received_async(self, recd):
        self.buffer += recd
        while True:
            try:
                message, used = pureber.berDecodeObject(self.berdecoder, self.buffer)
            except pureber.BERExceptionInsufficientData:
                message, used = None, 0
            self.buffer = self.buffer[used:]
            if message is None:
                return
            await self.handle_async(message)

    async def handle_async(self, msg):
        assert isinstance(msg.value, pureldap.LDAPProtocolRequest)
        if self.debug:
            logger.debug("S<-C %s", repr(msg))
        if msg.id == 0:
            self.unsolicitedNotification(msg.value)
            return

        name = msg.value.__class__.__name__
        handler = getattr(self, "handle_" + name, self.handleUnknown)
        responses = []
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
                await self._upgrade_to_tls(tls_upgrade[0], message.toWire())
    async def _run_reader(self):
        await self._read_from_stream()

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

async def serve_stream(stream, protocol_factory):
    server = protocol_factory()
    async with AsyncExitStack() as exit_stack:
        task_group = await exit_stack.enter_async_context(anyio.create_task_group())
        await server.attach_stream(stream, task_group)
        exit_stack.push_async_callback(server.aclose)
        await server.wait_closed()
    return server


async def serve(listener, protocol_factory):
    async with listener:
        with suppress(anyio.ClosedResourceError):
            await listener.serve(
                lambda stream: serve_stream(stream, protocol_factory)
            )


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
    task_status.started(listener.extra(SocketAttribute.local_address))
    await serve(listener, protocol_factory)


class LDAPServer(BaseLDAPServer):
    """An LDAP server"""

    boundUser = None

    fail_LDAPBindRequest = pureldap.LDAPBindResponse

    async def handle_LDAPBindRequest(self, request, controls, reply):
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError(
                "Version %u not supported" % request.version
            )

        self.checkControls(controls)

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

        entry = await entry.bind(request.auth)
        self.boundUser = entry
        return pureldap.LDAPBindResponse(
            resultCode=ldaperrors.Success.resultCode,
            matchedDN=entry.dn.getText(),
        )

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        # explicitly do not check unsupported critical controls -- we
        # have no way to return an error, anyway.
        self._start_anyio_close()

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

    async def handle_LDAPCompareRequest(self, request, controls, reply):
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

    async def _cbSearchGotBase(self, base, dn, request, reply):
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

    async def handle_LDAPSearchRequest(self, request, controls, reply):
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

    async def handle_LDAPDelRequest(self, request, controls, reply):
        self.checkControls(controls)

        dn = distinguishedname.DistinguishedName(request.value)
        root = self._get_root()
        entry = await root.lookup(dn)
        await entry.delete()
        return pureldap.LDAPDelResponse(resultCode=0)

    fail_LDAPAddRequest = pureldap.LDAPAddResponse

    async def handle_LDAPAddRequest(self, request, controls, reply):
        self.checkControls(controls)

        attributes = {}
        for name, vals in request.attributes:
            attributes.setdefault(name.value, set())
            attributes[name.value].update([x.value for x in vals])
        dn = distinguishedname.DistinguishedName(request.entry)
        rdn = dn.split()[0].getText()
        parent = dn.up()
        root = self._get_root()
        parent = await root.lookup(parent)
        await await_result(parent.addChild(rdn, attributes))
        return pureldap.LDAPAddResponse(resultCode=0)

    fail_LDAPModifyDNRequest = pureldap.LDAPModifyDNResponse

    async def handle_LDAPModifyDNRequest(self, request, controls, reply):
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
        entry = await root.lookup(dn)
        await entry.move(newdn)
        return pureldap.LDAPModifyDNResponse(resultCode=0)

    fail_LDAPModifyRequest = pureldap.LDAPModifyResponse

    async def handle_LDAPModifyRequest(self, request, controls, reply):
        self.checkControls(controls)

        root = self._get_root()
        mod = delta.ModifyOp.fromLDAP(request)
        entry = await mod.patch(root)
        await entry.commit()
        return pureldap.LDAPModifyResponse(resultCode=0)

    fail_LDAPExtendedRequest = pureldap.LDAPExtendedResponse

    async def handle_LDAPExtendedRequest(self, request, controls, reply):
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

                try:
                    return await await_result(handler(*values, reply=reply))
                except ldaperrors.LDAPException as exc:
                    return pureldap.LDAPExtendedResponse(
                        resultCode=exc.resultCode,
                        errorMessage=exc.message,
                        responseName=request.requestName,
                    )

        raise ldaperrors.LDAPProtocolError(
            b"Unknown extended request: %s" % request.requestName
        )

    async def extendedRequest_LDAPPasswordModifyRequest(self, data, reply):
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
        await self.boundUser.commit()
        return pureldap.LDAPExtendedResponse(
            resultCode=ldaperrors.Success.resultCode,
            responseName=self.extendedRequest_LDAPPasswordModifyRequest.oid,
        )

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
