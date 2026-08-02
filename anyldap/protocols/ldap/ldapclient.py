"""LDAP protocol client"""

import anyio
from anyio.streams.tls import TLSStream

from anyldap._async import ResultSlot
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldaperrors
from anyldap.runtime import ConnectionDone, Failure, Protocol, logger, unwrap_failure


class _PrebufferedStream:
    def __init__(self, stream, buffered):
        self.stream = stream
        self.buffered = buffered

    @property
    def extra_attributes(self):
        return self.stream.extra_attributes

    async def receive(self, max_bytes=65536):
        if self.buffered:
            data = self.buffered[:max_bytes]
            self.buffered = self.buffered[max_bytes:]
            return data
        return await self.stream.receive(max_bytes)

    async def send(self, item):
        await self.stream.send(item)

    async def send_eof(self):
        await self.stream.send_eof()

    async def aclose(self):
        await self.stream.aclose()


class LDAPClientConnectionLostException(ldaperrors.LDAPException):
    def toWire(self):
        return b"Connection lost"


class LDAPStartTLSBusyError(ldaperrors.LDAPOperationsError):
    def __init__(self, onwire, message=None):
        self.onwire = onwire
        ldaperrors.LDAPOperationsError.__init__(self, message=message)

    def toWire(self):
        return b"Cannot STARTTLS while operations on wire: %r" % self.onwire


class LDAPStartTLSInvalidResponseName(ldaperrors.LDAPException):
    def __init__(self, responseName):
        self.responseName = responseName
        ldaperrors.LDAPException.__init__(self)

    def toWire(self):
        return b"Invalid responseName in STARTTLS response: %r" % (self.responseName,)


class LDAPClient(Protocol):
    """An LDAP client"""

    debug = False

    def __init__(self):
        self.onwire = {}
        self.buffer = b""
        self.connected = None
        self._anyio_stream = None
        self._anyio_task_group = None
        self._anyio_write_lock = None
        self._anyio_reader_scope = None
        self._anyio_closing = False
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

    def dataReceived(self, recd):
        self.buffer += recd
        while 1:
            try:
                o, bytes = pureber.berDecodeObject(self.berdecoder, self.buffer)
            except pureber.BERExceptionInsufficientData:
                o, bytes = None, 0
            self.buffer = self.buffer[bytes:]
            if not o:
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
        self._anyio_write_lock = None
        self._anyio_reader_scope = None
        self._anyio_closing = False
        tls_upgrade = self._tls_upgrade
        self._tls_upgrade = None
        if tls_upgrade is not None:
            tls_upgrade["event"].set()
        # notify handlers of operations in flight
        while self.onwire:
            k, v = self.onwire.popitem()
            slot, _, _, _, _ = v
            slot.set_exception(unwrap_failure(reason))

    def _send(self, op, controls=None):
        if not self.connected:
            raise LDAPClientConnectionLostException()
        msg = pureldap.LDAPMessage(op, controls=controls)
        if self.debug:
            logger.debug("C->S %s", repr(msg))
        assert msg.id not in self.onwire
        return msg

    async def send(self, op, controls=None):
        """
        Send an LDAP operation to the server.
        @param op: the operation to send
        @type op: LDAPProtocolRequest
        @param controls: Any controls to be included in the request.
        @type controls: LDAPControls
        @return: the response from server
        @rtype: LDAPProtocolResponse
        """
        return await self._send_and_wait(op, controls, False, None, (), {})

    async def send_multiResponse(self, op, handler, *args, **kwargs):
        """
        Send an LDAP operation to the server, expecting one or more
        responses.

        `handler` receives a LDAP response as its first argument and
        returns a boolean, whether this was the final response. This
        call completes once the handler has claimed a response as final.

        @param op: the operation to send
        @type op: LDAPProtocolRequest
        @param handler: a callable that will be called for each
        response. It should return a boolean, whether this was the
        final response.
        @param args: positional arguments to pass to handler
        @param kwargs: keyword arguments to pass to handler
        @return: the final LDAP response
        @rtype: LDAPProtocolResponse
        """
        return await self._send_and_wait(op, None, False, handler, args, kwargs)

    async def send_multiResponse_ex(
        self, op, controls=None, handler=None, *args, **kwargs
    ):
        """
        Send an LDAP operation to the server, expecting one or more
        responses.

        `handler` receives a LDAP response *and* response controls as its
        first 2 arguments and returns a boolean, whether this was the final
        response.

        @param op: the operation to send
        @type op: LDAPProtocolRequest
        @param controls: LDAP controls to send with the message.
        @type controls: LDAPControls
        @param handler: a callable that will be called for each
        response. It should return a boolean, whether this was the
        final response.
        @param args: positional arguments to pass to handler
        @param kwargs: keyword arguments to pass to handler
        @return: a tuple of the final LDAP response and its controls
        @rtype: tuple
        """
        return await self._send_and_wait(op, controls, True, handler, args, kwargs)

    async def _send_and_wait(self, op, controls, return_controls, handler, args, kwargs):
        msg = self._send(op, controls=controls)
        assert op.needs_answer
        slot = ResultSlot()
        self.onwire[msg.id] = (slot, return_controls, handler, args, kwargs)
        await self._send_anyio_write(msg.toWire())
        return await slot.wait()

    # The `_async` spelling is the documented public API; the shorter names
    # match the LDAP client interface these protocols implement.
    send_async = send
    send_multiResponse_async = send_multiResponse
    send_multiResponse_ex_async = send_multiResponse_ex

    def unsolicitedNotification(self, msg):
        logger.info("Got unsolicited notification: %s", repr(msg))

    def handle(self, msg):
        assert isinstance(msg.value, pureldap.LDAPProtocolResponse)
        if self.debug:
            logger.debug("C<-S %s", repr(msg))

        if msg.id == 0:
            self.unsolicitedNotification(msg.value)
        else:
            tls_upgrade = self._tls_upgrade
            if tls_upgrade is not None and msg.id == tls_upgrade["message_id"]:
                try:
                    self._validate_start_tls_response(msg.value)
                except Exception as exc:
                    tls_upgrade["error"] = exc
                tls_upgrade["response_received"] = True
            slot, return_controls, handler, args, kwargs = self.onwire[msg.id]

            if handler is None:
                assert (args is None) or (args == ())
                assert (kwargs is None) or (kwargs == {})
                if return_controls:
                    slot.set_value((msg.value, msg.controls))
                else:
                    slot.set_value(msg.value)
                del self.onwire[msg.id]
            else:
                assert args is not None
                assert kwargs is not None
                # Return true to mark request as fully handled
                if return_controls:
                    if handler(msg.value, msg.controls, *args, **kwargs):
                        slot.set_value((msg.value, msg.controls))
                        del self.onwire[msg.id]
                else:
                    if handler(msg.value, *args, **kwargs):
                        slot.set_value(msg.value)
                        del self.onwire[msg.id]

    async def bind(self, dn="", auth=""):
        if not self.connected:
            raise LDAPClientConnectionLostException()
        result = await self.send(pureldap.LDAPBindRequest(dn=dn, auth=auth))
        return self._handle_bind_msg(result)

    bind_async = bind

    def _handle_bind_msg(self, msg):
        assert isinstance(msg, pureldap.LDAPBindResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(msg.resultCode, msg.errorMessage)
        return (msg.matchedDN, msg.serverSaslCreds)

    def _validate_start_tls_response(self, msg):
        assert isinstance(msg, pureldap.LDAPExtendedResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(msg.resultCode, msg.errorMessage)

        if (msg.responseName is not None) and (
            msg.responseName != pureldap.LDAPStartTLSResponse.oid
        ):
            raise LDAPStartTLSInvalidResponseName(msg.responseName)

        return msg

    async def startTLS(self, ctx=None, hostname=None):
        if not self.connected:
            raise LDAPClientConnectionLostException()
        if self.onwire:
            raise LDAPStartTLSBusyError(self.onwire)
        event = anyio.Event()
        op = pureldap.LDAPStartTLSRequest()
        msg = self._send(op)
        slot = ResultSlot()
        self.onwire[msg.id] = (slot, False, None, None, None)
        tls_upgrade = {
            "context": ctx,
            "hostname": hostname,
            "event": event,
            "message_id": msg.id,
            "response_received": False,
            "error": None,
        }
        self._tls_upgrade = tls_upgrade
        await self._send_anyio_write(msg.toWire())
        await slot.wait()
        await event.wait()
        self._tls_upgrade = None
        if tls_upgrade["error"] is not None:
            raise tls_upgrade["error"]
        return self

    startTLS_async = startTLS

    async def send_noResponse(self, op, controls=None):
        msg = self._send(op, controls=controls)
        assert not op.needs_answer
        await self._send_anyio_write(msg.toWire())

    send_noResponse_async = send_noResponse

    async def attach_stream(self, stream, task_group):
        self._anyio_stream = stream
        self._anyio_task_group = task_group
        self._anyio_write_lock = anyio.Lock()
        self.connectionMade()
        task_group.start_soon(self._run_reader, stream)
        return self

    async def aclose(self):
        stream = self._anyio_stream
        self._anyio_stream = None
        self._anyio_closing = True
        if self.connected:
            self.connectionLost(Failure(ConnectionDone()))
        if stream is not None:
            await stream.aclose()

    async def _read_from_stream(self, stream):
        try:
            while True:
                data = await stream.receive()
                tls_upgrade = self._tls_upgrade
                if tls_upgrade is None:
                    self.dataReceived(data)
                else:
                    self.buffer += data
                    try:
                        message, used = pureber.berDecodeObject(
                            self.berdecoder, self.buffer
                        )
                    except pureber.BERExceptionInsufficientData:
                        continue
                    self.buffer = self.buffer[used:]
                    self.handle(message)
                if tls_upgrade is not None and tls_upgrade["response_received"]:
                    if tls_upgrade["error"] is None:
                        try:
                            await self._upgrade_to_tls(
                                tls_upgrade["context"],
                                tls_upgrade["hostname"],
                                self.buffer,
                            )
                            self.buffer = b""
                        except Exception as exc:
                            tls_upgrade["error"] = exc
                    tls_upgrade["event"].set()
                    stream = self._anyio_stream
                    assert stream is not None
        except (anyio.EndOfStream, anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass
        finally:
            if self.connected:
                stream = self._anyio_stream
                self._anyio_stream = None
                assert stream is not None
                await stream.aclose()
                self.connectionLost(Failure(ConnectionDone()))

    async def _run_reader(self, stream):
        await self._read_from_stream(stream)

    async def _upgrade_to_tls(self, ssl_context, hostname, buffered=b""):
        lock = self._anyio_write_lock
        if lock is None:
            raise LDAPClientConnectionLostException()
        async with lock:
            stream = self._anyio_stream
            if stream is None:
                raise LDAPClientConnectionLostException()
            stream = _PrebufferedStream(stream, buffered)
            self._anyio_stream = await TLSStream.wrap(
                stream,
                server_side=False,
                hostname=hostname,
                ssl_context=ssl_context,
                standard_compatible=False,
            )

    async def _send_anyio_write(self, data):
        lock = self._anyio_write_lock
        if not self.connected or lock is None:
            raise LDAPClientConnectionLostException()
        async with lock:
            stream = self._anyio_stream
            if stream is None:
                raise LDAPClientConnectionLostException()
            try:
                await stream.send(data)
            except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                await self.aclose()
