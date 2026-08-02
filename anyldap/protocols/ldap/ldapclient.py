"""LDAP protocol client"""

import anyio
from anyio.streams.tls import TLSStream

from anyldap._async import await_deferred
from anyldap.deferred import DeferredSource
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldaperrors
from anyldap.runtime import ConnectionDone, Failure, Protocol, logger


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
            d, _, _, _, _ = v
            d.errback(reason)

    def _send(self, op, controls=None):
        if not self.connected:
            raise LDAPClientConnectionLostException()
        msg = pureldap.LDAPMessage(op, controls=controls)
        if self.debug:
            logger.debug("C->S %s", repr(msg))
        assert msg.id not in self.onwire
        return msg

    def send(self, op, controls=None):
        """
        Send an LDAP operation to the server.
        @param op: the operation to send
        @type op: LDAPProtocolRequest
        @param controls: Any controls to be included in the request.
        @type controls: LDAPControls
        @return: the response from server
        @rtype: Deferred LDAPProtocolResponse
        """
        msg = self._send(op, controls=controls)
        assert op.needs_answer
        source = DeferredSource()
        self.onwire[msg.id] = (source, False, None, None, None)
        self._queue_anyio_write(msg.toWire())
        return source.deferred

    async def send_async(self, op, controls=None):
        msg = self._send(op, controls=controls)
        assert op.needs_answer
        source = DeferredSource()
        self.onwire[msg.id] = (source, False, None, None, None)
        await self._send_anyio_write(msg.toWire())
        return await await_deferred(source.deferred)

    def send_multiResponse(self, op, handler, *args, **kwargs):
        """
        Send an LDAP operation to the server, expecting one or more
        responses.

        If `handler` is provided, it will receive a LDAP response as
        its first argument. The Deferred returned by this function will
        never fire.

        If `handler` is not provided, the Deferred returned by this
        function will fire with the final LDAP response.

        @param op: the operation to send
        @type op: LDAPProtocolRequest
        @param handler: a callable that will be called for each
        response. It should return a boolean, whether this was the
        final response.
        @param args: positional arguments to pass to handler
        @param kwargs: keyword arguments to pass to handler
        @return: the result from the first handler as a deferred that
        completes when the first response has been received
        @rtype: Deferred LDAPProtocolResponse
        """
        msg = self._send(op)
        assert op.needs_answer
        source = DeferredSource()
        self.onwire[msg.id] = (source, False, handler, args, kwargs)
        self._queue_anyio_write(msg.toWire())
        return source.deferred

    async def send_multiResponse_async(self, op, handler, *args, **kwargs):
        msg = self._send(op)
        assert op.needs_answer
        source = DeferredSource()
        self.onwire[msg.id] = (source, False, handler, args, kwargs)
        await self._send_anyio_write(msg.toWire())
        result = await source.deferred
        return result

    def send_multiResponse_ex(self, op, controls=None, handler=None, *args, **kwargs):
        """
        Send an LDAP operation to the server, expecting one or more
        responses.

        If `handler` is provided, it will receive a LDAP response *and*
        response controls as its first 2 arguments. The Deferred returned
        by this function will never fire.

        If `handler` is not provided, the Deferred returned by this
        function will fire with a tuple of the first LDAP response
        and any associated response controls.

        @param op: the operation to send
        @type op: LDAPProtocolRequest
        @param controls: LDAP controls to send with the message.
        @type controls: LDAPControls
        @param handler: a callable that will be called for each
        response. It should return a boolean, whether this was the
        final response.
        @param args: positional arguments to pass to handler
        @param kwargs: keyword arguments to pass to handler
        @return: the result from the last handler as a deferred that
        completes when the last response has been received
        @rtype: Deferred LDAPProtocolResponse
        """
        msg = self._send(op, controls=controls)
        assert op.needs_answer
        source = DeferredSource()
        self.onwire[msg.id] = (source, True, handler, args, kwargs)
        self._queue_anyio_write(msg.toWire())
        return source.deferred

    async def send_multiResponse_ex_async(
        self, op, controls=None, handler=None, *args, **kwargs
    ):
        msg = self._send(op, controls=controls)
        assert op.needs_answer
        source = DeferredSource()
        self.onwire[msg.id] = (source, True, handler, args, kwargs)
        await self._send_anyio_write(msg.toWire())
        result = await source.deferred
        return result

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
            d, return_controls, handler, args, kwargs = self.onwire[msg.id]

            if handler is None:
                assert (args is None) or (args == ())
                assert (kwargs is None) or (kwargs == {})
                if return_controls:
                    d.callback((msg.value, msg.controls))
                else:
                    d.callback(msg.value)
                del self.onwire[msg.id]
            else:
                assert args is not None
                assert kwargs is not None
                # Return true to mark request as fully handled
                if return_controls:
                    if handler(msg.value, msg.controls, *args, **kwargs):
                        d.callback((msg.value, msg.controls))
                        del self.onwire[msg.id]
                else:
                    if handler(msg.value, *args, **kwargs):
                        d.callback(msg.value)
                        del self.onwire[msg.id]

    async def bind_async(self, dn="", auth=""):
        if not self.connected:
            raise LDAPClientConnectionLostException()
        result = await self.send_async(pureldap.LDAPBindRequest(dn=dn, auth=auth))
        return self._handle_bind_msg(result)

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

    async def startTLS_async(self, ctx=None, hostname=None):
        if not self.connected:
            raise LDAPClientConnectionLostException()
        if self.onwire:
            raise LDAPStartTLSBusyError(self.onwire)
        event = anyio.Event()
        op = pureldap.LDAPStartTLSRequest()
        msg = self._send(op)
        source = DeferredSource()
        self.onwire[msg.id] = (source, False, None, None, None)
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
        await await_deferred(source.deferred)
        await event.wait()
        self._tls_upgrade = None
        if tls_upgrade["error"] is not None:
            raise tls_upgrade["error"]
        return self

    async def send_noResponse_async(self, op, controls=None):
        msg = self._send(op, controls=controls)
        assert not op.needs_answer
        await self._send_anyio_write(msg.toWire())

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

    def _queue_anyio_write(self, data):
        if (
            not self.connected
            or self._anyio_stream is None
            or self._anyio_task_group is None
            or self._anyio_write_lock is None
        ):
            raise LDAPClientConnectionLostException()
        self._anyio_task_group.start_soon(self._send_anyio_write, data)

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
