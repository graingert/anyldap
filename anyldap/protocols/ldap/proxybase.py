"""
LDAP protocol proxy server.
"""

from collections.abc import Awaitable, Callable, Iterable

from anyldap._async import await_result
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors, ldapserver
from anyldap.protocols.ldap.ldapclient import LDAPClientLike
from anyldap.runtime import Failure, Protocol, logger

Controls = Iterable[pureldap.Control] | None

# A request waiting for the client connection, with what to answer it on.
Queued = tuple[pureldap.LDAPProtocolRequest, Controls, ldapserver.Reply]


class ProxyBase(ldapserver.BaseLDAPServer):
    """
    An LDAP server proxy.
    Override `handleBeforeForwardRequest()` to inspect/modify requests from
    the client.
    Override `handleProxiedResponse()` to inspect/modify responses from
    the proxied server.
    """

    client: LDAPClientLike | None = None
    unbound = False
    use_tls = False
    clientConnector: (
        Callable[[], LDAPClientLike | Awaitable[LDAPClientLike]] | None
    ) = None

    def __init__(self) -> None:
        ldapserver.BaseLDAPServer.__init__(self)
        # Requests that are ready before the client connection is established
        # are queued.
        self.queuedRequests: list[Queued] = []
        self.startTLS_initiated = False

    def connectionLost(self, reason: BaseException = Protocol.connectionDone) -> None:
        if self.client is not None and self.client.connected:
            if self._anyio_task_group is not None:
                self._anyio_task_group.start_soon(self.client.aclose)
            self.unbound = True
        self.client = None
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    def _failedToConnectToProxiedServer(self, err: Failure) -> None:
        """
        The connection to the proxied server failed.
        """
        logger.error(
            "[ERROR] Could not connect to proxied server.  "
            f"Error was:\n{err}"
        )
        while len(self.queuedRequests) > 0:
            request, controls, reply = self.queuedRequests.pop(0)
            msg: pureldap.LDAPProtocolResponse
            if isinstance(request, pureldap.LDAPBindRequest):
                msg = pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPUnavailable.resultCode
                )
            elif isinstance(request, pureldap.LDAPStartTLSRequest):
                msg = pureldap.LDAPStartTLSResponse(
                    resultCode=ldaperrors.LDAPUnavailable.resultCode
                )
            else:
                continue
            reply(msg)
        self._start_anyio_close()

    async def _processBacklog_async(self) -> None:
        while len(self.queuedRequests) > 0:
            request, controls, reply = self.queuedRequests.pop(0)
            await self._forwardRequestToProxiedServer_async(request, controls, reply)

    async def _forwardRequestToProxiedServer_async(
        self,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> None:
        if self.client is None:
            self.queuedRequests.append((request, controls, reply))
            return

        result = await await_result(
            self.handleBeforeForwardRequest(request, controls, reply)
        )
        if result is None:
            return
        request, controls = result
        if request.needs_answer:
            await self.client.send_multiResponse_async(
                request,
                self._gotResponseFromProxiedServer,
                reply,
                request,
                controls,
            )
        else:
            await self.client.send_noResponse_async(request)

    def handleBeforeForwardRequest(
        self,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> (
        tuple[pureldap.LDAPProtocolRequest, Controls]
        | Awaitable[tuple[pureldap.LDAPProtocolRequest, Controls] | None]
        | None
    ):
        """
        Override to modify request and/or controls forwarded on to the proxied server.
        Must return a tuple of request, controls, or an awaitable of the same.
        Return `None` (or an awaitable of `None`) to bypass forwarding the
        request to the proxied server.  In this case, any response can be sent to the
        client via `reply(response)`.
        """
        return (request, controls)

    def _gotResponseFromProxiedServer(
        self,
        response: pureldap.LDAPProtocolResponse,
        reply: ldapserver.Reply,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
    ) -> bool:
        """
        Returns True if this is the last response to the request.
        """
        reply(self.handleProxiedResponse(response, request, controls))
        return isinstance(
            response,
            (
                pureldap.LDAPSearchResultDone,
                pureldap.LDAPBindResponse,
            ),
        )

    def handleProxiedResponse(
        self,
        response: pureldap.LDAPProtocolResponse,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
    ) -> pureldap.LDAPProtocolResponse:
        """
        Override to intercept and modify proxied responses.
        Must return the modified response.
        """
        return response

    def handleUnknown(  # type: ignore[override]
        self,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> Awaitable[None]:
        """
        Forwards requests to the proxied server.
        This handler is overridden from `anyldap.protocol.ldap.server.BaseServer`.
        And request for which no corresponding `handle_xxx()` method is
        implemented is dispatched to this handler.
        """
        return self._forwardRequestToProxiedServer_async(request, controls, reply)

    async def handle_LDAPExtendedRequest(
        self,
        request: pureldap.LDAPExtendedRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> object:
        """
        Handler for extended LDAP requests (e.g. startTLS).
        """
        if self.debug:
            logger.info("Received extended request: %s", request.requestName)
        if request.requestName == pureldap.LDAPStartTLSRequest.oid:
            return self.handleStartTLSRequest(request, controls, reply)
        return await await_result(self.handleUnknown(request, controls, reply))

    def handleStartTLSRequest(
        self,
        request: pureldap.LDAPExtendedRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> pureldap.LDAPStartTLSResponse | None:
        """
        If the protocol factory has an `options` attribute it is assumed
        to be a TLS context/options object that can be used to initiate TLS
        on the transport.

        Otherwise, this method returns an `unavailable` result code.
        """
        debug_flag = self.debug
        msg: pureldap.LDAPStartTLSResponse | None
        if debug_flag:
            logger.info("Received startTLS request: %r", request)
        if hasattr(self.factory, "options"):
            if self.startTLS_initiated:
                msg = pureldap.LDAPStartTLSResponse(
                    resultCode=ldaperrors.LDAPOperationsError.resultCode
                )
                logger.info(
                    "Session already using TLS.  "
                    "Responding with 'operationsError' (1): " + repr(msg)
                )
            else:
                if debug_flag:
                    logger.info("Setting success result code ...")
                msg = pureldap.LDAPStartTLSResponse(
                    resultCode=ldaperrors.Success.resultCode
                )
                self.start_tls(self.factory.options)
                if debug_flag:
                    logger.info("Replying with successful LDAPStartTLSResponse ...")
                reply(msg)
                self.startTLS_initiated = True
                msg = None
        else:
            msg = pureldap.LDAPStartTLSResponse(
                resultCode=ldaperrors.LDAPUnavailable.resultCode
            )
            logger.info(
                "StartTLS not implemented.  "
                "Responding with 'unavailable' (52): " + repr(msg)
            )
        return msg

    def handle_LDAPUnbindRequest(
        self,
        request: pureldap.LDAPUnbindRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> Awaitable[None]:
        """
        The client has requested to gracefully end the connection.
        Disconnect from the proxied server.
        """
        self.unbound = True
        return self.handleUnknown(request, controls, reply)

    async def connectionMade_async(self) -> None:
        assert self.clientConnector is not None, (
            "You must set the `clientConnector` property on this instance.  "
            "It should be a callable that attempts to connect to a server. "
            "This callable should be awaitable and resolve to a "
            "protocol instance when the connection is complete."
        )
        ldapserver.BaseLDAPServer.connectionMade(self)
        try:
            proto = await await_result(self.clientConnector())
        except Exception as exc:
            self._failedToConnectToProxiedServer(Failure(exc))
            return

        if self.use_tls:
            proto = await proto.startTLS_async()

        self.client = proto
        if not self.connected:
            await self.client.aclose()
            self.client = None
            self.queuedRequests = []
            return
        await self._processBacklog_async()


class ExampleProxy(ProxyBase):
    """
    A simple example of using `ProxyBase` to log responses.
    """

    def handleProxiedResponse(
        self,
        response: pureldap.LDAPProtocolResponse,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
    ) -> pureldap.LDAPProtocolResponse:
        """
        Log the representation of the responses received.
        """
        logger.info("Received response from proxied service: %s", repr(response))
        return response


if __name__ == "__main__":
    raise SystemExit("Use the AnyIO server entrypoints instead of the legacy demo.")
