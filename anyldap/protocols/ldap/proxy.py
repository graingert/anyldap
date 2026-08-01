"""LDAP protocol proxy server"""

from anyldap._async import await_result
from anyldap.deferred import DeferredSource, maybeDeferred, succeed
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapserver


class Proxy(ldapserver.BaseLDAPServer):
    protocol = ldapclient.LDAPClient

    client = None
    waitingConnect = []
    unbound = False

    def __init__(self, config):
        """
        Initialize the object.

        @param config: The configuration.
        @type config: anyldap.interfaces.ILDAPConfig
        """
        ldapserver.BaseLDAPServer.__init__(self)
        self.config = config

    def _whenConnected(self, fn, *a, **kw):
        if self.client is None:
            d = DeferredSource()
            self.waitingConnect.append((d, fn, a, kw))
            return d.deferred
        else:
            return maybeDeferred(fn, *a, **kw)

    def _cbConnectionMade(self, proto):
        self.client = proto
        while self.waitingConnect:
            d, fn, a, kw = self.waitingConnect.pop(0)
            d2 = maybeDeferred(fn, *a, **kw)
            d2.addCallbacks(d.callback, d.errback)

    def _clientQueue(self, request, controls, reply):
        # TODO controls
        if request.needs_answer:
            self.client.send_multiResponse(request, self._gotResponse, reply)
            # TODO handle errbacks from the deferred above
        else:
            self.client.send_noResponse(request)

    async def _clientQueue_async(self, request, controls, reply):
        if request.needs_answer:
            if hasattr(self.client, "send_multiResponse_async"):
                await self.client.send_multiResponse_async(
                    request, self._gotResponse, reply
                )
            else:
                self.client.send_multiResponse(request, self._gotResponse, reply)
        else:
            if hasattr(self.client, "send_noResponse_async"):
                await self.client.send_noResponse_async(request)
            else:
                self.client.send_noResponse(request)

    def _gotResponse(self, response, reply):
        reply(response)

        # TODO this is ugly
        return isinstance(
            response,
            (
                pureldap.LDAPSearchResultDone,
                pureldap.LDAPBindResponse,
            ),
        )

    def _failConnection(self, reason):
        # TODO self.loseConnection()
        return reason  # TODO

    def connectionMade(self):
        clientCreator = ldapconnector.LDAPClientCreator(None, self.protocol)
        d = clientCreator.connect(
            dn="", overrides=self.config.getServiceLocationOverrides()
        )
        d.addCallback(self._cbConnectionMade)
        d.addErrback(self._failConnection)

        ldapserver.BaseLDAPServer.connectionMade(self)

    def connectionLost(self, reason):
        assert self.client is not None
        if self.client.connected:
            if not self.unbound:
                if hasattr(self.client, "unbind"):
                    self.client.unbind()
                elif hasattr(self.client, "aclose") and self._anyio_task_group is not None:
                    self._anyio_task_group.start_soon(self.client.aclose)
                self.unbound = True
            else:
                if hasattr(self.client, "transport"):
                    self.client.transport.loseConnection()
                elif hasattr(self.client, "aclose") and self._anyio_task_group is not None:
                    self._anyio_task_group.start_soon(self.client.aclose)
        self.client = None
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    def _handleUnknown(self, request, controls, reply):
        self._whenConnected(self._clientQueue, request, controls, reply)

    def handleUnknown(self, request, controls, reply):
        if self._anyio_stream is not None:
            return self._handleUnknown_async(request, controls, reply)
        d = succeed(request)
        d.addCallback(self._handleUnknown, controls, reply)
        return d

    async def _handleUnknown_async(self, request, controls, reply):
        await await_result(self._whenConnected(self._clientQueue_async, request, controls, reply))

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        self.unbound = True
        return self.handleUnknown(request, controls, reply)

    async def connectionMade_async(self):
        ldapserver.BaseLDAPServer.connectionMade(self)
        clientCreator = ldapconnector.LDAPClientCreator(None, self.protocol)
        try:
            proto = await clientCreator.connectAsync(
                dn="",
                overrides=self.config.getServiceLocationOverrides(),
            )
        except Exception as exc:
            self._failConnection(exc)
            return
        self._cbConnectionMade(proto)


if __name__ == "__main__":
    raise SystemExit("Use the AnyIO server entrypoints instead of the legacy demo.")
