"""LDAP protocol server, which acts as a proxy which
   forwards the requests to multiple LDAP servers and
   merges the results.
   Only Bind and Search requests are supported.
"""

from functools import partial
from queue import Queue

from anyldap._async import await_result
from anyldap.deferred import DeferredSource, logError, maybeDeferred, succeed
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldaperrors, ldapserver


class MergedLDAPServer(ldapserver.BaseLDAPServer):
    protocol = ldapclient.LDAPClient

    def __init__(self, configs, use_tls):
        ldapserver.BaseLDAPServer.__init__(self)
        self.clients = []
        self.configs = configs
        self.use_tls = use_tls
        self.all_connected = False
        self.merge_map = {}
        self.waitingConnect = []
        self.unbound = False

    def _whenConnected(self, fn, *a, **kw):
        if not self.all_connected:
            d = DeferredSource()
            self.waitingConnect.append((d, fn, a, kw))
            return d.deferred
        else:
            return maybeDeferred(fn, *a, **kw)

    def _failConnection(self, reason):
        self._start_anyio_close()
        raise ldaperrors.LDAPOther(f"Cannot connect to server.{reason}")

    def _cbConnectionMade(self, proto):
        self.clients.append(proto)

        if len(self.clients) == len(self.configs):
            self.all_connected = True

        # Only call once when all clients are connected.
        if self.all_connected:
            while self.waitingConnect:
                d, fn, a, kw = self.waitingConnect.pop(0)
                d2 = maybeDeferred(fn, *a, **kw)
                d2.addCallbacks(d.callback, d.errback)

    def _clientQueue(self, request, controls, reply):
        # Controls are ignored.
        for c in self.clients:
            if request.needs_answer:
                d = c.send_multiResponse(request, self._gotResponse, reply)
                d.addErrback(logError)
            else:
                c.send_noResponse(request)

    def queue(self, id, op):
        if isinstance(op, (pureldap.LDAPSearchResultDone, pureldap.LDAPBindResponse)):
            if id not in self.merge_map:
                self.merge_map[id] = Queue(len(self.clients))
                self.merge_map[id].put(op)
            else:
                self.merge_map[id].put(op)

            if self.merge_map[id].full():
                # Send success, if at least one success.
                for i in range(len(self.clients)):
                    r = self.merge_map[id].get()
                    if r.resultCode == ldaperrors.Success.resultCode:
                        op = r
                del self.merge_map[id]
                ldapserver.BaseLDAPServer.queue(self, id, op)
        else:
            ldapserver.BaseLDAPServer.queue(self, id, op)

    def connectionMade(self):
        clientCreator = ldapconnector.LDAPClientCreator(None, self.protocol)
        for (c, tls) in zip(self.configs, self.use_tls):
            d = clientCreator.connect(dn="", overrides=c.getServiceLocationOverrides())
            if tls:
                d.addCallback(lambda x: x.startTLS())
            d.addCallback(self._cbConnectionMade)
            d.addErrback(self._failConnection)

        ldapserver.BaseLDAPServer.connectionMade(self)

    async def connectionMade_async(self):
        ldapserver.BaseLDAPServer.connectionMade(self)
        clientCreator = ldapconnector.LDAPClientCreator(None, self.protocol)
        try:
            for c, tls in zip(self.configs, self.use_tls):
                connector = partial(
                    clientCreator.connectAsync,
                    dn="",
                    overrides=c.getServiceLocationOverrides(),
                    tls=tls,
                )
                proto = await connector()
                await await_result(self._cbConnectionMade(proto))
        except Exception as exc:
            self._failConnection(exc)

    def connectionLost(self, reason):
        for c in self.clients:
            assert c is not None
            if c.connected:
                if hasattr(c, "aclose") and self._anyio_task_group is not None:
                    self._anyio_task_group.start_soon(c.aclose)
                else:
                    c.unbind()

        self.clients = []
        self.unbound = True
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

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

    def _handleUnknown(self, request, controls, reply):
        self._whenConnected(self._clientQueue, request, controls, reply)

    async def _clientQueue_async(self, request, controls, reply):
        for c in self.clients:
            if request.needs_answer:
                if hasattr(c, "send_multiResponse_async"):
                    await c.send_multiResponse_async(request, self._gotResponse, reply)
                else:
                    c.send_multiResponse(request, self._gotResponse, reply)
            else:
                if hasattr(c, "send_noResponse_async"):
                    await c.send_noResponse_async(request)
                else:
                    c.send_noResponse(request)

    def handleUnknown(self, request, controls, reply):
        if self._anyio_stream is not None:
            return self._handleUnknown_async(request, controls, reply)
        d = succeed(request)
        d.addCallback(self._handleUnknown, controls, reply)
        return d

    async def _handleUnknown_async(self, request, controls, reply):
        await await_result(self._whenConnected(self._clientQueue_async, request, controls, reply))

    def handle_LDAPBindRequest(self, request, controls, reply):
        return self.handleUnknown(request, controls, reply)

    def handle_LDAPSearchRequest(self, request, controls, reply):
        return self.handleUnknown(request, controls, reply)

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        self.unbound = True
        return self.handleUnknown(request, controls, reply)

    fail_LDAPDelRequest = pureldap.LDAPDelResponse

    def handle_LDAPDelRequest(self, request, controls, reply):
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPAddRequest = pureldap.LDAPAddResponse

    def handle_LDAPAddRequest(self, request, controls, reply):
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPModifyDNRequest = pureldap.LDAPModifyDNResponse

    def handle_LDAPModifyDNRequest(self, request, controls, reply):
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPModifyRequest = pureldap.LDAPModifyResponse

    def handle_LDAPModifyRequest(self, request, controls, reply):
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPExtendedRequest = pureldap.LDAPExtendedResponse

    def handle_LDAPExtendedRequest(self, request, controls, reply):
        raise ldaperrors.LDAPUnwillingToPerform()


if __name__ == "__main__":
    raise SystemExit("Use the AnyIO server entrypoints instead of the legacy demo.")
