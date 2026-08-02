"""LDAP protocol server, which acts as a proxy which
   forwards the requests to multiple LDAP servers and
   merges the results.
   Only Bind and Search requests are supported.
"""

from functools import partial

import anyio

from anyldap._async import await_result
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
        self.unbound = False
        self._connected = anyio.Event()

    async def _whenConnected(self, fn, *a, **kw):
        """Run `fn`, waiting first until every configured server is connected."""
        if not self.all_connected:
            await self._connected.wait()
        return await await_result(fn(*a, **kw))

    def _failConnection(self, reason):
        self._start_anyio_close()
        raise ldaperrors.LDAPOther(f"Cannot connect to server.{reason}")

    def _cbConnectionMade(self, proto):
        self.clients.append(proto)

        if len(self.clients) == len(self.configs):
            self.all_connected = True
            self._connected.set()

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
                self._cbConnectionMade(proto)
        except Exception as exc:
            self._failConnection(exc)

    def connectionLost(self, reason):
        for c in self.clients:
            assert c is not None
            if c.connected:
                if self._anyio_task_group is not None:
                    self._anyio_task_group.start_soon(c.aclose)

        self.clients = []
        self.unbound = True
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    async def _clientQueue_async(self, request, controls, reply):
        final_responses = []

        def got_response(response):
            final = isinstance(
                response,
                (pureldap.LDAPSearchResultDone, pureldap.LDAPBindResponse),
            )
            if final:
                final_responses.append(response)
                if len(final_responses) == len(self.clients):
                    successes = [
                        item
                        for item in final_responses
                        if item.resultCode == ldaperrors.Success.resultCode
                    ]
                    reply(successes[-1] if successes else final_responses[-1])
            else:
                reply(response)
            return final

        async def send(client):
            if request.needs_answer:
                await client.send_multiResponse_async(request, got_response)
            else:
                await client.send_noResponse_async(request)

        async with anyio.create_task_group() as task_group:
            for client in self.clients:
                task_group.start_soon(send, client)

    def handleUnknown(self, request, controls, reply):
        return self._handleUnknown_async(request, controls, reply)

    async def _handleUnknown_async(self, request, controls, reply):
        await self._whenConnected(self._clientQueue_async, request, controls, reply)

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
