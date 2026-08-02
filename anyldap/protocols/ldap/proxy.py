"""LDAP protocol proxy server"""

import anyio

from anyldap._async import await_result
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapserver


class Proxy(ldapserver.BaseLDAPServer):
    protocol = ldapclient.LDAPClient

    client = None
    unbound = False

    def __init__(self, config):
        """
        Initialize the object.

        @param config: The configuration.
        @type config: anyldap.interfaces.ILDAPConfig
        """
        ldapserver.BaseLDAPServer.__init__(self)
        self.config = config
        self._connected = anyio.Event()

    async def _whenConnected(self, fn, *a, **kw):
        """Run `fn`, waiting first if the proxied connection is not up yet."""
        if self.client is None:
            await self._connected.wait()
        return await await_result(fn(*a, **kw))

    def _cbConnectionMade(self, proto):
        self.client = proto
        self._connected.set()

    async def _clientQueue_async(self, request, controls, reply):
        if request.needs_answer:
            await self.client.send_multiResponse_async(request, self._gotResponse, reply)
        else:
            await self.client.send_noResponse_async(request)

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

    def connectionLost(self, reason):
        assert self.client is not None
        if self.client.connected:
            if self._anyio_task_group is not None:
                self._anyio_task_group.start_soon(self.client.aclose)
            self.unbound = True
        self.client = None
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    def handleUnknown(self, request, controls, reply):
        return self._handleUnknown_async(request, controls, reply)

    async def _handleUnknown_async(self, request, controls, reply):
        await self._whenConnected(self._clientQueue_async, request, controls, reply)

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
