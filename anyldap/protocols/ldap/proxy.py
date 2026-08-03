"""LDAP protocol proxy server"""

from collections.abc import Awaitable, Callable, Iterable
from typing import Any

import anyio

from anyldap import interfaces
from anyldap._async import await_result
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapserver
from anyldap.runtime import Protocol

Controls = Iterable[pureldap.Control] | None


class Proxy(ldapserver.BaseLDAPServer):
    protocol: Callable[[], ldapclient.LDAPClientLike] = ldapclient.LDAPClient

    client: ldapclient.LDAPClientLike | None = None
    unbound = False

    def __init__(self, config: interfaces.ILDAPConfig) -> None:
        """
        Initialize the object.

        @param config: The configuration.
        @type config: anyldap.interfaces.ILDAPConfig
        """
        ldapserver.BaseLDAPServer.__init__(self)
        self.config = config
        self._connected = anyio.Event()

    async def _whenConnected(
        self, fn: Callable[..., Any], *a: object, **kw: object
    ) -> object:
        """Run `fn`, waiting first if the proxied connection is not up yet."""
        if self.client is None:
            await self._connected.wait()
        return await await_result(fn(*a, **kw))

    def _cbConnectionMade(self, proto: ldapclient.LDAPClientLike) -> None:
        self.client = proto
        self._connected.set()

    async def _clientQueue_async(
        self,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> None:
        assert self.client is not None
        if request.needs_answer:
            await self.client.send_multiResponse_async(request, self._gotResponse, reply)
        else:
            await self.client.send_noResponse_async(request)

    def _gotResponse(
        self, response: pureldap.LDAPProtocolResponse, reply: ldapserver.Reply
    ) -> bool:
        reply(response)

        # TODO this is ugly
        return isinstance(
            response,
            (
                pureldap.LDAPSearchResultDone,
                pureldap.LDAPBindResponse,
            ),
        )

    def _failConnection(self, reason: BaseException) -> BaseException:
        # TODO self.loseConnection()
        return reason  # TODO

    def connectionLost(self, reason: BaseException = Protocol.connectionDone) -> None:
        assert self.client is not None
        if self.client.connected:
            if self._anyio_task_group is not None:
                self._anyio_task_group.start_soon(self.client.aclose)
            self.unbound = True
        self.client = None
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    def handleUnknown(  # type: ignore[override]
        self,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> Awaitable[None]:
        return self._handleUnknown_async(request, controls, reply)

    async def _handleUnknown_async(
        self,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> None:
        await self._whenConnected(self._clientQueue_async, request, controls, reply)

    def handle_LDAPUnbindRequest(
        self,
        request: pureldap.LDAPUnbindRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> Awaitable[None]:
        self.unbound = True
        return self.handleUnknown(request, controls, reply)

    async def connectionMade_async(self) -> None:
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
