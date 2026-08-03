"""LDAP protocol server, which acts as a proxy which
   forwards the requests to multiple LDAP servers and
   merges the results.
   Only Bind and Search requests are supported.
"""

from collections.abc import Awaitable, Callable, Iterable, Sequence
from functools import partial
from typing import Any, NoReturn

import anyio

from anyldap import interfaces
from anyldap._async import await_result
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldaperrors, ldapserver
from anyldap.runtime import Protocol

Controls = Iterable[pureldap.Control] | None


class MergedLDAPServer(ldapserver.BaseLDAPServer):
    protocol: Callable[[], ldapclient.LDAPClientLike] = ldapclient.LDAPClient

    def __init__(
        self,
        configs: Sequence[interfaces.ILDAPConfig],
        use_tls: Sequence[bool],
    ) -> None:
        ldapserver.BaseLDAPServer.__init__(self)
        self.clients: list[ldapclient.LDAPClientLike] = []
        self.configs = configs
        self.use_tls = use_tls
        self.all_connected = False
        self.unbound = False
        self._connected = anyio.Event()

    async def _whenConnected(
        self, fn: Callable[..., Any], *a: object, **kw: object
    ) -> object:
        """Run `fn`, waiting first until every configured server is connected."""
        if not self.all_connected:
            await self._connected.wait()
        return await await_result(fn(*a, **kw))

    def _failConnection(self, reason: BaseException) -> NoReturn:
        self._start_anyio_close()
        raise ldaperrors.LDAPOther(f"Cannot connect to server.{reason}")

    def _cbConnectionMade(self, proto: ldapclient.LDAPClientLike) -> None:
        self.clients.append(proto)

        if len(self.clients) == len(self.configs):
            self.all_connected = True
            self._connected.set()

    async def connectionMade_async(self) -> None:
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

    def connectionLost(self, reason: BaseException = Protocol.connectionDone) -> None:
        for c in self.clients:
            assert c is not None
            if c.connected:
                if self._anyio_task_group is not None:
                    self._anyio_task_group.start_soon(c.aclose)

        self.clients = []
        self.unbound = True
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    async def _clientQueue_async(
        self,
        request: pureldap.LDAPProtocolRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> None:
        final_responses: list[Any] = []

        def got_response(response: pureldap.LDAPProtocolResponse) -> bool:
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

        async def send(client: ldapclient.LDAPClientLike) -> None:
            if request.needs_answer:
                await client.send_multiResponse_async(request, got_response)
            else:
                await client.send_noResponse_async(request)

        async with anyio.create_task_group() as task_group:
            for client in self.clients:
                task_group.start_soon(send, client)

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

    def handle_LDAPBindRequest(
        self,
        request: pureldap.LDAPBindRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> Awaitable[None]:
        return self.handleUnknown(request, controls, reply)

    def handle_LDAPSearchRequest(
        self,
        request: pureldap.LDAPSearchRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> Awaitable[None]:
        return self.handleUnknown(request, controls, reply)

    def handle_LDAPUnbindRequest(
        self,
        request: pureldap.LDAPUnbindRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> Awaitable[None]:
        self.unbound = True
        return self.handleUnknown(request, controls, reply)

    fail_LDAPDelRequest = pureldap.LDAPDelResponse

    def handle_LDAPDelRequest(
        self,
        request: pureldap.LDAPDelRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> NoReturn:
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPAddRequest = pureldap.LDAPAddResponse

    def handle_LDAPAddRequest(
        self,
        request: pureldap.LDAPAddRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> NoReturn:
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPModifyDNRequest = pureldap.LDAPModifyDNResponse

    def handle_LDAPModifyDNRequest(
        self,
        request: pureldap.LDAPModifyDNRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> NoReturn:
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPModifyRequest = pureldap.LDAPModifyResponse

    def handle_LDAPModifyRequest(
        self,
        request: pureldap.LDAPModifyRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> NoReturn:
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPExtendedRequest = pureldap.LDAPExtendedResponse

    def handle_LDAPExtendedRequest(
        self,
        request: pureldap.LDAPExtendedRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> NoReturn:
        raise ldaperrors.LDAPUnwillingToPerform()


if __name__ == "__main__":
    raise SystemExit("Use the AnyIO server entrypoints instead of the legacy demo.")
