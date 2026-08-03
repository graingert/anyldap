import ssl
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AsyncExitStack
from types import TracebackType
from typing import Any

import anyio
from anyio.abc import ByteStream

from anyldap import interfaces
from anyldap._async import await_result
from anyldap._encoder import get_strings
from anyldap.protocols.ldap import distinguishedname

# What builds the protocol object once the stream is up.
ProtocolFactory = Callable[[], Any]

# An override either says where the server is, or takes over connecting.
Override = interfaces.ServiceLocation | Callable[..., Any]


async def connectToLDAPEndpoint(
    reactor: object, endpointStr: str, clientProtocol: ProtocolFactory
) -> "AsyncLDAPClientConnection":
    return await connectToLDAPEndpointAsync(endpointStr, clientProtocol)


def _parseTCPEndpoint(endpointStr: str) -> tuple[str, int]:
    pieces = endpointStr.split(":")
    if not pieces or pieces[0] != "tcp":
        raise ValueError(f"Unsupported endpoint string {endpointStr!r}")

    options: dict[str, str] = {}
    for piece in pieces[1:]:
        key, sep, value = piece.partition("=")
        if not sep:
            raise ValueError(f"Malformed endpoint option {piece!r}")
        options[key] = value

    if "host" not in options or "port" not in options:
        raise ValueError(f"TCP endpoint must define host and port: {endpointStr!r}")

    return options["host"], int(options["port"])


class AsyncLDAPClientConnection:
    def __init__(self, exit_stack: AsyncExitStack, protocol: Any) -> None:
        self._exit_stack = exit_stack
        self.protocol = protocol

    async def aclose(self) -> None:
        await self._exit_stack.aclose()

    async def __aenter__(self) -> Any:
        return self.protocol

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.protocol, name)


def _findOverride(
    dn: distinguishedname.DistinguishedName,
    overrides: Mapping[Any, Override],
) -> Override | None:
    while True:
        for dn_variant in get_strings(dn):
            if dn_variant in overrides:
                return overrides[dn_variant]
        if dn == "":
            break
        dn = dn.up()
    return None


async def _resolveServiceLocationAsync(
    dn: interfaces.AnyDN,
    overrides: Mapping[Any, Override] | None = None,
    resolver: Callable[..., Awaitable[Any]] | None = None,
) -> tuple[str, int] | Callable[..., Any]:
    target = (
        dn
        if isinstance(dn, distinguishedname.DistinguishedName)
        else distinguishedname.DistinguishedName(stringValue=dn)
    )
    if overrides is None:
        overrides = {}

    override = _findOverride(target, overrides)
    if callable(override):
        return override

    domain = target.getDomainName() or ""
    overriddenHost: str | None = None
    overriddenPort: str | int | None = None
    if override is not None:
        overriddenHost, overriddenPort = override

    if overriddenHost is not None and overriddenPort is not None:
        return overriddenHost, int(overriddenPort)

    if resolver is None:
        import dns.asyncresolver

        resolver = dns.asyncresolver.resolve

    host: str | None = overriddenHost
    port: str | int | None = overriddenPort
    if domain:
        answers = await resolver(f"_ldap._tcp.{domain}", "SRV")
        records = sorted(
            answers,
            key=lambda answer: (answer.priority, -answer.weight, str(answer.target)),
        )
        if records:
            record = records[0]
            if host is None:
                host = str(record.target).rstrip(".")
            if port is None:
                port = int(record.port)

    if host is None:
        host = domain
    if port is None:
        port = 389
    return host, int(port)


async def _connect(
    host: str,
    port: int,
    *,
    bindAddress: tuple[str, int] | None = None,
    tls: bool = False,
    ssl_context: ssl.SSLContext | None = None,
) -> ByteStream:
    """anyio.connect_tcp, whose overloads take tls as a literal.

    A protocol reads its stream from its own task, so closing cannot also
    read: an LDAPS stream is closed the same way STARTTLS closes the one it
    upgraded.
    """
    return await anyio.connect_tcp(  # type: ignore[call-overload,no-any-return]
        host,
        port,
        local_host=bindAddress[0] if bindAddress else None,
        local_port=bindAddress[1] if bindAddress else None,
        tls=tls,
        ssl_context=ssl_context,
        tls_standard_compatible=False,
    )


async def connectToLDAPEndpointAsync(
    endpointStr: str,
    clientProtocol: ProtocolFactory,
    *,
    tls: bool = False,
    ssl_context: ssl.SSLContext | None = None,
) -> AsyncLDAPClientConnection:
    host, port = _parseTCPEndpoint(endpointStr)
    stream = await _connect(host, port, tls=tls, ssl_context=ssl_context)
    exit_stack = AsyncExitStack()
    await exit_stack.__aenter__()
    task_group = await exit_stack.enter_async_context(anyio.create_task_group())
    exit_stack.push_async_callback(stream.aclose)

    protocol_instance = clientProtocol()
    await protocol_instance.attach_stream(stream, task_group)
    exit_stack.push_async_callback(protocol_instance.aclose)
    return AsyncLDAPClientConnection(exit_stack, protocol_instance)


async def connectToLDAPDNAsync(
    dn: interfaces.AnyDN,
    clientProtocol: ProtocolFactory,
    *,
    overrides: Mapping[Any, Override] | None = None,
    bindAddress: tuple[str, int] | None = None,
    resolver: Callable[..., Awaitable[Any]] | None = None,
    tls: bool = False,
    ssl_context: ssl.SSLContext | None = None,
) -> Any:
    resolved = await _resolveServiceLocationAsync(
        dn, overrides=overrides, resolver=resolver
    )
    if callable(resolved):
        return resolved(clientProtocol)

    host, port = resolved
    stream = await _connect(
        host, port, bindAddress=bindAddress, tls=tls, ssl_context=ssl_context
    )
    exit_stack = AsyncExitStack()
    await exit_stack.__aenter__()
    task_group = await exit_stack.enter_async_context(anyio.create_task_group())
    exit_stack.push_async_callback(stream.aclose)

    protocol_instance = clientProtocol()
    await protocol_instance.attach_stream(stream, task_group)
    exit_stack.push_async_callback(protocol_instance.aclose)
    return AsyncLDAPClientConnection(exit_stack, protocol_instance)


class LDAPConnector:
    def _findOverRide(
        self,
        dn: distinguishedname.DistinguishedName,
        overrides: Mapping[Any, Override],
    ) -> Override | None:
        return _findOverride(dn, overrides)


class LDAPClientCreator:
    def __init__(
        self,
        reactor: object,
        protocolClass: Callable[..., Any],
        *args: object,
        **kwargs: object,
    ) -> None:
        self.reactor = reactor
        self.protocolClass = protocolClass
        self.args = args
        self.kwargs = kwargs

    async def connect(
        self,
        dn: interfaces.AnyDN,
        overrides: Mapping[Any, Override] | None = None,
        bindAddress: tuple[str, int] | None = None,
    ) -> Any:
        override = _findOverride(
            distinguishedname.DistinguishedName(stringValue=dn)
            if not isinstance(dn, distinguishedname.DistinguishedName)
            else dn,
            overrides or {},
        )
        if callable(override):
            return await await_result(
                override(lambda: self.protocolClass(*self.args, **self.kwargs))
            )
        return await self.connectAsync(
            dn,
            overrides=overrides,
            bindAddress=bindAddress,
        )

    async def connectAnonymously(
        self, dn: interfaces.AnyDN, overrides: Mapping[Any, Override] | None = None
    ) -> Any:
        """Connect to remote host and bind anonymously, returning the protocol instance."""
        client = await self.connect(dn, overrides=overrides)
        bind = getattr(client, "bind", None)
        if bind is None:
            return client
        return await await_result(bind())

    async def connectToEndpointAsync(
        self,
        endpointStr: str,
        *,
        tls: bool = False,
        ssl_context: ssl.SSLContext | None = None,
    ) -> AsyncLDAPClientConnection:
        return await connectToLDAPEndpointAsync(
            endpointStr,
            lambda: self.protocolClass(*self.args, **self.kwargs),
            tls=tls,
            ssl_context=ssl_context,
        )

    async def connectAsync(
        self,
        dn: interfaces.AnyDN,
        overrides: Mapping[Any, Override] | None = None,
        bindAddress: tuple[str, int] | None = None,
        resolver: Callable[..., Awaitable[Any]] | None = None,
        *,
        tls: bool = False,
        ssl_context: ssl.SSLContext | None = None,
    ) -> Any:
        return await connectToLDAPDNAsync(
            dn,
            lambda: self.protocolClass(*self.args, **self.kwargs),
            overrides=overrides,
            bindAddress=bindAddress,
            resolver=resolver,
            tls=tls,
            ssl_context=ssl_context,
        )

    async def connectAnonymouslyAsync(
        self,
        dn: interfaces.AnyDN,
        overrides: Mapping[Any, Override] | None = None,
        bindAddress: tuple[str, int] | None = None,
        resolver: Callable[..., Awaitable[Any]] | None = None,
        *,
        tls: bool = False,
        ssl_context: ssl.SSLContext | None = None,
    ) -> Any:
        client = await self.connectAsync(
            dn,
            overrides=overrides,
            bindAddress=bindAddress,
            resolver=resolver,
            tls=tls,
            ssl_context=ssl_context,
        )
        await client.bind_async()
        return client
