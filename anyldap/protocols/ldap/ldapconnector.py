import ssl
from collections.abc import Awaitable, Callable, Iterable, Mapping
from contextlib import AsyncExitStack
from types import TracebackType
from typing import Any, Generic, Protocol, TypeVar

import anyio
from anyio.abc import ByteStream, TaskGroup

from anyldap import interfaces
from anyldap._async import await_result
from anyldap._encoder import get_strings
from anyldap.protocols.ldap import distinguishedname


class AsyncCloseable(Protocol):
    """Something whose only remaining job is to be closed."""

    async def aclose(self) -> None: ...


class AttachableProtocol(Protocol):
    """A protocol object the connector can hand a stream to."""

    async def attach_stream(
        self, stream: ByteStream, task_group: TaskGroup
    ) -> object: ...

    async def aclose(self) -> None: ...


_P = TypeVar("_P", bound=AttachableProtocol)

# An override either says where the server is, or takes over connecting.
Override = interfaces.ServiceLocation

# A mapping keyed by however the caller spelled the DN, which is why the key
# is not narrowed: Mapping is invariant in it, and _findOverride looks up
# every spelling get_strings produces.
Overrides = Mapping[Any, Override]


class SRVRecord(Protocol):
    """What this reads off an SRV answer to pick a server."""

    @property
    def priority(self) -> int: ...

    @property
    def weight(self) -> int: ...

    @property
    def target(self) -> object: ...

    @property
    def port(self) -> int: ...


Resolver = Callable[[str, str], Awaitable[Iterable[SRVRecord]]]


async def connectToLDAPEndpoint(
    reactor: object, endpointStr: str, clientProtocol: Callable[[], _P]
) -> "AsyncLDAPClientConnection[_P]":
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


class AsyncLDAPClientConnection(Generic[_P]):
    def __init__(self, exit_stack: AsyncCloseable, protocol: _P) -> None:
        self._exit_stack = exit_stack
        self.protocol = protocol

    async def aclose(self) -> None:
        await self._exit_stack.aclose()

    async def __aenter__(self) -> _P:
        return self.protocol

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # A connection stands in for the protocol it wraps, so what an attribute
    # is depends on the protocol; the wrapper cannot say.
    def __getattr__(self, name: str) -> Any:
        return getattr(self.protocol, name)


def _findOverride(
    dn: distinguishedname.DistinguishedName, overrides: Overrides
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
    overrides: Overrides | None = None,
    resolver: Resolver | None = None,
) -> tuple[str, int] | interfaces.ServiceConnector:
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

    A context is a request for TLS on its own, which is the condition anyio
    applies; saying it here is what lets the literal be a literal.

    A protocol reads its stream from its own task, so closing cannot also
    read: an LDAPS stream is closed the same way STARTTLS closes the one it
    upgraded.
    """
    local_host = bindAddress[0] if bindAddress else None
    local_port = bindAddress[1] if bindAddress else None
    if tls or ssl_context is not None:
        return await anyio.connect_tcp(
            host,
            port,
            local_host=local_host,
            local_port=local_port,
            tls=True,
            ssl_context=ssl_context,
            tls_standard_compatible=False,
        )
    return await anyio.connect_tcp(
        host,
        port,
        local_host=local_host,
        local_port=local_port,
        tls=False,
        tls_standard_compatible=False,
    )


async def connectToLDAPEndpointAsync(
    endpointStr: str,
    clientProtocol: Callable[[], _P],
    *,
    tls: bool = False,
    ssl_context: ssl.SSLContext | None = None,
) -> AsyncLDAPClientConnection[_P]:
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
    clientProtocol: Callable[[], _P],
    *,
    overrides: Overrides | None = None,
    bindAddress: tuple[str, int] | None = None,
    resolver: Resolver | None = None,
    tls: bool = False,
    ssl_context: ssl.SSLContext | None = None,
    # A connection, or whatever an override handed back in its place. The
    # override is the caller's own, so this cannot say what it produced.
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
        overrides: Overrides,
    ) -> Override | None:
        return _findOverride(dn, overrides)


class LDAPClientCreator(Generic[_P]):
    def __init__(
        self,
        reactor: object,
        protocolClass: Callable[..., _P],
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
        overrides: Overrides | None = None,
        bindAddress: tuple[str, int] | None = None,
        # See connectToLDAPDNAsync: an override's product is the caller's.
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
        self, dn: interfaces.AnyDN, overrides: Overrides | None = None
        # See connectToLDAPDNAsync: an override's product is the caller's.
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
    ) -> AsyncLDAPClientConnection[_P]:
        return await connectToLDAPEndpointAsync(
            endpointStr,
            lambda: self.protocolClass(*self.args, **self.kwargs),
            tls=tls,
            ssl_context=ssl_context,
        )

    async def connectAsync(
        self,
        dn: interfaces.AnyDN,
        overrides: Overrides | None = None,
        bindAddress: tuple[str, int] | None = None,
        resolver: Resolver | None = None,
        *,
        tls: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        # See connectToLDAPDNAsync: an override's product is the caller's.
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
        overrides: Overrides | None = None,
        bindAddress: tuple[str, int] | None = None,
        resolver: Resolver | None = None,
        *,
        tls: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        # See connectToLDAPDNAsync: an override's product is the caller's.
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
