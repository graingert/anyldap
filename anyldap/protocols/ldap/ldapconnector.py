from contextlib import AsyncExitStack

import anyio

from anyldap._async import await_result
from anyldap._encoder import get_strings
from anyldap.protocols.ldap import distinguishedname


async def connectToLDAPEndpoint(reactor, endpointStr, clientProtocol):
    return await connectToLDAPEndpointAsync(endpointStr, clientProtocol)


def _parseTCPEndpoint(endpointStr):
    pieces = endpointStr.split(":")
    if not pieces or pieces[0] != "tcp":
        raise ValueError(f"Unsupported endpoint string {endpointStr!r}")

    options = {}
    for piece in pieces[1:]:
        key, sep, value = piece.partition("=")
        if not sep:
            raise ValueError(f"Malformed endpoint option {piece!r}")
        options[key] = value

    if "host" not in options or "port" not in options:
        raise ValueError(f"TCP endpoint must define host and port: {endpointStr!r}")

    return options["host"], int(options["port"])


class AsyncLDAPClientConnection:
    def __init__(self, exit_stack, protocol):
        self._exit_stack = exit_stack
        self.protocol = protocol

    async def aclose(self):
        await self._exit_stack.aclose()

    async def __aenter__(self):
        return self.protocol

    async def __aexit__(self, exc_type, exc, tb):
        await self.aclose()

    def __getattr__(self, name):
        return getattr(self.protocol, name)


def _findOverride(dn, overrides):
    while True:
        for dn_variant in get_strings(dn):
            if dn_variant in overrides:
                return overrides[dn_variant]
        if dn == "":
            break
        dn = dn.up()
    return None


async def _resolveServiceLocationAsync(dn, overrides=None, resolver=None):
    if not isinstance(dn, distinguishedname.DistinguishedName):
        dn = distinguishedname.DistinguishedName(stringValue=dn)
    if overrides is None:
        overrides = {}

    override = _findOverride(dn, overrides)
    if callable(override):
        return override

    domain = dn.getDomainName() or ""
    overriddenHost = None
    overriddenPort = None
    if override is not None:
        overriddenHost, overriddenPort = override

    if overriddenHost is not None and overriddenPort is not None:
        return overriddenHost, int(overriddenPort)

    if resolver is None:
        import dns.asyncresolver

        resolver = dns.asyncresolver.resolve

    host = overriddenHost
    port = overriddenPort
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


async def connectToLDAPEndpointAsync(endpointStr, clientProtocol, *, tls=False):
    host, port = _parseTCPEndpoint(endpointStr)
    stream = await anyio.connect_tcp(host, port, tls=tls)
    exit_stack = AsyncExitStack()
    await exit_stack.__aenter__()
    task_group = await exit_stack.enter_async_context(anyio.create_task_group())
    exit_stack.push_async_callback(stream.aclose)

    protocol_instance = clientProtocol()
    await protocol_instance.attach_stream(stream, task_group)
    exit_stack.push_async_callback(protocol_instance.aclose)
    return AsyncLDAPClientConnection(exit_stack, protocol_instance)


async def connectToLDAPDNAsync(
    dn,
    clientProtocol,
    *,
    overrides=None,
    bindAddress=None,
    resolver=None,
    tls=False,
):
    resolved = await _resolveServiceLocationAsync(
        dn, overrides=overrides, resolver=resolver
    )
    if callable(resolved):
        return resolved(clientProtocol)

    host, port = resolved
    stream = await anyio.connect_tcp(
        host,
        port,
        local_host=bindAddress[0] if bindAddress else None,
        local_port=bindAddress[1] if bindAddress else None,
        tls=tls,
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
    def _findOverRide(self, dn, overrides):
        return _findOverride(dn, overrides)


class LDAPClientCreator:
    def __init__(self, reactor, protocolClass, *args, **kwargs):
        self.reactor = reactor
        self.protocolClass = protocolClass
        self.args = args
        self.kwargs = kwargs

    async def connect(self, dn, overrides=None, bindAddress=None):
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

    async def connectAnonymously(self, dn, overrides=None):
        """Connect to remote host and bind anonymously, returning the protocol instance."""
        client = await self.connect(dn, overrides=overrides)
        bind = getattr(client, "bind", None)
        if bind is None:
            return client
        return await await_result(bind())

    async def connectToEndpointAsync(self, endpointStr, *, tls=False):
        return await connectToLDAPEndpointAsync(
            endpointStr,
            lambda: self.protocolClass(*self.args, **self.kwargs),
            tls=tls,
        )

    async def connectAsync(
        self, dn, overrides=None, bindAddress=None, resolver=None, *, tls=False
    ):
        return await connectToLDAPDNAsync(
            dn,
            lambda: self.protocolClass(*self.args, **self.kwargs),
            overrides=overrides,
            bindAddress=bindAddress,
            resolver=resolver,
            tls=tls,
        )

    async def connectAnonymouslyAsync(
        self, dn, overrides=None, bindAddress=None, resolver=None, *, tls=False
    ):
        client = await self.connectAsync(
            dn,
            overrides=overrides,
            bindAddress=bindAddress,
            resolver=resolver,
            tls=tls,
        )
        await client.bind_async()
        return client
