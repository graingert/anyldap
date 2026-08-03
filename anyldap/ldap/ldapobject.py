"""An LDAP connection with python-ldap's API, awaited rather than blocking.

Every method python-ldap spells synchronously is a coroutine here; the
arguments it takes and the values it hands back are the ones python-ldap
documents, so code ports by adding ``await``.

Like python-ldap, this reads the connection only while an operation is being
waited for: an operation is started by writing its request and remembering
its message id, and ``result3()`` reads answers off the socket, handing each
to whichever operation it belongs to, until the one asked for is finished.
Nothing runs in the background, so a connection needs no task group and can
be used from whichever task has it.
"""

import ssl
from collections.abc import AsyncGenerator, Iterable, Sequence
from contextlib import asynccontextmanager
from types import TracebackType
from urllib.parse import urlparse

import anyio
from anyio.abc import ByteStream
from anyio.streams.tls import TLSStream

from anyldap._encoder import to_bytes, to_unicode
from anyldap.ldap import errors
from anyldap.ldap.constants import (
    AUTH_SIMPLE,
    DEREF_NEVER,
    MOD_BVALUES,
    MSG_ALL,
    OPT_DEREF,
    OPT_NETWORK_TIMEOUT,
    OPT_PROTOCOL_VERSION,
    OPT_REFERRALS,
    OPT_SIZELIMIT,
    OPT_TIMELIMIT,
    OPT_TIMEOUT,
    OPT_URI,
    RES_ADD,
    RES_ANY,
    RES_BIND,
    RES_COMPARE,
    RES_DELETE,
    RES_EXTENDED,
    RES_MODIFY,
    RES_MODRDN,
    RES_SEARCH_ENTRY,
    RES_SEARCH_RESULT,
    SCOPE_BASE,
    SCOPE_SUBTREE,
    VERSION3,
    WHOAMI_OID,
)
from anyldap.ldapfilter import InvalidLDAPFilter, parseFilter
from anyldap.protocols import pureber, pureldap
from anyldap.runtime import logger

# A value as it goes out on the wire, or the text of one.
Value = str | bytes

# What add_s() takes: the attributes of the entry being created.
AddModlist = Sequence[tuple[str, Sequence[Value] | Value]]

# What modify_s() takes: the operation, the attribute, and its values.
ModifyModlist = Sequence[tuple[int, str, Sequence[Value] | Value | None]]

# An entry as a search hands it back, and a reference to another server.
Entry = tuple[str, dict[str, list[bytes]]]
Reference = tuple[None, list[str]]
ResultData = list[Entry | Reference]

# Controls are (type, criticality, value) triples, as anyldap spells them.
Controls = Iterable[pureldap.Control] | None

BERDECODER = pureldap.LDAPBERDecoderContext_TopLevel(
    inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
    )
)


class _Pending:
    """An operation that has been sent, and what has come back for it.

    An operation knows the result type it answers with and the response
    class that carries it, so a response meant for something else is caught
    rather than reported as this operation's own.
    """

    def __init__(self, rtype: int, response: type[pureldap.LDAPResult]) -> None:
        self.rtype = rtype
        self.response = response
        self.data: ResultData = []
        self.controls: Sequence[pureldap.Control] = []
        self.name: str | None = None
        self.value: bytes | None = None
        self.error: errors.LDAPError | None = None
        self.done = False


@asynccontextmanager
async def _deadline(timeout: float | None) -> AsyncGenerator[None, None]:
    """Wait no longer than python-ldap would, and fail the way it does."""
    if timeout is None or timeout < 0:
        yield
        return
    try:
        with anyio.fail_after(timeout):
            yield
    except TimeoutError:
        raise errors.TIMEOUT({"desc": errors.TIMEOUT.desc}) from None


def _values(values: Sequence[Value] | Value | None) -> list[bytes]:
    """The values of one attribute, however the caller spelled them."""
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        return [to_bytes(values)]
    return [to_bytes(value) for value in values]


def _entry(message: pureldap.LDAPSearchResultEntry) -> Entry:
    attributes: dict[str, list[bytes]] = {}
    for key, values in message.attributes:
        attributes.setdefault(to_unicode(key), []).extend(
            to_bytes(value) for value in values
        )
    return to_unicode(message.objectName), attributes


def _reference(message: pureldap.LDAPSearchResultReference) -> Reference:
    uris = []
    for uri in message.uris:
        assert isinstance(uri, pureber.BEROctetString)
        uris.append(to_unicode(uri.value))
    return None, uris


def _controls(controls: object) -> Sequence[pureldap.Control]:
    if controls is None:
        return []
    assert isinstance(controls, Sequence)
    return controls


def _modification(
    operation: int, attribute: str, values: Sequence[Value] | Value | None
) -> pureber.BERSequence:
    return pureber.BERSequence(
        [
            # MOD_BVALUES says the values are bytes, which they always are here.
            pureber.BEREnumerated(operation & ~MOD_BVALUES),
            pureber.BERSequence(
                [
                    pureldap.LDAPAttributeDescription(attribute),
                    pureber.BERSet(
                        [pureldap.LDAPString(value) for value in _values(values)]
                    ),
                ]
            ),
        ]
    )


def _parse_uri(uri: str) -> tuple[str, int, bool]:
    """The host, port and whether to raise TLS, out of an LDAP URL."""
    parsed = urlparse(uri)
    if parsed.scheme not in ("ldap", "ldaps"):
        raise ValueError("unsupported LDAP URL scheme {!r}".format(parsed.scheme))
    tls = parsed.scheme == "ldaps"
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("bad port in LDAP URL {!r}".format(uri)) from exc
    return parsed.hostname or "localhost", port or (636 if tls else 389), tls


class SimpleLDAPObject:
    """A connection to one LDAP server, with the API of python-ldap's own.

    The connection is opened by the first operation that needs it, so that
    ``initialize()`` stays the plain call python-ldap makes it. Closing it is
    ``unbind_s()``, and ``async with`` closes it however the block ends.
    """

    def __init__(
        self,
        uri: str,
        trace_level: int = 0,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.uri = uri
        self.trace_level = trace_level
        self.protocol_version = VERSION3
        self.timeout: float = -1
        self.network_timeout: float = -1
        self.deref = DEREF_NEVER
        self.sizelimit = 0
        self.timelimit = 0
        self.referrals = 0
        self._ssl_context = ssl_context
        self._host, self._port, self._tls = _parse_uri(uri)
        self._stream: ByteStream | None = None
        self._buffer = b""
        self._pending: dict[int, _Pending] = {}
        self._reading = anyio.Lock()
        self._writing = anyio.Lock()
        self._unbound = False

    async def __aenter__(self) -> "SimpleLDAPObject":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.unbind_s()

    # Opening and closing the connection.

    async def _connect_stream(self) -> ByteStream:
        # anyio.connect_tcp takes tls as a literal, and a context is a
        # request for TLS on its own.
        if self._tls:
            return await anyio.connect_tcp(
                self._host,
                self._port,
                tls=True,
                ssl_context=self._ssl_context,
                tls_standard_compatible=False,
            )
        return await anyio.connect_tcp(self._host, self._port)

    async def _connected(self) -> ByteStream:
        if self._unbound:
            raise errors.LDAPError({"desc": "unbind() was already called"})
        stream = self._stream
        if stream is not None:
            return stream
        try:
            async with _deadline(
                None if self.network_timeout < 0 else self.network_timeout
            ):
                stream = await self._connect_stream()
        except OSError as exc:
            raise errors.SERVER_DOWN(
                {"desc": errors.SERVER_DOWN.desc, "info": str(exc)}
            ) from exc
        self._stream = stream
        return stream

    async def _lost(self, reason: str) -> None:
        """The connection has gone: every operation on it fails with it."""
        stream = self._stream
        self._stream = None
        pending = list(self._pending.values())
        self._pending.clear()
        for operation in pending:
            operation.error = errors.SERVER_DOWN(
                {"desc": errors.SERVER_DOWN.desc, "info": reason}
            )
            operation.done = True
        if stream is not None:
            # The socket has to be given back even when whoever noticed the
            # connection was gone is itself being cancelled.
            await anyio.aclose_forcefully(stream)

    # Writing requests.

    async def _send(
        self, op: pureldap.LDAPProtocolRequest, controls: Controls
    ) -> pureldap.LDAPMessage:
        stream = await self._connected()
        message = pureldap.LDAPMessage(
            op, controls=None if controls is None else list(controls)
        )
        if self.trace_level:
            logger.debug("*** %s C->S %r", self.uri, message)
        async with self._writing:
            try:
                await stream.send(message.toWire())
            except (anyio.BrokenResourceError, anyio.ClosedResourceError) as exc:
                await self._lost(str(exc))
                raise errors.SERVER_DOWN(
                    {"desc": errors.SERVER_DOWN.desc, "info": str(exc)}
                ) from exc
        return message

    async def _start(
        self,
        op: pureldap.LDAPProtocolRequest,
        controls: Controls,
        rtype: int,
        response: type[pureldap.LDAPResult],
    ) -> int:
        """Send a request and answer with the message id of the operation."""
        message = await self._send(op, controls)
        self._pending[message.id] = _Pending(rtype, response)
        return message.id

    # Reading answers, and handing each to the operation it belongs to.

    async def _read_once(self) -> None:
        stream = self._stream
        assert stream is not None
        try:
            data = await stream.receive()
        except (
            anyio.EndOfStream,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
        ) as exc:
            await self._lost(str(exc) or "connection closed")
            return
        self._buffer += data
        while True:
            try:
                message, used = pureber.berDecodeObject(BERDECODER, self._buffer)
            except pureber.BERExceptionInsufficientData:
                return
            if message is None:
                return
            self._buffer = self._buffer[used:]
            assert isinstance(message, pureldap.LDAPMessage)
            if self.trace_level:
                logger.debug("*** %s C<-S %r", self.uri, message)
            self._dispatch(message)

    def _dispatch(self, message: pureldap.LDAPMessage) -> None:
        operation = self._pending.get(message.id)
        if operation is None:
            # An answer to something abandoned, or a notification the server
            # sent of its own accord: there is nobody waiting for it.
            logger.info("Unsolicited response: %r", message)
            return
        response = message.value
        if operation.rtype == RES_SEARCH_RESULT and isinstance(
            response,
            (pureldap.LDAPSearchResultEntry, pureldap.LDAPSearchResultReference),
        ):
            if isinstance(response, pureldap.LDAPSearchResultEntry):
                operation.data.append(_entry(response))
            else:
                operation.data.append(_reference(response))
            return
        if not isinstance(response, operation.response):
            operation.error = errors.PROTOCOL_ERROR(
                {
                    "desc": errors.PROTOCOL_ERROR.desc,
                    "info": "unexpected response: {!r}".format(response),
                }
            )
        elif response.resultCode != 0:
            operation.error = errors.error_for_result(
                response.resultCode, response.errorMessage
            )
        else:
            operation.controls = _controls(message.controls)
            if isinstance(response, pureldap.LDAPExtendedResponse):
                operation.name = (
                    None
                    if response.responseName is None
                    else to_unicode(response.responseName)
                )
                operation.value = (
                    None if response.response is None else to_bytes(response.response)
                )
        operation.done = True

    async def _wait(
        self, operation: _Pending, timeout: float | None, all: int = MSG_ALL
    ) -> None:
        """Read the connection until this operation has what was asked for.

        With ``all`` set to ``MSG_ONE`` that is the next message it produces,
        which is how python-ldap walks a large search one entry at a time.
        """

        def enough() -> bool:
            return operation.done or bool(not all and operation.data)

        async with _deadline(timeout):
            while not enough():
                async with self._reading:
                    # Another task may have read this operation's answer
                    # while this one waited for its turn to read.
                    if enough():
                        return
                    await self._read_once()

    async def result(
        self, msgid: int = RES_ANY, all: int = 1, timeout: float | None = None
    ) -> tuple[int, ResultData]:
        rtype, data, _, _ = await self.result3(msgid, all, timeout)
        return rtype, data

    async def result2(
        self, msgid: int = RES_ANY, all: int = 1, timeout: float | None = None
    ) -> tuple[int, ResultData, int]:
        rtype, data, rmsgid, _ = await self.result3(msgid, all, timeout)
        return rtype, data, rmsgid

    async def result3(
        self, msgid: int = RES_ANY, all: int = 1, timeout: float | None = None
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        """Wait for an operation started earlier, and answer with its result.

        ``RES_ANY`` takes the operation that was started first, which is the
        one python-ldap would most likely hand back.
        """
        rtype, data, rmsgid, controls, _, _ = await self.result4(msgid, all, timeout)
        return rtype, data, rmsgid, controls

    async def result4(
        self,
        msgid: int = RES_ANY,
        all: int = 1,
        timeout: float | None = None,
        add_ctrls: int = 0,
        add_intermediates: int = 0,
        add_extop: int = 0,
    ) -> tuple[
        int, ResultData, int, Sequence[pureldap.Control], str | None, bytes | None
    ]:
        if msgid == RES_ANY:
            if not self._pending:
                raise errors.NO_RESULTS_RETURNED(
                    {"desc": errors.NO_RESULTS_RETURNED.desc}
                )
            msgid = next(iter(self._pending))
        operation = self._pending.get(msgid)
        if operation is None:
            raise errors.PARAM_ERROR(
                {"desc": errors.PARAM_ERROR.desc, "info": "unknown msgid %d" % msgid}
            )
        # One message at a time: an entry that has already arrived goes out
        # before the connection is read again, and the operation stays on
        # the wire until its result has been asked for too.
        if not all and operation.data:
            return RES_SEARCH_ENTRY, [operation.data.pop(0)], msgid, [], None, None
        await self._wait(operation, timeout, all)
        if not all and operation.data:
            return RES_SEARCH_ENTRY, [operation.data.pop(0)], msgid, [], None, None
        # A timed-out wait leaves the operation to be collected later, so it
        # is only forgotten once it has actually answered. A connection that
        # was lost has already forgotten every operation on it.
        self._pending.pop(msgid, None)
        if operation.error is not None:
            raise operation.error
        return (
            operation.rtype,
            operation.data,
            msgid,
            operation.controls,
            operation.name,
            operation.value,
        )

    async def abandon(self, msgid: int, serverctrls: Controls = None) -> None:
        """Tell the server to stop working on an operation, and forget it."""
        if self._pending.pop(msgid, None) is None:
            return
        await self._send(pureldap.LDAPAbandonRequest(id=msgid), serverctrls)

    # Options.

    def set_option(self, option: int, invalue: object) -> None:
        if option == OPT_PROTOCOL_VERSION:
            assert isinstance(invalue, int)
            self.protocol_version = invalue
        elif option == OPT_SIZELIMIT:
            assert isinstance(invalue, int)
            self.sizelimit = invalue
        elif option == OPT_TIMELIMIT:
            assert isinstance(invalue, int)
            self.timelimit = invalue
        elif option == OPT_TIMEOUT:
            assert isinstance(invalue, (int, float))
            self.timeout = invalue
        elif option == OPT_NETWORK_TIMEOUT:
            assert isinstance(invalue, (int, float))
            self.network_timeout = invalue
        elif option == OPT_DEREF:
            assert isinstance(invalue, int)
            self.deref = invalue
        elif option == OPT_REFERRALS:
            assert isinstance(invalue, int)
            self.referrals = invalue
        else:
            raise ValueError("unknown option {!r}".format(option))

    def get_option(self, option: int) -> object:
        if option == OPT_PROTOCOL_VERSION:
            return self.protocol_version
        if option == OPT_SIZELIMIT:
            return self.sizelimit
        if option == OPT_TIMELIMIT:
            return self.timelimit
        if option == OPT_TIMEOUT:
            return self.timeout
        if option == OPT_NETWORK_TIMEOUT:
            return self.network_timeout
        if option == OPT_DEREF:
            return self.deref
        if option == OPT_REFERRALS:
            return self.referrals
        if option == OPT_URI:
            return self.uri
        raise ValueError("unknown option {!r}".format(option))

    # Binding.

    async def simple_bind(
        self,
        who: str = "",
        cred: Value = "",
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> int:
        return await self._start(
            pureldap.LDAPBindRequest(
                version=self.protocol_version, dn=who, auth=cred
            ),
            serverctrls,
            RES_BIND,
            pureldap.LDAPBindResponse,
        )

    async def simple_bind_s(
        self,
        who: str = "",
        cred: Value = "",
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        msgid = await self.simple_bind(who, cred, serverctrls, clientctrls)
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def bind(self, who: str, cred: Value, method: int = AUTH_SIMPLE) -> int:
        if method != AUTH_SIMPLE:
            raise errors.AUTH_UNKNOWN(
                {
                    "desc": errors.AUTH_UNKNOWN.desc,
                    "info": "only simple authentication is supported",
                }
            )
        return await self.simple_bind(who, cred)

    async def bind_s(
        self, who: str, cred: Value, method: int = AUTH_SIMPLE
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        msgid = await self.bind(who, cred, method)
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def unbind_ext(
        self, serverctrls: Controls = None, clientctrls: Controls = None
    ) -> None:
        """Say goodbye to the server and close the connection."""
        if self._unbound:
            return
        try:
            if self._stream is not None:
                # A server that has already gone is a closed connection, not
                # an error: there is nothing left to say goodbye to.
                try:
                    await self._send(pureldap.LDAPUnbindRequest(), serverctrls)
                except errors.SERVER_DOWN:
                    pass
        finally:
            self._unbound = True
            await self._lost("unbind() was called")

    unbind_ext_s = unbind_ext
    unbind = unbind_ext
    unbind_s = unbind_ext

    # Searching.

    async def search_ext(
        self,
        base: str,
        scope: int = SCOPE_SUBTREE,
        filterstr: str = "(objectClass=*)",
        attrlist: Sequence[str] | None = None,
        attrsonly: int = 0,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
        timeout: float = -1,
        sizelimit: int = 0,
    ) -> int:
        return await self._start(
            self._search_request(
                base, scope, filterstr, attrlist, attrsonly, timeout, sizelimit
            ),
            serverctrls,
            RES_SEARCH_RESULT,
            pureldap.LDAPSearchResultDone,
        )

    async def search_ext_s(
        self,
        base: str,
        scope: int = SCOPE_SUBTREE,
        filterstr: str = "(objectClass=*)",
        attrlist: Sequence[str] | None = None,
        attrsonly: int = 0,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
        timeout: float = -1,
        sizelimit: int = 0,
    ) -> ResultData:
        msgid = await self.search_ext(
            base,
            scope,
            filterstr,
            attrlist,
            attrsonly,
            serverctrls,
            clientctrls,
            timeout,
            sizelimit,
        )
        _, data, _, _ = await self.result3(msgid, all=1, timeout=timeout)
        return data

    async def search(
        self,
        base: str,
        scope: int = SCOPE_SUBTREE,
        filterstr: str = "(objectClass=*)",
        attrlist: Sequence[str] | None = None,
        attrsonly: int = 0,
    ) -> int:
        return await self.search_ext(base, scope, filterstr, attrlist, attrsonly)

    async def search_s(
        self,
        base: str,
        scope: int = SCOPE_SUBTREE,
        filterstr: str = "(objectClass=*)",
        attrlist: Sequence[str] | None = None,
        attrsonly: int = 0,
    ) -> ResultData:
        return await self.search_ext_s(
            base, scope, filterstr, attrlist, attrsonly, timeout=self.timeout
        )

    async def search_st(
        self,
        base: str,
        scope: int = SCOPE_SUBTREE,
        filterstr: str = "(objectClass=*)",
        attrlist: Sequence[str] | None = None,
        attrsonly: int = 0,
        timeout: float = -1,
    ) -> ResultData:
        return await self.search_ext_s(
            base, scope, filterstr, attrlist, attrsonly, timeout=timeout
        )

    async def read_s(
        self,
        dn: str,
        filterstr: str = "(objectClass=*)",
        attrlist: Sequence[str] | None = None,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
        timeout: float = -1,
    ) -> dict[str, list[bytes]] | None:
        """The attributes of one entry, or None when it is not there."""
        data = await self.search_ext_s(
            dn,
            SCOPE_BASE,
            filterstr,
            attrlist,
            serverctrls=serverctrls,
            clientctrls=clientctrls,
            timeout=timeout,
        )
        if not data:
            return None
        _, attributes = data[0]
        assert not isinstance(attributes, list)
        return attributes

    def _search_request(
        self,
        base: str,
        scope: int,
        filterstr: str,
        attrlist: Sequence[str] | None,
        attrsonly: int,
        timeout: float,
        sizelimit: int,
    ) -> pureldap.LDAPSearchRequest:
        try:
            parsed = parseFilter(filterstr)
        except InvalidLDAPFilter as exc:
            raise errors.FILTER_ERROR(
                {"desc": errors.FILTER_ERROR.desc, "info": str(exc)}
            ) from exc
        return pureldap.LDAPSearchRequest(
            baseObject=base,
            scope=scope,
            derefAliases=self.deref,
            sizeLimit=sizelimit or self.sizelimit,
            timeLimit=int(timeout) if timeout >= 0 else self.timelimit,
            typesOnly=attrsonly,
            filter=parsed,
            # An empty list is how LDAP asks for every attribute.
            attributes=list(attrlist) if attrlist is not None else [],
        )

    # Adding, modifying and removing entries.

    async def add_ext(
        self,
        dn: str,
        modlist: AddModlist,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> int:
        attributes = [
            (
                pureldap.LDAPAttributeDescription(attribute),
                pureber.BERSet(
                    [pureldap.LDAPAttributeValue(value) for value in _values(values)]
                ),
            )
            for attribute, values in modlist
        ]
        return await self._start(
            pureldap.LDAPAddRequest(entry=dn, attributes=attributes),
            serverctrls,
            RES_ADD,
            pureldap.LDAPAddResponse,
        )

    async def add_ext_s(
        self,
        dn: str,
        modlist: AddModlist,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        msgid = await self.add_ext(dn, modlist, serverctrls, clientctrls)
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def add(self, dn: str, modlist: AddModlist) -> int:
        return await self.add_ext(dn, modlist)

    async def add_s(
        self, dn: str, modlist: AddModlist
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        return await self.add_ext_s(dn, modlist)

    async def modify_ext(
        self,
        dn: str,
        modlist: ModifyModlist,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> int:
        return await self._start(
            pureldap.LDAPModifyRequest(
                object=dn,
                modification=[
                    _modification(operation, attribute, values)
                    for operation, attribute, values in modlist
                ],
            ),
            serverctrls,
            RES_MODIFY,
            pureldap.LDAPModifyResponse,
        )

    async def modify_ext_s(
        self,
        dn: str,
        modlist: ModifyModlist,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        msgid = await self.modify_ext(dn, modlist, serverctrls, clientctrls)
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def modify(self, dn: str, modlist: ModifyModlist) -> int:
        return await self.modify_ext(dn, modlist)

    async def modify_s(
        self, dn: str, modlist: ModifyModlist
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        return await self.modify_ext_s(dn, modlist)

    async def delete_ext(
        self,
        dn: str,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> int:
        return await self._start(
            pureldap.LDAPDelRequest(entry=dn),
            serverctrls,
            RES_DELETE,
            pureldap.LDAPDelResponse,
        )

    async def delete_ext_s(
        self,
        dn: str,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        msgid = await self.delete_ext(dn, serverctrls, clientctrls)
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def delete(self, dn: str) -> int:
        return await self.delete_ext(dn)

    async def delete_s(
        self, dn: str
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        return await self.delete_ext_s(dn)

    async def rename(
        self,
        dn: str,
        newrdn: str,
        newsuperior: str | None = None,
        delold: int = 1,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> int:
        return await self._start(
            pureldap.LDAPModifyDNRequest(
                entry=dn,
                newrdn=newrdn,
                deleteoldrdn=delold,
                newSuperior=newsuperior,
            ),
            serverctrls,
            RES_MODRDN,
            pureldap.LDAPModifyDNResponse,
        )

    async def rename_s(
        self,
        dn: str,
        newrdn: str,
        newsuperior: str | None = None,
        delold: int = 1,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        msgid = await self.rename(
            dn, newrdn, newsuperior, delold, serverctrls, clientctrls
        )
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def modrdn(self, dn: str, newrdn: str, delold: int = 1) -> int:
        return await self.rename(dn, newrdn, None, delold)

    async def modrdn_s(
        self, dn: str, newrdn: str, delold: int = 1
    ) -> tuple[int, ResultData, int, Sequence[pureldap.Control]]:
        return await self.rename_s(dn, newrdn, None, delold)

    async def compare_ext(
        self,
        dn: str,
        attr: str,
        value: Value,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> int:
        return await self._start(
            pureldap.LDAPCompareRequest(
                entry=dn,
                ava=pureldap.LDAPAttributeValueAssertion(
                    attributeDesc=pureldap.LDAPAttributeDescription(attr),
                    assertionValue=pureldap.LDAPAssertionValue(to_bytes(value)),
                ),
            ),
            serverctrls,
            RES_COMPARE,
            pureldap.LDAPCompareResponse,
        )

    async def compare_ext_s(
        self,
        dn: str,
        attr: str,
        value: Value,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> bool:
        msgid = await self.compare_ext(dn, attr, value, serverctrls, clientctrls)
        try:
            await self.result3(msgid, all=1, timeout=self.timeout)
        except errors.COMPARE_TRUE:
            return True
        except errors.COMPARE_FALSE:
            return False
        raise errors.PROTOCOL_ERROR(
            {
                "desc": errors.PROTOCOL_ERROR.desc,
                "info": "compare answered neither true nor false",
            }
        )

    async def compare(self, dn: str, attr: str, value: Value) -> int:
        return await self.compare_ext(dn, attr, value)

    async def compare_s(self, dn: str, attr: str, value: Value) -> bool:
        return await self.compare_ext_s(dn, attr, value)

    # Extended operations.

    async def extop(
        self,
        extreq: pureldap.LDAPExtendedRequest,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> int:
        return await self._start(
            extreq, serverctrls, RES_EXTENDED, pureldap.LDAPExtendedResponse
        )

    async def extop_s(
        self,
        extreq: pureldap.LDAPExtendedRequest,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> tuple[str | None, bytes | None]:
        msgid = await self.extop(extreq, serverctrls, clientctrls)
        _, _, _, _, name, value = await self.result4(
            msgid, all=1, timeout=self.timeout, add_extop=1
        )
        return name, value

    async def passwd(
        self,
        user: Value | None = None,
        oldpw: Value | None = None,
        newpw: Value | None = None,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> int:
        return await self.extop(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity=user, oldPasswd=oldpw, newPasswd=newpw
            ),
            serverctrls,
            clientctrls,
        )

    async def passwd_s(
        self,
        user: Value | None = None,
        oldpw: Value | None = None,
        newpw: Value | None = None,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
        extract_newpw: bool = False,
    ) -> tuple[str | None, bytes | None]:
        return await self.extop_s(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity=user, oldPasswd=oldpw, newPasswd=newpw
            ),
            serverctrls,
            clientctrls,
        )

    async def whoami_s(self) -> str:
        """The identity the server has this connection bound as."""
        _, value = await self.extop_s(
            pureldap.LDAPExtendedRequest(requestName=WHOAMI_OID)
        )
        return "" if value is None else to_unicode(value)

    async def start_tls_s(self) -> None:
        """Raise TLS on the connection, as StartTLS does.

        Nothing else is reading the connection, so the handshake follows the
        response on the same stream, with no request in flight to confuse.
        """
        stream = await self._connected()
        msgid = await self._start(
            pureldap.LDAPStartTLSRequest(),
            None,
            RES_EXTENDED,
            pureldap.LDAPExtendedResponse,
        )
        _, _, _, _, name, _ = await self.result4(
            msgid, all=1, timeout=self.timeout, add_extop=1
        )
        if name is not None and name != to_unicode(pureldap.LDAPStartTLSRequest.oid):
            raise errors.PROTOCOL_ERROR(
                {
                    "desc": errors.PROTOCOL_ERROR.desc,
                    "info": "StartTLS answered to {!r}".format(name),
                }
            )
        if self._buffer:
            raise errors.PROTOCOL_ERROR(
                {
                    "desc": errors.PROTOCOL_ERROR.desc,
                    "info": "the server wrote past its StartTLS response",
                }
            )
        self._stream = await TLSStream.wrap(
            stream,
            server_side=False,
            hostname=self._host,
            ssl_context=self._ssl_context,
            standard_compatible=False,
        )


# python-ldap's own name for the class it hands back, and the one it uses
# when a connection needs no re-connecting logic of its own.
LDAPObject = SimpleLDAPObject
ReconnectLDAPObject = SimpleLDAPObject


def initialize(
    uri: str,
    trace_level: int = 0,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> SimpleLDAPObject:
    """A connection to the server named by an ``ldap://`` or ``ldaps://`` URL.

    Nothing is sent until the first operation is awaited, which is what lets
    this stay the plain call python-ldap makes it.
    """
    return SimpleLDAPObject(uri, trace_level, ssl_context=ssl_context)


# python-ldap's older spelling of the same thing.
def open(host: str, port: int = 389, trace_level: int = 0) -> SimpleLDAPObject:
    return initialize("ldap://%s:%d" % (host, port), trace_level)
