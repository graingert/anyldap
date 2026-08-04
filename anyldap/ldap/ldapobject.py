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
from collections.abc import AsyncGenerator, Callable, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Any, ClassVar, TypeVar, cast
from urllib.parse import unquote, urlparse

import anyio
from anyio.abc import ByteStream
from anyio.streams.tls import TLSStream

from anyldap._encoder import to_bytes, to_unicode
from anyldap.ldap import controls, errors, sasl, schema
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
    OPT_X_SASL_AUTHCID,
    OPT_X_SASL_AUTHZID,
    OPT_X_SASL_MAXBUFSIZE,
    OPT_X_SASL_MECH,
    OPT_X_SASL_NOCANON,
    OPT_X_SASL_REALM,
    OPT_X_SASL_SECPROPS,
    OPT_X_SASL_SSF,
    OPT_X_SASL_SSF_EXTERNAL,
    OPT_X_SASL_SSF_MAX,
    OPT_X_SASL_SSF_MIN,
    OPT_X_SASL_USERNAME,
    OPT_X_TLS_ALLOW,
    OPT_X_TLS_CACERTDIR,
    OPT_X_TLS_CACERTFILE,
    OPT_X_TLS_CERTFILE,
    OPT_X_TLS_CIPHER_SUITE,
    OPT_X_TLS_CTX,
    OPT_X_TLS_KEYFILE,
    OPT_X_TLS_NEVER,
    OPT_X_TLS_NEWCTX,
    OPT_X_TLS_PROTOCOL_MAX,
    OPT_X_TLS_PROTOCOL_MIN,
    OPT_X_TLS_REQUIRE_CERT,
    RES_ADD,
    RES_ANY,
    RES_BIND,
    RES_COMPARE,
    RES_DELETE,
    RES_EXTENDED,
    RES_INTERMEDIATE,
    RES_MODIFY,
    RES_MODRDN,
    RES_SEARCH_ENTRY,
    RES_SEARCH_RESULT,
    SASL_QUIET,
    SCOPE_BASE,
    SCOPE_SUBTREE,
    VERSION3,
    WHOAMI_OID,
)
from anyldap.ldap.schema import SCHEMA_ATTRS
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

# What an intermediate response says: the name of the message and its value,
# which is what add_intermediates=1 asks to be handed.
Intermediate = tuple[str | None, bytes | None]

# The same three, each with the controls the message carried, which is what
# add_ctrls=1 asks for.
EntryWithControls = tuple[str, dict[str, list[bytes]], Sequence["controls.ResponseControl"]]
ReferenceWithControls = tuple[None, list[str], Sequence["controls.ResponseControl"]]
IntermediateWithControls = tuple[
    str | None, bytes | None, Sequence["controls.ResponseControl"]
]

# Everything result4() can hand back, which is more than a search finds.
Result4Data = list[
    Entry
    | Reference
    | Intermediate
    | EntryWithControls
    | ReferenceWithControls
    | IntermediateWithControls
]

# One thing the server sent while an operation was running: what kind of
# message it was, what it said, and the controls it carried.
_Answer = tuple[int, "Entry | Reference | Intermediate", Sequence["pureldap.Control"]]

# Controls are given either as the objects ``anyldap.ldap.controls`` builds
# or as the (type, criticality, value) triples that go on the wire.
Controls = Iterable["controls.RequestControl | pureldap.Control"] | None

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
        # What has arrived and not yet been handed out, in the order the
        # server sent it: entries, references, and whatever the server said
        # in between while the operation was still running.
        self.queue: list[_Answer] = []
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


def _found(queue: Sequence[_Answer], add_ctrls: int) -> Result4Data:
    """Everything a search found, in the order the server sent it.

    An intermediate response is not one of the things a search found, so it
    is not among them however the caller asked to be given the rest.
    """
    found: Result4Data = []
    for rtype, payload, payload_controls in queue:
        if rtype == RES_INTERMEDIATE:
            continue
        if add_ctrls:
            found.append(
                (*payload, controls.decode_controls(payload_controls))
            )
        else:
            found.append(payload)
    return found


def _timeout(value: object) -> float | None:
    """How long an operation may take, as an option says it.

    ``None`` and ``-1`` both mean no limit, which is what libldap makes of
    them; anything else negative is not a length of time at all.
    """
    if value is None:
        return None
    seconds = float(value)  # type: ignore[arg-type]
    if seconds == -1:
        return None
    if seconds < 0:
        raise ValueError(f"timeout {seconds!r} is not a length of time")
    return seconds


def _controls(value: object) -> Sequence[pureldap.Control]:
    """The response controls a message carried, as triples."""
    if value is None:
        return []
    assert isinstance(value, Sequence)
    return value


def _requested(value: Controls) -> list[pureldap.Control] | None:
    """The controls to send, however the caller spelled them.

    A control object knows how to encode itself; a triple is already what
    goes on the wire.
    """
    if value is None:
        return None
    sending: list[pureldap.Control] = []
    for control in value:
        if isinstance(control, controls.RequestControl):
            sending.append(
                (
                    to_bytes(control.controlType or ""),
                    1 if control.criticality else 0,
                    control.encodeControlValue(),
                )
            )
        else:
            sending.append(control)
    return sending


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


def _attributes(attrlist: Sequence[str] | None) -> list[str]:
    """The attributes a search asks for, refusing what is not a list of them.

    A bare string is a sequence of characters, and a search for those is
    never what the caller meant, so it is refused as python-ldap refuses it.
    """
    if attrlist is None:
        return []
    if isinstance(attrlist, (str, bytes)):
        raise TypeError("attrlist must be a list of strings, not a string")
    attributes = list(attrlist)
    for attribute in attributes:
        if not isinstance(attribute, str):
            raise TypeError(
                "attrs_from_List(): expected string in list", attribute
            )
    return attributes


def _parse_uri(uri: str) -> tuple[str, int, bool]:
    """The host, port and whether to raise TLS, out of an LDAP URL.

    An ``ldapi://`` URL names a socket in the filesystem rather than a host
    and port, and its path is percent-encoded, as OpenLDAP writes it.
    """
    parsed = urlparse(uri)
    if parsed.scheme == "ldapi":
        path = unquote(parsed.netloc or parsed.path) or "/var/run/ldapi"
        return path, 0, False
    if parsed.scheme not in ("ldap", "ldaps"):
        raise ValueError(f"unsupported LDAP URL scheme {parsed.scheme!r}")
    tls = parsed.scheme == "ldaps"
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"bad port in LDAP URL {uri!r}") from exc
    return parsed.hostname or "localhost", port or (636 if tls else 389), tls


# The TLS options that describe a context, and what each does to it.
_TLS_OPTIONS = frozenset(
    {
        OPT_X_TLS_CACERTFILE,
        OPT_X_TLS_CACERTDIR,
        OPT_X_TLS_CERTFILE,
        OPT_X_TLS_KEYFILE,
        OPT_X_TLS_REQUIRE_CERT,
        OPT_X_TLS_CIPHER_SUITE,
        OPT_X_TLS_PROTOCOL_MIN,
        OPT_X_TLS_PROTOCOL_MAX,
    }
)

# The options a SASL bind is tuned with. Cyrus SASL is what libldap hands
# these to; the mechanisms here answer for themselves, so what these do is
# supply the defaults a mechanism reads and say what the bind ended up with.
_SASL_READ_ONLY_OPTIONS = frozenset({OPT_X_SASL_USERNAME, OPT_X_SASL_SSF})
_SASL_OPTIONS = frozenset(
    {
        OPT_X_SASL_MECH,
        OPT_X_SASL_REALM,
        OPT_X_SASL_AUTHCID,
        OPT_X_SASL_AUTHZID,
        OPT_X_SASL_SSF_EXTERNAL,
        OPT_X_SASL_SECPROPS,
        OPT_X_SASL_SSF_MIN,
        OPT_X_SASL_SSF_MAX,
        OPT_X_SASL_MAXBUFSIZE,
        OPT_X_SASL_NOCANON,
    }
)

# Which option says what a mechanism would otherwise have to be told.
_SASL_DEFAULTS = {
    sasl.CB_GETREALM: OPT_X_SASL_REALM,
    sasl.CB_AUTHNAME: OPT_X_SASL_AUTHCID,
    sasl.CB_USER: OPT_X_SASL_AUTHZID,
}

# What OPT_X_TLS_PROTOCOL_MIN and _MAX name, in ssl's own spelling.
_TLS_VERSIONS = {
    0x300: ssl.TLSVersion.SSLv3,
    0x301: ssl.TLSVersion.TLSv1,
    0x302: ssl.TLSVersion.TLSv1_1,
    0x303: ssl.TLSVersion.TLSv1_2,
    0x304: ssl.TLSVersion.TLSv1_3,
}


def _tls_context(options: Mapping[int, object]) -> ssl.SSLContext:
    """The ssl.SSLContext the TLS options that were set describe."""
    context = ssl.create_default_context()
    require = options.get(OPT_X_TLS_REQUIRE_CERT)
    if require in (OPT_X_TLS_NEVER, OPT_X_TLS_ALLOW):
        # Nothing is checked, which is what those two ask for.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    cacertfile = options.get(OPT_X_TLS_CACERTFILE)
    cacertdir = options.get(OPT_X_TLS_CACERTDIR)
    if cacertfile is not None or cacertdir is not None:
        assert cacertfile is None or isinstance(cacertfile, str)
        assert cacertdir is None or isinstance(cacertdir, str)
        context.load_verify_locations(cafile=cacertfile, capath=cacertdir)
    certfile = options.get(OPT_X_TLS_CERTFILE)
    if certfile is not None:
        assert isinstance(certfile, str)
        keyfile = options.get(OPT_X_TLS_KEYFILE)
        assert keyfile is None or isinstance(keyfile, str)
        context.load_cert_chain(certfile, keyfile)
    ciphers = options.get(OPT_X_TLS_CIPHER_SUITE)
    if ciphers is not None:
        assert isinstance(ciphers, str)
        context.set_ciphers(ciphers)
    minimum = options.get(OPT_X_TLS_PROTOCOL_MIN)
    if minimum is not None:
        context.minimum_version = _TLS_VERSIONS[int(minimum)]  # type: ignore[call-overload]
    maximum = options.get(OPT_X_TLS_PROTOCOL_MAX)
    if maximum is not None:
        context.maximum_version = _TLS_VERSIONS[int(maximum)]  # type: ignore[call-overload]
    return context


# Whatever a connection was opened as, which is what a with statement on it
# hands back: a subclass stays itself.
_Connection = TypeVar("_Connection", bound="SimpleLDAPObject")


class SimpleLDAPObject:
    """A connection to one LDAP server, with the API of python-ldap's own.

    The connection is opened by the first operation that needs it, so that
    ``initialize()`` stays the plain call python-ldap makes it. Closing it is
    ``unbind_s()``, and ``async with`` closes it however the block ends.
    """

    # The attributes that are options underneath: setting one of these
    # goes through set_option(), which is what python-ldap does with them.
    CLASSATTR_OPTION_MAPPING: ClassVar[dict[str, int]] = {
        "protocol_version": OPT_PROTOCOL_VERSION,
        "deref": OPT_DEREF,
        "referrals": OPT_REFERRALS,
        "timelimit": OPT_TIMELIMIT,
        "sizelimit": OPT_SIZELIMIT,
        "network_timeout": OPT_NETWORK_TIMEOUT,
    }

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
        self.timeout: float | None = None
        self.network_timeout: float | None = None
        self.deref = DEREF_NEVER
        self.sizelimit = 0
        self.timelimit = 0
        self.referrals = 0
        self._given_context = ssl_context
        self._built_context: ssl.SSLContext | None = None
        self._tls_options: dict[int, object] = {}
        self._host, self._port, self._tls = _parse_uri(uri)
        self._unix = urlparse(uri).scheme == "ldapi"
        self._stream: ByteStream | None = None
        self._buffer = b""
        self._pending: dict[int, _Pending] = {}
        self._reading = anyio.Lock()
        self._writing = anyio.Lock()
        self._unbound = False
        self._sasl_mechanism: bytes | None = None
        self._sasl_options: dict[int, object] = {}
        self._sasl_username: str | None = None

    def __setattr__(self, name: str, value: Any) -> None:
        """An attribute that is an option underneath is set as one.

        ``connection.network_timeout = -1`` says the same thing as
        ``set_option(OPT_NETWORK_TIMEOUT, -1)``, which is what python-ldap
        makes of it too; the value that is kept is what the option made of
        what was given.
        """
        option = self.CLASSATTR_OPTION_MAPPING.get(name)
        if option is None:
            object.__setattr__(self, name, value)
        else:
            self.set_option(option, value)

    async def __aenter__(self: _Connection) -> _Connection:
        # Whatever this was opened as is what the body of the with
        # statement is handed, so a subclass keeps its own methods.
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.unbind_s()

    # Opening and closing the connection.

    @property
    def _ssl_context(self) -> ssl.SSLContext | None:
        """The context to raise TLS with, built from the options if need be.

        A context passed to ``initialize()`` is used as it stands; otherwise
        one is built the first time it is wanted, and again whenever
        ``OPT_X_TLS_NEWCTX`` says to start over.
        """
        if self._given_context is not None:
            return self._given_context
        if self._built_context is None and self._tls_options:
            self._built_context = _tls_context(self._tls_options)
        return self._built_context

    async def _connect_stream(self) -> ByteStream:
        if self._unix:
            return await anyio.connect_unix(self._host)
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
            async with _deadline(self.network_timeout):
                stream = await self._connect_stream()
        except OSError as exc:
            raise errors.SERVER_DOWN(
                {"desc": errors.SERVER_DOWN.desc, "info": str(exc)}
            ) from exc
        self._stream = stream
        return stream

    def fileno(self) -> int:
        """The socket this connection is open on.

        For a caller that wants to watch the connection with something of
        its own. It raises if nothing is open yet, because there is no
        socket to name until the first operation has been awaited.
        """
        stream = self._stream
        if stream is None:
            raise errors.LDAPError({"desc": "the connection is not open"})
        # A TLS stream hands on what the socket underneath it says, so this
        # is the same number whether or not TLS was raised.
        return int(stream.extra(anyio.abc.SocketAttribute.raw_socket).fileno())

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
        self, op: pureldap.LDAPProtocolRequest, serverctrls: Controls
    ) -> pureldap.LDAPMessage:
        stream = await self._connected()
        message = pureldap.LDAPMessage(op, controls=_requested(serverctrls))
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
            found: Entry | Reference
            if isinstance(response, pureldap.LDAPSearchResultEntry):
                found = _entry(response)
            else:
                found = _reference(response)
            operation.queue.append(
                (RES_SEARCH_ENTRY, found, _controls(message.controls))
            )
            return
        if isinstance(response, pureldap.LDAPIntermediateResponse):
            # Something the server says while the operation is still
            # running, which is how syncrepl says where it has got to.
            operation.queue.append(
                (
                    RES_INTERMEDIATE,
                    (
                        None
                        if response.responseName is None
                        else to_unicode(response.responseName),
                        response.responseValue,
                    ),
                    _controls(message.controls),
                )
            )
            return
        response_controls = _controls(message.controls)
        if not isinstance(response, operation.response):
            operation.error = errors.PROTOCOL_ERROR(
                {
                    "desc": errors.PROTOCOL_ERROR.desc,
                    "info": f"unexpected response: {response!r}",
                    "msgid": message.id,
                    "ctrls": controls.decode_controls(response_controls),
                }
            )
        elif response.resultCode != 0:
            fields: dict[str, object] = {
                "msgid": message.id,
                "msgtype": operation.rtype,
                "ctrls": controls.decode_controls(response_controls),
            }
            if isinstance(response, pureldap.LDAPBindResponse):
                # A bind that is not finished carries the server's next
                # challenge, which the mechanism answers.
                creds = response.serverSaslCreds
                fields["serverSaslCreds"] = (
                    None if creds is None else to_bytes(creds)
                )
            operation.error = errors.error_for_result(
                response.resultCode, response.errorMessage, **fields
            )
        else:
            operation.controls = response_controls
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
            return operation.done or bool(not all and operation.queue)

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
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
        """Wait for an operation started earlier, and answer with its result.

        ``RES_ANY`` takes the operation that was started first, which is the
        one python-ldap would most likely hand back.
        """
        rtype, data, rmsgid, controls, _, _ = await self.result4(msgid, all, timeout)
        # Without add_ctrls or add_intermediates, what result4() hands back
        # is what a search found and nothing else.
        return rtype, cast(ResultData, data), rmsgid, controls

    async def result4(
        self,
        msgid: int = RES_ANY,
        all: int = 1,
        timeout: float | None = None,
        add_ctrls: int = 0,
        add_intermediates: int = 0,
        add_extop: int = 0,
    ) -> tuple[
        int,
        Result4Data,
        int,
        Sequence["controls.ResponseControl"],
        str | None,
        bytes | None,
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
        # the wire until its result has been asked for too. What arrived and
        # was not asked for -- an intermediate response, usually -- is passed
        # over, and the connection read again rather than the operation
        # reported as finished when it is not.
        if not all:
            while True:
                queued = self._queued(operation, add_ctrls, add_intermediates)
                if queued is not None:
                    return queued[0], queued[1], msgid, [], None, None
                if operation.done:
                    break
                await self._wait(operation, timeout, all)
        else:
            await self._wait(operation, timeout, all)
        # A timed-out wait leaves the operation to be collected later, so it
        # is only forgotten once it has actually answered. A connection that
        # was lost has already forgotten every operation on it.
        self._pending.pop(msgid, None)
        if operation.error is not None:
            raise operation.error
        return (
            operation.rtype,
            _found(operation.queue, add_ctrls),
            msgid,
            controls.decode_controls(operation.controls),
            operation.name,
            operation.value,
        )

    @staticmethod
    def _queued(
        operation: _Pending, add_ctrls: int, add_intermediates: int
    ) -> tuple[int, Result4Data] | None:
        """The next message the operation has to hand out, if it has one.

        An intermediate response is passed over unless it was asked for,
        which is what python-ldap does with ``add_intermediates`` unset.
        """
        while operation.queue:
            rtype, payload, payload_controls = operation.queue[0]
            if rtype == RES_INTERMEDIATE and not add_intermediates:
                operation.queue.pop(0)
                continue
            operation.queue.pop(0)
            if add_ctrls:
                return rtype, [(*payload, controls.decode_controls(payload_controls))]
            return rtype, [payload]
        return None

    async def abandon_ext(
        self,
        msgid: int,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> None:
        """Tell the server to stop working on an operation, and forget it.

        Nothing is answered: an abandon is not a request the server replies
        to, which is what ``cancel()`` is for.
        """
        if self._pending.pop(msgid, None) is None:
            return
        await self._send(pureldap.LDAPAbandonRequest(id=msgid), serverctrls)

    async def abandon(self, msgid: int, serverctrls: Controls = None) -> None:
        await self.abandon_ext(msgid, serverctrls)

    async def cancel(
        self,
        cancelid: int,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> int:
        """Ask the server to stop working on an operation (RFC 3909).

        Unlike ``abandon()`` this is answered, so the caller learns whether
        the operation really did stop; the operation itself finishes with
        ``CANCELLED``.
        """
        return await self.extop(
            pureldap.LDAPCancelRequest(cancelID=cancelid), serverctrls, clientctrls
        )

    async def cancel_s(
        self,
        cancelid: int,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> tuple[int, ResultData] | None:
        msgid = await self.cancel(cancelid, serverctrls, clientctrls)
        try:
            return await self.result(msgid, all=1, timeout=self.timeout)
        except (errors.CANCELLED, errors.SUCCESS):
            # The server saying it has cancelled the operation is what was
            # asked for, not something to report as a failure.
            return None

    # Options.

    def set_option(self, option: int, invalue: object) -> None:
        if option == OPT_PROTOCOL_VERSION:
            assert isinstance(invalue, int)
            object.__setattr__(self, "protocol_version", invalue)
        elif option == OPT_SIZELIMIT:
            assert isinstance(invalue, int)
            object.__setattr__(self, "sizelimit", invalue)
        elif option == OPT_TIMELIMIT:
            assert isinstance(invalue, int)
            object.__setattr__(self, "timelimit", invalue)
        elif option == OPT_TIMEOUT:
            self.timeout = _timeout(invalue)
        elif option == OPT_NETWORK_TIMEOUT:
            object.__setattr__(self, "network_timeout", _timeout(invalue))
        elif option == OPT_URI:
            assert isinstance(invalue, str)
            self.uri = invalue
            self._host, self._port, self._tls = _parse_uri(invalue)
            self._unix = urlparse(invalue).scheme == "ldapi"
        elif option == OPT_DEREF:
            assert isinstance(invalue, int)
            object.__setattr__(self, "deref", invalue)
        elif option == OPT_REFERRALS:
            assert isinstance(invalue, int)
            object.__setattr__(self, "referrals", invalue)
        elif option in _TLS_OPTIONS:
            self._tls_options[option] = invalue
            # The context is described by every option together, so it is
            # built again once they have all been set.
            self._built_context = None
        elif option == OPT_X_TLS_NEWCTX:
            self._built_context = None
        elif option == OPT_X_TLS_CTX:
            assert invalue is None or isinstance(invalue, ssl.SSLContext)
            self._given_context = invalue
        elif option in _SASL_READ_ONLY_OPTIONS:
            # What the bind ended up with is the server's answer to say, not
            # the caller's, which is what libldap says of these too.
            raise ValueError(f"option {option!r} cannot be set")
        elif option in _SASL_OPTIONS:
            self._sasl_options[option] = invalue
        else:
            raise ValueError(f"unknown option {option!r}")

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
        if option == OPT_X_TLS_CTX:
            return self._ssl_context
        if option in _TLS_OPTIONS:
            return self._tls_options.get(option)
        if option == OPT_X_SASL_MECH:
            # Once a bind has been made this is the mechanism it was made
            # with, whatever was asked for beforehand.
            if self._sasl_mechanism is not None:
                return to_unicode(self._sasl_mechanism)
            return self._sasl_options.get(OPT_X_SASL_MECH)
        if option == OPT_X_SASL_USERNAME:
            return self._sasl_username
        if option == OPT_X_SASL_SSF:
            # No SASL security layer is negotiated: what protects the
            # connection is TLS, so the strength is whatever was said of it.
            return self._sasl_options.get(OPT_X_SASL_SSF_EXTERNAL, 0)
        if option in _SASL_OPTIONS:
            return self._sasl_options.get(option)
        raise ValueError(f"unknown option {option!r}")

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
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
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
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
        msgid = await self.bind(who, cred, method)
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def sasl_interactive_bind_s(
        self,
        who: str,
        auth: sasl.sasl,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
        sasl_flags: int = SASL_QUIET,
    ) -> None:
        """Bind with a SASL mechanism, answering the server until it is done.

        The mechanism is asked what to send, and asked again with whatever
        the server sent back, for as long as the server says the bind is
        still in progress. What the ``OPT_X_SASL_*`` options say fills in
        whatever the mechanism was not told directly.
        """
        for cb_id, option in _SASL_DEFAULTS.items():
            default = self._sasl_options.get(option)
            if default is not None and cb_id not in auth.cb_value_dict:
                assert isinstance(default, str)
                auth.cb_value_dict[cb_id] = default
        if isinstance(auth, sasl.gssapi) and auth.service is None:
            # The ticket is for the server being connected to, which is what
            # libldap works out for a GSSAPI bind as well.
            auth.service = f"ldap@{self._host}"
        credentials = auth.process()
        while True:
            message = await self._send(
                pureldap.LDAPBindRequest(
                    version=self.protocol_version,
                    dn=who,
                    auth=(auth.mech, credentials),
                    sasl=True,
                ),
                serverctrls,
            )
            operation = _Pending(RES_BIND, pureldap.LDAPBindResponse)
            self._pending[message.id] = operation
            try:
                await self._wait(operation, self.timeout)
            finally:
                self._pending.pop(message.id, None)
            if operation.error is None:
                self._sasl_mechanism = auth.mech
                # Who the bind ended up as, which OPT_X_SASL_USERNAME says.
                self._sasl_username = auth.cb_value_dict.get(
                    sasl.CB_AUTHNAME
                ) or auth.cb_value_dict.get(sasl.CB_USER, "")
                return
            if not isinstance(operation.error, errors.SASL_BIND_IN_PROGRESS):
                raise operation.error
            # The server has asked for the next step of the exchange.
            challenge = operation.error.args[0].get("serverSaslCreds")
            assert challenge is None or isinstance(challenge, bytes)
            credentials = auth.process(challenge)
            if credentials is None:
                # A step the mechanism has no answer for is the end of what
                # it can do, and the bind cannot finish.
                raise errors.AUTH_UNKNOWN(
                    {
                        "desc": errors.AUTH_UNKNOWN.desc,
                        "info": (
                            f"{to_unicode(auth.mech)} has no answer"
                            " for the challenge"
                        ),
                    }
                )

    async def sasl_non_interactive_bind_s(
        self,
        sasl_mech: str,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
        authz_id: str = "",
    ) -> None:
        """A SASL bind with a mechanism that asks the caller nothing."""
        mechanisms: dict[str, Callable[[str], sasl.sasl]] = {
            "EXTERNAL": sasl.external,
            "GSSAPI": sasl.gssapi,
        }
        if sasl_mech not in mechanisms:
            raise errors.AUTH_UNKNOWN(
                {
                    "desc": errors.AUTH_UNKNOWN.desc,
                    "info": f"{sasl_mech} needs credentials to bind with",
                }
            )
        await self.sasl_interactive_bind_s(
            "", mechanisms[sasl_mech](authz_id), serverctrls, clientctrls
        )

    async def sasl_gssapi_bind_s(
        self,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
        sasl_flags: int = SASL_QUIET,
        authz_id: str = "",
    ) -> None:
        """Bind with Kerberos, which is what the GSSAPI mechanism is."""
        await self.sasl_non_interactive_bind_s(
            "GSSAPI", serverctrls, clientctrls, authz_id
        )

    async def sasl_external_bind_s(
        self,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
        authz_id: str = "",
    ) -> None:
        """Bind as whoever the connection underneath already proved to be."""
        await self.sasl_non_interactive_bind_s(
            "EXTERNAL", serverctrls, clientctrls, authz_id
        )

    async def sasl_bind_s(
        self,
        dn: str,
        mech: str | bytes,
        cred: Value | None,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> bytes | None:
        """One step of a SASL bind, for callers driving the exchange itself.

        Answers with the credentials the server sent back, which is what the
        next step is built from.
        """
        message = await self._send(
            pureldap.LDAPBindRequest(
                version=self.protocol_version, dn=dn, auth=(mech, cred), sasl=True
            ),
            serverctrls,
        )
        operation = _Pending(RES_BIND, pureldap.LDAPBindResponse)
        self._pending[message.id] = operation
        try:
            await self._wait(operation, self.timeout)
        finally:
            self._pending.pop(message.id, None)
        if operation.error is not None:
            if not isinstance(operation.error, errors.SASL_BIND_IN_PROGRESS):
                raise operation.error
            creds = operation.error.args[0].get("serverSaslCreds")
            assert creds is None or isinstance(creds, bytes)
            return creds
        self._sasl_mechanism = to_bytes(mech)
        return operation.value

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
            base,
            scope,
            filterstr,
            attrlist,
            attrsonly,
            timeout=-1 if self.timeout is None else self.timeout,
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

    async def search_subschemasubentry_s(self, dn: str = "") -> str | None:
        """Where the server keeps the schema an entry is written against."""
        entry = await self.read_s(
            dn, "(objectClass=*)", ["subschemaSubentry"]
        )
        found = (entry or {}).get("subschemaSubentry")
        if not found:
            return None
        return to_unicode(found[0])

    async def read_subschemasubentry_s(
        self,
        subschemasubentry_dn: str,
        attrs: Sequence[str] | None = None,
    ) -> dict[str, list[bytes]] | None:
        """The schema itself, as the server publishes it."""
        return await self.read_s(
            subschemasubentry_dn,
            "(objectClass=subschema)",
            list(attrs) if attrs is not None else list(SCHEMA_ATTRS),
        )

    async def read_schema_s(self, dn: str = "") -> "schema.SubSchema":
        """The schema an entry is written against, read into objects.

        Not a method python-ldap has: it fetches schema with
        ``ldap.schema.urlfetch()``, which opens its own connection. This
        uses the connection that is already here.
        """
        subentry = await self.search_subschemasubentry_s(dn)
        if subentry is None:
            raise errors.NO_SUCH_OBJECT(
                {
                    "desc": errors.NO_SUCH_OBJECT.desc,
                    "info": f"{dn!r} names no subschema subentry",
                }
            )
        published = await self.read_subschemasubentry_s(subentry)
        return schema.SubSchema(published or {})

    async def find_unique_entry(
        self,
        base: str,
        scope: int = SCOPE_SUBTREE,
        filterstr: str = "(objectClass=*)",
        attrlist: Sequence[str] | None = None,
        attrsonly: int = 0,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
        timeout: float = -1,
    ) -> Entry:
        """The one entry a search found, or an error saying it was not one.

        The search asks for two entries, so a server that has more says so
        rather than sending them all.
        """
        data = await self.search_ext_s(
            base,
            scope,
            filterstr,
            attrlist,
            attrsonly,
            serverctrls,
            clientctrls,
            timeout,
            sizelimit=2,
        )
        if len(data) != 1:
            raise errors.NO_UNIQUE_ENTRY(
                {
                    "desc": errors.NO_UNIQUE_ENTRY.desc,
                    "info": f"no or non-unique search result for {filterstr!r}",
                }
            )
        dn, attributes = data[0]
        assert dn is not None and not isinstance(attributes, list)
        return dn, attributes

    async def read_rootdse_s(
        self, filterstr: str = "(objectClass=*)", attrlist: Sequence[str] | None = None
    ) -> dict[str, list[bytes]]:
        """What the server says about itself, from its root DSE."""
        return (
            await self.read_s(
                "", filterstr, ["*", "+"] if attrlist is None else attrlist
            )
            or {}
        )

    async def get_naming_contexts(self) -> list[bytes]:
        """The naming contexts the server holds."""
        rootdse = await self.read_rootdse_s(attrlist=["namingContexts"])
        return rootdse.get("namingContexts", [])

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
            attributes=_attributes(attrlist),
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
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
        msgid = await self.add_ext(dn, modlist, serverctrls, clientctrls)
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def add(self, dn: str, modlist: AddModlist) -> int:
        return await self.add_ext(dn, modlist)

    async def add_s(
        self, dn: str, modlist: AddModlist
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
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
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
        msgid = await self.modify_ext(dn, modlist, serverctrls, clientctrls)
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def modify(self, dn: str, modlist: ModifyModlist) -> int:
        return await self.modify_ext(dn, modlist)

    async def modify_s(
        self, dn: str, modlist: ModifyModlist
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
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
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
        msgid = await self.delete_ext(dn, serverctrls, clientctrls)
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def delete(self, dn: str) -> int:
        return await self.delete_ext(dn)

    async def delete_s(
        self, dn: str
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
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
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
        msgid = await self.rename(
            dn, newrdn, newsuperior, delold, serverctrls, clientctrls
        )
        return await self.result3(msgid, all=1, timeout=self.timeout)

    async def modrdn(self, dn: str, newrdn: str, delold: int = 1) -> int:
        return await self.rename(dn, newrdn, None, delold)

    async def modrdn_s(
        self, dn: str, newrdn: str, delold: int = 1
    ) -> tuple[int, ResultData, int, Sequence["controls.ResponseControl"]]:
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

    async def extop_result(
        self,
        msgid: int = RES_ANY,
        all: int = 1,
        timeout: float | None = None,
    ) -> tuple[str | None, bytes | None]:
        """Collect an extended operation started with ``extop()``."""
        _, _, _, _, name, value = await self.result4(
            msgid, all=1, timeout=self.timeout, add_ctrls=1, add_intermediates=1,
            add_extop=1,
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
                    "info": f"StartTLS answered to {name!r}",
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


class ReconnectLDAPObject(SimpleLDAPObject):
    """A connection that opens itself again when the server goes away.

    Each operation is tried, and if it fails with one of the errors that
    mean the connection rather than the request -- ``SERVER_DOWN``,
    ``UNAVAILABLE``, ``CONNECT_ERROR`` or ``TIMEOUT`` -- the connection is
    made again and the operation tried once more. Reconnecting replays what
    was done to the connection before: the options that were set, StartTLS
    if it was raised, and the last bind that was made.

    ``retry_max`` is how many times to try opening it again before giving
    up, and ``retry_delay`` how long to wait between tries.

    Unlike python-ldap's, this does not open the connection before the first
    operation: nothing is sent until something is awaited, so there is
    nothing to reconnect until an operation has failed.
    """

    # What is worth trying again, rather than telling the caller about.
    _reconnect_exceptions: tuple[type[errors.LDAPError], ...] = (
        errors.SERVER_DOWN,
        errors.UNAVAILABLE,
        errors.CONNECT_ERROR,
        errors.TIMEOUT,
    )

    # What cannot be pickled, because it is a socket or a lock.
    __transient_attrs__ = frozenset(
        {
            "_stream",
            "_buffer",
            "_pending",
            "_reading",
            "_writing",
            "_reconnecting",
            "_retrying",
        }
    )

    def __init__(
        self,
        uri: str,
        trace_level: int = 0,
        *,
        ssl_context: ssl.SSLContext | None = None,
        retry_max: int = 1,
        retry_delay: float = 60.0,
    ) -> None:
        # Set before the connection is built, because building it sets
        # options: what is written down is what a caller sets afterwards,
        # since the defaults are still there on a connection that is opened
        # again.
        self._options: list[tuple[int, object]] = []
        self._recording = False
        SimpleLDAPObject.__init__(self, uri, trace_level, ssl_context=ssl_context)
        self._recording = True
        self._uri = uri
        self._last_bind: tuple[str, tuple[Any, ...], dict[str, Any]] | None = None
        self._retry_max = retry_max
        self._retry_delay = retry_delay
        self._start_tls = 0
        self._reconnects_done = 0
        self._retrying = False
        self._reconnecting = anyio.Lock()

    def __getstate__(self) -> dict[str, Any]:
        """What of this can be written down, which is not the socket."""
        return {
            name: value
            for name, value in self.__dict__.items()
            if name not in self.__transient_attrs__
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        """Read back as a connection that is not open yet.

        It opens itself, with the options and the bind it was pickled with,
        the first time something is asked of it.
        """
        self.__dict__.update(state)
        # A connection that has not been opened, rather than one that was
        # said goodbye to: it opens itself when it is next used.
        self._unbound = False
        self._stream = None
        self._buffer = b""
        self._pending = {}
        self._reading = anyio.Lock()
        self._writing = anyio.Lock()
        self._reconnecting = anyio.Lock()
        self._retrying = False

    def _store_last_bind(self, method: str, *args: Any, **kwargs: Any) -> None:
        self._last_bind = (method, args, kwargs)

    async def _apply_last_bind(self) -> None:
        if self._last_bind is not None:
            method, args, kwargs = self._last_bind
            await getattr(SimpleLDAPObject, method)(self, *args, **kwargs)
        else:
            # An anonymous bind, sent to find out whether the server that
            # was reconnected to is really answering.
            await SimpleLDAPObject.simple_bind_s(self)

    def _restore_options(self) -> None:
        """Set again every option that was set on this connection."""
        for option, value in self._options:
            SimpleLDAPObject.set_option(self, option, value)

    def set_option(self, option: int, invalue: object) -> None:
        if self._recording:
            self._options.append((option, invalue))
        SimpleLDAPObject.set_option(self, option, invalue)

    async def reconnect(
        self,
        uri: str,
        retry_max: int = 1,
        retry_delay: float = 60.0,
        force: bool = True,
    ) -> None:
        """Open the connection again, and put it back as it was."""
        async with self._reconnecting:
            if self._stream is not None:
                if not force:
                    return
                await SimpleLDAPObject.unbind_ext(self)
            # Whatever was there has been given back, and this is a
            # connection that has not been opened rather than one that was
            # said goodbye to.
            self._unbound = False
            self._buffer = b""
            counter = retry_max
            while True:
                try:
                    try:
                        self._restore_options()
                        if self._start_tls:
                            await SimpleLDAPObject.start_tls_s(self)
                        await self._apply_last_bind()
                    except errors.LDAPError:
                        await SimpleLDAPObject.unbind_ext(self)
                        self._unbound = False
                        raise
                except (errors.SERVER_DOWN, errors.TIMEOUT):
                    counter -= 1
                    if not counter:
                        raise
                    if self.trace_level:
                        logger.debug("*** %s reconnect failed, waiting", uri)
                    await anyio.sleep(retry_delay)
                else:
                    self._reconnects_done += 1
                    return

    async def _apply_method_s(
        self, method: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """One operation, tried again on a connection that went away."""
        if self._retrying:
            # An operation written in terms of another one -- whoami_s is an
            # extended operation -- is retried once, by whichever of the two
            # the caller asked for.
            return await method(self, *args, **kwargs)
        self._retrying = True
        try:
            if (
                not self._unbound
                and self._stream is None
                and self._last_bind is not None
            ):
                # Nothing is open, and this connection was bound before it
                # was closed or written down: it is opened and bound again
                # before the operation rather than sent as nobody at all.
                await self.reconnect(
                    self._uri,
                    retry_max=self._retry_max,
                    retry_delay=self._retry_delay,
                    force=False,
                )
            try:
                return await method(self, *args, **kwargs)
            except self._reconnect_exceptions:
                await self.reconnect(
                    self._uri,
                    retry_max=self._retry_max,
                    retry_delay=self._retry_delay,
                    force=True,
                )
                return await method(self, *args, **kwargs)
        finally:
            self._retrying = False

    async def simple_bind_s(self, *args: Any, **kwargs: Any) -> Any:
        result = await self._apply_method_s(
            SimpleLDAPObject.simple_bind_s, *args, **kwargs
        )
        self._store_last_bind("simple_bind_s", *args, **kwargs)
        return result

    async def bind_s(self, *args: Any, **kwargs: Any) -> Any:
        result = await self._apply_method_s(SimpleLDAPObject.bind_s, *args, **kwargs)
        self._store_last_bind("bind_s", *args, **kwargs)
        return result

    async def sasl_interactive_bind_s(self, *args: Any, **kwargs: Any) -> Any:
        result = await self._apply_method_s(
            SimpleLDAPObject.sasl_interactive_bind_s, *args, **kwargs
        )
        self._store_last_bind("sasl_interactive_bind_s", *args, **kwargs)
        return result

    async def sasl_bind_s(self, *args: Any, **kwargs: Any) -> Any:
        result = await self._apply_method_s(
            SimpleLDAPObject.sasl_bind_s, *args, **kwargs
        )
        self._store_last_bind("sasl_bind_s", *args, **kwargs)
        return result

    async def start_tls_s(self, *args: Any, **kwargs: Any) -> Any:
        result = await self._apply_method_s(
            SimpleLDAPObject.start_tls_s, *args, **kwargs
        )
        self._start_tls = 1
        return result

    async def search_ext_s(self, *args: Any, **kwargs: Any) -> Any:
        return await self._apply_method_s(
            SimpleLDAPObject.search_ext_s, *args, **kwargs
        )

    async def add_ext_s(self, *args: Any, **kwargs: Any) -> Any:
        return await self._apply_method_s(SimpleLDAPObject.add_ext_s, *args, **kwargs)

    async def modify_ext_s(self, *args: Any, **kwargs: Any) -> Any:
        return await self._apply_method_s(
            SimpleLDAPObject.modify_ext_s, *args, **kwargs
        )

    async def delete_ext_s(self, *args: Any, **kwargs: Any) -> Any:
        return await self._apply_method_s(
            SimpleLDAPObject.delete_ext_s, *args, **kwargs
        )

    async def rename_s(self, *args: Any, **kwargs: Any) -> Any:
        return await self._apply_method_s(SimpleLDAPObject.rename_s, *args, **kwargs)

    async def compare_ext_s(self, *args: Any, **kwargs: Any) -> Any:
        return await self._apply_method_s(
            SimpleLDAPObject.compare_ext_s, *args, **kwargs
        )

    async def extop_s(self, *args: Any, **kwargs: Any) -> Any:
        return await self._apply_method_s(SimpleLDAPObject.extop_s, *args, **kwargs)

    async def cancel_s(self, *args: Any, **kwargs: Any) -> Any:
        return await self._apply_method_s(SimpleLDAPObject.cancel_s, *args, **kwargs)

    async def passwd_s(self, *args: Any, **kwargs: Any) -> Any:
        return await self._apply_method_s(SimpleLDAPObject.passwd_s, *args, **kwargs)

    async def whoami_s(self, *args: Any, **kwargs: Any) -> str:
        result = await self._apply_method_s(SimpleLDAPObject.whoami_s, *args, **kwargs)
        assert isinstance(result, str)
        return result


# python-ldap's own name for the class it hands back.
LDAPObject = SimpleLDAPObject


def initialize(
    uri: str,
    trace_level: int = 0,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> SimpleLDAPObject:
    """A connection to the server named by an ``ldap://`` or ``ldaps://`` URL.

    Nothing is sent until the first operation is awaited, which is what lets
    this stay the plain call python-ldap makes it. Whatever was given to
    ``ldap.set_option()`` is what the connection starts with.
    """
    from anyldap.ldap import functions

    connection = SimpleLDAPObject(uri, trace_level, ssl_context=ssl_context)
    for option, value in functions._defaults.items():
        connection.set_option(option, value)
    return connection


# python-ldap's older spelling of the same thing.
def open(host: str, port: int = 389, trace_level: int = 0) -> SimpleLDAPObject:
    return initialize("ldap://%s:%d" % (host, port), trace_level)
