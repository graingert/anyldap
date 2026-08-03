import base64

from anyldap import entry
from anyldap.runtime import Protocol


class LDIFParseError(Exception):
    """Error parsing LDIF"""

    def __str__(self) -> str:
        s = self.__doc__
        assert s is not None
        if self.args:
            s = ": ".join([s] + [str(x) for x in self.args])
        return s + "."


class LDIFLineWithoutSemicolonError(LDIFParseError):
    """LDIF line without semicolon seen"""


class LDIFEntryStartsWithNonDNError(LDIFParseError):
    """LDIF entry starts with a non-DN line"""


class LDIFEntryStartsWithSpaceError(LDIFParseError):
    """Invalid LDIF value format"""


class LDIFVersionNotANumberError(LDIFParseError):
    """Non-numeric LDIF version number"""


class LDIFUnsupportedVersionError(LDIFParseError):
    """LDIF version not supported"""


class LDIFTruncatedError(LDIFParseError):
    """LDIF appears to be truncated"""


HEADER = b"HEADER"
WAIT_FOR_DN = b"WAIT_FOR_DN"
IN_ENTRY = b"IN_ENTRY"


class _LineReceiver(Protocol):
    delimiter = b"\n"

    def __init__(self) -> None:
        self._buffer = b""

    def dataReceived(self, data: bytes) -> None:
        self._buffer += data
        while True:
            index = self._buffer.find(self.delimiter)
            if index == -1:
                break
            line = self._buffer[:index]
            self._buffer = self._buffer[index + len(self.delimiter) :]
            self.lineReceived(line)

    def lineReceived(self, line: bytes) -> None:
        raise NotImplementedError()


class LDIF(_LineReceiver):
    delimiter = b"\n"
    mode = HEADER

    dn: bytes | None = None
    data: dict[bytes, list[bytes]] | None = None
    lastLine: bytes | None = None

    version: int | None = None

    def __init__(self) -> None:
        super().__init__()

    def logicalLineReceived(self, line: bytes) -> None:
        if line.startswith(b"#"):
            # comments are allowed everywhere
            return
        getattr(self, "state_" + self.mode.decode("ascii"))(line)

    def lineReceived(self, line: bytes) -> None:
        if line.startswith(b" "):
            if self.lastLine is None:
                raise LDIFEntryStartsWithSpaceError()
            self.lastLine = self.lastLine + line[1:]
        else:
            if self.lastLine is not None:
                self.logicalLineReceived(self.lastLine)
            self.lastLine = line
            if line == b"":
                self.logicalLineReceived(line)
                self.lastLine = None

    def parseValue(self, val: bytes) -> bytes:
        if val.startswith(b":"):
            return base64.decodebytes(val[1:].lstrip(b" "))
        elif val.startswith(b"<"):
            raise NotImplementedError()
        else:
            return val.lstrip(b" ")

    def _parseLine(self, line: bytes) -> tuple[bytes, bytes]:
        try:
            key, val = line.split(b":", 1)
        except ValueError:
            # unpack list of wrong size
            # -> invalid input data
            raise LDIFLineWithoutSemicolonError(line)
        val = self.parseValue(val)
        return key, val

    def state_HEADER(self, line: bytes) -> None:
        key, val = self._parseLine(line)
        self.mode = WAIT_FOR_DN

        if key != b"version":
            self.logicalLineReceived(line)
        else:
            try:
                version = int(val)
            except ValueError:
                raise LDIFVersionNotANumberError(val)
            self.version = version
            if version > 1:
                raise LDIFUnsupportedVersionError(version)

    def state_WAIT_FOR_DN(self, line: bytes) -> None:
        assert self.dn is None, "self.dn must not be set when waiting for DN"
        assert self.data is None, "self.data must not be set when waiting for DN"
        if line == b"":
            # too many empty lines, but be tolerant
            return

        key, val = self._parseLine(line)

        if key.upper() != b"DN":
            raise LDIFEntryStartsWithNonDNError(line)

        self.dn = val
        self.data = {}
        self.mode = IN_ENTRY

    def state_IN_ENTRY(self, line: bytes) -> None:
        assert self.dn is not None, "self.dn must be set when in entry"
        assert self.data is not None, "self.data must be set when in entry"

        if line == b"":
            # end of entry
            self.mode = WAIT_FOR_DN
            o = entry.BaseLDAPEntry(dn=self.dn, attributes=self.data)
            self.dn = None
            self.data = None
            self.gotEntry(o)
            return

        key, val = self._parseLine(line)

        if not key in self.data:
            self.data[key] = []

        self.data[key].append(val)

    def gotEntry(self, obj: object) -> None:
        """Called with whatever this parser produces.

        The base parser produces entries; the delta parser produces
        operations.
        """

    def connectionLost(self, reason: BaseException = Protocol.connectionDone) -> None:
        if self.mode != WAIT_FOR_DN:
            raise LDIFTruncatedError(reason)
