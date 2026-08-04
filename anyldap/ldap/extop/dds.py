"""``ldap.extop.dds``: entries that go away by themselves (RFC 2589).

A dynamic entry lives for as long as its time to live says, and a refresh
request asks the server to start that clock again.
"""

from anyldap._encoder import to_bytes
from anyldap.ldap._ber import elements
from anyldap.ldap.extop import ExtendedRequest, ExtendedResponse
from anyldap.protocols import pureber

__all__ = ["RefreshRequest", "RefreshResponse"]

# The entry being refreshed and how long it should live are written under
# tags of their own rather than by position.
_ENTRY_NAME = pureber.CLASS_CONTEXT | 0x00
_TTL = pureber.CLASS_CONTEXT | 0x01


class RefreshRequest(ExtendedRequest):
    """Ask that a dynamic entry go on living for another ``requestTtl``."""

    requestName = "1.3.6.1.4.1.1466.101.119.1"
    defaultRequestTtl = 86400

    def __init__(
        self,
        requestName: str | None = None,
        entryName: str | None = None,
        requestTtl: int | None = None,
    ) -> None:
        super().__init__(requestName or self.requestName, b"")
        self.entryName = entryName
        self.requestTtl = requestTtl or self.defaultRequestTtl

    def encodedRequestValue(self) -> bytes:
        return pureber.BERSequence(
            [
                pureber.BEROctetString(to_bytes(self.entryName or ""), tag=_ENTRY_NAME),
                pureber.BERInteger(self.requestTtl, tag=_TTL),
            ]
        ).toWire()


class RefreshResponse(ExtendedResponse):
    """How long the server says the entry has left."""

    responseName = "1.3.6.1.4.1.1466.101.119.1"

    def decodeResponseValue(self, value: bytes) -> int:
        [(_, content)] = elements(value)
        [(_, ttl)] = elements(content)
        self.responseTtl = pureber.ber2int(ttl)
        return self.responseTtl
