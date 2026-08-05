"""``ldap.controls.pagedresults``: reading a large search a page at a time.

RFC 2696. The control carries how many entries a page holds and, after the
first page, the cookie the server gave for asking for the next one.
"""

from anyldap.ldap.constants import CONTROL_PAGEDRESULTS
from anyldap.ldap.controls import (
    KNOWN_RESPONSE_CONTROLS,
    RequestControl,
    ResponseControl,
)
from anyldap.protocols import pureber


class SimplePagedResultsControl(RequestControl, ResponseControl):
    """How big a page is, and where the last one left off.

    ``cookie`` is empty to ask for the first page, and is whatever the
    server last sent to ask for the one after it. An empty cookie coming
    back means there are no more pages.
    """

    controlType = CONTROL_PAGEDRESULTS

    def __init__(
        self,
        criticality: bool = False,
        size: int = 10,
        cookie: bytes = b"",
    ) -> None:
        self.controlType = CONTROL_PAGEDRESULTS
        self.criticality = criticality
        self.size = size
        self.cookie = cookie

    def encodeControlValue(self) -> bytes:
        return pureber.BERSequence(
            [pureber.BERInteger(self.size), pureber.BEROctetString(self.cookie)]
        ).toWire()

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        value, _ = pureber.berDecodeObject(
            pureber.BERDecoderContext(), encodedControlValue
        )
        assert isinstance(value, pureber.BERSequence)
        size, cookie = value[0], value[1]
        assert isinstance(size, pureber.BERInteger)
        assert isinstance(cookie, pureber.BEROctetString)
        self.size = size.value
        self.cookie = (
            cookie.value if isinstance(cookie.value, bytes) else cookie.value.encode()
        )


KNOWN_RESPONSE_CONTROLS[CONTROL_PAGEDRESULTS] = SimplePagedResultsControl
