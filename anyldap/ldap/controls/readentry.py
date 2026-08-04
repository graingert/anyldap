"""``ldap.controls.readentry``: the entry as it was, or as it became.

RFC 4527. A pre-read control asks for the entry the way it stood before the
operation, a post-read for the way it stands after, so a caller does not
have to search again to find out.
"""

from collections.abc import Sequence

from anyldap._encoder import to_bytes, to_unicode
from anyldap.ldap.constants import CONTROL_POST_READ, CONTROL_PRE_READ
from anyldap.ldap.controls import (
    KNOWN_RESPONSE_CONTROLS,
    RequestControl,
    ResponseControl,
)
from anyldap.protocols import pureber, pureldap


class ReadEntryControl(RequestControl, ResponseControl):
    """The attributes to read, and the entry that came back."""

    def __init__(
        self, criticality: bool = False, attrList: Sequence[str] | None = None
    ) -> None:
        self.criticality = criticality
        self.attrList = list(attrList or [])
        self.dn: str | None = None
        self.entry: dict[str, list[bytes]] | None = None

    def encodeControlValue(self) -> bytes:
        return pureber.BERSequence(
            [pureldap.LDAPAttributeDescription(attribute) for attribute in self.attrList]
        ).toWire()

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        # RFC 4527: the value is a search result entry, which is the entry
        # the server read for the operation.
        decoder = pureldap.LDAPBERDecoderContext(
            fallback=pureber.BERDecoderContext()
        )
        value, _ = pureber.berDecodeObject(decoder, encodedControlValue)
        assert isinstance(value, pureldap.LDAPSearchResultEntry)
        self.dn = to_unicode(value.objectName)
        entry: dict[str, list[bytes]] = {}
        for key, values in value.attributes:
            entry.setdefault(to_unicode(key), []).extend(
                to_bytes(item) for item in values
            )
        self.entry = entry


class PreReadControl(ReadEntryControl):
    """The entry as it stood before the operation."""

    controlType = CONTROL_PRE_READ

    def __init__(
        self, criticality: bool = False, attrList: Sequence[str] | None = None
    ) -> None:
        ReadEntryControl.__init__(self, criticality, attrList)
        self.controlType = CONTROL_PRE_READ


class PostReadControl(ReadEntryControl):
    """The entry as it stands after the operation."""

    controlType = CONTROL_POST_READ

    def __init__(
        self, criticality: bool = False, attrList: Sequence[str] | None = None
    ) -> None:
        ReadEntryControl.__init__(self, criticality, attrList)
        self.controlType = CONTROL_POST_READ


KNOWN_RESPONSE_CONTROLS[CONTROL_PRE_READ] = PreReadControl
KNOWN_RESPONSE_CONTROLS[CONTROL_POST_READ] = PostReadControl
