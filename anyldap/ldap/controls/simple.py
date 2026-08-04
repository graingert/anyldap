"""``ldap.controls.simple``: the controls whose value is simple or absent."""

from anyldap._encoder import to_bytes, to_unicode
from anyldap.ldap.constants import (
    CONTROL_MANAGEDSAIT,
    CONTROL_PROXY_AUTHZ,
    CONTROL_RELAX,
)
from anyldap.ldap.controls import (
    KNOWN_RESPONSE_CONTROLS,
    RequestControl,
    ResponseControl,
)
from anyldap.protocols import pureber

AUTHORIZATION_IDENTITY_REQUEST_OID = "2.16.840.1.113730.3.4.16"
AUTHORIZATION_IDENTITY_RESPONSE_OID = "2.16.840.1.113730.3.4.15"


class ValueLessRequestControl(RequestControl):
    """A control that says all it has to say by being there at all."""

    def __init__(self, controlType: str | None = None, criticality: bool = False):
        self.controlType = controlType
        self.criticality = criticality

    def encodeControlValue(self) -> bytes | None:
        return None


class OctetStringInteger(RequestControl, ResponseControl):
    """A control whose value is one integer, written as an octet string."""

    def __init__(
        self,
        controlType: str | None = None,
        criticality: bool = False,
        integerValue: int | None = None,
    ) -> None:
        self.controlType = controlType
        self.criticality = criticality
        self.integerValue = integerValue

    def encodeControlValue(self) -> bytes:
        assert self.integerValue is not None
        return pureber.BERInteger(self.integerValue).toWire()

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        value, _ = pureber.berDecodeObject(
            pureber.BERDecoderContext(), encodedControlValue
        )
        assert isinstance(value, pureber.BERInteger)
        self.integerValue = value.value


class BooleanControl(RequestControl, ResponseControl):
    """A control whose value is yes or no."""

    boolean2ber = {True: b"\x01\x01\xff", False: b"\x01\x01\x00"}

    def __init__(
        self,
        controlType: str | None = None,
        criticality: bool = False,
        booleanValue: bool = False,
    ) -> None:
        self.controlType = controlType
        self.criticality = criticality
        self.booleanValue = booleanValue

    def encodeControlValue(self) -> bytes:
        return self.boolean2ber[bool(self.booleanValue)]

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        value, _ = pureber.berDecodeObject(
            pureber.BERDecoderContext(), encodedControlValue
        )
        assert isinstance(value, pureber.BERBoolean)
        self.booleanValue = bool(value.value)


class ManageDSAITControl(ValueLessRequestControl):
    """Ask for the entry itself rather than what it refers to."""

    def __init__(self, criticality: bool = False) -> None:
        ValueLessRequestControl.__init__(self, CONTROL_MANAGEDSAIT, criticality)


class RelaxRulesControl(ValueLessRequestControl):
    """Ask the server to allow what its own rules would not."""

    def __init__(self, criticality: bool = False) -> None:
        ValueLessRequestControl.__init__(self, CONTROL_RELAX, criticality)


class ProxyAuthzControl(RequestControl):
    """Ask the server to act as somebody else, if it will let you."""

    def __init__(self, criticality: bool, authzId: str) -> None:
        RequestControl.__init__(self, CONTROL_PROXY_AUTHZ, criticality)
        self.authzId = authzId

    def encodeControlValue(self) -> bytes:
        return to_bytes(self.authzId)


class AuthorizationIdentityRequestControl(ValueLessRequestControl):
    """Ask the bind to say which identity it ended up as."""

    def __init__(self, criticality: bool = False) -> None:
        ValueLessRequestControl.__init__(
            self, AUTHORIZATION_IDENTITY_REQUEST_OID, criticality
        )


class AuthorizationIdentityResponseControl(ResponseControl):
    """The identity the bind ended up as."""

    def __init__(
        self,
        controlType: str | None = AUTHORIZATION_IDENTITY_RESPONSE_OID,
        criticality: bool = False,
    ) -> None:
        ResponseControl.__init__(self, controlType, criticality)
        self.authzId: str | None = None

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        self.authzId = to_unicode(encodedControlValue)


KNOWN_RESPONSE_CONTROLS[AUTHORIZATION_IDENTITY_RESPONSE_OID] = (
    AuthorizationIdentityResponseControl
)
