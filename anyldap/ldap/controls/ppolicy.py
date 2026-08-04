"""``ldap.controls.ppolicy``: what the server says about the password.

The password policy response control (draft-behera-ldap-password-policy):
how long the password has left, how many grace logins remain, and what is
wrong with it if the operation was refused because of it.
"""

from anyldap.ldap.constants import (
    CONTROL_PASSWORDPOLICYREQUEST,
    CONTROL_PASSWORDPOLICYRESPONSE,
)
from anyldap.ldap.controls import KNOWN_RESPONSE_CONTROLS, ResponseControl
from anyldap.ldap.controls.simple import ValueLessRequestControl
from anyldap.protocols import pureber

# The warning is written with a tag saying which warning it is, and the
# error alongside it with one of its own.
_WARNING = pureber.CLASS_CONTEXT | pureber.STRUCTURED | 0x00
_TIME_BEFORE_EXPIRATION = pureber.CLASS_CONTEXT | 0x00
_GRACE_AUTHNS_REMAINING = pureber.CLASS_CONTEXT | 0x01
_ERROR = pureber.CLASS_CONTEXT | 0x01


def _parts(data: bytes) -> list[tuple[int, bytes]]:
    """The tag and content of each element written one after another.

    Read by hand rather than through a decoder context: which warning the
    server sent is told by the tag alone, and a context looks a tag up
    without the bit that says it is constructed.
    """
    elements = []
    while data:
        tag = data[0]
        length, lengthlength = pureber.berDecodeLength(data, offset=1)
        start = 1 + lengthlength
        elements.append((tag, data[start : start + length]))
        data = data[start + length :]
    return elements


class PasswordPolicyControl(ValueLessRequestControl, ResponseControl):
    """Ask about the password policy, and read what the server said."""

    controlType = CONTROL_PASSWORDPOLICYREQUEST

    def __init__(self, criticality: bool = False) -> None:
        ValueLessRequestControl.__init__(
            self, CONTROL_PASSWORDPOLICYREQUEST, criticality
        )
        self.timeBeforeExpiration: int | None = None
        self.graceAuthNsRemaining: int | None = None
        self.error: int | None = None

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        [(_, content)] = _parts(encodedControlValue)
        for tag, value in _parts(content):
            if tag == _WARNING:
                # The warning is a CHOICE, so it says one thing or the other.
                [(warning, number)] = _parts(value)
                if warning == _TIME_BEFORE_EXPIRATION:
                    self.timeBeforeExpiration = pureber.ber2int(number)
                else:
                    self.graceAuthNsRemaining = pureber.ber2int(number)
            elif tag == _ERROR:
                self.error = pureber.ber2int(value)


KNOWN_RESPONSE_CONTROLS[CONTROL_PASSWORDPOLICYRESPONSE] = PasswordPolicyControl
