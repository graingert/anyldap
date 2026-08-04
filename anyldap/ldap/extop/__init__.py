"""``ldap.extop``: the extended operations a server may offer.

An extended operation is a request named by an OID with a value whose shape
that OID decides, and a response of the same shape. These classes are what a
caller builds one out of: a subclass says what its OID is, writes its request
value out and reads its response value back, and
:meth:`~anyldap.ldap.ldapobject.SimpleLDAPObject.extop_s` sends it.
"""

__all__ = [
    "ExtendedRequest",
    "ExtendedResponse",
    "RefreshRequest",
    "RefreshResponse",
    "PasswordModifyResponse",
]


class ExtendedRequest:
    """An extended operation being asked for.

    ``requestName`` is the OID that says which operation it is, and
    ``requestValue`` the bytes that go with it.
    """

    def __init__(self, requestName: str, requestValue: bytes) -> None:
        self.requestName = requestName
        self.requestValue = requestValue

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.requestName},{self.requestValue!r})"

    def encodedRequestValue(self) -> bytes:
        """The request value, written out as it goes on the wire."""
        return self.requestValue


class ExtendedResponse:
    """What the server answered an extended operation with."""

    def __init__(self, responseName: str | None, encodedResponseValue: bytes) -> None:
        self.responseName = responseName
        self.responseValue = self.decodeResponseValue(encodedResponseValue)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.responseName},{self.responseValue!r})"

    def decodeResponseValue(self, value: bytes) -> object:
        """Read the response value, and say what it said."""
        return value


# The operations that are here, which are written in terms of the two
# classes above and so are imported once those exist.
from anyldap.ldap.extop.dds import (
    RefreshRequest as RefreshRequest,
)
from anyldap.ldap.extop.dds import (
    RefreshResponse as RefreshResponse,
)
from anyldap.ldap.extop.passwd import (
    PasswordModifyResponse as PasswordModifyResponse,
)
