"""``ldap.extop.passwd``: the password modify operation (RFC 3062)."""

from anyldap.ldap._ber import elements
from anyldap.ldap.extop import ExtendedResponse

__all__ = ["PasswordModifyResponse"]


class PasswordModifyResponse(ExtendedResponse):
    """The password the server made up, when it was not given one."""

    responseName = None

    def decodeResponseValue(self, value: bytes) -> bytes:
        [(_, content)] = elements(value)
        [(_, generated)] = elements(content)
        self.genPasswd = generated
        return self.genPasswd
