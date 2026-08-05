"""
    Test cases for anyldap.protocols.ldap.ldaperrors module.
"""

from anyldap.protocols.ldap import ldaperrors


class UnnamedException(ldaperrors.LDAPException):
    """LDAP exception with undefined name"""


class TestGetTests:
    """Getting LDAP exception implementation by error code"""

    def test_get_success(self) -> None:
        """Getting OK message"""
        success = ldaperrors.get(0, "Some message")
        assert success.__class__ == ldaperrors.Success
        assert success.resultCode == 0
        assert success.name == b"success"

    def test_get_existing_exception(self) -> None:
        """Getting existing LDAPException subclass"""
        exception = ldaperrors.get(49, "Error message")
        assert exception.__class__ == ldaperrors.LDAPInvalidCredentials
        assert exception.resultCode == 49
        assert exception.name == b"invalidCredentials"
        assert exception.message == "Error message"

    def test_get_nonexisting_exception(self) -> None:
        """Getting non-existing LDAP error"""
        exception = ldaperrors.get(55, "Error message")
        assert exception.__class__ == ldaperrors.LDAPUnknownError
        assert exception.code == 55
        assert exception.message == "Error message"


class TestLDAPExceptionTests:
    """Getting bytes representations of LDAP exceptions"""

    def test_exception_with_message(self) -> None:
        """Exception with a text message"""
        exception = ldaperrors.LDAPProtocolError("Error message")
        assert exception.toWire() == b"protocolError: Error message"

    def test_empty_exception(self) -> None:
        """Exception with no message"""
        exception = ldaperrors.LDAPCompareFalse()
        assert exception.toWire() == b"compareFalse"

    def test_unnamed_exception(self) -> None:
        """Exception with no name"""
        exception = UnnamedException()
        assert exception.toWire() == b"Unknown LDAP error UnnamedException()"

    def test_unknown_exception_with_message(self) -> None:
        """Unknown exception with a text message"""
        exception = ldaperrors.LDAPUnknownError(56, "Error message")
        assert exception.toWire() == b"unknownError(56): Error message"

    def test_unknown_empty_exception(self) -> None:
        """Unknown exception with no message"""
        exception = ldaperrors.LDAPUnknownError(57)
        assert exception.toWire() == b"unknownError(57)"


class TestLDAPExceptionStrTests:
    """Getting string representations of LDAP exceptions"""

    def test_exception_with_message(self) -> None:
        """Exception with a text message"""
        exception = ldaperrors.LDAPProtocolError("Error message")
        assert str(exception) == "protocolError: Error message"
