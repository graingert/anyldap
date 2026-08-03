"""The exceptions python-ldap raises, keyed by the result code that causes them.

Each class carries the LDAP result code it stands for, and an instance holds
the same ``args[0]`` dictionary python-ldap builds: a ``desc`` describing the
code, and the server's own ``info`` message when it sent one.
"""

from typing import ClassVar

from anyldap._encoder import to_unicode


class LDAPError(Exception):
    """The base of every error raised here, as ``ldap.LDAPError`` is."""

    # The result code this stands for, or None for the errors that are
    # raised without one having arrived.
    result: ClassVar[int | None] = None
    desc: ClassVar[str] = "Unknown error"

    # Which class answers for a result code. First one registered wins, so
    # the canonical name keeps the code and its aliases do not take it.
    _by_result: ClassVar[dict[int, type["LDAPError"]]] = {}

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if cls.result is not None:
            LDAPError._by_result.setdefault(cls.result, cls)

    @property
    def _fields(self) -> dict[str, object]:
        if self.args and isinstance(self.args[0], dict):
            # The mapping python-ldap puts in args[0], which is where its
            # own callers read desc and info from.
            fields: dict[str, object] = self.args[0]
            return fields
        return {}

    @property
    def info(self) -> str | None:
        """The diagnostic message the server sent, if it sent one."""
        value = self._fields.get("info")
        return None if value is None else str(value)


class SERVER_DOWN(LDAPError):
    """The connection could not be opened, or was lost."""

    result = -1
    desc = "Can't contact LDAP server"


class LOCAL_ERROR(LDAPError):
    result = -2
    desc = "Local error"


class ENCODING_ERROR(LDAPError):
    result = -3
    desc = "Encoding error"


class DECODING_ERROR(LDAPError):
    result = -4
    desc = "Decoding error"


class TIMEOUT(LDAPError):
    """The client gave up waiting before the server answered."""

    result = -5
    desc = "Timed out"


class AUTH_UNKNOWN(LDAPError):
    result = -6
    desc = "Unknown authentication method"


class FILTER_ERROR(LDAPError):
    """The search filter could not be parsed."""

    result = -7
    desc = "Bad search filter"


class USER_CANCELLED(LDAPError):
    result = -8
    desc = "User cancelled operation"


class PARAM_ERROR(LDAPError):
    result = -9
    desc = "Bad parameter to an ldap routine"


class NO_MEMORY(LDAPError):
    result = -10
    desc = "Out of memory"


class CONNECT_ERROR(LDAPError):
    result = -11
    desc = "Connect error"


class NOT_SUPPORTED(LDAPError):
    result = -12
    desc = "Not supported"


class CONTROL_NOT_FOUND(LDAPError):
    result = -13
    desc = "Control not found"


class NO_RESULTS_RETURNED(LDAPError):
    result = -14
    desc = "No results returned"


class MORE_RESULTS_TO_RETURN(LDAPError):
    result = -15
    desc = "More results to return"


class CLIENT_LOOP(LDAPError):
    result = -16
    desc = "Client loop"


class REFERRAL_LIMIT_EXCEEDED(LDAPError):
    result = -17
    desc = "Referral limit exceeded"


class NO_UNIQUE_ENTRY(LDAPError):
    """A read expecting one entry found none, or several."""

    desc = "No or non-unique search result"


class OPERATIONS_ERROR(LDAPError):
    result = 1
    desc = "Operations error"


class PROTOCOL_ERROR(LDAPError):
    result = 2
    desc = "Protocol error"


class TIMELIMIT_EXCEEDED(LDAPError):
    result = 3
    desc = "Time limit exceeded"


class SIZELIMIT_EXCEEDED(LDAPError):
    result = 4
    desc = "Size limit exceeded"


class COMPARE_FALSE(LDAPError):
    """A compare that answered no; compare_s() turns this into False."""

    result = 5
    desc = "Compare False"


class COMPARE_TRUE(LDAPError):
    """A compare that answered yes; compare_s() turns this into True."""

    result = 6
    desc = "Compare True"


class AUTH_METHOD_NOT_SUPPORTED(LDAPError):
    result = 7
    desc = "Authentication method not supported"


class STRONG_AUTH_REQUIRED(LDAPError):
    result = 8
    desc = "Strong(er) authentication required"


class PARTIAL_RESULTS(LDAPError):
    result = 9
    desc = "Partial results and referral received"


class REFERRAL(LDAPError):
    result = 10
    desc = "Referral"


class ADMINLIMIT_EXCEEDED(LDAPError):
    result = 11
    desc = "Administrative limit exceeded"


class UNAVAILABLE_CRITICAL_EXTENSION(LDAPError):
    result = 12
    desc = "Critical extension is unavailable"


class CONFIDENTIALITY_REQUIRED(LDAPError):
    result = 13
    desc = "Confidentiality required"


class SASL_BIND_IN_PROGRESS(LDAPError):
    result = 14
    desc = "SASL bind in progress"


class NO_SUCH_ATTRIBUTE(LDAPError):
    result = 16
    desc = "No such attribute"


class UNDEFINED_TYPE(LDAPError):
    result = 17
    desc = "Undefined attribute type"


class INAPPROPRIATE_MATCHING(LDAPError):
    result = 18
    desc = "Inappropriate matching"


class CONSTRAINT_VIOLATION(LDAPError):
    result = 19
    desc = "Constraint violation"


class TYPE_OR_VALUE_EXISTS(LDAPError):
    result = 20
    desc = "Type or value exists"


class INVALID_SYNTAX(LDAPError):
    result = 21
    desc = "Invalid syntax"


class NO_SUCH_OBJECT(LDAPError):
    result = 32
    desc = "No such object"


class ALIAS_PROBLEM(LDAPError):
    result = 33
    desc = "Alias problem"


class INVALID_DN_SYNTAX(LDAPError):
    result = 34
    desc = "Invalid DN syntax"


class IS_LEAF(LDAPError):
    result = 35
    desc = "Is a leaf"


class ALIAS_DEREF_PROBLEM(LDAPError):
    result = 36
    desc = "Alias dereferencing problem"


class INAPPROPRIATE_AUTH(LDAPError):
    result = 48
    desc = "Inappropriate authentication"


class INVALID_CREDENTIALS(LDAPError):
    result = 49
    desc = "Invalid credentials"


class INSUFFICIENT_ACCESS(LDAPError):
    result = 50
    desc = "Insufficient access"


class BUSY(LDAPError):
    result = 51
    desc = "Server is busy"


class UNAVAILABLE(LDAPError):
    result = 52
    desc = "Server is unavailable"


class UNWILLING_TO_PERFORM(LDAPError):
    result = 53
    desc = "Server is unwilling to perform"


class LOOP_DETECT(LDAPError):
    result = 54
    desc = "Loop detected"


class NAMING_VIOLATION(LDAPError):
    result = 64
    desc = "Naming violation"


class OBJECT_CLASS_VIOLATION(LDAPError):
    result = 65
    desc = "Object class violation"


class NOT_ALLOWED_ON_NONLEAF(LDAPError):
    result = 66
    desc = "Operation not allowed on non-leaf"


class NOT_ALLOWED_ON_RDN(LDAPError):
    result = 67
    desc = "Operation not allowed on RDN"


class ALREADY_EXISTS(LDAPError):
    result = 68
    desc = "Already exists"


class NO_OBJECT_CLASS_MODS(LDAPError):
    result = 69
    desc = "Cannot modify object class"


class RESULTS_TOO_LARGE(LDAPError):
    result = 70
    desc = "Results too large"


class AFFECTS_MULTIPLE_DSAS(LDAPError):
    result = 71
    desc = "Operation affects multiple DSAs"


class OTHER(LDAPError):
    result = 80
    desc = "Other"


class SUCCESS(LDAPError):
    """The code that is not an error; nothing here is raised with it."""

    result = 0
    desc = "Success"


class X_PROXY_AUTHZ_FAILURE(LDAPError):
    result = 47
    desc = "Proxy authorization failure"


class VLV_ERROR(LDAPError):
    result = 76
    desc = "Virtual List View error"


class CANCELLED(LDAPError):
    result = 118
    desc = "Cancelled"


class NO_SUCH_OPERATION(LDAPError):
    result = 119
    desc = "No such operation"


class TOO_LATE(LDAPError):
    result = 120
    desc = "Too late"


class CANNOT_CANCEL(LDAPError):
    result = 121
    desc = "Cannot cancel"


class ASSERTION_FAILED(LDAPError):
    result = 122
    desc = "Assertion failed"


class PROXIED_AUTHORIZATION_DENIED(LDAPError):
    result = 123
    desc = "Proxied authorization denied"


# Names python-ldap also answers to.
STRONG_AUTH_NOT_SUPPORTED = AUTH_METHOD_NOT_SUPPORTED
ADMIN_LIMIT_EXCEEDED = ADMINLIMIT_EXCEEDED


def error_for_result(code: int, message: str | bytes | None = None) -> LDAPError:
    """The exception a result code stands for, carrying the server's message."""
    cls = LDAPError._by_result.get(code, OTHER)
    fields: dict[str, object] = {"desc": cls.desc, "result": code}
    if message:
        fields["info"] = to_unicode(message)
    return cls(fields)
