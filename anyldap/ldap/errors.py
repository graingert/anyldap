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
    # raised without one having arrived. python-ldap calls it errnum.
    errnum: ClassVar[int | None] = None
    desc: ClassVar[str] = "Unknown error"

    # Which class answers for a result code. First one registered wins, so
    # the canonical name keeps the code and its aliases do not take it.
    _by_result: ClassVar[dict[int, type["LDAPError"]]] = {}

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if cls.errnum is not None:
            LDAPError._by_result.setdefault(cls.errnum, cls)

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

    errnum = -1
    desc = "Can't contact LDAP server"


class LOCAL_ERROR(LDAPError):
    errnum = -2
    desc = "Local error"


class ENCODING_ERROR(LDAPError):
    errnum = -3
    desc = "Encoding error"


class DECODING_ERROR(LDAPError):
    errnum = -4
    desc = "Decoding error"


class TIMEOUT(LDAPError):
    """The client gave up waiting before the server answered."""

    errnum = -5
    desc = "Timed out"


class AUTH_UNKNOWN(LDAPError):
    errnum = -6
    desc = "Unknown authentication method"


class FILTER_ERROR(LDAPError):
    """The search filter could not be parsed."""

    errnum = -7
    desc = "Bad search filter"


class USER_CANCELLED(LDAPError):
    errnum = -8
    desc = "User cancelled operation"


class PARAM_ERROR(LDAPError):
    errnum = -9
    desc = "Bad parameter to an ldap routine"


class NO_MEMORY(LDAPError):
    errnum = -10
    desc = "Out of memory"


class CONNECT_ERROR(LDAPError):
    errnum = -11
    desc = "Connect error"


class NOT_SUPPORTED(LDAPError):
    errnum = -12
    desc = "Not supported"


class CONTROL_NOT_FOUND(LDAPError):
    errnum = -13
    desc = "Control not found"


class NO_RESULTS_RETURNED(LDAPError):
    errnum = -14
    desc = "No results returned"


class MORE_RESULTS_TO_RETURN(LDAPError):
    errnum = -15
    desc = "More results to return"


class CLIENT_LOOP(LDAPError):
    errnum = -16
    desc = "Client loop"


class REFERRAL_LIMIT_EXCEEDED(LDAPError):
    errnum = -17
    desc = "Referral limit exceeded"


class OPERATIONS_ERROR(LDAPError):
    errnum = 1
    desc = "Operations error"


class PROTOCOL_ERROR(LDAPError):
    errnum = 2
    desc = "Protocol error"


class TIMELIMIT_EXCEEDED(LDAPError):
    errnum = 3
    desc = "Time limit exceeded"


class SIZELIMIT_EXCEEDED(LDAPError):
    errnum = 4
    desc = "Size limit exceeded"


class COMPARE_FALSE(LDAPError):
    """A compare that answered no; compare_s() turns this into False."""

    errnum = 5
    desc = "Compare False"


class COMPARE_TRUE(LDAPError):
    """A compare that answered yes; compare_s() turns this into True."""

    errnum = 6
    desc = "Compare True"


class AUTH_METHOD_NOT_SUPPORTED(LDAPError):
    errnum = 7
    desc = "Authentication method not supported"


class STRONG_AUTH_REQUIRED(LDAPError):
    errnum = 8
    desc = "Strong(er) authentication required"


class PARTIAL_RESULTS(LDAPError):
    errnum = 9
    desc = "Partial results and referral received"


class REFERRAL(LDAPError):
    errnum = 10
    desc = "Referral"


class ADMINLIMIT_EXCEEDED(LDAPError):
    errnum = 11
    desc = "Administrative limit exceeded"


class UNAVAILABLE_CRITICAL_EXTENSION(LDAPError):
    errnum = 12
    desc = "Critical extension is unavailable"


class CONFIDENTIALITY_REQUIRED(LDAPError):
    errnum = 13
    desc = "Confidentiality required"


class SASL_BIND_IN_PROGRESS(LDAPError):
    errnum = 14
    desc = "SASL bind in progress"


class NO_SUCH_ATTRIBUTE(LDAPError):
    errnum = 16
    desc = "No such attribute"


class UNDEFINED_TYPE(LDAPError):
    errnum = 17
    desc = "Undefined attribute type"


class INAPPROPRIATE_MATCHING(LDAPError):
    errnum = 18
    desc = "Inappropriate matching"


class CONSTRAINT_VIOLATION(LDAPError):
    errnum = 19
    desc = "Constraint violation"


class TYPE_OR_VALUE_EXISTS(LDAPError):
    errnum = 20
    desc = "Type or value exists"


class INVALID_SYNTAX(LDAPError):
    errnum = 21
    desc = "Invalid syntax"


class NO_SUCH_OBJECT(LDAPError):
    errnum = 32
    desc = "No such object"


class NO_UNIQUE_ENTRY(NO_SUCH_OBJECT):
    """A read expecting one entry found none, or several.

    Not a result code a server sends: it is what this raises when a read
    that must find exactly one entry did not, which is what python-ldap
    raises it for too.
    """

    desc = "No or non-unique search result"


class ALIAS_PROBLEM(LDAPError):
    errnum = 33
    desc = "Alias problem"


class INVALID_DN_SYNTAX(LDAPError):
    errnum = 34
    desc = "Invalid DN syntax"


class IS_LEAF(LDAPError):
    errnum = 35
    desc = "Is a leaf"


class ALIAS_DEREF_PROBLEM(LDAPError):
    errnum = 36
    desc = "Alias dereferencing problem"


class INAPPROPRIATE_AUTH(LDAPError):
    errnum = 48
    desc = "Inappropriate authentication"


class INVALID_CREDENTIALS(LDAPError):
    errnum = 49
    desc = "Invalid credentials"


class INSUFFICIENT_ACCESS(LDAPError):
    errnum = 50
    desc = "Insufficient access"


class BUSY(LDAPError):
    errnum = 51
    desc = "Server is busy"


class UNAVAILABLE(LDAPError):
    errnum = 52
    desc = "Server is unavailable"


class UNWILLING_TO_PERFORM(LDAPError):
    errnum = 53
    desc = "Server is unwilling to perform"


class LOOP_DETECT(LDAPError):
    errnum = 54
    desc = "Loop detected"


class NAMING_VIOLATION(LDAPError):
    errnum = 64
    desc = "Naming violation"


class OBJECT_CLASS_VIOLATION(LDAPError):
    errnum = 65
    desc = "Object class violation"


class NOT_ALLOWED_ON_NONLEAF(LDAPError):
    errnum = 66
    desc = "Operation not allowed on non-leaf"


class NOT_ALLOWED_ON_RDN(LDAPError):
    errnum = 67
    desc = "Operation not allowed on RDN"


class ALREADY_EXISTS(LDAPError):
    errnum = 68
    desc = "Already exists"


class NO_OBJECT_CLASS_MODS(LDAPError):
    errnum = 69
    desc = "Cannot modify object class"


class RESULTS_TOO_LARGE(LDAPError):
    errnum = 70
    desc = "Results too large"


class AFFECTS_MULTIPLE_DSAS(LDAPError):
    errnum = 71
    desc = "Operation affects multiple DSAs"


class OTHER(LDAPError):
    errnum = 80
    desc = "Other"


class SUCCESS(LDAPError):
    """The code that is not an error; nothing here is raised with it."""

    errnum = 0
    desc = "Success"


class X_PROXY_AUTHZ_FAILURE(LDAPError):
    errnum = 47
    desc = "Proxy authorization failure"


class VLV_ERROR(LDAPError):
    errnum = 76
    desc = "Virtual List View error"


class CANCELLED(LDAPError):
    errnum = 118
    desc = "Cancelled"


class NO_SUCH_OPERATION(LDAPError):
    errnum = 119
    desc = "No such operation"


class TOO_LATE(LDAPError):
    errnum = 120
    desc = "Too late"


class CANNOT_CANCEL(LDAPError):
    errnum = 121
    desc = "Cannot cancel"


class ASSERTION_FAILED(LDAPError):
    errnum = 122
    desc = "Assertion failed"


class PROXIED_AUTHORIZATION_DENIED(LDAPError):
    errnum = 123
    desc = "Proxied authorization denied"


# Names python-ldap also answers to.
STRONG_AUTH_NOT_SUPPORTED = AUTH_METHOD_NOT_SUPPORTED
ADMIN_LIMIT_EXCEEDED = ADMINLIMIT_EXCEEDED


def error_for_result(
    code: int,
    message: str | bytes | None = None,
    **fields: object,
) -> LDAPError:
    """The exception a result code stands for, carrying the server's message.

    Anything else the response said about itself -- which message it was,
    what kind, the controls it carried -- goes in the same dictionary, where
    python-ldap puts it.
    """
    cls = LDAPError._by_result.get(code, OTHER)
    args: dict[str, object] = {"desc": cls.desc, "result": code}
    if message:
        args["info"] = to_unicode(message)
    args.update(fields)
    return cls(args)
