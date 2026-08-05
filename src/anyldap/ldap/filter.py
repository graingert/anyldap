"""``ldap.filter``: building search filters out of untrusted values."""

import time
from collections.abc import Iterable

from anyldap._encoder import to_unicode
from anyldap.ldap.functions import strf_secs as strf_secs
from anyldap.ldap.ldapobject import Value

# RFC 4515 says these four have to be escaped, and so does anything that is
# not a printable character.
_ESCAPED = {
    "*": r"\2a",
    "(": r"\28",
    ")": r"\29",
    "\\": r"\5c",
    "\x00": r"\00",
}


def escape_filter_chars(assertion_value: Value, escape_mode: int = 0) -> str:
    """An assertion value with the characters a filter would read escaped.

    ``escape_mode`` 0 escapes what RFC 4515 requires, 1 escapes everything
    outside the printable range as well, and 2 escapes every character.

    Each mode escapes what python-ldap's own escapes, character by character
    as it does, so a filter built here is the one it would have built.
    """
    if not isinstance(assertion_value, (str, bytes)):
        raise TypeError("assertion_value must be of type str.")
    if escape_mode not in (0, 1, 2):
        raise ValueError("escape_mode must be 0, 1 or 2.")
    text = to_unicode(assertion_value)
    if escape_mode == 0:
        return "".join(_ESCAPED.get(char, char) for char in text)
    escaped = []
    for char in text:
        if escape_mode == 2 or char < "0" or char > "z" or char in "\\*()":
            escaped.append("\\%02x" % ord(char))
        else:
            escaped.append(char)
    return "".join(escaped)


def filter_format(filter_template: str, assertion_values: Iterable[Value]) -> str:
    """A filter built from a template, with every value escaped first."""
    return filter_template % tuple(
        escape_filter_chars(value) for value in assertion_values
    )


def time_span_filter(
    filterstr: str = "",
    from_timestamp: float = 0,
    until_timestamp: float | None = None,
    delta_attr: str = "modifyTimestamp",
) -> str:
    """This filter, narrowed to what changed between two times.

    A negative ``from_timestamp`` is that many seconds before the end of the
    span, which is now unless ``until_timestamp`` says otherwise.
    """
    if until_timestamp is None:
        until_timestamp = time.time()
        if from_timestamp < 0:
            from_timestamp = until_timestamp + from_timestamp
    if from_timestamp > until_timestamp:
        raise ValueError(
            "from_timestamp {!r} must not be greater than until_timestamp {!r}".format(
                from_timestamp, until_timestamp
            )
        )
    return (
        "(&"
        "{filterstr}"
        "({delta_attr}>={from_timestr})"
        "(!({delta_attr}>={until_timestr}))"
        ")"
    ).format(
        filterstr=filterstr,
        delta_attr=delta_attr,
        from_timestr=strf_secs(from_timestamp),
        until_timestr=strf_secs(until_timestamp),
    )
