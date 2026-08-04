"""``ldap.filter``: building search filters out of untrusted values."""

from collections.abc import Iterable

from anyldap._encoder import to_unicode
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
