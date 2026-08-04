"""``ldap.dn``: taking distinguished names apart and putting them together."""

import re
import string
from collections.abc import Sequence

from anyldap._encoder import to_unicode
from anyldap.ldap import errors
from anyldap.ldap.ldapobject import Value
from anyldap.protocols.ldap import distinguishedname as _dn

# How python-ldap says a value was spelled: plain text, or text that had to
# be escaped to be written down.
AVA_NULL = 0
AVA_STRING = 1
AVA_BINARY = 2
AVA_NONPRINTABLE = 4

# One attribute and its value, and the RDNs those make up, as python-ldap
# hands them back.
AVA = tuple[str, str, int]
RDN = list[AVA]
DN = list[RDN]

# An attribute type is a name or an OID, and nothing else is one.
_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+")


def escape_dn_chars(s: str) -> str:
    """A value with the characters a DN would read escaped."""
    return _dn.escape(s)


def _unescape(text: str) -> str:
    """One AVA's value, with the escapes a DN is written with taken out.

    A ``\\xx`` pair is one octet of the value, so the octets are gathered up
    and read as the UTF-8 they are, rather than one character each.
    """
    raw = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            raw.extend(char.encode("utf-8"))
            index += 1
            continue
        pair = text[index + 1 : index + 3]
        if len(pair) == 2 and all(digit in string.hexdigits for digit in pair):
            raw.append(int(pair, 16))
            index += 3
        elif len(text) > index + 1:
            raw.extend(text[index + 1].encode("utf-8"))
            index += 2
        else:
            raise errors.DECODING_ERROR(
                {"desc": errors.DECODING_ERROR.desc, "info": "DN ends in a backslash"}
            )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise errors.DECODING_ERROR(
            {"desc": errors.DECODING_ERROR.desc, "info": str(exc)}
        ) from exc


def _flag(value: str) -> int:
    """How the value was written: as it stands, or escaped to be written."""
    if value.isascii() and value.isprintable():
        return AVA_STRING
    return AVA_NONPRINTABLE


def _ava(text: str) -> AVA:
    attribute, sep, value = text.partition("=")
    if not sep or not _TYPE.fullmatch(attribute):
        raise errors.DECODING_ERROR(
            {
                "desc": errors.DECODING_ERROR.desc,
                "info": f"not an attribute and value: {text!r}",
            }
        )
    unescaped = _unescape(value)
    return attribute, unescaped, _flag(unescaped)


def str2dn(dn: Value | None, flags: int = 0) -> DN:
    """A DN taken apart into its RDNs, each a list of attribute/value pairs.

    Raises ``DECODING_ERROR`` for text that is not a distinguished name,
    which is what python-ldap raises for it.
    """
    if dn is None:
        return []
    text = to_unicode(dn)
    if not text:
        return []
    return [[_ava(ava) for ava in _split(rdn, "+")] for rdn in _split(text, ",")]


def _split(text: str, separator: str) -> list[str]:
    """The parts of a DN or RDN, split on the separators that are not escaped.

    Nothing between two separators is not a part, so a name that starts or
    ends with one is not a name at all.
    """
    parts = _dn._splitOnNotEscaped(text, separator)
    if not parts or separator.join(parts) != text:
        raise errors.DECODING_ERROR(
            {
                "desc": errors.DECODING_ERROR.desc,
                "info": f"empty part in {text!r}",
            }
        )
    return parts


def dn2str(dn: Sequence[Sequence[AVA]]) -> str:
    """The text of a DN that was taken apart by str2dn()."""
    return ",".join(
        "+".join(
            f"{escape_dn_chars(attribute)}={escape_dn_chars(value)}"
            for attribute, value, _ in rdn
        )
        for rdn in dn
    )


def explode_dn(dn: Value, notypes: int = 0, flags: int = 0) -> list[str]:
    """The RDNs of a DN, as text, optionally without their attribute types."""
    if not dn:
        return []
    return [
        "+".join(value for _, value, _ in rdn) if notypes else dn2str([rdn])
        for rdn in str2dn(dn, flags)
    ]


def explode_rdn(rdn: Value, notypes: int = 0, flags: int = 0) -> list[str]:
    """The attribute/value pairs of one RDN, as text."""
    if not rdn:
        return []
    parsed = str2dn(rdn, flags)[0]
    if notypes:
        return [value for _, value, _ in parsed]
    return [dn2str([[ava]]) for ava in parsed]


def is_dn(s: str, flags: int = 0) -> bool:
    """Whether this is a distinguished name that can be parsed."""
    try:
        str2dn(s, flags)
    except errors.DECODING_ERROR:
        return False
    return True
