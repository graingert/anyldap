"""``ldap.dn``: taking distinguished names apart and putting them together."""

from collections.abc import Sequence

from anyldap._encoder import to_unicode
from anyldap.ldap.ldapobject import Value
from anyldap.protocols.ldap import distinguishedname as _dn

# How python-ldap says a value was spelled. Values are text here, so a
# decoded DN always says so.
AVA_STRING = 1
AVA_BINARY = 2
AVA_NONPRINTABLE = 4

# One attribute and its value, and the RDNs those make up, as python-ldap
# hands them back.
AVA = tuple[str, str, int]
RDN = list[AVA]
DN = list[RDN]


def escape_dn_chars(value: str) -> str:
    """A value with the characters a DN would read escaped."""
    return _dn.escape(value)


def str2dn(dn: Value | None, flags: int = 0) -> DN:
    """A DN taken apart into its RDNs, each a list of attribute/value pairs."""
    if dn is None:
        return []
    parsed = _dn.DistinguishedName(stringValue=to_unicode(dn))
    return [
        [
            (ava.attributeType, ava.value, AVA_STRING)
            for ava in rdn.split()
        ]
        for rdn in parsed.split()
    ]


def dn2str(dn: Sequence[Sequence[AVA]]) -> str:
    """The text of a DN that was taken apart by str2dn()."""
    return ",".join(
        "+".join(
            f"{_dn.escape(attribute)}={_dn.escape(value)}"
            for attribute, value, _ in rdn
        )
        for rdn in dn
    )


def explode_dn(dn: Value, notypes: int = 0, flags: int = 0) -> list[str]:
    """The RDNs of a DN, as text, optionally without their attribute types."""
    if not dn:
        return []
    return [
        dn2str([rdn]) if not notypes else "+".join(value for _, value, _ in rdn)
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


def is_dn(dn: str, flags: int = 0) -> bool:
    """Whether this is a distinguished name that can be parsed."""
    try:
        str2dn(dn, flags)
    except (ValueError, _dn.InvalidRelativeDistinguishedName):
        return False
    return True
