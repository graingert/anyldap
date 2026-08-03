from collections.abc import Iterable
from functools import total_ordering

from anyldap._encoder import TextStrAlias, to_unicode

# See rfc2253
# Note that RFC 2253 sections 2.4 and 3 disagree whether "=" needs to
# be quoted. Let's trust the syntax, slapd refuses to accept unescaped
# "=" in RDN values.
escapedChars = ',+"\\<>;='
escapedChars_leading = " #"
escapedChars_trailing = " #"


def escape(s: str) -> str:
    r = ""
    r_trailer = ""

    if s and s[0] in escapedChars_leading:
        r = "\\" + s[0]
        s = s[1:]

    if s and s[-1] in escapedChars_trailing:
        r_trailer = "\\" + s[-1]
        s = s[:-1]

    for c in s:
        if c in escapedChars:
            r = r + "\\" + c
        elif ord(c) <= 31:
            r = r + "\\%02X" % ord(c)
        else:
            r = r + c

    return r + r_trailer


def unescape(s: str) -> str:
    r = ""

    while s:
        if s[0] == "\\":
            if s[1] in "0123456789abcdef":
                r = r + chr(int(s[1:3], 16))
                s = s[3:]
            else:
                r = r + s[1]
                s = s[2:]
        else:
            r = r + s[0]
            s = s[1:]

    return r


def _splitOnNotEscaped(s: str, separator: str) -> list[str]:
    if not s:
        return []

    r = [""]
    while s:
        first = s[0:1]

        if first == "\\":
            r[-1] = r[-1] + s[:2]
            s = s[2:]
        else:

            if first == separator:
                r.append("")
                s = s[1:]
                while s[0:1] == " ":
                    s = s[1:]
            else:
                r[-1] = r[-1] + first
                s = s[1:]

    return r


class InvalidRelativeDistinguishedName(Exception):
    """
    Invalid relative distinguished name.
    It is assumed that passed RDN is of str type:
    bytes for PY2 and unicode for PY3.
    """

    def __init__(self, rdn: object) -> None:
        Exception.__init__(self)
        self.rdn = rdn

    def __str__(self) -> str:
        return "Invalid relative distinguished name %s." % repr(self.rdn)


class LDAPAttributeTypeAndValue(TextStrAlias):
    # TODO I should be used everywhere
    attributeType: str
    value: str

    def __init__(
        self,
        stringValue: str | bytes | None = None,
        attributeType: str | bytes | None = None,
        value: str | bytes | None = None,
    ) -> None:
        if stringValue is None:
            assert attributeType is not None
            assert value is not None
            self.attributeType = to_unicode(attributeType)
            self.value = to_unicode(value)
        else:
            assert attributeType is None
            assert value is None

            text: str = to_unicode(stringValue)

            if "=" not in text:
                raise InvalidRelativeDistinguishedName(text)
            self.attributeType, self.value = text.split("=", 1)

    def getText(self) -> str:
        return "=".join((escape(self.attributeType), escape(self.value)))

    def __repr__(self) -> str:
        return (
            self.__class__.__name__
            + "(attributeType="
            + repr(self.attributeType)
            + ", value="
            + repr(self.value)
            + ")"
        )

    def __hash__(self) -> int:
        return hash((self.attributeType, self.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LDAPAttributeTypeAndValue):
            return NotImplemented
        return (
            self.attributeType.lower() == other.attributeType.lower()
            and self.value.lower() == other.value.lower()
        )

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, LDAPAttributeTypeAndValue):
            return False
        if self.attributeType != other.attributeType:
            return self.attributeType < other.attributeType
        else:
            return self.value < other.value

    def __gt__(self, other: object) -> bool:
        return self != other and not self < other

    def __le__(self, other: object) -> bool:
        return not self > other

    def __ge__(self, other: object) -> bool:
        return not self < other


class RelativeDistinguishedName(TextStrAlias):
    """LDAP Relative Distinguished Name."""

    attributeTypesAndValues: tuple[LDAPAttributeTypeAndValue, ...]

    def __init__(
        self,
        magic: object = None,
        stringValue: str | bytes | None = None,
        attributeTypesAndValues: Iterable[LDAPAttributeTypeAndValue] | None = None,
    ) -> None:
        if magic is not None:
            assert stringValue is None
            assert attributeTypesAndValues is None
            if isinstance(magic, RelativeDistinguishedName):
                attributeTypesAndValues = magic.split()
            elif isinstance(magic, (bytes, str)):
                stringValue = magic
            else:
                assert isinstance(magic, Iterable)
                attributeTypesAndValues = magic

        if stringValue is None:
            assert attributeTypesAndValues is not None
            assert not isinstance(attributeTypesAndValues, (bytes, str))
            self.attributeTypesAndValues = tuple(attributeTypesAndValues)
        else:
            assert attributeTypesAndValues is None
            self.attributeTypesAndValues = tuple(
                LDAPAttributeTypeAndValue(stringValue=unescape(x))
                for x in _splitOnNotEscaped(to_unicode(stringValue), "+")
            )

    def split(self) -> tuple[LDAPAttributeTypeAndValue, ...]:
        return self.attributeTypesAndValues

    def getText(self) -> str:
        return "+".join([x.getText() for x in self.attributeTypesAndValues])

    def __repr__(self) -> str:
        return (
            self.__class__.__name__
            + "(attributeTypesAndValues="
            + repr(self.attributeTypesAndValues)
            + ")"
        )

    def __hash__(self) -> int:
        return hash(self.attributeTypesAndValues)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RelativeDistinguishedName):
            return NotImplemented
        return self.split() == other.split()

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RelativeDistinguishedName):
            return False
        return self.split() < other.split()

    def __gt__(self, other: object) -> bool:
        return bool(self != other and self >= other)

    def __le__(self, other: object) -> bool:
        return not self > other

    def __ge__(self, other: object) -> bool:
        return not self < other

    def count(self) -> int:
        return len(self.attributeTypesAndValues)


@total_ordering
class DistinguishedName(TextStrAlias):
    """LDAP Distinguished Name."""

    listOfRDNs: tuple[RelativeDistinguishedName, ...]

    def __init__(
        self,
        magic: object = None,
        stringValue: str | bytes | None = None,
        listOfRDNs: Iterable[RelativeDistinguishedName] | None = None,
    ) -> None:
        assert magic is not None or stringValue is not None or listOfRDNs is not None
        if magic is not None:
            assert stringValue is None
            assert listOfRDNs is None
            if isinstance(magic, DistinguishedName):
                listOfRDNs = magic.split()
            elif isinstance(magic, (bytes, str)):
                # This might need to be expended if we want to support
                # different encodings.
                stringValue = magic
            else:
                assert isinstance(magic, Iterable)
                listOfRDNs = magic

        if stringValue is None:
            assert listOfRDNs is not None
            for x in listOfRDNs:
                assert isinstance(x, RelativeDistinguishedName)
            self.listOfRDNs = tuple(listOfRDNs)
        else:
            assert listOfRDNs is None
            self.listOfRDNs = tuple(
                RelativeDistinguishedName(stringValue=x)
                for x in _splitOnNotEscaped(to_unicode(stringValue), ",")
            )

    def split(self) -> tuple[RelativeDistinguishedName, ...]:
        return self.listOfRDNs

    def up(self) -> "DistinguishedName":
        return DistinguishedName(listOfRDNs=self.listOfRDNs[1:])

    def getText(self) -> str:
        return ",".join([x.getText() for x in self.listOfRDNs])

    def __repr__(self) -> str:
        return self.__class__.__name__ + "(listOfRDNs=" + repr(self.listOfRDNs) + ")"

    def __hash__(self) -> int:
        return hash(self.getText())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, bytes):
            return self.getText().encode("utf-8") == other
        if isinstance(other, str):
            return self.getText() == other
        if not isinstance(other, DistinguishedName):
            return NotImplemented
        return self.split() == other.split()

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def __lt__(self, other: object) -> bool:
        """
        Comparison used for determining the hierarchy.
        """
        if not isinstance(other, DistinguishedName):
            return NotImplemented

        # The comparison is naive and broken.
        # See https://github.com/graingert/anyldap/issues/94
        return self.split() < other.split()

    def getDomainName(self) -> str | None:
        domainParts: list[str] = []
        l = list(self.listOfRDNs)
        l.reverse()
        for rdn in l:
            if rdn.count() != 1:
                break
            attributeTypeAndValue = rdn.split()[0]
            if attributeTypeAndValue.attributeType.upper() != "DC":
                break
            domainParts.insert(0, attributeTypeAndValue.value)
        if domainParts:
            return ".".join(domainParts)
        else:
            return None

    def contains(self, other: object) -> int:
        """Does the tree rooted at DN contain or equal the other DN."""
        if self == other:
            return 1
        if not isinstance(other, DistinguishedName):
            other = DistinguishedName(other)
        its = list(other.split())
        mine = list(self.split())

        while mine and its:
            m = mine.pop()
            i = its.pop()
            if m != i:
                return 0
        if mine:
            return 0
        return 1
