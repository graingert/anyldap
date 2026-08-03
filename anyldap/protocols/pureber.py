"""Pure, simple, BER encoding and decoding"""

# This BER library is currently aimed at supporting LDAP, thus
# the following restrictions from RFC2251 apply:
#
# (1) Only the definite form of length encoding will be used.
#
# (2) OCTET STRING values will be encoded in the primitive form
#     only.
#
# (3) If the value of a BOOLEAN type is true, the encoding MUST have
#     its contents octets set to hex "FF".
#
# (4) If a value of a type is its default value, it MUST be absent.
#     Only some BOOLEAN and INTEGER types have default values in
#     this protocol definition.

from collections import UserList
from collections.abc import Iterable, Sized
from typing import ClassVar, Protocol, Self

from anyldap._encoder import WireStrAlias, to_bytes

# xxxxxxxx
# |/|\.../
# | | |
# | | tag
# | |
# | primitive (0) or structured (1)
# |
# class

CLASS_MASK = 0xC0
CLASS_UNIVERSAL = 0x00
CLASS_APPLICATION = 0x40
CLASS_CONTEXT = 0x80
CLASS_PRIVATE = 0xC0

STRUCTURED_MASK = 0x20
STRUCTURED = 0x20
NOT_STRUCTURED = 0x00

TAG_MASK = 0x1F


# LENGTH
# 0xxxxxxx = 0..127
# 1xxxxxxx = len is stored in the next 0xxxxxxx octets
# indefinite form not supported


class UnknownBERTag(Exception):
    def __init__(self, tag: int, context: "BERDecoderContext") -> None:
        Exception.__init__(self)
        self.tag = tag
        self.context = context

    def __str__(self) -> str:
        return f"BERDecoderContext has no tag 0x{self.tag:02x}: {self.context}"


def berDecodeLength(m: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Return a tuple of (length, lengthLength).
    m must be atleast one byte long.
    """
    l = ber2int(m[offset + 0 : offset + 1])
    ll = 1
    if l & 0x80:
        ll = 1 + (l & 0x7F)
        need(m, offset + ll)
        l = ber2int(m[offset + 1 : offset + ll], signed=False)
    return (l, ll)


def int2berlen(i: int) -> bytes:
    assert i >= 0
    e = int2ber(i, signed=False)
    if i <= 127:
        return e
    else:
        l = len(e)
        assert l > 0
        assert l <= 127
        return bytes((0x80 | l,)) + e


def int2ber(i: int, signed: bool = True) -> bytes:
    encoded = b""
    while (signed and (i > 127 or i < -128)) or (not signed and (i > 255)):
        encoded = bytes((i % 256,)) + encoded
        i = i >> 8
    encoded = bytes((i % 256,)) + encoded
    return encoded


def ber2int(e: bytes, signed: bool = True) -> int:
    need(e, 1)
    v = 0 + ord(e[0:1])
    if v & 0x80 and signed:
        v = v - 256
    for i in range(1, len(e)):
        v = (v << 8) | ord(e[i : i + 1])
    return v


class BERBase(WireStrAlias):
    # Every concrete class carries a tag, and a decoded object may override it
    # per instance, so this is not a ClassVar. The base itself has none: it
    # encodes to b"" and never asks for its identification.
    tag: int

    def identification(self) -> int:
        return self.tag

    def __init__(self, tag: int | None = None) -> None:
        if tag is not None:
            self.tag = tag

    def __len__(self) -> int:
        return len(self.toWire())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BERBase):
            return NotImplemented
        return self.toWire() == other.toWire()

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, BERBase):
            return NotImplemented

        return self.toWire() != other.toWire()

    def __hash__(self) -> int:
        return hash(self.toWire())

    def toWire(self) -> bytes:
        return b""


class BERDecodable(Protocol):
    """A BER class that can rebuild an object from wire content.

    BERBase itself does not decode -- only its concrete subclasses do -- so a
    decoder context holds these rather than plain BER classes.
    """

    @classmethod
    def fromBER(
        cls,
        tag: int,
        content: bytes,
        berdecoder: "BERDecoderContext | None" = None,
    ) -> BERBase: ...


class BERStructured(BERBase):
    def identification(self) -> int:
        return STRUCTURED | self.tag


class BERException(Exception):
    pass


class BERExceptionInsufficientData(Exception):
    pass


def need(buf: Sized, n: int) -> None:
    d = n - len(buf)
    if d > 0:
        raise BERExceptionInsufficientData(d)


class BERInteger(BERBase):
    tag = 0x02
    value: int

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: "BERDecoderContext | None" = None,
    ) -> Self:
        assert len(content) > 0
        value = ber2int(content)
        r = klass(value=value, tag=tag)
        return r

    def __init__(self, value: int | None = None, tag: int | None = None) -> None:
        """Create a new BERInteger object.
        value is an integer.
        """
        BERBase.__init__(self, tag)
        assert value is not None
        self.value = value

    def toWire(self) -> bytes:
        encoded = int2ber(self.value)
        return bytes((self.identification(),)) + int2berlen(len(encoded)) + encoded

    def __repr__(self) -> str:
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%r)" % self.value
        else:
            return self.__class__.__name__ + "(value=%r, tag=%d)" % (
                self.value,
                self.tag,
            )


class BEROctetString(BERBase):
    tag = 0x04

    # Built from wire content as bytes, but the callers that construct a
    # request spell their values as text.
    value: str | bytes

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: "BERDecoderContext | None" = None,
    ) -> Self:
        assert len(content) >= 0
        r = klass(value=content, tag=tag)
        return r

    def __init__(
        self, value: str | bytes | None = None, tag: int | None = None
    ) -> None:
        BERBase.__init__(self, tag)
        assert value is not None
        self.value = value

    def toWire(self) -> bytes:
        value = to_bytes(self.value)
        result = bytes((self.identification(),)) + int2berlen(len(value)) + value
        return result

    def __repr__(self) -> str:
        value = self.value
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(value)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                repr(value),
                self.tag,
            )


class BERNull(BERBase):
    tag = 0x05

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: "BERDecoderContext | None" = None,
    ) -> Self:
        assert len(content) == 0
        r = klass(tag=tag)
        return r

    def __init__(self, tag: int | None = None) -> None:
        BERBase.__init__(self, tag)

    def toWire(self) -> bytes:
        return bytes((self.identification(),)) + bytes((0,))

    def __repr__(self) -> str:
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "()"
        else:
            return self.__class__.__name__ + "(tag=%d)" % self.tag


class BERBoolean(BERBase):
    tag = 0x01

    value: int

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: "BERDecoderContext | None" = None,
    ) -> Self:
        assert len(content) > 0
        value = ber2int(content)
        r = klass(value=value, tag=tag)
        return r

    def __init__(self, value: int | None = None, tag: int | None = None) -> None:
        """Create a new BERInteger object.
        value is an integer.
        """
        BERBase.__init__(self, tag)
        assert value is not None
        if value:
            value = 0xFF
        self.value = value

    def toWire(self) -> bytes:
        assert self.value == 0 or self.value == 0xFF
        return bytes((self.identification(),)) + int2berlen(1) + bytes((self.value,))

    def __repr__(self) -> str:
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%d)" % self.value
        else:
            return self.__class__.__name__ + "(value=%d, tag=%d)" % (
                self.value,
                self.tag,
            )


class BEREnumerated(BERInteger):
    tag = 0x0A


class BERSequence(BERStructured, UserList[BERBase]):
    # TODO __getslice__ calls __init__ with no args.
    tag = 0x10

    # UserList is unhashable and BERBase hashes its wire form. The MRO already
    # resolves that in BERBase's favour; saying so here settles it in the class
    # rather than leaving it to base ordering.
    __hash__ = BERBase.__hash__  # type: ignore[assignment]

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: "BERDecoderContext | None" = None,
    ) -> Self:
        # Decoding a sequence means decoding its members, which needs the
        # context; only the signature makes it optional.
        assert berdecoder is not None
        l = berDecodeMultiple(content, berdecoder)
        r = klass(l, tag=tag)
        return r

    def __init__(
        self, value: Iterable[BERBase] | None = None, tag: int | None = None
    ) -> None:
        BERStructured.__init__(self, tag)
        assert value is not None
        UserList.__init__(self, value)

    def toWire(self) -> bytes:
        r = b"".join(to_bytes(x) for x in self.data)
        return bytes((self.identification(),)) + int2berlen(len(r)) + r

    def __repr__(self) -> str:
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(self.data)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                repr(self.data),
                self.tag,
            )


class BERSequenceOf(BERSequence):
    pass


class BERSet(BERSequence):
    tag = 0x11


class BERDecoderContext:
    Identities: ClassVar[dict[int, type[BERDecodable]]] = {
        BERBoolean.tag: BERBoolean,
        BERInteger.tag: BERInteger,
        BEROctetString.tag: BEROctetString,
        BERNull.tag: BERNull,
        BEREnumerated.tag: BEREnumerated,
        BERSequence.tag: BERSequence,
        BERSet.tag: BERSet,
    }

    def __init__(
        self,
        fallback: "BERDecoderContext | None" = None,
        inherit: "BERDecoderContext | None" = None,
    ) -> None:
        self.fallback = fallback
        self.inherit_context = inherit

    def lookup_id(self, id: int) -> type[BERDecodable] | None:
        try:
            return self.Identities[id]
        except KeyError:
            if self.fallback:
                return self.fallback.lookup_id(id)
            else:
                return None

    def inherit(self) -> "BERDecoderContext":
        return self.inherit_context or self

    def __repr__(self) -> str:
        identities = []
        for tag, class_ in self.Identities.items():
            identities.append(f"0x{tag:02x}: {class_.__name__}")

        return (
            "<"
            + self.__class__.__name__
            + " identities={%s}" % ", ".join(identities)
            + " fallback="
            + repr(self.fallback)
            + " inherit="
            + repr(self.inherit_context)
            + ">"
        )


def berDecodeObject(context: BERDecoderContext, m: bytes) -> tuple[BERBase | None, int]:
    """berDecodeObject(context, bytes) -> (berobject, bytesUsed)
    berobject may be None.
    """
    while m:
        need(m, 2)
        i = ber2int(m[0:1], signed=False) & (CLASS_MASK | TAG_MASK)

        length, lenlen = berDecodeLength(m, offset=1)
        need(m, 1 + lenlen + length)
        m2 = m[1 + lenlen : 1 + lenlen + length]

        berclass = context.lookup_id(i)
        if berclass:
            inh = context.inherit()
            assert inh
            r = berclass.fromBER(tag=i, content=m2, berdecoder=inh)
            return (r, 1 + lenlen + length)
        else:
            print(str(UnknownBERTag(i, context)))  # TODO
            return (None, 1 + lenlen + length)
    return (None, 0)


def berDecodeMultiple(content: bytes, berdecoder: BERDecoderContext) -> list[BERBase]:
    """berDecodeMultiple(content, berdecoder) -> [objects]

    Decodes everything in content and returns a list of decoded
    objects.

    All of content will be decoded, and content must contain complete
    BER objects.
    """
    l: list[BERBase] = []
    while content:
        n, bytes = berDecodeObject(berdecoder, content)
        if n is not None:
            l.append(n)
        assert bytes <= len(content)
        content = content[bytes:]
    return l


# TODO unimplemented classes are below:

# class BERObjectIdentifier(BERBase):
#    tag = 0x06
#    pass

# class BERIA5String(BERBase):
#    tag = 0x16
#    pass

# class BERPrintableString(BERBase):
#    tag = 0x13
#    pass

# class BERT61String(BERBase):
#    tag = 0x14
#    pass

# class BERUTCTime(BERBase):
#    tag = 0x17
#    pass

# class BERBitString(BERBase):
#    tag = 0x03
#    pass
