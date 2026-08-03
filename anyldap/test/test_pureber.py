"""
Test cases for anyldap.protocols.pureber module.
"""
from typing import Any

import pytest

from anyldap.protocols import pureber


def test_custom_tag_representations_and_unknown_tag(capsys: pytest.CaptureFixture[str]) -> None:
    values = [
        pureber.BERInteger(1, tag=10),
        pureber.BEROctetString(b"value", tag=10),
        pureber.BERNull(tag=10),
        pureber.BERBoolean(True, tag=10),
        pureber.BERSequence([], tag=10),
    ]
    for value in values:
        assert "tag=10" in repr(value)

    context = pureber.BERDecoderContext()
    decoded, used = pureber.berDecodeObject(context, b"\x0e\x00")
    assert decoded is None
    assert used == 2
    assert "no tag 0x0e" in capsys.readouterr().out
    assert repr(pureber.BERBoolean(True)) == "BERBoolean(value=255)"
    assert pureber.berDecodeMultiple(b"\x0e\x00", context) == []


def s(*l: int) -> bytes:
    """Join all members of list to a byte string. Integer members are converted to bytes"""
    r = b""
    for e in l:
        r = r + bytes((e,))
    return r


def l(s: bytes) -> list[int]:
    """Split a byte string to ord's of chars."""
    return [[x][0] for x in s]


class TestBerLengths:
    knownValues = (
        (0, [0]),
        (1, [1]),
        (100, [100]),
        (126, [126]),
        (127, [127]),
        (128, [0x80 | 1, 128]),
        (129, [0x80 | 1, 129]),
        (255, [0x80 | 1, 255]),
        (256, [0x80 | 2, 1, 0]),
        (257, [0x80 | 2, 1, 1]),
        (65535, [0x80 | 2, 0xFF, 0xFF]),
        (65536, [0x80 | 3, 0x01, 0x00, 0x00]),
        (256 ** 127 - 1, [0x80 | 127] + 127 * [0xFF]),
    )

    def testToBER(self) -> None:
        for integer, encoded in self.knownValues:
            assert l(pureber.int2berlen(integer)) == encoded

    def testFromBER(self) -> None:
        for integer, encoded in self.knownValues:
            m = s(*encoded)
            got, bytes = pureber.berDecodeLength(m)
            assert bytes == len(m)
            assert got == integer

    def testPartialBER(self) -> None:
        m = bytes(pureber.int2berlen(3 * 256))
        assert 3 == len(m)
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeLength(m[:2])
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeLength(m[:1])

        m = bytes(pureber.int2berlen(256 ** 100 - 1))
        assert 101 == len(m)
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeLength(m[:100])


class TestBERBaseTests:
    """
    Unit tests for generic BERBase.
    """

    valuesToTest: tuple[tuple[type[pureber.BERBase], list[Any]], ...] = (
        (pureber.BERBase, []),
        (pureber.BERInteger, [0]),
        (pureber.BERInteger, [1]),
        (pureber.BERInteger, [4000]),
        (pureber.BERSequence, [[pureber.BERInteger(1000), pureber.BERInteger(2000)]]),
        (pureber.BERSequence, [[pureber.BERInteger(2000), pureber.BERInteger(1000)]]),
        (pureber.BEROctetString, ["foo"]),
        (pureber.BEROctetString, ["b" + chr(0xE4) + chr(0xE4)]),
    )

    def testEquality(self) -> None:
        """
        BER objects equal BER objects with same type and content
        """
        for class_, args in self.valuesToTest:
            x = class_(*args)
            y = class_(*args)
            assert x == x
            assert x == y

    def testInequalityWithBER(self) -> None:
        """
        BER objects do not equal BER objects with different type or content
        """
        for i in range(len(self.valuesToTest)):
            for j in range(len(self.valuesToTest)):
                if i != j:
                    i_class, i_args = self.valuesToTest[i]
                    j_class, j_args = self.valuesToTest[j]
                    x = i_class(*i_args)
                    y = j_class(*j_args)
                    assert x != y

    def testInequalityWithNonBER(self) -> None:
        """
        BER objects are not equal with non-BER objects.
        """
        sut = pureber.BERInteger(0)

        assert not (0 == sut)
        assert 0 != sut

    def testHashEquality(self) -> None:
        """
        Objects which are equal have the same hash.
        """
        for klass, arguments in self.valuesToTest:
            first = klass(*arguments)
            second = klass(*arguments)
            assert hash(first) == hash(second)


class TestBERDecoderContextRepr:
    def testRepr(self) -> None:
        # Not decoder contexts: the repr shows whatever it was given.
        context = pureber.BERDecoderContext(
            fallback="foo",  # type: ignore[arg-type]
            inherit="bar",  # type: ignore[arg-type]
        )
        assert repr(context) == ("<BERDecoderContext identities={"
            "0x01: BERBoolean, "
            "0x02: BERInteger, "
            "0x04: BEROctetString, "
            "0x05: BERNull, "
            "0x0a: BEREnumerated, "
            "0x10: BERSequence, "
            "0x11: BERSet"
            "} fallback='foo' inherit='bar'>")


class TestBERIntegerKnownValues:
    knownValues = (
        (0, [0x02, 0x01, 0]),
        (1, [0x02, 0x01, 1]),
        (2, [0x02, 0x01, 2]),
        (125, [0x02, 0x01, 125]),
        (126, [0x02, 0x01, 126]),
        (127, [0x02, 0x01, 127]),
        (-1, [0x02, 0x01, 256 - 1]),
        (-2, [0x02, 0x01, 256 - 2]),
        (-3, [0x02, 0x01, 256 - 3]),
        (-126, [0x02, 0x01, 256 - 126]),
        (-127, [0x02, 0x01, 256 - 127]),
        (-128, [0x02, 0x01, 256 - 128]),
        (-129, [0x02, 0x02, 256 - 1, 256 - 129]),
        (128, [0x02, 0x02, 0, 128]),
        (256, [0x02, 0x02, 1, 0]),
    )

    def testToBERIntegerKnownValues(self) -> None:
        """BERInteger(n).toWire() should give known result with known input"""
        for integer, encoded in self.knownValues:
            assert encoded == l(pureber.BERInteger(integer).toWire())

    def testFromBERIntegerKnownValues(self) -> None:
        """BERInteger(encoded="...") should give known result with known input"""
        for integer, encoded in self.knownValues:
            m = s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            assert bytes == len(m)
            assert isinstance(result, pureber.BERInteger)
            assert integer == result.value

    def testPartialBERIntegerEncodings(self) -> None:
        """BERInteger(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BERInteger(42).toWire()
        assert 3 == len(m)
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:2])
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:1])
        assert (None, 0) == pureber.berDecodeObject(pureber.BERDecoderContext(), b"")


class TestBERIntegerSanityCheck:
    def testSanity(self) -> None:
        """BERInteger(encoded=BERInteger(n)).value==n for -1000..1000"""
        for n in range(-1000, 1001, 10):
            encoded = pureber.BERInteger(n).toWire()
            result, bytes = pureber.berDecodeObject(
                pureber.BERDecoderContext(), encoded
            )
            assert bytes == len(encoded)
            assert isinstance(result, pureber.BERInteger)
            assert n == result.value


class ObjectWithToWireMethod:
    def toWire(self) -> bytes:
        return b"bar"


class TestBEROctetString:
    """
    Unit tests for BEROctetString.
    """

    knownValues = (
        ("", [0x04, 0]),
        ("foo", [0x04, 3] + l(b"foo")),
        (100 * "x", [0x04, 100] + l(100 * b"x")),
        (ObjectWithToWireMethod(), [0x04, 3] + l(b"bar")),
    )

    def testToBEROctetStringKnownValues(self) -> None:
        """BEROctetString(n).toWire() should give known result with known input"""
        for st, encoded in self.knownValues:
            # The object with a toWire is not an attribute value; toWire hands
            # whatever it holds to to_bytes, which renders anything wire-able.
            octets = pureber.BEROctetString(st)  # type: ignore[arg-type]
            assert encoded == l(octets.toWire())

    def testFromBEROctetStringKnownValues(self) -> None:
        """BEROctetString(encoded="...") should give known result with known input"""
        for st, encoded in self.knownValues:
            m = s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            assert bytes == len(m)
            assert isinstance(result, pureber.BEROctetString)
            assert encoded == l(result.toWire())

    def testPartialBEROctetStringEncodings(self) -> None:
        """BEROctetString(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BEROctetString("x").toWire()
        assert 3 == len(m)
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:2])
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:1])
        assert (None, 0) == pureber.berDecodeObject(pureber.BERDecoderContext(), b"")

    def testSanity(self) -> None:
        """BEROctetString(encoded=BEROctetString(n*'x')).value==n*'x' for some values of n"""
        for n in 0, 1, 2, 3, 4, 5, 6, 100, 126, 127, 128, 129, 1000, 2000:
            encoded = pureber.BEROctetString(n * b"x").toWire()
            result, bytes = pureber.berDecodeObject(
                pureber.BERDecoderContext(), encoded
            )
            assert bytes == len(encoded)
            assert isinstance(result, pureber.BEROctetString)
            assert n * b"x" == result.value


class TestBERNullKnownValues:
    def testToBERNullKnownValues(self) -> None:
        """BERNull().toWire() should give known result"""
        assert [0x05, 0x00] == l(pureber.BERNull().toWire())

    def testFromBERNullKnownValues(self) -> None:
        """BERNull(encoded="...") should give known result with known input"""
        encoded = [0x05, 0x00]
        m = s(*encoded)
        result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
        assert bytes == len(m)
        assert isinstance(result, pureber.BERNull)
        assert 0x05 == result.tag

    def testPartialBERNullEncodings(self) -> None:
        """BERNull(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BERNull().toWire()
        assert 2 == len(m)
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:1])
        assert (None, 0) == pureber.berDecodeObject(pureber.BERDecoderContext(), b"")


class TestBERBooleanKnownValues:
    knownValues = (
        (0, [0x01, 0x01, 0], 0),
        (1, [0x01, 0x01, 0xFF], 0xFF),
        (2, [0x01, 0x01, 0xFF], 0xFF),
        (125, [0x01, 0x01, 0xFF], 0xFF),
        (126, [0x01, 0x01, 0xFF], 0xFF),
        (127, [0x01, 0x01, 0xFF], 0xFF),
        (-1, [0x01, 0x01, 0xFF], 0xFF),
        (-2, [0x01, 0x01, 0xFF], 0xFF),
        (-3, [0x01, 0x01, 0xFF], 0xFF),
        (-126, [0x01, 0x01, 0xFF], 0xFF),
        (-127, [0x01, 0x01, 0xFF], 0xFF),
        (-128, [0x01, 0x01, 0xFF], 0xFF),
        (-129, [0x01, 0x01, 0xFF], 0xFF),
        (-9999, [0x01, 0x01, 0xFF], 0xFF),
        (128, [0x01, 0x01, 0xFF], 0xFF),
        (255, [0x01, 0x01, 0xFF], 0xFF),
        (256, [0x01, 0x01, 0xFF], 0xFF),
        (9999, [0x01, 0x01, 0xFF], 0xFF),
    )

    def testToBERBooleanKnownValues(self) -> None:
        """BERBoolean(n).toWire() should give known result with known input"""
        for integer, encoded, dummy in self.knownValues:
            assert encoded == l(pureber.BERBoolean(integer).toWire())

    def testFromBERBooleanKnownValues(self) -> None:
        """BERBoolean(encoded="...") should give known result with known input"""
        for integer, encoded, canon in self.knownValues:
            m = s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            assert bytes == len(m)
            assert isinstance(result, pureber.BERBoolean)
            assert canon == result.value

    def testPartialBERBooleanEncodings(self) -> None:
        """BERBoolean(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BERBoolean(42).toWire()
        assert 3 == len(m)
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:2])
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:1])
        assert (None, 0) == pureber.berDecodeObject(pureber.BERDecoderContext(), b"")


class TestBEREnumeratedKnownValues:
    knownValues = (
        (0, [0x0A, 0x01, 0]),
        (1, [0x0A, 0x01, 1]),
        (2, [0x0A, 0x01, 2]),
        (125, [0x0A, 0x01, 125]),
        (126, [0x0A, 0x01, 126]),
        (127, [0x0A, 0x01, 127]),
        (-1, [0x0A, 0x01, 256 - 1]),
        (-2, [0x0A, 0x01, 256 - 2]),
        (-3, [0x0A, 0x01, 256 - 3]),
        (-126, [0x0A, 0x01, 256 - 126]),
        (-127, [0x0A, 0x01, 256 - 127]),
        (-128, [0x0A, 0x01, 256 - 128]),
        (-129, [0x0A, 0x02, 256 - 1, 256 - 129]),
        (128, [0x0A, 0x02, 0, 128]),
        (256, [0x0A, 0x02, 1, 0]),
    )

    def testToBEREnumeratedKnownValues(self) -> None:
        """BEREnumerated(n).toWire() should give known result with known input"""
        for integer, encoded in self.knownValues:
            assert encoded == l(pureber.BEREnumerated(integer).toWire())

    def testFromBEREnumeratedKnownValues(self) -> None:
        """BEREnumerated(encoded="...") should give known result with known input"""
        for integer, encoded in self.knownValues:
            m = s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            assert bytes == len(m)
            assert isinstance(result, pureber.BEREnumerated)
            assert integer == result.value

    def testPartialBEREnumeratedEncodings(self) -> None:
        """BEREnumerated(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BEREnumerated(42).toWire()
        assert 3 == len(m)
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:2])
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:1])
        assert (None, 0) == pureber.berDecodeObject(pureber.BERDecoderContext(), b"")


class TestBEREnumeratedSanityCheck:
    def testSanity(self) -> None:
        """BEREnumerated(encoded=BEREnumerated(n)).value==n for -1000..1000"""
        for n in range(-1000, 1001, 10):
            encoded = pureber.BEREnumerated(n).toWire()
            result, bytes = pureber.berDecodeObject(
                pureber.BERDecoderContext(), encoded
            )
            assert bytes == len(encoded)
            assert isinstance(result, pureber.BEREnumerated)
            assert n == result.value


class TestBERSequence:
    """
    Unit test for BERSequence.
    """

    def testStringRepresentationEmpty(self) -> None:
        """
        It can return the byte string representation for empty sequence which
        is just the zero/null byte.
        """
        sut = pureber.BERSequence([])

        result = sut.toWire()

        assert b"0\x00" == result

    def testStringRepresentatinSmallInteger(self) -> None:
        """
        It can represent a sequence of a single integer which has a
        single byte value.
        """
        sut = pureber.BERSequence([pureber.BERInteger(2)])

        result = sut.toWire()

        assert b"0\x03\x02\x01\x02" == result

    def testStringRepresentatinLargerInteger(self) -> None:
        """
        It can represent a sequence of a single integer which has a
        multi bites value.
        """
        sut = pureber.BERSequence([pureber.BERInteger(128)])

        result = sut.toWire()

        assert b"0\x04\x02\x02\x00\x80" == result

    def testStringRepresentatinMultipleIntegers(self) -> None:
        """
        It can represent a sequence of multiple integer.
        """
        sut = pureber.BERSequence([pureber.BERInteger(3), pureber.BERInteger(128)])

        result = sut.toWire()

        assert b"0\x07\x02\x01\x03\x02\x02\x00\x80" == result

    def testDecodeValidInput(self) -> None:
        """
        It can be decoded from its bytes serialization.
        """
        knownValues: tuple[tuple[list[pureber.BERBase], list[int]], ...] = (
            ([], [0x30, 0x00]),
            ([pureber.BERInteger(2)], [0x30, 0x03, 0x02, 0x01, 2]),
            ([pureber.BERInteger(3)], [0x30, 0x03, 0x02, 0x01, 3]),
            ([pureber.BERInteger(128)], [0x30, 0x04, 0x02, 0x02, 0, 128]),
            (
                [
                    pureber.BERInteger(2),
                    pureber.BERInteger(3),
                    pureber.BERInteger(128),
                ],
                [0x30, 0x0A] + [0x02, 0x01, 2] + [0x02, 0x01, 3] + [0x02, 0x02, 0, 128],
            ),
        )

        for content, encoded in knownValues:
            m = s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            assert bytes == len(m)
            assert isinstance(result, pureber.BERSequence)
            assert len(content) == len(result.data)
            for i in range(len(content)):
                assert content[i] == result.data[i]
            assert content == result.data

    def testDecdeInvalidInput(self) -> None:
        """
        It raises BERExceptionInsufficientData when trying to decode from
        data which is not valid.
        """
        m = pureber.BERSequence([pureber.BERInteger(2)]).toWire()
        assert 5 == len(m)

        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:4])
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:3])
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:2])
        with pytest.raises(pureber.BERExceptionInsufficientData):
            pureber.berDecodeObject(pureber.BERDecoderContext(), m[:1])
        assert (None, 0) == pureber.berDecodeObject(pureber.BERDecoderContext(), b"")
