"""
    Test cases for anyldap.encoder module
"""

import pytest

import anyldap._encoder


class WireableObject:
    """
    Object with bytes representation as a constant toWire value
    """

    def toWire(self) -> bytes:
        return b"wire"


class TextObject(anyldap._encoder.TextStrAlias):
    """
    Object with human readable representation as a constant getText value
    """

    def getText(self) -> str:
        return "text"


class TestEncoderTests:
    def test_wireable_object(self) -> None:
        """
        to_bytes function use object`s toWire method
        to get its bytes representation if it has one
        """
        obj = WireableObject()
        assert anyldap._encoder.to_bytes(obj) == b"wire"

    def test_unicode_object(self) -> None:
        """
        unicode string is encoded to utf-8 if passed
        to to_bytes function
        """
        obj = "unicode"
        assert anyldap._encoder.to_bytes(obj) == b"unicode"

    def test_bytes_object(self) -> None:
        """
        byte string is returned without changes
        if passed to to_bytes function
        """
        obj = b"bytes"
        assert anyldap._encoder.to_bytes(obj) == b"bytes"

    def test_int_object(self) -> None:
        """
        integer is converted to a string representation, then encoded to bytes
        if passed to to_bytes function
        """
        obj = 42
        assert anyldap._encoder.to_bytes(obj) == b"42"


class WireObject(anyldap._encoder.WireStrAlias):
    def toWire(self) -> bytes:
        return b"wire"


class TestWireStrAliasTests:
    def test_toWire_not_implemented(self) -> None:
        """
        WireStrAlias.toWire is an abstract method and raises NotImplementedError
        """
        obj = anyldap._encoder.WireStrAlias()
        with pytest.raises(NotImplementedError):
            obj.toWire()

    def test_deprecation_warning(self, recwarn: pytest.WarningsRecorder) -> None:
        """
        __str__ warns, then fails: toWire returns bytes, which __str__ may not.
        """
        with pytest.raises(TypeError, match="returned non-string"):
            str(WireObject())
        assert [w.category for w in recwarn] == [DeprecationWarning]
        assert str(recwarn[0].message) == (
            "WireObject.__str__ method is deprecated and will not be used "
            "for getting bytes representation in the future "
            "releases, use WireObject.toWire instead"
        )


class TestTextStrAliasTests:
    def test_deprecation_warning(self, recwarn: pytest.WarningsRecorder) -> None:
        str(TextObject())
        msg = (
            "TextObject.__str__ method is deprecated and will not be used "
            "for getting human readable representation in the future "
            "releases, use TextObject.getText instead"
        )
        assert len(recwarn) == 1
        assert recwarn[0].category is DeprecationWarning
        assert str(recwarn[0].message) == msg

    def test_getText_not_implemented(self) -> None:
        """
        TextStrAlias.getText is an abstract method and raises NotImplementedError
        """
        obj = anyldap._encoder.TextStrAlias()
        with pytest.raises(NotImplementedError):
            obj.getText()
