"""
    Encoding / decoding utilities
"""

import warnings
from collections.abc import Iterable
from typing import Any, Protocol, TypeVar, overload


class SupportsToWire(Protocol):
    """Anything that can render itself as LDAP wire bytes."""

    def toWire(self) -> bytes: ...


@overload
def to_bytes(value: SupportsToWire) -> bytes: ...
@overload
def to_bytes(value: int | str | bytes | bytearray | memoryview | Iterable[int]) -> bytes: ...
def to_bytes(
    value: SupportsToWire | int | str | bytes | bytearray | memoryview | Iterable[int],
) -> bytes:
    """
    Converts value to its bytes representation:

    * Uses value`s toWire method if it has one
    * Encodes to utf-8 if the value is a unicode string
    * Otherwise wraps value into bytes()
    """
    if hasattr(value, "toWire"):
        return value.toWire()
    if isinstance(value, int):
        return str(value).encode("utf-8")
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


_T = TypeVar("_T")


@overload
def to_unicode(value: bytes) -> str: ...
@overload
def to_unicode(value: _T) -> _T: ...
# The overloads say what callers see: bytes become str, and anything else is
# handed straight back with its own type. An implementation returning both has
# to be spelled Any.
def to_unicode(value: Any) -> Any:
    """
    Converts string to unicode:

    * Decodes value from utf-8 if it is a byte string
    * Otherwise just returns the same value
    """
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


@overload
def get_strings(value: str) -> tuple[str, bytes]: ...
@overload
def get_strings(value: bytes) -> tuple[bytes, str]: ...
@overload
def get_strings(value: str | bytes) -> tuple[str | bytes, str | bytes]: ...
@overload
def get_strings(value: object) -> tuple[object, ...]: ...
# Text and bytes each come back as both spellings, and anything else as
# itself; an implementation producing all three has to be spelled Any.
def get_strings(value: Any) -> tuple[Any, ...]:
    """
    Getting tuple of available string values
    (byte string and unicode string) for
    given value
    """
    if isinstance(value, str):
        return value, value.encode("utf-8")
    if isinstance(value, bytes):
        return value, value.decode("utf-8")
    return (value,)


class WireStrAlias:
    """
    A helper base or mixin class which adds __str__ method
    as an alias of toWire method but marks it as deprecated
    """

    def __str__(self) -> str:
        warnings.simplefilter("always", DeprecationWarning)
        warnings.warn(
            f"{self.__class__.__name__}.__str__ method is deprecated and will not be used "
            "for getting bytes representation in the future "
            f"releases, use {self.__class__.__name__}.toWire instead",
            category=DeprecationWarning,
            stacklevel=2,
        )
        warnings.simplefilter("default", DeprecationWarning)
        # Deliberately wrong: toWire returns bytes, so this raises TypeError.
        # The method only exists to warn callers off, and is tested for it.
        return self.toWire()  # type: ignore[return-value]

    def toWire(self) -> bytes:
        raise NotImplementedError("toWire method is not implemented")


class TextStrAlias:
    """
    A helper base or mixin class which adds __str__ method
    as an alias of getText method but marks it as deprecated
    """

    def __str__(self) -> str:
        warnings.simplefilter("always", DeprecationWarning)
        warnings.warn(
            f"{self.__class__.__name__}.__str__ method is deprecated and will not be used "
            "for getting human readable representation in the future "
            f"releases, use {self.__class__.__name__}.getText instead",
            category=DeprecationWarning,
            stacklevel=2,
        )
        warnings.simplefilter("default", DeprecationWarning)
        text = self.getText()
        return text

    def getText(self) -> str:
        raise NotImplementedError("getText method is not implemented")
