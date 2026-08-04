"""Reading BER by hand, for the shapes a decoder context cannot tell apart.

:class:`anyldap.protocols.pureber.BERDecoderContext` looks a tag up without
the bit that says it is constructed, so a ``[0]`` that holds a sequence and a
``[0]`` that holds an integer come out the same. Where the tag alone is what
says which alternative of a CHOICE the server sent -- the password policy
warning, the syncrepl info message -- the elements are read out here instead
and each one's tag is left as it was written.
"""

from anyldap.protocols import pureber

__all__ = ["elements"]


def elements(data: bytes) -> list[tuple[int, bytes]]:
    """The tag and content of each element written one after another."""
    read = []
    while data:
        tag = data[0]
        length, lengthlength = pureber.berDecodeLength(data, offset=1)
        start = 1 + lengthlength
        read.append((tag, data[start : start + length]))
        data = data[start + length :]
    return read
