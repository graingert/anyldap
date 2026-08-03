from collections.abc import Iterable
from copy import deepcopy
from typing import Self, TypeVar

from anyldap._encoder import get_strings

# An attribute value is text on the way in and bytes off the wire. A set is
# usually all of one or all of the other, and says which; where an entry has
# been handed both, the variable solves to the union.
AttributeValue = TypeVar("AttributeValue", bound=str | bytes)


class LDAPAttributeSet(set[AttributeValue]):
    def __init__(
        self, key: str | bytes, values: Iterable[AttributeValue] = ()
    ) -> None:
        """
        Represents all the values for an attribute in an LDAP entry. An entry
        might have "cn" or "objectClass" or "uid" attributes, and this class
        represents each of those.

        You can find the name of the LDAP entry attribute (eg. "uid") with the
        ``.key`` member variable.

        You can find the values of the LDAP attribute by casting this to a
        ``list``.
        @param key: the key of the attribute, eg "uid".
        @type key: str
        @param values: set of values for this attribute, eg. "jsmith"
        """
        self.key = key
        super().__init__(values)

    def __repr__(self) -> str:
        values = list(self)
        values.sort()
        attributes = ", ".join([repr(x) for x in values])
        return f"{self.__class__.__name__}({self.key!r}, [{attributes}])"

    def __eq__(self, other: object) -> bool:
        """
        Note that LDAPAttributeSets can also be compared against any
        iterator. In that case the attributeType will be ignored.
        """
        if isinstance(other, LDAPAttributeSet):
            if self.key != other.key:
                return False
            return super().__eq__(other)
        elif isinstance(other, Iterable):
            me = list(self)
            me.sort()
            him = sorted(other)
            return me == him
        else:
            return NotImplemented

    def __ne__(self, other: object) -> bool:
        return not self == other

    def add(self, key: AttributeValue) -> None:
        """
        Adding key to the attributes with checking
        if it exists as byte or unicode string
        """
        for k in get_strings(key):
            if k in self:
                return

        set.add(self, key)

    def remove(self, key: AttributeValue) -> None:
        """
        Removing key from the attributes with checking
        if it exists as byte or unicode string
        """
        for k in get_strings(key):
            if k in self:
                set.remove(self, k)
                return

        raise KeyError(key)

    def copy(self) -> Self:
        result = self.__class__(self.key)
        result.update(self)
        return result

    __copy__ = copy

    def __deepcopy__(self, memo: dict[int, object]) -> Self:
        result = self.__class__(self.key)
        memo[id(self)] = result
        data = deepcopy(set(self), memo)
        result.update(data)
        return result
