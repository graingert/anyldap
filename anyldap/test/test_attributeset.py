"""
Test cases for anyldap.attributeset
"""
from functools import total_ordering

import pytest

from anyldap import attributeset


class TestLDAPAttributeSet:
    """
    Unit tests for LDAPAttributeSet.
    """

    def testEquality_True_Set(self) -> None:
        """
        Attributes are equal when the have the same key and value.
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        assert a == b

    def testEquality_True_Set_Ordering(self) -> None:
        """
        The order of the element in the value doesn't matter for
        equality.
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = attributeset.LDAPAttributeSet("k", ["b", "d", "c"])
        assert a == b

    def testEquality_True_List(self) -> None:
        """
        It can be compared with a list and in this case the key is
        ignored.
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = ["b", "c", "d"]
        assert a == b

    def testEquality_True_List_Ordering(self) -> None:
        """
        For list comparison the order of the element don't matter.
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = ["b", "d", "c"]
        assert a == b

    def testEquality_False_NotIterable(self) -> None:
        """
        Comparing against something that is not a set of values at all
        answers no, rather than failing to iterate it.
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        assert not a == 3
        assert a != 3

    def testEquality_False_Value(self) -> None:
        """
        LDAPAttributeSet objects are not equal when they have
        different values.
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = attributeset.LDAPAttributeSet("k", ["b", "c", "e"])
        assert a != b

    def testEquality_False_Key(self) -> None:
        """
        Equality fails if attributes have different keys.
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = attributeset.LDAPAttributeSet("l", ["b", "c", "d"])
        assert a != b

    def testDifference(self) -> None:
        """
        Different operation will ignore the attribute's key and will
        perform the operation onlyb based on the attribute's value.
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = attributeset.LDAPAttributeSet("l", ["b", "c", "e"])

        result = a - b

        assert {"d"} == result

    def testAddNewValue(self) -> None:
        """
        Adding new value
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        a.add("e")

        assert a == {"b", "c", "d", "e"}

    def testAddExistingValue(self) -> None:
        """
        Adding existing value as a byte or unicode string
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])

        a.add(b"b")
        assert a == {"b", "c", "d"}

        a.add("b")
        assert a == {"b", "c", "d"}

    def testRemoveExistingValue(self) -> None:
        """
        Removing existing value as a byte or unicode string
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        a.remove(b"b")
        a.remove("c")

        assert a == {"d"}

    def testRemoveNonexistingValue(self) -> None:
        """
        Removing non-existing value
        """
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])

        with pytest.raises(KeyError):
            a.remove("e")

    def testUnion(self) -> None:
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = attributeset.LDAPAttributeSet("k", ["b", "c", "e"])
        assert a | b == {"b", "c", "d", "e"}

    def testIntersection(self) -> None:
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = attributeset.LDAPAttributeSet("k", ["b", "c", "e"])
        assert a & b == {"b", "c"}

    def testSymmetricDifference(self) -> None:
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        b = attributeset.LDAPAttributeSet("k", ["b", "c", "e"])
        assert a ^ b == {"d", "e"}

    def testCopy(self) -> None:
        class Magic:
            def __lt__(self, other):
                return False

            def __gt__(self, other):
                return True

        m1 = Magic()
        assert not (m1 < object())
        assert m1 > object()
        a = attributeset.LDAPAttributeSet("k", ["b", "c", "d", m1])
        b = a.__copy__()
        assert a == b
        assert a is not b

        magicFromA = [val for val in a if isinstance(val, Magic)][0]
        magicFromB = [val for val in b if isinstance(val, Magic)][0]
        assert magicFromA == magicFromB
        assert magicFromA is magicFromB

        a.update("x")
        assert a == {"b", "c", "d", m1, "x"}
        assert b == {"b", "c", "d", m1}

    def testDeepCopy(self) -> None:
        @total_ordering
        class Magic:
            def __eq__(self, other):
                return isinstance(other, self.__class__)

            def __hash__(self):
                return 42

            def __lt__(self, other):
                return False

        m1 = Magic()
        a = attributeset.LDAPAttributeSet("k", ["a", m1])
        b = a.__deepcopy__({})
        assert a == b
        assert a is not b

        magicFromA = [val for val in a if isinstance(val, Magic)][0]
        magicFromB = [val for val in b if isinstance(val, Magic)][0]
        assert magicFromA == magicFromB
        assert magicFromA is not magicFromB

        a.update("x")
        assert a == {"a", m1, "x"}
        assert b == {"a", m1}
