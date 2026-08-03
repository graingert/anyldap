from collections.abc import Iterable, Sequence
from typing import TypeVar

_T = TypeVar("_T")


class FailTest(AssertionError):
    """Raised by test helpers when an expectation was not met."""


def assert_permutation(first: Iterable[object], second: Iterable[object]) -> None:
    """Assert both iterables hold the same items, in any order.

    Unlike ``sorted(a) == sorted(b)`` this works for items that are not
    orderable, which covers most of the LDAP value types.
    """
    left = list(first)
    right = list(second)
    remaining = list(right)
    for item in left:
        if item not in remaining:
            raise FailTest(f"{left!r} is not a permutation of {right!r}")
        remaining.remove(item)
    if remaining:
        raise FailTest(f"{left!r} is not a permutation of {right!r}")


def collected(result: Sequence[_T] | None) -> Sequence[_T]:
    """What walking a tree hands back when it was given no callback.

    children() and subtree() answer with the entries, or with nothing when a
    callback took them one at a time.
    """
    assert result is not None
    return result
