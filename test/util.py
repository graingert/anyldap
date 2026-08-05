from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import TypeVar

from anyldap.testutil import FailTest

__all__ = ["FailTest", "appender", "assert_permutation", "collected", "discard"]

_T = TypeVar("_T")


async def discard(response: object) -> None:
    """A reply that goes nowhere.

    Handlers write their responses through the reply they are handed; tests
    that only care whether the call returns or raises give them this one.
    """


def appender(target: list[_T]) -> Callable[[_T], Awaitable[None]]:
    """``target.append`` as a coroutine function.

    Replies and tree walks hand over one item at a time and await the
    callback, so a test that only wants to collect them still has to give a
    coroutine function.
    """

    async def append(item: _T) -> None:
        target.append(item)

    return append


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
