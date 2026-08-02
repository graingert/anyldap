class FailTest(AssertionError):
    """Raised by test helpers when an expectation was not met."""


def assert_permutation(first, second):
    """Assert both iterables hold the same items, in any order.

    Unlike ``sorted(a) == sorted(b)`` this works for items that are not
    orderable, which covers most of the LDAP value types.
    """
    first = list(first)
    second = list(second)
    remaining = list(second)
    for item in first:
        if item not in remaining:
            raise FailTest(f"{first!r} is not a permutation of {second!r}")
        remaining.remove(item)
    if remaining:
        raise FailTest(f"{first!r} is not a permutation of {second!r}")
