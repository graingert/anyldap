"""``ldap.cidict``: a dictionary that ignores the case of its keys.

LDAP attribute types are case-insensitive, so an entry read back as
``givenName`` answers to ``givenname`` too.
"""

from collections.abc import Iterator, Mapping, MutableMapping
from typing import TypeVar

_V = TypeVar("_V")


class cidict(MutableMapping[str, _V]):
    """A dictionary keyed by attribute type, whatever case it is written in.

    The case a key was first written in is the one iteration hands back, as
    python-ldap's own does.
    """

    def __init__(self, default: Mapping[str, _V] | None = None) -> None:
        # Keyed by the lowered key: what it was spelled as, and its value.
        self._data: dict[str, tuple[str, _V]] = {}
        if default is not None:
            self.update(default)

    def __getitem__(self, key: str) -> _V:
        return self._data[key.lower()][1]

    def __setitem__(self, key: str, value: _V) -> None:
        lowered = key.lower()
        spelling = self._data[lowered][0] if lowered in self._data else key
        self._data[lowered] = (spelling, value)

    def __delitem__(self, key: str) -> None:
        del self._data[key.lower()]

    def __iter__(self) -> Iterator[str]:
        return iter([spelling for spelling, _ in self._data.values()])

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({dict(self.items())!r})"
