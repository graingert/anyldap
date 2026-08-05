from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from typing import TypeVar, overload

_Key = TypeVar("_Key")
_Value = TypeVar("_Value")
_Default = TypeVar("_Default")


class InsensitiveDict(MutableMapping[_Key, _Value]):
    """A mapping whose string keys compare case-insensitively.

    The key a value was first stored under is remembered, so iteration and
    items() give back the original spelling rather than the folded one.
    """

    def __init__(
        self,
        initial: Mapping[_Key, _Value] | Iterable[tuple[_Key, _Value]] | None = None,
    ) -> None:
        # Keyed by the folded key, which is not the key's own type: anything
        # without a lower() is stored as itself.
        self.data: dict[object, tuple[_Key, _Value]] = {}
        if initial is not None:
            self.update(initial)

    def _normalize(self, key: object) -> object:
        if hasattr(key, "lower"):
            return key.lower()
        return key

    def __getitem__(self, key: _Key) -> _Value:
        return self.data[self._normalize(key)][1]

    def __setitem__(self, key: _Key, value: _Value) -> None:
        self.data[self._normalize(key)] = (key, value)

    def __delitem__(self, key: _Key) -> None:
        del self.data[self._normalize(key)]

    def __iter__(self) -> Iterator[_Key]:
        return self.iterkeys()

    def __len__(self) -> int:
        return len(self.data)

    def __contains__(self, key: object) -> bool:
        return self._normalize(key) in self.data

    @overload
    def get(self, key: _Key) -> _Value | None: ...
    @overload
    def get(self, key: _Key, default: _Value | _Default) -> _Value | _Default: ...
    def get(
        self, key: _Key, default: _Value | _Default | None = None
    ) -> _Value | _Default | None:
        item = self.data.get(self._normalize(key))
        if item is None:
            return default
        return item[1]

    # These deliberately return lists rather than the views MutableMapping
    # specifies; callers index and sort the results.
    def items(self) -> list[tuple[_Key, _Value]]:  # type: ignore[override]
        return [(key, value) for key, value in self.data.values()]

    def keys(self) -> list[_Key]:  # type: ignore[override]
        return [key for key, _ in self.data.values()]

    def values(self) -> list[_Value]:  # type: ignore[override]
        return [value for _, value in self.data.values()]

    def iterkeys(self) -> Iterator[_Key]:
        for key, _ in self.data.values():
            yield key
