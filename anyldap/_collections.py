from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from typing import Any


class InsensitiveDict(MutableMapping[Any, Any]):
    """A mapping whose string keys compare case-insensitively.

    The key a value was first stored under is remembered, so iteration and
    items() give back the original spelling rather than the folded one.
    """

    def __init__(
        self, initial: Mapping[Any, Any] | Iterable[tuple[Any, Any]] | None = None
    ) -> None:
        self.data: dict[Any, tuple[Any, Any]] = {}
        if initial is not None:
            self.update(initial)

    def _normalize(self, key: Any) -> Any:
        try:
            return key.lower()
        except AttributeError:
            return key

    def __getitem__(self, key: Any) -> Any:
        return self.data[self._normalize(key)][1]

    def __setitem__(self, key: Any, value: Any) -> None:
        self.data[self._normalize(key)] = (key, value)

    def __delitem__(self, key: Any) -> None:
        del self.data[self._normalize(key)]

    def __iter__(self) -> Iterator[Any]:
        return self.iterkeys()

    def __len__(self) -> int:
        return len(self.data)

    def __contains__(self, key: Any) -> bool:
        return self._normalize(key) in self.data

    def get(self, key: Any, default: Any = None) -> Any:
        item = self.data.get(self._normalize(key))
        if item is None:
            return default
        return item[1]

    # These deliberately return lists rather than the views MutableMapping
    # specifies; callers index and sort the results.
    def items(self) -> list[tuple[Any, Any]]:  # type: ignore[override]
        return [(key, value) for key, value in self.data.values()]

    def keys(self) -> list[Any]:  # type: ignore[override]
        return [key for key, _ in self.data.values()]

    def values(self) -> list[Any]:  # type: ignore[override]
        return [value for _, value in self.data.values()]

    def iterkeys(self) -> Iterator[Any]:
        for key, _ in self.data.values():
            yield key
