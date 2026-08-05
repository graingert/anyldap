"""Helpers for bridging callback-style protocol code to async/await."""

import inspect
from collections.abc import Awaitable
from typing import Generic, TypeVar, overload

import anyio
import outcome

_T = TypeVar("_T")


@overload
async def await_result(result: Awaitable[_T]) -> _T: ...
@overload
async def await_result(result: _T | Awaitable[_T]) -> _T: ...
async def await_result(result: object) -> object:
    """Await ``result`` when it is awaitable, otherwise return it unchanged.

    Protocol handlers may be written as either plain or async functions, so
    dispatch code cannot know up front whether it has a value or a coroutine.
    Either way what comes back is what the handler produced.
    """
    if inspect.isawaitable(result):
        return await result
    return result


class ResultSlot(Generic[_T]):
    """A one-shot result cell that a single consumer can await.

    Producers running in callback context (a wire response arriving, a
    connection dropping) record an `outcome.Outcome`; the consumer awaits
    `wait()`, which replays it as either a value or a raised exception.
    """

    def __init__(self) -> None:
        self._event = anyio.Event()
        self._outcome: outcome.Outcome[_T] | None = None

    @property
    def is_set(self) -> bool:
        return self._outcome is not None

    def set_outcome(self, result: outcome.Outcome[_T]) -> None:
        if self._outcome is not None:
            raise RuntimeError("result already set")
        self._outcome = result
        self._event.set()

    def set_value(self, value: _T) -> None:
        self.set_outcome(outcome.Value(value))

    def set_exception(self, exc: BaseException) -> None:
        self.set_outcome(outcome.Error(exc))

    async def wait(self) -> _T:
        await self._event.wait()
        assert self._outcome is not None
        return self._outcome.unwrap()
