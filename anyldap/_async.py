"""Helpers for bridging callback-style protocol code to async/await."""

import inspect
from typing import Any

import anyio
import outcome


async def await_result(result: Any) -> Any:
    """Await ``result`` when it is awaitable, otherwise return it unchanged.

    Protocol handlers may be written as either plain or async functions, so
    dispatch code cannot know up front whether it has a value or a coroutine.
    """
    if inspect.isawaitable(result):
        return await result
    return result


class ResultSlot:
    """A one-shot result cell that a single consumer can await.

    Producers running in callback context (a wire response arriving, a
    connection dropping) record an `outcome.Outcome`; the consumer awaits
    `wait()`, which replays it as either a value or a raised exception.
    """

    def __init__(self) -> None:
        self._event = anyio.Event()
        self._outcome: outcome.Outcome[Any] | None = None

    @property
    def is_set(self) -> bool:
        return self._outcome is not None

    def set_outcome(self, result: outcome.Outcome[Any]) -> None:
        if self._outcome is not None:
            raise RuntimeError("result already set")
        self._outcome = result
        self._event.set()

    def set_value(self, value: Any = None) -> None:
        self.set_outcome(outcome.Value(value))

    def set_exception(self, exc: BaseException) -> None:
        self.set_outcome(outcome.Error(exc))

    async def wait(self) -> Any:
        await self._event.wait()
        assert self._outcome is not None
        return self._outcome.unwrap()
