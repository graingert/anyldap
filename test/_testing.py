import heapq
import itertools
import logging
from collections.abc import Callable, Mapping, Sequence


class _DelayedCall:
    def __init__(
        self,
        when: float,
        func: Callable[..., object],
        args: Sequence[object],
        kwargs: Mapping[str, object],
    ) -> None:
        self.when = when
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class Clock:
    def __init__(self) -> None:
        self.seconds = 0.0
        self._calls: list[tuple[float, int, _DelayedCall]] = []
        self._counter = itertools.count()

    def callLater(
        self,
        delay: float,
        func: Callable[..., object],
        *args: object,
        **kwargs: object,
    ) -> _DelayedCall:
        call = _DelayedCall(self.seconds + delay, func, args, kwargs)
        heapq.heappush(self._calls, (call.when, next(self._counter), call))
        return call

    def advance(self, amount: float) -> None:
        target = self.seconds + amount
        while self._calls and self._calls[0][0] <= target:
            when, _, call = heapq.heappop(self._calls)
            self.seconds = when
            if not call.cancelled:
                call.func(*call.args, **call.kwargs)
        self.seconds = target


class _LogCaptureHandler(logging.Handler):
    def __init__(self, level: int) -> None:
        super().__init__(level=level)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def capture_logs(
    cleanups: list[Callable[[], object]],
    logger_name: str = "anyldap",
    level: int = logging.INFO,
) -> list[str]:
    logger = logging.getLogger(logger_name)
    handler = _LogCaptureHandler(level)
    previous_level = logger.level
    logger.addHandler(handler)
    if logger.level == logging.NOTSET or logger.level > level:
        logger.setLevel(level)

    def cleanup() -> None:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)

    cleanups.append(cleanup)
    return handler.messages
