import heapq
import itertools
import logging


class _DelayedCall:
    def __init__(self, when, func, args, kwargs):
        self.when = when
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class Clock:
    def __init__(self):
        self.seconds = 0.0
        self._calls = []
        self._counter = itertools.count()

    def callLater(self, delay, func, *args, **kwargs):
        call = _DelayedCall(self.seconds + delay, func, args, kwargs)
        heapq.heappush(self._calls, (call.when, next(self._counter), call))
        return call

    def advance(self, amount):
        target = self.seconds + amount
        while self._calls and self._calls[0][0] <= target:
            when, _, call = heapq.heappop(self._calls)
            self.seconds = when
            if not call.cancelled:
                call.func(*call.args, **call.kwargs)
        self.seconds = target


class _LogCaptureHandler(logging.Handler):
    def __init__(self, level):
        super().__init__(level=level)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def capture_logs(test_case, logger_name="anyldap", level=logging.INFO):
    logger = logging.getLogger(logger_name)
    handler = _LogCaptureHandler(level)
    previous_level = logger.level
    logger.addHandler(handler)
    if logger.level == logging.NOTSET or logger.level > level:
        logger.setLevel(level)

    def cleanup():
        logger.removeHandler(handler)
        logger.setLevel(previous_level)

    test_case.addCleanup(cleanup)
    return handler.messages
