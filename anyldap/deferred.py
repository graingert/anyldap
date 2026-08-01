import inspect
from dataclasses import dataclass, field

import anyio

from anyldap.runtime import Failure

_UNSET = object()


def _coerce_exception(value):
    if hasattr(value, "value") and isinstance(value.value, BaseException):
        value = value.value
    if isinstance(value, BaseException):
        return value
    return RuntimeError(value)


def _as_failure(value):
    if isinstance(value, Failure):
        return value
    if hasattr(value, "trap") and hasattr(value, "check"):
        return value
    if isinstance(value, BaseException):
        return Failure(value)
    return Failure(RuntimeError(value))


@dataclass
class _DeferredState:
    _event: anyio.Event = field(default_factory=anyio.Event)
    _result: object = _UNSET
    _failed: bool = False
    _called: bool = False


@dataclass
class Deferred:
    _state: _DeferredState = field(default_factory=_DeferredState)
    _callbacks: list = field(default_factory=list)
    _running: bool = False
    _waiting: bool = False
    _awaitable: object = _UNSET

    @property
    def called(self):
        return self._state._called

    def __await__(self):
        return self._wait().__await__()

    async def _wait(self):
        if self._waiting and self._awaitable is not _UNSET:
            await self._run_awaitable()
        await self._state._event.wait()
        if self._state._failed:
            raise _coerce_exception(self._state._result)
        return self._state._result

    def _callback(self, result=None):
        if self._state._called:
            raise RuntimeError("Deferred already fired")
        self._state._called = True
        self._state._result = result
        self._state._failed = False
        self._advance()
        return self

    def _errback(self, fail):
        if self._state._called:
            raise RuntimeError("Deferred already fired")
        self._state._called = True
        self._state._result = _as_failure(fail)
        self._state._failed = True
        self._advance()
        return self

    def addCallback(self, callback, *args, **kwargs):
        return self._add_handler(False, callback, args, kwargs)

    def addErrback(self, errback, *args, **kwargs):
        return self._add_handler(True, errback, args, kwargs)

    def addBoth(self, callback, *args, **kwargs):
        self.addCallback(callback, *args, **kwargs)
        self.addErrback(callback, *args, **kwargs)
        return self

    def addCallbacks(self, callback, errback, callbackArgs=(), errbackArgs=()):
        self.addCallback(callback, *callbackArgs)
        self.addErrback(errback, *errbackArgs)
        return self

    def _add_handler(self, failed, callback, args, kwargs):
        self._callbacks.append((failed, callback, args, kwargs))
        if self._state._called:
            self._advance()
        return self

    def _advance(self):
        if self._running or self._waiting:
            return
        self._running = True
        while self._callbacks:
            failed, callback, args, kwargs = self._callbacks.pop(0)
            if failed != self._state._failed:
                continue
            try:
                result = callback(self._state._result, *args, **kwargs)
            except Exception as exc:
                self._state._result = Failure(exc)
                self._state._failed = True
                continue
            if isinstance(result, Deferred):
                self._waiting = True
                self._running = False
                result.addCallbacks(self._resume_callback, self._resume_errback)
                if result.called and not result._waiting:
                    result._advance()
                return
            if inspect.isawaitable(result):
                self._awaitable = result
                self._waiting = True
                self._running = False
                return
            self._state._result = result
            self._state._failed = isinstance(result, Failure)
        self._running = False
        self._state._event.set()

    def _resume_callback(self, result):
        self._state._result = result
        self._state._failed = isinstance(result, Failure)
        self._waiting = False
        self._advance()
        return result

    def _resume_errback(self, fail):
        self._state._result = _as_failure(fail)
        self._state._failed = True
        self._waiting = False
        self._advance()
        return fail

    async def _run_awaitable(self):
        awaitable = self._awaitable
        self._awaitable = _UNSET
        try:
            value = await awaitable
        except Exception as exc:
            self._state._result = Failure(exc)
            self._state._failed = True
        else:
            self._state._result = value
            self._state._failed = isinstance(value, Failure)
        self._waiting = False
        self._advance()


@dataclass
class DeferredSource:
    deferred: Deferred = field(default_factory=Deferred)

    @property
    def called(self):
        return self.deferred.called

    def callback(self, result=None):
        self.deferred._callback(result)
        return self.deferred

    def errback(self, fail):
        self.deferred._errback(fail)
        return self.deferred


def succeed(result=None):
    return DeferredSource().callback(result)


def fail(exc):
    return DeferredSource().errback(exc)


def _from_foreign_deferred(deferred):
    source = DeferredSource()
    deferred.addCallbacks(source.callback, source.errback)
    return source.deferred


def maybeDeferred(func, *args, **kwargs):
    try:
        result = func(*args, **kwargs)
    except Exception as exc:
        return fail(exc)
    if isinstance(result, Deferred):
        return result
    if hasattr(result, "addCallback") and hasattr(result, "addErrback"):
        return _from_foreign_deferred(result)
    if inspect.isawaitable(result):
        return ensureDeferred(result)
    return succeed(result)


def ensureDeferred(awaitable):
    d = Deferred()
    d._awaitable = awaitable
    d._waiting = True
    return d


def logError(error):
    return error
