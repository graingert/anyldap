import pytest

from anyldap import deferred
from anyldap.runtime import Failure

pytestmark = pytest.mark.anyio


async def test_exception_coercion_and_failure_conversion():
    error = ValueError("bad")
    assert deferred._coerce_exception(Failure(error)) is error
    assert deferred._coerce_exception(error) is error
    assert isinstance(deferred._coerce_exception("bad"), RuntimeError)

    class ForeignFailure:
        def trap(self, *types):
            pass

        def check(self, *types):
            pass

    foreign = ForeignFailure()
    assert foreign.trap() is None
    assert foreign.check() is None
    assert deferred._as_failure(foreign) is foreign
    assert isinstance(deferred._as_failure(error), Failure)
    assert isinstance(deferred._as_failure("bad").value, RuntimeError)


async def test_deferred_cannot_fire_twice():
    source = deferred.DeferredSource()
    assert not source.called
    source.callback("done")
    assert source.called
    with pytest.raises(RuntimeError, match="already fired"):
        source.callback("again")

    source = deferred.DeferredSource()
    source.errback(ValueError("bad"))
    with pytest.raises(RuntimeError, match="already fired"):
        source.errback(ValueError("again"))


async def test_callbacks_can_return_awaitables_and_raise():
    async def value():
        return "async value"

    result = deferred.succeed(None)
    result.addCallback(lambda ignored: value())
    assert await result == "async value"

    async def broken():
        raise ValueError("async failure")

    result = deferred.succeed(None)
    result.addCallback(lambda ignored: broken())
    with pytest.raises(ValueError, match="async failure"):
        await result

    result = deferred.succeed(None)
    result.addCallback(lambda ignored: 1 / 0)
    result.addErrback(lambda failure: "recovered")
    assert await result == "recovered"


async def test_add_both_handles_success_and_failure():
    successes = []
    result = deferred.succeed("done")
    result.addBoth(lambda value: successes.append(value) or value)
    assert await result == "done"
    assert successes == ["done"]

    failures = []
    result = deferred.fail(ValueError("bad"))
    result.addBoth(lambda failure: failures.append(failure) or "recovered")
    assert await result == "recovered"
    assert isinstance(failures[0], Failure)


async def test_callbacks_can_chain_deferred_success_and_failure():
    result = deferred.succeed(None)
    result.addCallback(lambda ignored: deferred.succeed("nested"))
    assert await result == "nested"

    result = deferred.succeed(None)
    result.addCallback(lambda ignored: deferred.fail(ValueError("nested failure")))
    with pytest.raises(ValueError, match="nested failure"):
        await result

    child = deferred.Deferred()
    result = deferred.succeed(None)
    result.addCallback(lambda ignored: child)
    assert result._waiting
    child.callback("later")
    assert await result == "later"


async def test_advance_ignores_running_or_waiting_deferred():
    result = deferred.Deferred()
    result._running = True
    assert result._advance() is None
    result._running = False
    result._waiting = True
    assert result._advance() is None


async def test_foreign_deferred_adapter_and_helpers():
    class ForeignDeferred:
        def addCallbacks(self, callback, errback):
            callback("foreign")

        def addCallback(self, callback):
            pass

        def addErrback(self, errback):
            pass

    assert await deferred.maybeDeferred(lambda: ForeignDeferred()) == "foreign"
    foreign_deferred = ForeignDeferred()
    assert foreign_deferred.addCallback(None) is None
    assert foreign_deferred.addErrback(None) is None
    assert await deferred.maybeDeferred(lambda: deferred.succeed("native")) == "native"
    assert await deferred.maybeDeferred(lambda: "plain") == "plain"

    async def asynchronous():
        return "awaitable"

    assert await deferred.maybeDeferred(asynchronous) == "awaitable"
    with pytest.raises(ValueError, match="synchronous failure"):
        await deferred.maybeDeferred(
            lambda: (_ for _ in ()).throw(ValueError("synchronous failure"))
        )
    assert await deferred.ensureDeferred(asynchronous()) == "awaitable"
    assert deferred.logError("error") == "error"
