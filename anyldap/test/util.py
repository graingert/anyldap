import functools

import anyio

from anyldap._async import await_deferred
from anyldap.deferred import ensureDeferred
from anyldap.runtime import Failure


def _getDeferredResult(d):
    try:
        return anyio.run(await_deferred, d)
    except Exception as exc:
        return Failure(exc)


def pumpingDeferredResult(d):
    result = _getDeferredResult(d)
    return result.raiseException() if isinstance(result, Failure) else result


def fromCoroutineFunction(corofn):
    @functools.wraps(corofn)
    def wrapper(*args, **kwargs):
        return ensureDeferred(corofn(*args, **kwargs))

    return wrapper
