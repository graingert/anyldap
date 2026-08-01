import inspect

from anyldap.deferred import Deferred as AnyIODeferred


async def await_deferred(deferred):
    if isinstance(deferred, AnyIODeferred):
        return await deferred
    if inspect.isawaitable(deferred):
        return await deferred
    raise TypeError(f"Unsupported deferred object: {deferred!r}")


async def await_result(result):
    if isinstance(result, AnyIODeferred):
        return await await_deferred(result)
    if inspect.isawaitable(result):
        return await result
    return result
