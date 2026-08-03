import logging
import sys
from collections.abc import Callable

import anyio
import pytest

from anyldap import testutil
from anyldap.protocols import pureldap
from anyldap.test import util
from anyldap.test._anyio_helpers import AsyncLDAPClientDriver, MemoryByteStream
from anyldap.test._testing import Clock, capture_logs

pytestmark = pytest.mark.anyio


async def test_memory_byte_stream_all_operations() -> None:
    stream = MemoryByteStream()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(stream.feed, b"incoming")
        assert await stream.receive() == b"incoming"
        task_group.start_soon(stream.send, b"outgoing")
        assert await stream.next_write() == b"outgoing"
    await stream.close_input()
    await stream.aclose()
    assert stream.closed


async def test_async_client_driver_response_paths() -> None:
    request = pureldap.LDAPBindRequest()
    response = pureldap.LDAPBindResponse(resultCode=0)
    driver = AsyncLDAPClientDriver([response], [ValueError("bad")])
    assert await driver.send(request) is response
    with pytest.raises(ValueError, match="bad"):
        await driver.send(request)
    driver.assert_sent(request, request)


async def test_async_client_driver_extended_and_no_response_paths() -> None:
    request = pureldap.LDAPBindRequest()
    response = pureldap.LDAPBindResponse(resultCode=0)
    received = []
    driver = AsyncLDAPClientDriver([response], [response], [])
    await driver.send_multiResponse_ex(
        request, None, lambda value, controls: received.append((value, controls))
    )
    assert received == [(response, None)]
    await driver.send_noResponse_async(request)
    await driver.send_noResponse_async(request)
    await driver.send_noResponse_async(request)
    driver.unbind()
    assert not driver.connected
    await driver.aclose()
    assert driver.closed


async def test_async_client_driver_extended_handler_error() -> None:
    driver = AsyncLDAPClientDriver([pureldap.LDAPBindResponse(resultCode=0)])

    def broken(*args: object) -> None:
        raise RuntimeError("handler failed")

    with pytest.raises(RuntimeError, match="handler failed"):
        await driver.send_multiResponse_ex(pureldap.LDAPBindRequest(), None, broken)


def test_clock_cancel_and_order() -> None:
    clock = Clock()
    calls: list[str] = []
    cancelled = clock.callLater(1, calls.append, "cancelled")
    cancelled.cancel()
    clock.callLater(2, calls.append, "second")
    clock.callLater(1, calls.append, "first")
    clock.advance(3)
    assert calls == ["first", "second"]
    assert clock.seconds == 3


def test_capture_logs_restores_logger() -> None:
    cleanups: list[Callable[[], object]] = []
    logger = logging.getLogger("anyldap.helper-test")
    original_level = logger.level
    messages = capture_logs(cleanups, logger.name, logging.INFO)
    logger.info("captured")
    assert messages == ["captured"]
    for cleanup in cleanups:
        cleanup()
    assert logger.level == original_level


def test_capture_logs_preserves_more_verbose_logger_level() -> None:
    cleanups: list[Callable[[], object]] = []
    logger = logging.getLogger("anyldap.verbose-helper-test")
    original_level = logger.level
    logger.setLevel(logging.DEBUG)
    messages = capture_logs(cleanups, logger.name, logging.INFO)
    logger.info("captured")
    assert messages == ["captured"]
    for cleanup in cleanups:
        cleanup()
    assert logger.level == logging.DEBUG
    logger.setLevel(original_level)


def test_assert_permutation_ignores_order() -> None:
    util.assert_permutation([{"a": 1}, {"b": 2}], [{"b": 2}, {"a": 1}])
    with pytest.raises(util.FailTest, match="permutation"):
        util.assert_permutation([{"a": 1}], [{"b": 2}])
    with pytest.raises(util.FailTest, match="permutation"):
        util.assert_permutation([{"a": 1}], [{"a": 1}, {"b": 2}])


async def test_legacy_client_driver_paths() -> None:
    request = pureldap.LDAPBindRequest()
    response = pureldap.LDAPBindResponse(resultCode=0)
    driver = testutil.LDAPClientTestDriver([response])
    driver.connectionMade()
    assert await driver.send(request) is response
    driver.assertSent(request)
    driver.responses.append([])
    driver.send_noResponse(request)
    driver.unbind()
    assert not driver.connected


def test_must_raise() -> None:
    with pytest.raises(util.FailTest):
        testutil.mustRaise(None)


def test_calltrace_profiles_calls(capsys: pytest.CaptureFixture[str]) -> None:
    testutil._print_func_name(sys._getframe(), "call", None)
    testutil.calltrace()
    sys.setprofile(None)
    assert "call" in capsys.readouterr().out
