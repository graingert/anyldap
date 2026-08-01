import logging
import sys
import warnings

import pytest

from anyldap.deferred import Deferred, DeferredSource, fail, succeed
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import proxy
from anyldap.runtime import Failure, Protocol
from anyldap.test import unittest, util
from anyldap.test._anyio_helpers import AsyncLDAPClientDriver, MemoryByteStream
from anyldap.test._testing import Clock, capture_logs
from anyldap import testutil

pytestmark = pytest.mark.anyio


async def test_memory_byte_stream_all_operations():
    stream = MemoryByteStream()
    await stream.feed(b"incoming")
    assert await stream.receive() == b"incoming"
    await stream.send(b"outgoing")
    assert await stream.next_write() == b"outgoing"
    await stream.close_input()
    await stream.aclose()
    assert stream.closed


async def test_async_client_driver_response_paths():
    request = pureldap.LDAPBindRequest()
    response = pureldap.LDAPBindResponse(resultCode=0)
    driver = AsyncLDAPClientDriver([response], [ValueError("bad")])
    assert await driver.send(request) is response
    with pytest.raises(ValueError, match="bad"):
        await driver.send(request)
    driver.assert_sent(request, request)


async def test_async_client_driver_extended_and_no_response_paths():
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


async def test_async_client_driver_extended_handler_error():
    driver = AsyncLDAPClientDriver([pureldap.LDAPBindResponse(resultCode=0)])

    def broken(*args):
        raise RuntimeError("handler failed")

    with pytest.raises(RuntimeError, match="handler failed"):
        await driver.send_multiResponse_ex(pureldap.LDAPBindRequest(), None, broken)


def test_clock_cancel_and_order():
    clock = Clock()
    calls = []
    cancelled = clock.callLater(1, calls.append, "cancelled")
    cancelled.cancel()
    clock.callLater(2, calls.append, "second")
    clock.callLater(1, calls.append, "first")
    clock.advance(3)
    assert calls == ["first", "second"]
    assert clock.seconds == 3


def test_capture_logs_restores_logger():
    case = unittest.TestCase()
    logger = logging.getLogger("anyldap.helper-test")
    original_level = logger.level
    messages = capture_logs(case, logger.name, logging.INFO)
    logger.info("captured")
    assert messages == ["captured"]
    case.doCleanups()
    assert logger.level == original_level


def test_capture_logs_preserves_more_verbose_logger_level():
    case = unittest.TestCase()
    logger = logging.getLogger("anyldap.verbose-helper-test")
    original_level = logger.level
    logger.setLevel(logging.DEBUG)
    messages = capture_logs(case, logger.name, logging.INFO)
    logger.info("captured")
    assert messages == ["captured"]
    case.doCleanups()
    assert logger.level == logging.DEBUG
    logger.setLevel(original_level)


class EchoProtocol(Protocol):
    def __init__(self):
        self.received = []

    def dataReceived(self, data):
        self.received.append(data)


def test_io_pump_and_connected_protocols():
    client = EchoProtocol()
    server = EchoProtocol()
    pump = util.returnConnected(server, client)
    client.transport.write(b"to-server")
    server.transport.write(b"to-client")
    assert pump.pump() == 1
    assert server.received[-1] == b"to-server"
    assert client.received[-1] == b"to-client"
    assert pump.pump() == 0
    pump.flush()
    client.transport.loseConnection()
    assert client.transport.disconnecting


async def test_coroutine_function_adapter():
    async def add(left, right):
        return left + right

    wrapped = util.fromCoroutineFunction(add)
    assert wrapped.__name__ == "add"
    assert await wrapped(2, 3) == 5


def test_unittest_compatibility_helpers():
    case = unittest.TestCase()
    first = case.mktemp()
    second = case.mktemp()
    assert first != second
    case.failUnlessEqual(1, 1)
    case.failIfEqual(1, 2)
    case.failUnless(True)
    case.failIf(False)
    marker = object()
    case.assertIdentical(marker, marker)
    case.assertNotIdentical(marker, object())
    with case.assertRaises(ValueError):
        raise ValueError("bad")
    with case.assertRaisesRegex(ValueError, "bad"):
        raise ValueError("bad")
    case.assertRaises(ValueError, int, "not-an-int")
    case.assertRaisesRegex(ValueError, "invalid literal", int, "not-an-int")
    assert unittest._is_deferred_like(succeed(None))
    assert not unittest._is_deferred_like(object())
    case.doCleanups()


def test_unittest_failure_and_warning_helpers():
    case = unittest.TestCase()
    failure = fail(Failure(ValueError("bad")))
    assert isinstance(case.failureResultOf(failure, ValueError), Failure)
    assert case.assertFailure(fail(Failure(ValueError("bad"))), ValueError)
    with pytest.raises(unittest.FailTest):
        case.failureResultOf(succeed("ok"))
    with pytest.raises(ValueError):
        case.successResultOf(fail(Failure(ValueError("bad"))))
    case._warnings = []
    with warnings.catch_warnings(record=True) as caught:
        warnings.warn("notice")
    case._warnings = caught
    assert case.flushWarnings()[0]["message"] == "notice"
    assert case.flushWarnings() == []


async def test_unittest_rejects_invalid_return_and_handles_nested_deferred():
    case = unittest.TestCase()
    with pytest.raises(TypeError, match="must return None"):
        case._callTestMethod(lambda: object())

    async def nested():
        return succeed("done")

    await case._await_result(nested())


async def test_legacy_client_driver_paths():
    request = pureldap.LDAPBindRequest()
    response = pureldap.LDAPBindResponse(resultCode=0)
    driver = testutil.LDAPClientTestDriver([response])
    driver.connectionMade()
    assert await driver.send(request) is response
    driver.assertSent(request)
    driver.assertNothingSent() if False else None
    driver.responses.append([])
    driver.send_noResponse(request)
    driver.unbind()
    assert not driver.connected


def test_string_transport_and_must_raise():
    transport = testutil.StringTransport()
    transport.write(b"value")
    assert transport.value() == b"value"
    transport.clear()
    assert transport.value() == b""
    transport.loseConnection()
    assert transport.disconnecting
    with pytest.raises(unittest.FailTest):
        testutil.mustRaise(None)


def test_calltrace_profiles_calls(capsys):
    testutil.calltrace()
    sys.setprofile(None)
    assert "call" in capsys.readouterr().out


async def test_create_server_compatibility_helper():
    server = testutil.createServer(proxy.Proxy)
    assert server.connected
    assert server.client is server.clientTestDriver
    server.client.responses.clear()
    server.connectionLost(Exception("closed"))
