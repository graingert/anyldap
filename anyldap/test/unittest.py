import inspect
import os
import shutil
import tempfile
import unittest
import warnings

from anyldap.deferred import Deferred
from anyldap.runtime import Failure
from anyldap.test import util


class FailTest(AssertionError):
    pass


class TestCase(unittest.TestCase):
    def _callTestMethod(self, method):
        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always")
            self._warnings = caught_warnings
            result = method()
            if _is_deferred_like(result):
                util.pumpingDeferredResult(result)
                return
            if inspect.iscoroutine(result):
                import anyio

                anyio.run(self._await_result, result)
                return
            if result is not None:
                raise TypeError(
                    "Test methods must return None, Deferred, or a coroutine"
                )
            return

    async def _await_result(self, result):
        awaited = await result
        if isinstance(awaited, Deferred):
            await awaited

    def mktemp(self):
        counter = getattr(self, "_mktemp_counter", 0)
        root = tempfile.mkdtemp(prefix="anyldap-test-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        path = os.path.join(root, f"tmp-{counter}")
        self._mktemp_counter = counter + 1
        return path

    def successResultOf(self, deferred):
        result = util._getDeferredResult(deferred)
        if isinstance(result, Failure):
            result.raiseException()
        return result

    def failureResultOf(self, deferred, *expected):
        result = util._getDeferredResult(deferred)
        if not isinstance(result, Failure):
            raise FailTest(f"Deferred succeeded unexpectedly: {result!r}")
        if expected:
            result.trap(*expected)
        return result

    def assertFailure(self, deferred, *expected):
        self.failureResultOf(deferred, *expected)
        return deferred

    def assertRaises(self, expected_exception, *args, **kwargs):
        if not args:
            return super().assertRaises(expected_exception)
        with super().assertRaises(expected_exception) as context:
            args[0](*args[1:], **kwargs)
        return context.exception

    def assertRaisesRegex(self, expected_exception, expected_regex, *args, **kwargs):
        if not args:
            return super().assertRaisesRegex(expected_exception, expected_regex)
        with super().assertRaisesRegex(expected_exception, expected_regex) as context:
            args[0](*args[1:], **kwargs)
        return context.exception

    def flushWarnings(self):
        warnings_seen = getattr(self, "_warnings", [])
        flushed = [
            {
                "category": warning.category,
                "message": str(warning.message),
                "filename": warning.filename,
                "lineno": warning.lineno,
            }
            for warning in warnings_seen
        ]
        self._warnings = []
        return flushed

    def failUnlessEqual(self, first, second, msg=None):
        self.assertEqual(first, second, msg)

    def failIfEqual(self, first, second, msg=None):
        self.assertNotEqual(first, second, msg)

    def failUnless(self, expr, msg=None):
        self.assertTrue(expr, msg)

    def failIf(self, expr, msg=None):
        self.assertFalse(expr, msg)

    def assertIdentical(self, first, second, msg=None):
        self.assertIs(first, second, msg)

    def assertNotIdentical(self, first, second, msg=None):
        self.assertIsNot(first, second, msg)


class SynchronousTestCase(TestCase):
    pass


def _is_deferred_like(result):
    return isinstance(result, Deferred) or (
        hasattr(result, "addCallback")
        and hasattr(result, "addErrback")
        and hasattr(result, "asFuture")
    )


SkipTest = unittest.SkipTest
expectedFailure = unittest.expectedFailure
skip = unittest.skip
skipIf = unittest.skipIf
skipUnless = unittest.skipUnless
