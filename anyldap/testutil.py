"""Utilities for writing unit tests and debugging."""

from anyldap import config
from anyldap._encoder import to_bytes
from anyldap.deferred import DeferredSource, fail, succeed
from anyldap.runtime import Failure
from anyldap.test import unittest


class StringTransport:
    disconnecting = False

    def __init__(self):
        self._data = bytearray()

    def write(self, data):
        self._data.extend(data)

    def value(self):
        return bytes(self._data)

    def clear(self):
        self._data.clear()

    def loseConnection(self):
        self.disconnecting = True


def mustRaise(dummy):
    raise unittest.FailTest("Should have raised an exception.")


def calltrace():
    """Print out all function calls. For debug use only."""

    def printfuncnames(frame, event, arg):
        print(
            "|%s: %s:%d:%s"
            % (
                event,
                frame.f_code.co_filename,
                frame.f_code.co_firstlineno,
                frame.f_code.co_name,
            )
        )

    import sys

    sys.setprofile(printfuncnames)


class FakeTransport:
    def __init__(self, proto):
        self.proto = proto

    def loseConnection(self):
        self.proto.connectionLost()


class LDAPClientTestDriver:
    """

    A test driver that looks somewhat like a real LDAPClient.

    Pass in a list of lists of LDAPProtocolResponses. For each sent
    LDAP message, the first item of said list is iterated through, and
    all the items are sent as responses to the callback. The sent LDAP
    messages are stored in self.sent, so you can assert that the sent
    messages are what they are supposed to be.

    It is also possible to include a Failure instance instead of a list
    of LDAPProtocolResponses which will cause the errback to be called
    with the failure.
    """

    fakeUnbindResponse = "fake-unbind-by-LDAPClientTestDriver"

    def __init__(self, *responses):
        self.sent = []
        self.responses = list(responses)
        self.connected = None
        self.transport = FakeTransport(self)

    def send(self, op):
        self.sent.append(op)
        resps = self._response()
        assert len(resps) == 1, "got %d responses for a .send()" % len(resps)
        r = resps[0]
        if isinstance(r, Failure):
            return fail(r)
        else:
            return succeed(r)

    def send_multiResponse_(
        self, op, controls, return_controls, handler, *args, **kwargs
    ):
        d = DeferredSource()
        self.sent.append(op)
        responses = self._response()
        response_controls = None
        while responses:
            r = responses.pop(0)
            if isinstance(r, Failure):
                d.errback(r)
                break
            if return_controls:
                ret = handler(r, response_controls, *args, **kwargs)
            else:
                ret = handler(r, *args, **kwargs)
            if responses:
                msg = (
                    "got %d responses still to give, "
                    "but handler wants none (got %r)."
                ) % (len(responses), ret)
                assert not ret, msg
            else:
                msg = (
                    "no more responses to give, but handler "
                    "still wants more (got %r)." % ret
                )
                assert ret, msg
        return d.deferred

    def send_multiResponse(self, op, handler, *args, **kwargs):
        return self.send_multiResponse_(op, None, False, handler, *args, **kwargs)

    def send_multiResponse_ex(self, op, controls, handler, *args, **kwargs):
        return self.send_multiResponse_(op, controls, True, handler, *args, **kwargs)

    def send_noResponse(self, op):
        if len(self.responses) == 0:
            msg = "Ran out of responses"
            assert op == self.fakeUnbindResponse, msg
        else:
            self.responses.pop(0)
        self.sent.append(op)

    def _response(self):
        assert self.responses, "Ran out of responses"
        responses = self.responses.pop(0)
        return responses

    def assertNothingSent(self):
        # just a bit more explicit
        self.assertSent()

    def assertSent(self, *shouldBeSent):
        shouldBeSent = list(shouldBeSent)
        msg = f"{self.__class__.__name__} expected to send {shouldBeSent!r} but sent {self.sent!r}"
        assert self.sent == shouldBeSent, msg
        sentStr = b"".join([to_bytes(x) for x in self.sent])
        shouldBeSentStr = b"".join([to_bytes(x) for x in shouldBeSent])
        msg = f"{self.__class__.__name__} expected to send data {shouldBeSentStr!r} but sent {sentStr!r}"
        assert sentStr == shouldBeSentStr, msg

    def connectionMade(self):
        """TCP connection has opened"""
        self.connected = 1

    def connectionLost(self, reason=None):
        """
        Called when TCP connection has been lost
        """
        msg = (
            "connectionLost called even when have "
            "responses left: %r" % self.responses
        )
        assert not self.responses, msg
        self.connected = 0

    def unbind(self):
        assert self.connected
        r = self.fakeUnbindResponse
        self.send_noResponse(r)
        self.transport.loseConnection()


def createServer(proto, *responses, **kw):
    """
    Create an LDAP server for testing.
    :param proto: The server protocol factory (e.g. `ProxyBase`).
    :param responses: The responses to initialize the `LDAPClientTestDrive`.
    :param proto_args: Optional mapping passed as keyword args to protocol factory.
    """
    if "proto_args" in kw:
        proto_args = kw["proto_args"]
        del kw["proto_args"]
    else:
        proto_args = {}

    def createClient(factory):
        proto = factory()
        proto.connectionMade()
        return proto

    overrides = kw.setdefault("serviceLocationOverrides", {})
    overrides.setdefault("", createClient)
    conf = config.LDAPConfig(**kw)
    server = proto(conf, **proto_args)
    clientTestDriver = LDAPClientTestDriver(*responses)
    server.protocol = lambda: clientTestDriver
    server.clientTestDriver = clientTestDriver
    server.transport = StringTransport()
    server.connectionMade()
    return server
