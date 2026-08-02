"""Utilities for writing unit tests and debugging."""

import anyio
from anyio.abc import SocketAttribute

from anyldap import config
from anyldap._encoder import to_bytes
from anyldap.deferred import DeferredSource, fail, succeed
from anyldap.runtime import Failure
from anyldap.test import unittest


async def exchange_async(protocol, wire_data):
    chunks = []
    server_stopped = anyio.Event()

    async def serve(server_stream):
        async with anyio.create_task_group() as protocol_tasks:
            await protocol.attach_stream(server_stream, protocol_tasks)
            await protocol.wait_closed()
            protocol_tasks.cancel_scope.cancel()
        server_stopped.set()

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    host, port = listener.extra(SocketAttribute.local_address)
    async with listener, anyio.create_task_group() as task_group:
        task_group.start_soon(listener.serve, serve)
        client_stream = await anyio.connect_tcp(host, port)
        await client_stream.send(wire_data)
        with anyio.move_on_after(0.1):
            while True:
                chunks.append(await client_stream.receive())
        await client_stream.aclose()
        await server_stopped.wait()
        task_group.cancel_scope.cancel()
    return b"".join(chunks)


def exchange(protocol, wire_data):
    return anyio.run(exchange_async, protocol, wire_data)

def mustRaise(dummy):
    raise unittest.FailTest("Should have raised an exception.")


def _print_func_name(frame, event, arg):
    print(
        "|%s: %s:%d:%s"
        % (
            event,
            frame.f_code.co_filename,
            frame.f_code.co_firstlineno,
            frame.f_code.co_name,
        )
    )


def calltrace():
    """Print out all function calls. For debug use only."""

    import sys

    sys.setprofile(_print_func_name)


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
        self.connectionLost()


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
    return server
