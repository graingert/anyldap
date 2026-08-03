"""Utilities for writing unit tests and debugging."""

from collections.abc import Callable, Iterable
from types import FrameType
from typing import Any, NoReturn

import anyio
from anyio.abc import ByteStream, SocketAttribute, SocketListener, TaskGroup

from anyldap._encoder import to_bytes
from anyldap.runtime import Failure
from anyldap.test import util


async def exchange_async(protocol: Any, wire_data: bytes) -> bytes:
    chunks: list[bytes] = []
    from anyldap.protocols.ldap import ldapserver

    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=0)
    address = listener.extra(SocketAttribute.local_address)
    assert isinstance(address, tuple)
    host, port = address
    assert isinstance(port, int)
    client_stream = await anyio.connect_tcp(host, port)
    inner = listener.listeners[0]
    assert isinstance(inner, SocketListener)
    server_stream = await inner.accept()
    async with anyio.create_task_group() as task_group:
        task_group.start_soon(ldapserver.serve_stream, server_stream, lambda: protocol)
        await client_stream.send(wire_data)
        try:
            with anyio.move_on_after(0.1):
                while True:
                    chunks.append(await client_stream.receive())
        except anyio.EndOfStream:
            pass
        await client_stream.aclose()
        await protocol.wait_closed()
    await listener.aclose()
    return b"".join(chunks)


def mustRaise(dummy: object) -> NoReturn:
    raise util.FailTest("Should have raised an exception.")


def _print_func_name(frame: FrameType, event: str, arg: object) -> None:
    print(
        "|%s: %s:%d:%s"
        % (
            event,
            frame.f_code.co_filename,
            frame.f_code.co_firstlineno,
            frame.f_code.co_name,
        )
    )


def calltrace() -> None:
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
    of LDAPProtocolResponses, which makes the call raise instead.
    """

    fakeUnbindResponse = "fake-unbind-by-LDAPClientTestDriver"

    def __init__(self, *responses: Iterable[Any] | Failure) -> None:
        self.sent: list[Any] = []
        self.responses = list(responses)
        self.connected: int | None = None

    async def send(self, op: Any) -> Any:
        self.sent.append(op)
        resps = self._response()
        assert len(resps) == 1, "got %d responses for a .send()" % len(resps)
        r = resps[0]
        if isinstance(r, Failure):
            r.raiseException()
        return r

    send_async = send

    async def send_multiResponse_(
        self,
        op: Any,
        controls: object,
        return_controls: bool,
        handler: Callable[..., object] | None,
        *args: object,
        **kwargs: object,
    ) -> None:
        self.sent.append(op)
        responses = self._response()
        response_controls = None
        while responses:
            r = responses.pop(0)
            if isinstance(r, Failure):
                r.raiseException()
            assert handler is not None
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

    async def send_multiResponse(
        self, op: Any, handler: Callable[..., object], *args: object, **kwargs: object
    ) -> None:
        await self.send_multiResponse_(op, None, False, handler, *args, **kwargs)

    send_multiResponse_async = send_multiResponse

    async def send_multiResponse_ex(
        self,
        op: Any,
        controls: object = None,
        handler: Callable[..., object] | None = None,
        *args: object,
        **kwargs: object,
    ) -> None:
        await self.send_multiResponse_(op, controls, True, handler, *args, **kwargs)

    send_multiResponse_ex_async = send_multiResponse_ex

    def send_noResponse(self, op: Any) -> None:
        if len(self.responses) == 0:
            msg = "Ran out of responses"
            assert op == self.fakeUnbindResponse, msg
        else:
            self.responses.pop(0)
        self.sent.append(op)

    async def send_noResponse_async(self, op: Any) -> None:
        self.send_noResponse(op)

    def _response(self) -> list[Any]:
        assert self.responses, "Ran out of responses"
        responses = self.responses.pop(0)
        assert not isinstance(responses, Failure)
        return list(responses)

    def assertNothingSent(self) -> None:
        # just a bit more explicit
        self.assertSent()

    def assertSent(self, *shouldBeSent: Any) -> None:
        expected = list(shouldBeSent)
        msg = f"{self.__class__.__name__} expected to send {expected!r} but sent {self.sent!r}"
        assert self.sent == expected, msg
        sentStr = b"".join([to_bytes(x) for x in self.sent])
        shouldBeSentStr = b"".join([to_bytes(x) for x in expected])
        msg = f"{self.__class__.__name__} expected to send data {shouldBeSentStr!r} but sent {sentStr!r}"
        assert sentStr == shouldBeSentStr, msg

    def connectionMade(self) -> None:
        """TCP connection has opened"""
        self.connected = 1

    def connectionLost(self, reason: BaseException | None = None) -> None:
        """
        Called when TCP connection has been lost
        """
        msg = (
            "connectionLost called even when have "
            "responses left: %r" % self.responses
        )
        assert not self.responses, msg
        self.connected = 0

    async def aclose(self) -> None:
        self.connected = 0

    async def attach_stream(self, stream: ByteStream, task_group: TaskGroup) -> NoReturn:
        """A driver answers from its script, so nothing ever attaches it."""
        raise AssertionError(f"{self.__class__.__name__} has no stream to attach")

    def unbind(self) -> None:
        assert self.connected
        r = self.fakeUnbindResponse
        self.send_noResponse(r)
        self.connectionLost()
