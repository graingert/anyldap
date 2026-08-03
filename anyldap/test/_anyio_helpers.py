from collections.abc import Awaitable, Callable, Iterable
from typing import Any

import anyio
import pytest
from anyio.abc import ByteStream, SocketAttribute, SocketListener

from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldapserver


class MemoryByteStream(ByteStream):
    def __init__(self) -> None:
        self._incoming_send, self._incoming_recv = anyio.create_memory_object_stream[
            bytes
        ](0)
        self._outgoing_send, self._outgoing_recv = anyio.create_memory_object_stream[
            bytes
        ](0)
        self.closed = False
        self.closed_event = anyio.Event()

    async def send(self, data: bytes) -> None:
        await self._outgoing_send.send(data)

    async def receive(self, max_bytes: int = 65536) -> bytes:
        data = await self._incoming_recv.receive()
        assert isinstance(data, bytes)
        return data

    async def send_eof(self) -> None:
        await self._outgoing_send.aclose()

    async def aclose(self) -> None:
        self.closed = True
        self.closed_event.set()
        await self._incoming_send.aclose()
        await self._incoming_recv.aclose()
        await self._outgoing_send.aclose()
        await self._outgoing_recv.aclose()

    async def feed(self, data: bytes) -> None:
        await self._incoming_send.send(data)

    async def next_write(self) -> bytes:
        data = await self._outgoing_recv.receive()
        assert isinstance(data, bytes)
        return data

    async def close_input(self) -> None:
        await self._incoming_send.aclose()

    async def close_output(self) -> None:
        await self._outgoing_recv.aclose()


def accept_one(listener: anyio.abc.Listener[Any]) -> Awaitable[ByteStream]:
    """The next connection to a listener these tests started."""
    inner = listener.listeners[0]  # type: ignore[attr-defined]
    assert isinstance(inner, SocketListener)
    return inner.accept()


def local_address(listener: anyio.abc.Listener[Any]) -> tuple[str, int]:
    """The host and port a listener bound to.

    A listener's address is only a pair for the socket families these tests
    use; anyio has to allow for the ones where it is a path.
    """
    address = listener.extra(SocketAttribute.local_address)
    assert isinstance(address, tuple)
    host, port = address
    assert isinstance(host, str)
    assert isinstance(port, int)
    return host, port


def decode_message(wire_bytes: bytes) -> pureber.BERBase | None:
    message, _ = pureber.berDecodeObject(ldapserver.BaseLDAPServer.berdecoder, wire_bytes)
    return message


class AsyncLDAPClientDriver:
    fake_unbind_response = "fake-unbind-by-AsyncLDAPClientDriver"

    def __init__(self, *responses: Iterable[Any] | BaseException) -> None:
        self.responses = list(responses)
        self.sent: list[Any] = []
        self.connected = True
        self.closed = False
        self.closed_event = anyio.Event()

    def _response(self) -> list[Any]:
        assert self.responses, "Ran out of responses"
        item = self.responses.pop(0)
        assert not isinstance(item, BaseException)
        return list(item)

    async def send(self, op: Any) -> Any:
        self.sent.append(op)
        responses = self._response()
        assert len(responses) == 1, f"got {len(responses)} responses for .send()"
        response = responses[0]
        if isinstance(response, BaseException):
            raise response
        return response

    send_async = send

    async def send_multiResponse(
        self, op: Any, handler: Callable[..., object], *args: object, **kwargs: object
    ) -> None:
        self.sent.append(op)
        for response in self._response():
            handler(response, *args, **kwargs)

    send_multiResponse_async = send_multiResponse

    async def send_multiResponse_ex(
        self,
        op: Any,
        controls: object = None,
        handler: Callable[..., object] | None = None,
        *args: object,
        **kwargs: object,
    ) -> None:
        self.sent.append(op)
        assert handler is not None
        for response in self._response():
            handler(response, None, *args, **kwargs)

    send_multiResponse_ex_async = send_multiResponse_ex

    async def send_noResponse_async(self, op: Any) -> None:
        self.sent.append(op)
        if self.responses:
            self._response()

    def unbind(self) -> None:
        assert self.connected
        self.sent.append(pureldap.LDAPUnbindRequest())
        self.connected = False

    async def aclose(self) -> None:
        self.closed = True
        self.connected = False
        self.closed_event.set()

    def assert_sent(self, *expected: object) -> None:
        assert self.sent == list(expected)


def patch_client_creator(
    monkeypatch: pytest.MonkeyPatch, module: Any, client: object
) -> None:
    class FakeCreator:
        def __init__(self, reactor: object, protocol: object) -> None:
            self.protocol = protocol

        async def connectAsync(
            self,
            dn: object,
            overrides: object = None,
            bindAddress: object = None,
            resolver: object = None,
            tls: bool = False,
        ) -> object:
            return client

    monkeypatch.setattr(module.ldapconnector, "LDAPClientCreator", FakeCreator)
