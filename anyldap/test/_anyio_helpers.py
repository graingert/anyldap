import anyio

from anyldap.deferred import DeferredSource
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldapserver


class MemoryByteStream:
    def __init__(self):
        self._incoming_send, self._incoming_recv = anyio.create_memory_object_stream(0)
        self._outgoing_send, self._outgoing_recv = anyio.create_memory_object_stream(0)
        self.closed = False

    async def send(self, data):
        await self._outgoing_send.send(data)

    async def receive(self):
        return await self._incoming_recv.receive()

    async def aclose(self):
        self.closed = True
        await self._incoming_send.aclose()
        await self._incoming_recv.aclose()
        await self._outgoing_send.aclose()
        await self._outgoing_recv.aclose()

    async def feed(self, data):
        await self._incoming_send.send(data)

    async def next_write(self):
        return await self._outgoing_recv.receive()

    async def close_input(self):
        await self._incoming_send.aclose()


def decode_message(wire_bytes):
    message, _ = pureber.berDecodeObject(ldapserver.BaseLDAPServer.berdecoder, wire_bytes)
    return message


class AsyncLDAPClientDriver:
    fake_unbind_response = "fake-unbind-by-AsyncLDAPClientDriver"

    def __init__(self, *responses):
        self.responses = list(responses)
        self.sent = []
        self.connected = True
        self.closed = False

    def _response(self):
        assert self.responses, "Ran out of responses"
        return self.responses.pop(0)

    def send(self, op):
        self.sent.append(op)
        responses = self._response()
        assert len(responses) == 1, f"got {len(responses)} responses for .send()"
        deferred = DeferredSource()
        response = responses[0]
        if isinstance(response, BaseException):
            deferred.errback(response)
        else:
            deferred.callback(response)
        return deferred.deferred

    async def send_multiResponse_async(self, op, handler, *args, **kwargs):
        self.sent.append(op)
        for response in self._response():
            handler(response, *args, **kwargs)

    def send_multiResponse_ex(self, op, controls, handler, *args, **kwargs):
        self.sent.append(op)
        deferred = DeferredSource()
        try:
            for response in self._response():
                handler(response, None, *args, **kwargs)
        except Exception as exc:
            deferred.errback(exc)
        else:
            deferred.callback(None)
        return deferred.deferred

    async def send_noResponse_async(self, op):
        self.sent.append(op)
        if self.responses:
            self._response()

    def unbind(self):
        assert self.connected
        self.sent.append(pureldap.LDAPUnbindRequest())
        self.connected = False

    async def aclose(self):
        self.closed = True
        self.connected = False

    def assert_sent(self, *expected):
        assert self.sent == list(expected)


def patch_client_creator(monkeypatch, module, client):
    class FakeCreator:
        def __init__(self, reactor, protocol):
            self.protocol = protocol

        async def connectAsync(
            self, dn, overrides=None, bindAddress=None, resolver=None, tls=False
        ):
            return client

    monkeypatch.setattr(module.ldapconnector, "LDAPClientCreator", FakeCreator)
