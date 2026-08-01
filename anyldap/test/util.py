import functools
from io import BytesIO

import anyio

from anyldap._async import await_deferred
from anyldap.deferred import ensureDeferred
from anyldap.runtime import Failure


class FakeTransport:
    disconnecting = False
    disconnect_done = False

    def __init__(self):
        self.data = BytesIO()

    def write(self, data):
        self.data.seek(0, 2)
        self.data.write(data)

    def loseConnection(self):
        self.disconnecting = True


class IOPump:
    active = []

    def __init__(self, client, server, clientTransport, serverTransport):
        self.client = client
        self.server = server
        self.clientTransport = clientTransport
        self.serverTransport = serverTransport
        self.clientIO = clientTransport.data
        self.serverIO = serverTransport.data
        self.active.append(self)

    def pump(self):
        """Move data back and forth.

        Returns whether any data was moved.
        """
        self.clientIO.seek(0)
        self.serverIO.seek(0)
        cData = self.clientIO.read()
        sData = self.serverIO.read()
        self.clientIO.seek(0)
        self.serverIO.seek(0)
        self.clientIO.truncate()
        self.serverIO.truncate()
        self.server.dataReceived(cData)
        self.client.dataReceived(sData)
        return 1 if cData or sData else 0

    def flush(self):
        while self.pump():
            pass


def returnConnected(server, client):
    """Take two Protocol instances and connect them."""
    clientTransport = FakeTransport()
    client.makeConnection(clientTransport)
    serverTransport = FakeTransport()
    server.makeConnection(serverTransport)
    pump = IOPump(client, server, clientTransport, serverTransport)
    # Challenge-response authentication:
    pump.flush()
    # Uh...
    pump.flush()
    return pump


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
