import logging

logger = logging.getLogger("anyldap")


class ConnectionDone(Exception):
    pass


class ConnectionLost(Exception):
    pass


class Protocol:
    transport = None
    connectionDone = ConnectionDone()

    def makeConnection(self, transport):
        self.transport = transport
        self.connectionMade()

    def connectionMade(self):
        pass

    def connectionLost(self, reason=connectionDone):
        pass

    def dataReceived(self, data):
        pass


class Failure(Exception):
    def __init__(self, value):
        try:
            message = str(value)
        except Exception:
            message = repr(value)
        super().__init__(message)
        self.value = value

    def trap(self, *expected):
        if isinstance(self.value, expected):
            return type(self.value)
        raise self.value

    def check(self, *expected):
        for item in expected:
            if isinstance(self.value, item):
                return item
        return None

    def getErrorMessage(self):
        return str(self.value)

    def raiseException(self):
        raise self.value
