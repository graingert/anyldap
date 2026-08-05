import logging
from typing import NoReturn

logger = logging.getLogger("anyldap")


class ConnectionDone(Exception):
    pass


class ConnectionLost(Exception):
    pass


class Protocol:
    connectionDone = ConnectionDone()

    def connectionMade(self) -> None:
        pass

    def connectionLost(self, reason: BaseException = connectionDone) -> None:
        pass

    def dataReceived(self, data: bytes) -> None:
        pass


class Failure(Exception):
    def __init__(self, value: BaseException) -> None:
        try:
            message = str(value)
        except Exception:
            message = repr(value)
        super().__init__(message)
        self.value = value

    def trap(self, *expected: type[BaseException]) -> type[BaseException]:
        if isinstance(self.value, expected):
            return type(self.value)
        raise self.value

    def check(self, *expected: type[BaseException]) -> type[BaseException] | None:
        for item in expected:
            if isinstance(self.value, item):
                return item
        return None

    def getErrorMessage(self) -> str:
        return str(self.value)

    def raiseException(self) -> NoReturn:
        raise self.value


def unwrap_failure(reason: BaseException) -> BaseException:
    """Return the exception ``reason`` describes.

    Connection-lost reasons reach us either as a bare exception or wrapped in
    a `Failure`; callers that want to raise the reason need the former.
    """
    if isinstance(reason, Failure):
        return reason.value
    return reason
