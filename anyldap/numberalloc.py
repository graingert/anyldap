"""Find an available uidNumber/gidNumber/other similar number."""

from collections.abc import Awaitable, Callable

from anyldap import interfaces
from anyldap.protocols import pureldap


class freeNumberGuesser:
    def __init__(
        self,
        makeAGuess: Callable[[int], Awaitable[int]],
        min: int | None = None,
        max: int | None = None,
    ) -> None:
        self.makeAGuess = makeAGuess
        self.min = 0 if min is None else min
        self.max = max

    async def startGuessing(self) -> int:
        guess = self.min
        while True:
            found = await self.makeAGuess(guess)
            if found:
                self.min = guess
            else:
                self.max = guess

            if self.max == self.min or self.max == self.min + 1:
                # Only ever reached once a guess has narrowed the top end.
                assert self.max is not None
                return self.max

            max = self.max
            if max is None:
                max = self.min + 1000

            guess = (max + self.min) // 2


class ldapGuesser:
    def __init__(
        self, ldapObject: interfaces.IConnectedLDAPEntry, numberType: str
    ) -> None:
        self.numberType = numberType
        self.ldapObject = ldapObject

    async def guess(self, num: int) -> int:
        results = await self.ldapObject.search(
            filterObject=pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription(value=self.numberType),
                assertionValue=pureldap.LDAPAssertionValue(value=str(num)),
            ),
            sizeLimit=1,
        )
        assert results is not None
        return len(results)


async def getFreeNumber(
    ldapObject: interfaces.IConnectedLDAPEntry,
    numberType: str,
    min: int | None = None,
    max: int | None = None,
) -> int:
    g = freeNumberGuesser(ldapGuesser(ldapObject, numberType).guess, min=min, max=max)
    return await g.startGuessing()
