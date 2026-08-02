"""Find an available uidNumber/gidNumber/other similar number."""

from anyldap.protocols import pureldap


class freeNumberGuesser:
    def __init__(self, makeAGuess, min=None, max=None):
        self.makeAGuess = makeAGuess
        self.min = min
        if self.min is None:
            self.min = 0
        self.max = max

    async def startGuessing(self):
        guess = self.min
        while True:
            found = await self.makeAGuess(guess)
            if found:
                self.min = guess
            else:
                self.max = guess

            if self.max == self.min or self.max == self.min + 1:
                return self.max

            max = self.max
            if max is None:
                max = self.min + 1000

            guess = (max + self.min) // 2


class ldapGuesser:
    def __init__(self, ldapObject, numberType):
        self.numberType = numberType
        self.ldapObject = ldapObject

    async def guess(self, num):
        results = await self.ldapObject.search(
            filterObject=pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription(value=self.numberType),
                assertionValue=pureldap.LDAPAssertionValue(value=str(num)),
            ),
            sizeLimit=1,
        )
        return len(results)


async def getFreeNumber(ldapObject, numberType, min=None, max=None):
    g = freeNumberGuesser(ldapGuesser(ldapObject, numberType).guess, min=min, max=max)
    return await g.startGuessing()
