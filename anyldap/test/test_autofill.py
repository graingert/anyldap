"""
Test cases for anyldap.protocols.ldap.autofill module.
"""

from collections.abc import Sequence

import pytest

from anyldap import interfaces
from anyldap.protocols.ldap import ldapsyntax
from anyldap.testutil import LDAPClientTestDriver

pytestmark = pytest.mark.anyio


class Autofill_sum:  # TODO baseclass
    def __init__(self, resultAttr: str, sumAttrs: Sequence[str]) -> None:
        self.resultAttr = resultAttr
        self.sumAttrs = sumAttrs

    def start(self, ldapObject: object) -> None:
        pass

    def notify(self, ldapObject: object, attributeType: str | bytes) -> None:
        assert interfaces.IEditableLDAPEntry.providedBy(ldapObject)
        if attributeType not in self.sumAttrs:
            return

        total = 0
        for sumAttr in self.sumAttrs:
            if sumAttr not in ldapObject:
                continue
            for val in ldapObject[sumAttr]:
                total += int(val)
        ldapObject[self.resultAttr] = [str(total)]


class TestLDAPAutoFill_Simple:
    async def testSimpleSum(self) -> None:
        """A simple autofiller that calculates sums of attributes should work.."""
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["some", "other"],
            },
        )


        await o.addAutofiller(Autofill_sum(resultAttr="sum", sumAttrs=["a", "b"]))
        client.assertNothingSent()

        o["a"] = ["1"]
        o["b"] = ["2", "3"]

        assert "sum" in o
        assert o["sum"] == ["6"]
