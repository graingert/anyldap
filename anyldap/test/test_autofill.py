"""
Test cases for anyldap.protocols.ldap.autofill module.
"""

import pytest

from anyldap.protocols.ldap import ldapsyntax
from anyldap.testutil import LDAPClientTestDriver

pytestmark = pytest.mark.anyio


class Autofill_sum:  # TODO baseclass
    def __init__(self, resultAttr, sumAttrs):
        self.resultAttr = resultAttr
        self.sumAttrs = sumAttrs

    def start(self, ldapObject):
        pass

    def notify(self, ldapObject, attributeType):
        if attributeType not in self.sumAttrs:
            return

        sum = 0
        for sumAttr in self.sumAttrs:
            if sumAttr not in ldapObject:
                continue
            for val in ldapObject[sumAttr]:
                val = int(val)
                sum += val
        sum = str(sum)
        ldapObject[self.resultAttr] = [sum]


class TestLDAPAutoFill_Simple:
    async def testSimpleSum(self):
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
