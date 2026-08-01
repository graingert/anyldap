"""
Test cases for anyldap.protocols.ldap.autofill module.
"""

from anyldap.protocols.ldap import ldapsyntax
from anyldap.test import unittest
from anyldap.testutil import LDAPClientTestDriver


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


class LDAPAutoFill_Simple(unittest.TestCase):
    def testSimpleSum(self):
        """A simple autofiller that calculates sums of attributes should work.."""
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["some", "other"],
            },
        )
        d = o.addAutofiller(Autofill_sum(resultAttr="sum", sumAttrs=["a", "b"]))

        def cb(dummy):
            client.assertNothingSent()

            o["a"] = ["1"]
            o["b"] = ["2", "3"]

            self.assertTrue("sum" in o)
            self.assertEqual(o["sum"], ["6"])

        d.addCallback(cb)
        return d
