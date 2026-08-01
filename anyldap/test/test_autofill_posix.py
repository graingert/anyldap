"""
Test cases for anyldap.protocols.ldap.autofill.posixAccount module.
"""

import pytest

from anyldap.deferred import fail, succeed
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import autofill, ldapsyntax
from anyldap.protocols.ldap.autofill import posixAccount
from anyldap.runtime import Failure
from anyldap.test import unittest
from anyldap.testutil import LDAPClientTestDriver


@pytest.mark.anyio
async def test_gather_numbers_propagates_failure():
    autofiller = posixAccount.Autofill_posix("dc=example,dc=com")
    deferred = autofiller._gather_numbers(
        fail(Failure(ValueError("allocation failed"))), succeed(1000)
    )
    with pytest.raises(ValueError, match="allocation failed"):
        await deferred


def test_got_numbers_re_raises_failed_allocations_and_notify_is_noop():
    autofiller = posixAccount.Autofill_posix("dc=example,dc=com")
    entry = {}
    failure = Failure(ValueError("allocation failed"))
    with pytest.raises(ValueError, match="allocation failed"):
        autofiller._cb_gotNumbers(((False, failure), (True, 1000)), entry)
    with pytest.raises(ValueError, match="allocation failed"):
        autofiller._cb_gotNumbers(((True, 1000), (False, failure)), entry)
    assert autofiller.notify(entry, "uidNumber") is None


class LDAPAutoFill_Posix(unittest.TestCase):
    def testMustHaveObjectClass(self):
        """Test that Autofill_posix fails unless object is a posixAccount."""
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["something", "other"],
            },
        )
        autoFiller = posixAccount.Autofill_posix(baseDN="dc=example,dc=com")

        d = o.addAutofiller(autoFiller)

        failure = self.failureResultOf(d)
        self.assertIsInstance(failure.value, autofill.ObjectMissingObjectClassException)
        client.assertNothingSent()

    def testDefaultSetting(self):
        """Test that fields get their default values."""

        client = LDAPClientTestDriver(
            # uid==1000 -> free
            [
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1000 -> taken
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="",
                    attributes=[("objectClass", ("foo", "posixAccount", "bar"))],
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1500 -> free
            [
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1250 -> free
            [
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1125 -> free
            [
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1062 -> free
            [
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1031 -> free
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="",
                    attributes=[("objectClass", ("foo", "posixAccount", "bar"))],
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1046 -> free
            [
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1038 -> taken
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="",
                    attributes=[("objectClass", ("foo", "posixAccount", "bar"))],
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1042 -> free
            [
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1040 -> taken
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="",
                    attributes=[("objectClass", ("foo", "posixAccount", "bar"))],
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            # gid==1041 -> taken
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="",
                    attributes=[("objectClass", ("foo", "posixAccount", "bar"))],
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
        )

        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["posixAccount", "other"],
            },
        )

        d = o.addAutofiller(posixAccount.Autofill_posix(baseDN="dc=example,dc=com"))
        d.addCallback(self._cb_testDefaultSetting, client, o)
        return d

    def _cb_testDefaultSetting(self, val, client, o):
        client.assertSent(
            *[
                pureldap.LDAPSearchRequest(
                    baseObject="dc=example,dc=com",
                    scope=2,
                    derefAliases=0,
                    sizeLimit=1,
                    timeLimit=0,
                    typesOnly=0,
                    filter=pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription(
                            value="uidNumber"
                        ),
                        assertionValue=pureldap.LDAPAssertionValue(value="1000"),
                    ),
                    attributes=(),
                ),
            ]
            + [
                pureldap.LDAPSearchRequest(
                    baseObject="dc=example,dc=com",
                    scope=2,
                    derefAliases=0,
                    sizeLimit=1,
                    timeLimit=0,
                    typesOnly=0,
                    filter=pureldap.LDAPFilter_equalityMatch(
                        attributeDesc=pureldap.LDAPAttributeDescription(
                            value="gidNumber"
                        ),
                        assertionValue=pureldap.LDAPAssertionValue(value=str(x)),
                    ),
                    attributes=(),
                )
                for x in (
                    1000,
                    1500,
                    1250,
                    1125,
                    1062,
                    1031,
                    1046,
                    1038,
                    1042,
                    1040,
                    1041,
                )
            ]
        )

        self.assertTrue("loginShell" in o)
        self.assertEqual(o["loginShell"], ["/bin/sh"])

        self.assertTrue("uidNumber" in o)
        self.assertEqual(o["uidNumber"], ["1000"])
        self.assertTrue("gidNumber" in o)
        self.assertEqual(o["gidNumber"], ["1042"])
