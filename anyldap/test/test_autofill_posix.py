"""
Test cases for anyldap.protocols.ldap.autofill.posixAccount module.
"""

import outcome
import pytest

from anyldap.protocols import pureldap
from anyldap.protocols.ldap import autofill, ldapsyntax
from anyldap.protocols.ldap.autofill import posixAccount
from anyldap.testutil import LDAPClientTestDriver

pytestmark = pytest.mark.anyio


async def test_start_reports_the_first_failed_allocation() -> None:
    attempted = []

    async def allocate(baseObject, numberType, min):
        attempted.append(numberType)
        if numberType == "uidNumber":
            raise ValueError("allocation failed")
        return 1000

    autofiller = posixAccount.Autofill_posix(
        "dc=example,dc=com", freeNumberGetter=allocate
    )
    entry = ldapsyntax.LDAPEntryWithAutoFill(
        client=LDAPClientTestDriver(),
        dn="cn=foo,dc=example,dc=com",
        attributes={"objectClass": ["posixAccount"]},
    )

    with pytest.raises(ValueError, match="allocation failed"):
        await autofiller.start(entry)
    # The gid allocation is still attempted, so its outcome is available too.
    assert attempted == ["uidNumber", "gidNumber"]


def test_got_numbers_re_raises_failed_allocations_and_notify_is_noop() -> None:
    autofiller = posixAccount.Autofill_posix("dc=example,dc=com")
    entry = {}
    # An Outcome may only be unwrapped once, so each case needs its own.
    def error():
        return outcome.Error(ValueError("allocation failed"))

    with pytest.raises(ValueError, match="allocation failed"):
        autofiller._cb_gotNumbers((error(), outcome.Value(1000)), entry)
    with pytest.raises(ValueError, match="allocation failed"):
        autofiller._cb_gotNumbers((outcome.Value(1000), error()), entry)
    assert autofiller.notify(entry, "uidNumber") is None


class TestLDAPAutoFill_Posix:
    async def testMustHaveObjectClass(self) -> None:
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

        with pytest.raises(autofill.ObjectMissingObjectClassException):
            await o.addAutofiller(autoFiller)
        client.assertNothingSent()

    async def testDefaultSetting(self) -> None:
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

        await o.addAutofiller(posixAccount.Autofill_posix(baseDN="dc=example,dc=com"))

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

        assert "loginShell" in o
        assert o["loginShell"] == ["/bin/sh"]

        assert "uidNumber" in o
        assert o["uidNumber"] == ["1000"]
        assert "gidNumber" in o
        assert o["gidNumber"] == ["1042"]
