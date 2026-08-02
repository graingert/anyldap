"""
Test cases for anyldap.protocols.ldap.autofill.sambaAccount module.
"""
import pytest

from anyldap import testutil
from anyldap.protocols.ldap import ldapsyntax
from anyldap.protocols.ldap.autofill import sambaAccount, sambaSamAccount

pytestmark = pytest.mark.anyio


def test_notify_ignores_unrelated_attributes():
    assert sambaAccount.Autofill_samba().notify({}, "description") is None
    assert (
        sambaSamAccount.Autofill_samba("S-1-5-21").notify({}, "description")
        is None
    )


class TestLDAPAutoFill_sambaAccount:
    async def testMustHaveObjectClass(self):
        """Test that Autofill_samba fails unless object is a sambaAccount."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["something", "other"],
            },
        )
        autoFiller = sambaAccount.Autofill_samba()
        with pytest.raises(sambaAccount.ObjectMissingObjectClassException):
            await o.addAutofiller(autoFiller)
        client.assertNothingSent()

    async def testDefaultSetting(self):
        """Test that fields get their default values."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaAccount", "other"],
            },
        )


        await o.addAutofiller(sambaAccount.Autofill_samba())
        client.assertNothingSent()

        assert "acctFlags" in o
        assert o["acctFlags"] == ["[UX         ]"]

        assert "pwdLastSet" in o
        assert o["pwdLastSet"] == ["0"]
        assert "logonTime" in o
        assert o["logonTime"] == ["0"]
        assert "logoffTime" in o
        assert o["logoffTime"] == ["0"]
        assert "pwdCanChange" in o
        assert o["pwdCanChange"] == ["0"]
        assert "pwdMustChange" in o
        assert o["pwdMustChange"] == ["0"]

    async def testRid(self):
        """Test that rid field is updated based on uidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaAccount", "other"],
            },
        )


        await o.addAutofiller(sambaAccount.Autofill_samba())
        client.assertNothingSent()

        o["uidNumber"] = ["1000"]
        assert "rid" in o
        assert o["rid"] == [str(2 * 1000 + 1000)]
        o["uidNumber"] = ["1001"]
        assert o["rid"] == [str(2 * 1001 + 1000)]
        o["uidNumber"] = ["1002"]
        assert o["rid"] == [str(2 * 1002 + 1000)]
        o["uidNumber"] = ["2000"]
        assert o["rid"] == [str(2 * 2000 + 1000)]
        o["uidNumber"] = ["3000"]
        assert o["rid"] == [str(2 * 3000 + 1000)]
        o["uidNumber"] = ["0"]
        assert o["rid"] == [str(2 * 0 + 1000)]
        o["uidNumber"] = ["16000"]
        assert o["rid"] == [str(2 * 16000 + 1000)]

    async def testPrimaryGroupId(self):
        """Test that primaryGroupID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaAccount", "other"],
            },
        )


        await o.addAutofiller(sambaAccount.Autofill_samba())
        client.assertNothingSent()

        o["gidNumber"] = ["1000"]
        assert "primaryGroupID" in o
        assert o["primaryGroupID"] == [str(2 * 1000 + 1001)]
        o["gidNumber"] = ["1001"]
        assert o["primaryGroupID"] == [str(2 * 1001 + 1001)]
        o["gidNumber"] = ["1002"]
        assert o["primaryGroupID"] == [str(2 * 1002 + 1001)]
        o["gidNumber"] = ["2000"]
        assert o["primaryGroupID"] == [str(2 * 2000 + 1001)]
        o["gidNumber"] = ["3000"]
        assert o["primaryGroupID"] == [str(2 * 3000 + 1001)]
        o["gidNumber"] = ["0"]
        assert o["primaryGroupID"] == [str(2 * 0 + 1001)]
        o["gidNumber"] = ["16000"]
        assert o["primaryGroupID"] == [str(2 * 16000 + 1001)]


class TestLDAPAutoFill_sambaSamAccount:
    async def testMustHaveObjectClass(self):
        """Test that Autofill_samba fails unless object is a sambaSamAccount."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["something", "other"],
            },
        )
        autoFiller = sambaSamAccount.Autofill_samba(domainSID="foo")
        with pytest.raises(sambaSamAccount.ObjectMissingObjectClassException):
            await o.addAutofiller(autoFiller)
        client.assertNothingSent()

    async def testDefaultSetting(self):
        """Test that fields get their default values."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )


        await o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))
        client.assertNothingSent()

        assert set(o.keys()) == ({
                "objectClass",
                "sambaAcctFlags",
                "sambaLogoffTime",
                "sambaLogonTime",
                "sambaPwdCanChange",
                "sambaPwdLastSet",
                "sambaPwdMustChange",
            })

        assert o["sambaAcctFlags"] == ["[UX         ]"]
        assert o["sambaPwdLastSet"] == ["1"]
        assert o["sambaLogonTime"] == ["0"]
        assert o["sambaLogoffTime"] == ["0"]
        assert o["sambaPwdCanChange"] == ["0"]
        assert o["sambaPwdMustChange"] == ["0"]

    async def testDefaultSetting_fixedPrimaryGroupSID(self):
        """Test that fields get their default values."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )


        await o.addAutofiller(
            sambaSamAccount.Autofill_samba(
                domainSID="foo", fixedPrimaryGroupSID=4131312
            )
        )
        client.assertNothingSent()

        assert set(o.keys()) == ({
                "objectClass",
                "sambaAcctFlags",
                "sambaLogoffTime",
                "sambaLogonTime",
                "sambaPwdCanChange",
                "sambaPwdLastSet",
                "sambaPwdMustChange",
                "sambaPrimaryGroupSID",
            })

        assert o["sambaPrimaryGroupSID"] == ["foo-4131312"]
        assert o["sambaAcctFlags"] == ["[UX         ]"]
        assert o["sambaPwdLastSet"] == ["1"]
        assert o["sambaLogonTime"] == ["0"]
        assert o["sambaLogoffTime"] == ["0"]
        assert o["sambaPwdCanChange"] == ["0"]
        assert o["sambaPwdMustChange"] == ["0"]

    async def testSambaSID(self):
        """Test that sambaSID field is updated based on uidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )


        await o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))
        client.assertNothingSent()

        o["uidNumber"] = ["1000"]
        assert "sambaSID" in o
        assert o["sambaSID"] == ["foo-%s" % (2 * 1000 + 1000)]
        o["uidNumber"] = ["1001"]
        assert o["sambaSID"] == ["foo-%s" % (2 * 1001 + 1000)]
        o["uidNumber"] = ["1002"]
        assert o["sambaSID"] == ["foo-%s" % (2 * 1002 + 1000)]
        o["uidNumber"] = ["2000"]
        assert o["sambaSID"] == ["foo-%s" % (2 * 2000 + 1000)]
        o["uidNumber"] = ["3000"]
        assert o["sambaSID"] == ["foo-%s" % (2 * 3000 + 1000)]
        o["uidNumber"] = ["0"]
        assert o["sambaSID"] == ["foo-%s" % (2 * 0 + 1000)]
        o["uidNumber"] = ["16000"]
        assert o["sambaSID"] == ["foo-%s" % (2 * 16000 + 1000)]

    async def testSambaSID_preExisting(self):
        """Test that sambaSID field is updated based on uidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
                "uidNumber": ["1000"],
            },
        )


        await o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))
        client.assertNothingSent()

        assert "sambaSID" in o
        assert o["sambaSID"] == ["foo-%s" % (2 * 1000 + 1000)]

    async def testSambaPrimaryGroupSID(self):
        """Test that sambaPrimaryGroupSID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )


        await o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))
        client.assertNothingSent()

        o["gidNumber"] = ["1000"]
        assert "sambaPrimaryGroupSID" in o
        assert o["sambaPrimaryGroupSID"] == ["foo-%s" % (2 * 1000 + 1001)]
        o["gidNumber"] = ["1001"]
        assert o["sambaPrimaryGroupSID"] == ["foo-%s" % (2 * 1001 + 1001)]
        o["gidNumber"] = ["1002"]
        assert o["sambaPrimaryGroupSID"] == ["foo-%s" % (2 * 1002 + 1001)]
        o["gidNumber"] = ["2000"]
        assert o["sambaPrimaryGroupSID"] == ["foo-%s" % (2 * 2000 + 1001)]
        o["gidNumber"] = ["3000"]
        assert o["sambaPrimaryGroupSID"] == ["foo-%s" % (2 * 3000 + 1001)]
        o["gidNumber"] = ["0"]
        assert o["sambaPrimaryGroupSID"] == ["foo-%s" % (2 * 0 + 1001)]
        o["gidNumber"] = ["16000"]
        assert o["sambaPrimaryGroupSID"] == ["foo-%s" % (2 * 16000 + 1001)]

    async def testSambaPrimaryGroupSID_preExisting(self):
        """Test that sambaPrimaryGroupSID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
                "gidNumber": ["1000"],
            },
        )


        await o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))
        client.assertNothingSent()

        assert "sambaPrimaryGroupSID" in o
        assert o["sambaPrimaryGroupSID"] == ["foo-%s" % (2 * 1000 + 1001)]

    async def testSambaPrimaryGroupSID_notUpdatedWhenFixed(self):
        """Test that sambaPrimaryGroupSID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )


        await o.addAutofiller(
            sambaSamAccount.Autofill_samba(domainSID="foo", fixedPrimaryGroupSID=4242)
        )
        client.assertNothingSent()

        assert "sambaPrimaryGroupSID" in o
        assert o["sambaPrimaryGroupSID"] == ["foo-4242"]
        o["gidNumber"] = ["1000"]
        assert "sambaPrimaryGroupSID" in o
        assert o["sambaPrimaryGroupSID"] == ["foo-4242"]
