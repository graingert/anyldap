"""
Test cases for the anyldap.config module.
"""

import os

from anyldap import config
from anyldap.test import unittest


def writeFile(path, content):
    f = open(path, "wb")
    f.write(content)
    f.close()


def reloadFromContent(testCase, content):
    """
    Reload the global configuration file with raw `content`.
    """
    base_path = testCase.mktemp()
    os.mkdir(base_path)
    config_path = os.path.join(base_path, "test.cfg")
    writeFile(config_path, content)

    # Reset to defaults after the test without recursively adding cleanups.
    testCase.addCleanup(config.loadConfig, configFiles=[], reload=True)

    return config.loadConfig(
        configFiles=[config_path],
        reload=True,
    )


class TestLoadConfig(unittest.TestCase):
    """
    Tests for loadConfig.
    """

    def testMultileConfigurationFile(self):
        """
        It can read configuration from multiple files, merging the
        loaded values.
        """
        self.dir = self.mktemp()
        os.mkdir(self.dir)
        self.f1 = os.path.join(self.dir, "one.cfg")
        writeFile(
            self.f1,
            b"""\
[fooSection]
fooVar = val

[barSection]
barVar = anotherVal
""",
        )
        self.f2 = os.path.join(self.dir, "two.cfg")
        writeFile(
            self.f2,
            b"""\
[fooSection]
fooVar = val2
""",
        )
        self.cfg = config.loadConfig(configFiles=[self.f1, self.f2], reload=True)

        val = self.cfg.get("fooSection", "fooVar")
        self.assertEqual(val, "val2")

        val = self.cfg.get("barSection", "barVar")
        self.assertEqual(val, "anotherVal")


class TestLDAPConfig(unittest.TestCase):
    """
    Unit tests for LDAPConfig.
    """

    def testGetBaseDNOK(self):
        """
        It will return the base DN found in the configuration in the [ldap]
        section as `base` option.
        """
        reloadFromContent(self, b"[ldap]\nbase=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        result = sut.getBaseDN()

        self.assertEqual("dc=test,dc=net", result)

    def testGetBaseDNNoSection(self):
        """
        It raise an exception when the the configuration has no [ldap]
        section.
        """
        reloadFromContent(self, b"[other]\nbase=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        self.assertRaises(
            config.MissingBaseDNError,
            sut.getBaseDN,
        )

    def testGetBaseDNNoOption(self):
        """
        It raise an exception when the the configuration has [ldap]
        section but no `base` option.
        """
        reloadFromContent(self, b"[ldap]\nbaseless=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        self.assertRaises(
            config.MissingBaseDNError,
            sut.getBaseDN,
        )

    def testGetIdentityBaseDNOK(self):
        """
        It will return the value found in the configuration in the
        [authentication] section as `identity-base` option.
        """
        reloadFromContent(
            self, b"[authentication]\n" b"identity-base=ou=users,dc=test,dc=net\n"
        )
        sut = config.LDAPConfig()

        result = sut.getIdentityBaseDN()

        self.assertEqual("ou=users,dc=test,dc=net", result)

    def testGetIdentityBaseSectionSection(self):
        """
        When the configuration does not contains the
        `[authentication]` section it will return the configured Base DN.
        """
        reloadFromContent(self, b"[ldap]\n" b"basE=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        result = sut.getIdentityBaseDN()

        self.assertEqual("dc=test,dc=net", result)

    def testGetIdentityBaseNoOption(self):
        """
        When the configuration does not contains the `identity-base` option
        inside the `[authentication]` section it will return the configured
        Base DN.
        """
        reloadFromContent(
            self,
            b"[ldap]\n"
            b"BASE=dc=test,dc=net\n"
            b"[authentication]\n"
            b"no-identity-base=dont care\n",
        )
        sut = config.LDAPConfig()

        result = sut.getIdentityBaseDN()

        self.assertEqual("dc=test,dc=net", result)

    def testGetIdentitySearchOK(self):
        """
        It will use the value from to configuration for its return value.
        """
        reloadFromContent(
            self,
            b"""[authentication]
identity-search = (something=%(name)s)
""",
        )
        sut = config.LDAPConfig()

        result = sut.getIdentitySearch("foo")

        self.assertEqual("(something=foo)", result)

    def testGetIdentitySearchNoSection(self):
        """
        When the configuration file does not contains the `authentication`
        section it will use a default expression.
        """
        sut = config.LDAPConfig()

        result = sut.getIdentitySearch("foo")

        self.assertEqual("(|(cn=foo)(uid=foo))", result)

    def testGetIdentitySearchNoOption(self):
        """
        When the configuration file contains the `authentication`
        section but without the identity search option,
        it will use a default expression.
        """
        reloadFromContent(self, b"[authentication]\nother_key=value")
        sut = config.LDAPConfig()

        result = sut.getIdentitySearch("foo")

        self.assertEqual("(|(cn=foo)(uid=foo))", result)

    def testgetIdentitySearchFromInitArguments(self):
        """
        When data is provided at LDAPConfig initialization it is used
        as the backend data.
        """
        sut = config.LDAPConfig(identitySearch="(&(bar=thud)(quux=%(name)s))")

        result = sut.getIdentitySearch("foo")

        self.assertEqual("(&(bar=thud)(quux=foo))", result)

    def testCopy(self):
        """
        It returns a copy of the configuration.
        """
        sut = config.LDAPConfig()

        copied = sut.copy(identitySearch="(&(bar=baz)(quux=%(name)s))")

        self.assertIsInstance(copied, config.LDAPConfig)

        result = copied.getIdentitySearch("foo")

        self.assertEqual("(&(bar=baz)(quux=foo))", result)

    def testExplicitConfigurationValues(self):
        sut = config.LDAPConfig(
            baseDN="dc=example,dc=com",
            identityBaseDN="ou=people,dc=example,dc=com",
            identitySearch="(mail=%(name)s)",
            serviceLocationOverrides={"dc=example,dc=com": ("explicit", 1389)},
        )
        self.assertEqual("dc=example,dc=com", sut.getBaseDN().getText())
        self.assertEqual(
            "ou=people,dc=example,dc=com", sut.getIdentityBaseDN().getText()
        )
        self.assertEqual("(mail=alice)", sut.getIdentitySearch("alice"))
        overrides = sut.getServiceLocationOverrides()
        self.assertEqual(("explicit", 1389), next(iter(overrides.values())))

    def testServiceLocationConfiguration(self):
        reloadFromContent(
            self,
            b"""[service-location dc=one,dc=example]
host=ldap-one.example
port=1389
[SERVICE-LOCATION dc=two,dc=example]
host=
port=
[unrelated]
host=ignored
""",
        )
        overrides = config.LDAPConfig().getServiceLocationOverrides()
        values = {dn.getText(): value for dn, value in overrides.items()}
        self.assertEqual(values["dc=one,dc=example"], ("ldap-one.example", "1389"))
        self.assertEqual(values["dc=two,dc=example"], (None, None))

    def testCopyPreservesAllDefaults(self):
        original = config.LDAPConfig(
            baseDN="dc=example",
            identityBaseDN="ou=people,dc=example",
            identitySearch="(uid=%(name)s)",
            serviceLocationOverrides={"dc=example": ("host", 389)},
        )
        copied = original.copy()
        self.assertEqual(copied.baseDN, original.baseDN)
        self.assertEqual(copied.identityBaseDN, original.identityBaseDN)
        self.assertEqual(copied.identitySearch, original.identitySearch)
        self.assertEqual(copied.serviceLocationOverrides, original.serviceLocationOverrides)

    def testUseLMHash(self):
        reloadFromContent(self, b"[samba]\nuse-lmhash=yes\n")
        self.assertTrue(config.useLMhash())
