"""
Test cases for the anyldap.config module.
"""

import os

import pytest

from anyldap import config


def writeFile(path, content):
    f = open(path, "wb")
    f.write(content)
    f.close()


def reloadFromContent(base_path, content):
    """
    Reload the global configuration file with raw `content`.

    Callers get the defaults back via the autouse `_reset_config` fixture.
    """
    config_path = os.path.join(base_path, "test.cfg")
    writeFile(config_path, content)

    return config.loadConfig(
        configFiles=[config_path],
        reload=True,
    )


@pytest.fixture(autouse=True)
def _reset_config():
    yield
    config.loadConfig(configFiles=[], reload=True)


class TestLoadConfig:
    """
    Tests for loadConfig.
    """

    def testMultileConfigurationFile(self, tmp_path):
        """
        It can read configuration from multiple files, merging the
        loaded values.
        """
        self.dir = tmp_path
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
        assert val == "val2"

        val = self.cfg.get("barSection", "barVar")
        assert val == "anotherVal"


class TestLDAPConfig:
    """
    Unit tests for LDAPConfig.
    """

    def testGetBaseDNOK(self, tmp_path):
        """
        It will return the base DN found in the configuration in the [ldap]
        section as `base` option.
        """
        reloadFromContent(
            tmp_path, b"[ldap]\nbase=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        result = sut.getBaseDN()

        assert "dc=test,dc=net" == result

    def testGetBaseDNNoSection(self, tmp_path):
        """
        It raise an exception when the the configuration has no [ldap]
        section.
        """
        reloadFromContent(
            tmp_path, b"[other]\nbase=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        with pytest.raises(config.MissingBaseDNError):
            sut.getBaseDN()

    def testGetBaseDNNoOption(self, tmp_path):
        """
        It raise an exception when the the configuration has [ldap]
        section but no `base` option.
        """
        reloadFromContent(
            tmp_path, b"[ldap]\nbaseless=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        with pytest.raises(config.MissingBaseDNError):
            sut.getBaseDN()

    def testGetIdentityBaseDNOK(self, tmp_path):
        """
        It will return the value found in the configuration in the
        [authentication] section as `identity-base` option.
        """
        reloadFromContent(
            tmp_path, b"[authentication]\n" b"identity-base=ou=users,dc=test,dc=net\n"
        )
        sut = config.LDAPConfig()

        result = sut.getIdentityBaseDN()

        assert "ou=users,dc=test,dc=net" == result

    def testGetIdentityBaseSectionSection(self, tmp_path):
        """
        When the configuration does not contains the
        `[authentication]` section it will return the configured Base DN.
        """
        reloadFromContent(
            tmp_path, b"[ldap]\n" b"basE=dc=test,dc=net\n")
        sut = config.LDAPConfig()

        result = sut.getIdentityBaseDN()

        assert "dc=test,dc=net" == result

    def testGetIdentityBaseNoOption(self, tmp_path):
        """
        When the configuration does not contains the `identity-base` option
        inside the `[authentication]` section it will return the configured
        Base DN.
        """
        reloadFromContent(
            tmp_path,
            b"[ldap]\n"
            b"BASE=dc=test,dc=net\n"
            b"[authentication]\n"
            b"no-identity-base=dont care\n",
        )
        sut = config.LDAPConfig()

        result = sut.getIdentityBaseDN()

        assert "dc=test,dc=net" == result

    def testGetIdentitySearchOK(self, tmp_path):
        """
        It will use the value from to configuration for its return value.
        """
        reloadFromContent(
            tmp_path,
            b"""[authentication]
identity-search = (something=%(name)s)
""",
        )
        sut = config.LDAPConfig()

        result = sut.getIdentitySearch("foo")

        assert "(something=foo)" == result

    def testGetIdentitySearchNoSection(self):
        """
        When the configuration file does not contains the `authentication`
        section it will use a default expression.
        """
        sut = config.LDAPConfig()

        result = sut.getIdentitySearch("foo")

        assert "(|(cn=foo)(uid=foo))" == result

    def testGetIdentitySearchNoOption(self, tmp_path):
        """
        When the configuration file contains the `authentication`
        section but without the identity search option,
        it will use a default expression.
        """
        reloadFromContent(
            tmp_path, b"[authentication]\nother_key=value")
        sut = config.LDAPConfig()

        result = sut.getIdentitySearch("foo")

        assert "(|(cn=foo)(uid=foo))" == result

    def testgetIdentitySearchFromInitArguments(self):
        """
        When data is provided at LDAPConfig initialization it is used
        as the backend data.
        """
        sut = config.LDAPConfig(identitySearch="(&(bar=thud)(quux=%(name)s))")

        result = sut.getIdentitySearch("foo")

        assert "(&(bar=thud)(quux=foo))" == result

    def testCopy(self):
        """
        It returns a copy of the configuration.
        """
        sut = config.LDAPConfig()

        copied = sut.copy(identitySearch="(&(bar=baz)(quux=%(name)s))")

        assert isinstance(copied, config.LDAPConfig)

        result = copied.getIdentitySearch("foo")

        assert "(&(bar=baz)(quux=foo))" == result

    def testExplicitConfigurationValues(self):
        sut = config.LDAPConfig(
            baseDN="dc=example,dc=com",
            identityBaseDN="ou=people,dc=example,dc=com",
            identitySearch="(mail=%(name)s)",
            serviceLocationOverrides={"dc=example,dc=com": ("explicit", 1389)},
        )
        assert "dc=example,dc=com" == sut.getBaseDN().getText()
        assert "ou=people,dc=example,dc=com" == sut.getIdentityBaseDN().getText()
        assert "(mail=alice)" == sut.getIdentitySearch("alice")
        overrides = sut.getServiceLocationOverrides()
        assert ("explicit", 1389) == next(iter(overrides.values()))

    def testServiceLocationConfiguration(self, tmp_path):
        reloadFromContent(
            tmp_path,
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
        assert values["dc=one,dc=example"] == ("ldap-one.example", "1389")
        assert values["dc=two,dc=example"] == (None, None)

    def testServiceLocationConfigurationWithoutHostOrPort(self, tmp_path):
        reloadFromContent(
            tmp_path, b"[service-location dc=example]\n")
        overrides = config.LDAPConfig().getServiceLocationOverrides()
        assert next(iter(overrides.values())) == (None, None)

    def testCopyPreservesAllDefaults(self):
        original = config.LDAPConfig(
            baseDN="dc=example",
            identityBaseDN="ou=people,dc=example",
            identitySearch="(uid=%(name)s)",
            serviceLocationOverrides={"dc=example": ("host", 389)},
        )
        copied = original.copy()
        assert copied.baseDN == original.baseDN
        assert copied.identityBaseDN == original.identityBaseDN
        assert copied.identitySearch == original.identitySearch
        assert copied.serviceLocationOverrides == original.serviceLocationOverrides

    def testCopyAcceptsAllExplicitValues(self):
        values = {
            "baseDN": "dc=new",
            "identityBaseDN": "ou=people,dc=new",
            "identitySearch": "(mail=%(name)s)",
            "serviceLocationOverrides": {"dc=new": ("new.example", 1389)},
        }
        copied = config.LDAPConfig().copy(**values)
        for name, value in values.items():
            assert getattr(copied, name) == value

    def testUseLMHash(self, tmp_path):
        reloadFromContent(
            tmp_path, b"[samba]\nuse-lmhash=yes\n")
        assert config.useLMhash()
