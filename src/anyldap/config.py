import configparser
import os.path
from collections.abc import Iterable

from anyldap import interfaces
from anyldap.protocols.ldap import distinguishedname


class MissingBaseDNError(Exception):
    """Configuration must specify a base DN"""

    def __str__(self) -> str:
        assert self.__doc__ is not None
        return self.__doc__


class LDAPConfig(interfaces.ILDAPConfig):

    baseDN: distinguishedname.DistinguishedName | None = None
    identityBaseDN: distinguishedname.DistinguishedName | None = None
    identitySearch: str | None = None

    def __init__(
        self,
        baseDN: interfaces.AnyDN | None = None,
        serviceLocationOverrides: interfaces.ServiceLocationOverrides | None = None,
        identityBaseDN: interfaces.AnyDN | None = None,
        identitySearch: str | None = None,
    ) -> None:
        if baseDN is not None:
            baseDN = distinguishedname.DistinguishedName(baseDN)
            self.baseDN = baseDN
        self.serviceLocationOverrides: dict[distinguishedname.DistinguishedName, interfaces.ServiceLocation] = {}
        if serviceLocationOverrides is not None:
            for k, v in serviceLocationOverrides.items():
                dn = distinguishedname.DistinguishedName(k)
                self.serviceLocationOverrides[dn] = v
        if identityBaseDN is not None:
            identityBaseDN = distinguishedname.DistinguishedName(identityBaseDN)
            self.identityBaseDN = identityBaseDN
        if identitySearch is not None:
            self.identitySearch = identitySearch

    def getBaseDN(self) -> distinguishedname.DistinguishedName | str:
        if self.baseDN is not None:
            return self.baseDN

        cfg = loadConfig()
        try:
            return cfg.get("ldap", "base")
        except (configparser.NoOptionError, configparser.NoSectionError):
            raise MissingBaseDNError()

    def getServiceLocationOverrides(self) -> dict[distinguishedname.DistinguishedName, interfaces.ServiceLocation]:
        r = self._loadServiceLocationOverrides()
        r.update(self.serviceLocationOverrides)
        return r

    def _loadServiceLocationOverrides(self) -> dict[distinguishedname.DistinguishedName, interfaces.ServiceLocation]:
        serviceLocationOverride: dict[distinguishedname.DistinguishedName, interfaces.ServiceLocation] = {}
        cfg = loadConfig()
        for section in cfg.sections():
            if section.lower().startswith("service-location "):
                base = section[len("service-location ") :].strip()

                host: str | None = None
                if cfg.has_option(section, "host"):
                    host = cfg.get(section, "host")
                    if not host:
                        host = None

                port: str | None = None
                if cfg.has_option(section, "port"):
                    port = cfg.get(section, "port")
                    if not port:
                        port = None

                dn = distinguishedname.DistinguishedName(stringValue=base)
                serviceLocationOverride[dn] = (host, port)
        return serviceLocationOverride

    def copy(
        self,
        baseDN: interfaces.AnyDN | None = None,
        serviceLocationOverrides: interfaces.ServiceLocationOverrides | None = None,
        identityBaseDN: interfaces.AnyDN | None = None,
        identitySearch: str | None = None,
    ) -> "LDAPConfig":
        return self.__class__(
            baseDN=self.baseDN if baseDN is None else baseDN,
            serviceLocationOverrides=(
                self.serviceLocationOverrides
                if serviceLocationOverrides is None
                else serviceLocationOverrides
            ),
            identityBaseDN=(
                self.identityBaseDN if identityBaseDN is None else identityBaseDN
            ),
            identitySearch=(
                self.identitySearch if identitySearch is None else identitySearch
            ),
        )

    def getIdentityBaseDN(self) -> distinguishedname.DistinguishedName | str:
        if self.identityBaseDN is not None:
            return self.identityBaseDN

        cfg = loadConfig()
        try:
            return cfg.get("authentication", "identity-base")
        except (configparser.NoOptionError, configparser.NoSectionError):
            return self.getBaseDN()

    def getIdentitySearch(self, name: str) -> str:
        data = {
            "name": name,
        }

        if self.identitySearch is not None:
            f = self.identitySearch % data
        else:
            cfg = loadConfig()
            try:
                f = cfg.get("authentication", "identity-search", vars=data)
            except (configparser.NoOptionError, configparser.NoSectionError):
                f = "(|(cn=%(name)s)(uid=%(name)s))" % data
        return f


DEFAULTS = {
    "samba": {"use-lmhash": "no"},
}

CONFIG_FILES = [
    "/etc/anyldap/global.cfg",
    os.path.expanduser("~/.anyldap/global.cfg"),
]

__config: configparser.ConfigParser | None = None


def loadConfig(
    configFiles: Iterable[str] | None = None, reload: bool = False
) -> configparser.ConfigParser:
    """
    Load configuration file.
    """
    global __config
    if __config is None or reload:
        x = configparser.ConfigParser()

        for section, options in DEFAULTS.items():
            x.add_section(section)
            for option, value in options.items():
                x.set(section, option, value)

        if configFiles is None:
            configFiles = CONFIG_FILES
        x.read(configFiles)
        __config = x
    return __config


def useLMhash() -> bool:
    """
    Read configuration file if necessary and return whether
    to use LanMan hashes or not.
    """
    cfg = loadConfig()
    return cfg.getboolean("samba", "use-lmhash")
