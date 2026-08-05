"""``ldapurl``: LDAP URLs, as RFC 4516 writes them.

A URL says where a server is and what to ask it: the host and port, the DN
to start from, the attributes, scope and filter of a search, and any
extensions after that. python-ldap keeps this in a top-level ``ldapurl``
module; the class and its parts are the same here.
"""

from collections.abc import Iterator, Mapping, MutableMapping, Sequence
from urllib.parse import quote, unquote

__all__ = [
    "SEARCH_SCOPE",
    "SEARCH_SCOPE_STR",
    "LDAP_SCOPE_BASE",
    "LDAP_SCOPE_ONELEVEL",
    "LDAP_SCOPE_SUBTREE",
    "LDAP_SCOPE_SUBORDINATES",
    "isLDAPUrl",
    "ldapUrlEscape",
    "LDAPUrlExtension",
    "LDAPUrlExtensions",
    "LDAPUrl",
]

LDAP_SCOPE_BASE = 0
LDAP_SCOPE_ONELEVEL = 1
LDAP_SCOPE_SUBTREE = 2
LDAP_SCOPE_SUBORDINATES = 3

SEARCH_SCOPE_STR: dict[int | None, str] = {
    None: "",
    LDAP_SCOPE_BASE: "base",
    LDAP_SCOPE_ONELEVEL: "one",
    LDAP_SCOPE_SUBTREE: "sub",
    LDAP_SCOPE_SUBORDINATES: "subordinates",
}

SEARCH_SCOPE: dict[str, int | None] = {
    "": None,
    # the search scope strings defined in RFC 4516
    "base": LDAP_SCOPE_BASE,
    "one": LDAP_SCOPE_ONELEVEL,
    "sub": LDAP_SCOPE_SUBTREE,
    # from draft-sermersheim-ldap-subordinate-scope
    "subordinates": LDAP_SCOPE_SUBORDINATES,
}

# The schemes an LDAP URL is written with.
_SCHEMES = ("ldap", "ldaps", "ldapi")


def isLDAPUrl(s: str) -> bool:
    """Whether this text is an LDAP URL, whichever case it is written in."""
    return s.lower().startswith(("ldap://", "ldaps://", "ldapi://"))


def ldapUrlEscape(s: str) -> str:
    """A part of a URL, with the characters a URL would read escaped."""
    return quote(s).replace(",", "%2C").replace("/", "%2F")


class LDAPUrlExtension:
    """One extension of a URL: its type, its value, and whether it is critical.

    An extension is written ``type=value``, with a leading exclamation mark
    when the server must understand it.
    """

    def __init__(
        self,
        extensionStr: str | None = None,
        critical: int = 0,
        extype: str | None = None,
        exvalue: str | None = None,
    ) -> None:
        self.critical = critical
        self.extype = extype
        self.exvalue = exvalue
        if extensionStr is not None:
            self._parse(extensionStr)

    def _parse(self, extension: str) -> None:
        extension = extension.strip()
        if not extension:
            # Don't parse empty strings
            self.extype, self.exvalue = None, None
            return
        self.critical = int(extension[0] == "!")
        if extension[0] == "!":
            extension = extension[1:].strip()
        extype, _, exvalue = extension.partition("=")
        self.extype = extype.strip()
        self.exvalue = unquote(exvalue.strip()) if exvalue else None

    def unparse(self) -> str:
        if self.exvalue is None:
            return "{}{}".format("!" * (self.critical > 0), self.extype)
        return "{}{}={}".format(
            "!" * (self.critical > 0),
            self.extype,
            quote(self.exvalue or ""),
        )

    def __str__(self) -> str:
        return self.unparse()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.__dict__!r}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LDAPUrlExtension):
            return NotImplemented
        return (
            self.critical == other.critical
            and self.extype == other.extype
            and self.exvalue == other.exvalue
        )

    def __ne__(self, other: object) -> bool:
        return not self == other


class LDAPUrlExtensions(MutableMapping[str, LDAPUrlExtension]):
    """The extensions of a URL, keyed by the type each one is of."""

    def __init__(
        self, default: Mapping[str, LDAPUrlExtension] | None = None
    ) -> None:
        self._data: dict[str, LDAPUrlExtension] = {}
        if default is not None:
            self.update(default)

    def __setitem__(self, name: str, value: LDAPUrlExtension) -> None:
        """Store an extension under its own type, which is its name."""
        if not isinstance(value, LDAPUrlExtension):
            raise TypeError(
                "value must be LDAPUrlExtension, not " + type(value).__name__
            )
        if name != value.extype:
            raise ValueError(
                f"key {name!r} does not match extension type {value.extype!r}"
            )
        self._data[name] = value

    def __getitem__(self, name: str) -> LDAPUrlExtension:
        return self._data[name]

    def __delitem__(self, name: str) -> None:
        del self._data[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __str__(self) -> str:
        return ",".join(str(value) for value in self.values())

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self._data!r}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LDAPUrlExtensions):
            return NotImplemented
        return self._data == other._data

    def parse(self, extListStr: str) -> None:
        for extension in extListStr.strip().split(","):
            if not extension:
                continue
            parsed = LDAPUrlExtension(extension)
            assert parsed.extype is not None
            self[parsed.extype] = parsed

    def unparse(self) -> str:
        return ",".join(value.unparse() for value in self.values())


class LDAPUrl:
    """An LDAP URL, taken apart into what it says.

    Either ``ldapUrl`` is given and read, or the parts are given one by one.
    ``attr2extype`` says which attribute of the object an extension stands
    for, which is what lets a subclass carry the bind DN in the URL.
    """

    attr2extype: dict[str, str] = {
        "who": "bindname",
        "cred": "X-BINDPW",
    }

    def __init__(
        self,
        ldapUrl: str | None = None,
        urlscheme: str = "ldap",
        hostport: str = "",
        dn: str = "",
        attrs: Sequence[str] | None = None,
        scope: int | None = None,
        filterstr: str | None = None,
        extensions: LDAPUrlExtensions | None = None,
        who: str | None = None,
        cred: str | None = None,
    ) -> None:
        self.urlscheme = urlscheme.lower()
        self.hostport = hostport
        self.dn = dn
        self.attrs = list(attrs) if attrs is not None else None
        self.scope = scope
        self.filterstr = filterstr
        self.extensions: LDAPUrlExtensions | None = extensions or LDAPUrlExtensions()
        if ldapUrl is not None:
            self._parse(ldapUrl)
        if who is not None:
            self.who: str | None = who
        if cred is not None:
            self.cred: str | None = cred

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LDAPUrl):
            return NotImplemented
        return (
            self.urlscheme == other.urlscheme
            and self.hostport == other.hostport
            and self.dn == other.dn
            and self.attrs == other.attrs
            and self.scope == other.scope
            and self.filterstr == other.filterstr
            and self.extensions == other.extensions
        )

    def __ne__(self, other: object) -> bool:
        return not self == other

    def _parse(self, ldap_url: str) -> None:
        """Read a URL into the parts it is made of.

        Only the parts the URL actually has are set, so what was given to
        the constructor stands for the rest.
        """
        if not isLDAPUrl(ldap_url):
            raise ValueError(
                f"Value {ldap_url!r} for ldap_url does not seem to be a LDAP URL."
            )
        scheme, rest = ldap_url.split("://", 1)
        self.urlscheme = scheme.lower()
        slash = rest.find("/")
        question = rest.find("?")
        if slash == -1 and question == -1:
            # No / and ? found at all
            self.hostport = unquote(rest)
            self.dn = ""
            return
        if slash != -1 and (question == -1 or slash < question):
            # Slash separates DN from hostport
            self.hostport = unquote(rest[:slash])
            rest = rest[slash + 1 :]
        else:
            # Question mark separates hostport from rest, DN is empty
            self.hostport = unquote(rest[:question])
            rest = rest[question:]

        # dn ? attributes ? scope ? filter ? extensions
        paramlist = rest.split("?", 4)
        self.dn = unquote(paramlist[0]).strip()
        if len(paramlist) >= 2 and paramlist[1]:
            self.attrs = unquote(paramlist[1].strip()).split(",")
        if len(paramlist) >= 3:
            scope = paramlist[2].strip()
            if scope not in SEARCH_SCOPE:
                raise ValueError(f"Invalid search scope {scope!r}")
            self.scope = SEARCH_SCOPE[scope]
        if len(paramlist) >= 4:
            filterstr = paramlist[3].strip()
            self.filterstr = unquote(filterstr) if filterstr else None
        if len(paramlist) >= 5:
            if paramlist[4]:
                self.extensions = LDAPUrlExtensions()
                self.extensions.parse(paramlist[4])
            else:
                # The field is there and says nothing, which is not the
                # same as a URL that has no extensions field at all.
                self.extensions = None

    def applyDefaults(self, defaults: Mapping[str, object]) -> None:
        """Fill in what the URL did not say from these defaults."""
        for key, value in defaults.items():
            if getattr(self, key) is None:
                setattr(self, key, value)

    def _hostport(self) -> str:
        if self.urlscheme == "ldapi":
            # The hostport of an ldapi URL is the path of a socket, which
            # has slashes in it, so it has to be escaped.
            return ldapUrlEscape(self.hostport)
        return self.hostport

    def initializeUrl(self) -> str:
        """The part of the URL that says which server to open."""
        return f"{self.urlscheme}://{self._hostport()}"

    def unparse(self) -> str:
        """The URL, written out again."""
        if self.attrs is None:
            attrs_str = ""
        else:
            attrs_str = ",".join(self.attrs)
        scope_str = SEARCH_SCOPE_STR[self.scope]
        filter_str = "" if self.filterstr is None else ldapUrlEscape(self.filterstr)
        dn_str = ldapUrlEscape(self.dn)
        ldap_url = "{}://{}/{}?{}?{}?{}".format(
            self.urlscheme,
            self._hostport(),
            dn_str,
            attrs_str,
            scope_str,
            filter_str,
        )
        if self.extensions:
            ldap_url = ldap_url + "?" + self.extensions.unparse()
        return ldap_url

    def htmlHREF(
        self,
        urlPrefix: str = "",
        hrefText: str | None = None,
        hrefTarget: str | None = None,
    ) -> str:
        """This URL as a link, for putting in a page."""
        assert isinstance(urlPrefix, str), TypeError("urlPrefix must be str")
        if hrefText is None:
            hrefText = self.unparse()
        assert isinstance(hrefText, str), TypeError("hrefText must be str")
        if hrefTarget is None:
            target = ""
        else:
            assert isinstance(hrefTarget, str), TypeError("hrefTarget must be str")
            target = f' target="{hrefTarget}"'
        return '<a{} href="{}{}">{}</a>'.format(
            target, urlPrefix, self.unparse(), hrefText
        )

    def __str__(self) -> str:
        return self.unparse()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__.split('.')[-1]} instance at {hex(id(self))}: {self.__dict__!r}>"

    def __getattr__(self, name: str) -> object:
        # An attribute the URL carries as an extension: who and cred are
        # the bind DN and its password, which is how a URL says them.
        if name in self.attr2extype:
            extype = self.attr2extype[name]
            if (
                self.extensions
                and extype in self.extensions
                and self.extensions[extype].exvalue is not None
            ):
                return unquote(self.extensions[extype].exvalue or "")
            return None
        raise AttributeError(f"{self.__class__.__name__} has no attribute {name}")

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.attr2extype:
            extype = self.attr2extype[name]
            if value is None:
                # A value of None means that extension is deleted
                delattr(self, name)
            else:
                assert isinstance(value, str)
                if self.extensions is None:
                    # The URL said it had no extensions; now it has one.
                    self.extensions = LDAPUrlExtensions()
                self.extensions[extype] = LDAPUrlExtension(
                    extype=extype, exvalue=unquote(value)
                )
        else:
            self.__dict__[name] = value

    def __delattr__(self, name: str) -> None:
        if name in self.attr2extype:
            extype = self.attr2extype[name]
            if self.extensions:
                self.extensions.pop(extype, None)
        else:
            del self.__dict__[name]
