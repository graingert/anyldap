from collections.abc import Sequence
from typing import Any, Protocol

from anyldap import config, interfaces, ldapfilter
from anyldap.protocols import pureber
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldaperrors, ldapsyntax


class UsernamePassword(Protocol):
    """The credentials this checker knows how to validate."""

    username: str
    password: str | bytes


class BoundEntry(Protocol):
    """The entry a successful check identifies.

    Read-only members, so that an entry naming its own kinds of dn and
    client still answers to this.
    """

    @property
    def dn(self) -> object: ...

    @property
    def client(self) -> Any: ...


class UnauthorizedLogin(Exception):
    pass


def makeFilter(
    name: str, template: str | None = None
) -> pureber.BERBase | None:
    filter_object: pureber.BERBase | None = None
    try:
        filter_object = ldapfilter.parseFilter(name)
    except ldapfilter.InvalidLDAPFilter:
        try:
            filter_object = ldapfilter.parseFilter(f"({name})")
        except ldapfilter.InvalidLDAPFilter:
            if template is not None:
                try:
                    filter_object = ldapfilter.parseFilter(template % {"name": name})
                except ldapfilter.InvalidLDAPFilter:
                    pass
    return filter_object


class LDAPBindingChecker:
    """
    Validate username/password credentials against LDAP.

    The avatar ID returned is an ``LDAPEntry``.
    """

    credentialInterfaces = ("username-password",)

    def __init__(self, cfg: interfaces.LDAPConfigLike) -> None:
        self.config = cfg

    async def requestAvatarId_async(
        self, credentials: UsernamePassword
    ) -> BoundEntry:
        try:
            base_dn = self.config.getIdentityBaseDN()
        except config.MissingBaseDNError as exc:
            raise UnauthorizedLogin(
                f"Disabled due configuration error: {exc}."
            ) from exc
        if not credentials.username:
            raise UnauthorizedLogin("Anonymous authentication is not supported")

        filt = makeFilter(self.config.getIdentitySearch(credentials.username))
        if filt is None:
            raise UnauthorizedLogin("Couldn't create filter")

        creator = ldapconnector.LDAPClientCreator(None, ldapclient.LDAPClient)
        client = await creator.connectAsync(
            base_dn,
            overrides=self.config.getServiceLocationOverrides(),
        )
        base = ldapsyntax.LDAPEntry(client, base_dn)
        results = await base.search_async(
            filterObject=filt,
            sizeLimit=1,
            attributes=[""],
        )
        assert isinstance(results, Sequence)
        if not results:
            raise UnauthorizedLogin("Invalid credentials")
        if len(results) != 1:
            raise UnauthorizedLogin("Expected a single identity match")
        entry: BoundEntry = results[0]
        try:
            await entry.client.bind_async(str(entry.dn), credentials.password)
        except (
            ldaperrors.LDAPInvalidCredentials,
            ldaperrors.LDAPUnwillingToPerform,
        ) as exc:
            raise UnauthorizedLogin() from exc
        return entry

    requestAvatarId = requestAvatarId_async
