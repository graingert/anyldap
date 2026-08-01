from anyldap import config, ldapfilter
from anyldap.deferred import ensureDeferred
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldaperrors, ldapsyntax


class UnauthorizedLogin(Exception):
    pass


def makeFilter(name, template=None):
    filter_object = None
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

    def __init__(self, cfg):
        self.config = cfg

    async def requestAvatarId_async(self, credentials):
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
        if not results:
            raise UnauthorizedLogin("Invalid credentials")
        if len(results) != 1:
            raise UnauthorizedLogin("Expected a single identity match")
        entry = results[0]
        try:
            await entry.client.bind_async(str(entry.dn), credentials.password)
        except (
            ldaperrors.LDAPInvalidCredentials,
            ldaperrors.LDAPUnwillingToPerform,
        ) as exc:
            raise UnauthorizedLogin() from exc
        return entry

    def requestAvatarId(self, credentials):
        return ensureDeferred(self.requestAvatarId_async(credentials))
