import datetime
from collections.abc import Awaitable, Iterable, Sequence

from anyldap._async import await_result
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors, ldapserver, ldapsyntax, proxy

Controls = Iterable[pureldap.Control] | None


class ServiceBindingProxy(proxy.Proxy):
    """
    An LDAP proxy that handles non-anonymous bind requests specially.

    BindRequests are intercepted and authentication is attempted
    against each configured service. This authentication is performed
    against a separate LDAP entry, found by searching for entries with

     - objectClass: serviceSecurityObject

     - owner: the DN of the original bind attempt

     - cn: the service name.

    starting at the identity-base as configured in the config file.

    Finally, if the authentication does not succeed against any of the
    configured services, the proxy can fallback to passing the bind
    request to the real server.
    """

    services: Sequence[str] = []

    fallback = False

    def __init__(
        self,
        services: Iterable[str] | None = None,
        fallback: bool | None = None,
        *a: object,
        **kw: object,
    ) -> None:
        """
        Initialize the object.

        @param services: List of service names to try to bind against.

        @param fallback: If none of the attempts to authenticate
        against a specific service succeeded, whether to fall back to
        the normal LDAP bind mechanism.
        """

        proxy.Proxy.__init__(self, *a, **kw)  # type: ignore[arg-type]
        if services is not None:
            self.services = list(services)
        if fallback is not None:
            self.fallback = fallback

    async def _startSearch_async(
        self,
        request: pureldap.LDAPBindRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> pureldap.LDAPBindResponse | None:
        services = list(self.services)
        baseDN = self.config.getIdentityBaseDN()
        # Only reached through _whenConnected, which waits for the client.
        assert self.client is not None
        e = ldapsyntax.LDAPEntryWithClient(client=self.client, dn=baseDN)
        entry = await self._tryService_async(services, e, request)
        return await self._maybeFallback_async(entry, request, controls, reply)

    _startSearch = _startSearch_async

    async def _maybeFallback_async(
        self,
        entry: object,
        request: pureldap.LDAPBindRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> pureldap.LDAPBindResponse | None:
        if entry is not None:
            return pureldap.LDAPBindResponse(
                resultCode=ldaperrors.Success.resultCode, matchedDN=request.dn
            )
        if self.fallback:
            await await_result(self.handleUnknown(request, controls, reply))
            return None
        return pureldap.LDAPBindResponse(
            resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
        )

    def timestamp(self) -> str:
        now = datetime.datetime.now()
        return now.strftime("%Y%m%d%H%M%SZ")

    async def _tryService_async(
        self,
        services: list[str],
        baseEntry: ldapsyntax.LDAPEntryWithClient,
        request: pureldap.LDAPBindRequest,
    ) -> object:
        while services:
            serviceName = services.pop(0)
            timestamp = self.timestamp()
            entries = await baseEntry.search_async(
                filterObject=pureldap.LDAPFilter_and(
                    [
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("objectClass"),
                            assertionValue=pureldap.LDAPAssertionValue(
                                "serviceSecurityObject"
                            ),
                        ),
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("owner"),
                            assertionValue=pureldap.LDAPAssertionValue(request.dn),
                        ),
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription("cn"),
                            assertionValue=pureldap.LDAPAssertionValue(serviceName),
                        ),
                        pureldap.LDAPFilter_or(
                            [
                                pureldap.LDAPFilter_not(
                                    pureldap.LDAPFilter_present("validFrom")
                                ),
                                pureldap.LDAPFilter_lessOrEqual(
                                    attributeDesc=pureldap.LDAPAttributeDescription(
                                        "validFrom"
                                    ),
                                    assertionValue=pureldap.LDAPAssertionValue(timestamp),
                                ),
                            ]
                        ),
                        pureldap.LDAPFilter_or(
                            [
                                pureldap.LDAPFilter_not(
                                    pureldap.LDAPFilter_present("validUntil")
                                ),
                                pureldap.LDAPFilter_greaterOrEqual(
                                    attributeDesc=pureldap.LDAPAttributeDescription(
                                        "validUntil"
                                    ),
                                    assertionValue=pureldap.LDAPAssertionValue(timestamp),
                                ),
                            ]
                        ),
                    ]
                ),
                attributes=("1.1",),
            )
            assert isinstance(entries, Sequence)
            if not entries:
                continue
            assert len(entries) == 1
            try:
                return await entries[0].bind_async(request.auth)
            except ldaperrors.LDAPInvalidCredentials:
                continue
        return None

    fail_LDAPBindRequest = pureldap.LDAPBindResponse

    def handle_LDAPBindRequest(
        self,
        request: pureldap.LDAPBindRequest,
        controls: Controls,
        reply: ldapserver.Reply,
    ) -> Awaitable[object]:
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError(
                "Version %u not supported" % request.version
            )

        self.checkControls(controls)

        if request.dn == "":
            # anonymous bind
            return self.handleUnknown(request, controls, reply)
        return self._whenConnected(self._startSearch_async, request, controls, reply)


if __name__ == "__main__":
    raise SystemExit("Run the packaged AnyIO examples instead of this legacy demo.")
