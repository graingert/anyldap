import datetime

from anyldap._async import await_result
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors, ldapsyntax, proxy


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

    services = []

    fallback = False

    def __init__(self, services=None, fallback=None, *a, **kw):
        """
        Initialize the object.

        @param services: List of service names to try to bind against.

        @param fallback: If none of the attempts to authenticate
        against a specific service succeeded, whether to fall back to
        the normal LDAP bind mechanism.
        """

        proxy.Proxy.__init__(self, *a, **kw)
        if services is not None:
            self.services = list(services)
        if fallback is not None:
            self.fallback = fallback

    def _startSearch(self, request, controls, reply):
        services = list(self.services)
        baseDN = self.config.getIdentityBaseDN()
        e = ldapsyntax.LDAPEntryWithClient(client=self.client, dn=baseDN)
        d = self._tryService(services, e, request, controls, reply)
        d.addCallback(self._maybeFallback, request, controls, reply)
        return d

    async def _startSearch_async(self, request, controls, reply):
        services = list(self.services)
        baseDN = self.config.getIdentityBaseDN()
        e = ldapsyntax.LDAPEntryWithClient(client=self.client, dn=baseDN)
        entry = await self._tryService_async(services, e, request)
        return await self._maybeFallback_async(entry, request, controls, reply)

    def _maybeFallback(self, entry, request, controls, reply):
        if entry is not None:
            msg = pureldap.LDAPBindResponse(
                resultCode=ldaperrors.Success.resultCode, matchedDN=request.dn
            )
            return msg
        elif self.fallback:
            self.handleUnknown(request, controls, reply)
        else:
            msg = pureldap.LDAPBindResponse(
                resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
            )
            return msg

    async def _maybeFallback_async(self, entry, request, controls, reply):
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

    def timestamp(self):
        now = datetime.datetime.now()
        return now.strftime("%Y%m%d%H%M%SZ")

    def _tryService(self, services, baseEntry, request, controls, reply):
        try:
            serviceName = services.pop(0)
        except IndexError:
            return None
        timestamp = self.timestamp()
        d = baseEntry.search(
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
                            # no time
                            pureldap.LDAPFilter_not(
                                pureldap.LDAPFilter_present("validFrom")
                            ),
                            # or already valid
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
                            # no time
                            pureldap.LDAPFilter_not(
                                pureldap.LDAPFilter_present("validUntil")
                            ),
                            # or still valid
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

        def _gotEntries(entries):
            if not entries:
                return None
            assert len(entries) == 1  # TODO
            e = entries[0]
            d = e.bind(request.auth)
            return d

        d.addCallback(_gotEntries)
        d.addCallbacks(
            callback=self._loopIfNone,
            callbackArgs=(services, baseEntry, request, controls, reply),
            errback=self._loopIfBindError,
            errbackArgs=(services, baseEntry, request, controls, reply),
        )
        return d

    async def _tryService_async(self, services, baseEntry, request):
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
            if not entries:
                continue
            assert len(entries) == 1
            try:
                return await entries[0].bind_async(request.auth)
            except ldaperrors.LDAPInvalidCredentials:
                continue
        return None

    def _loopIfNone(self, r, *a, **kw):
        if r is None:
            d = self._tryService(*a, **kw)
            return d
        else:
            return r

    def _loopIfBindError(self, fail, *a, **kw):
        fail.trap(ldaperrors.LDAPInvalidCredentials)
        d = self._tryService(*a, **kw)
        return d

    fail_LDAPBindRequest = pureldap.LDAPBindResponse

    def handle_LDAPBindRequest(self, request, controls, reply):
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError(
                "Version %u not supported" % request.version
            )

        self.checkControls(controls)

        if request.dn == "":
            # anonymous bind
            return self.handleUnknown(request, controls, reply)
        else:
            if self._anyio_stream is not None:
                return self._startSearch_async(request, controls, reply)
            d = self._whenConnected(self._startSearch, request, controls, reply)
            return d


if __name__ == "__main__":
    raise SystemExit("Run the packaged AnyIO examples instead of this legacy demo.")
