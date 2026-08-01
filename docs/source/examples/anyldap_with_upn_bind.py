"""
An anyldap LDAP server which can authenticate based on UPN, as AD does.

The LDAP entry needs to have the `userPrincipalName` attribute set.

dn: uid=bob,ou=people,dc=example,dc=org
objectclass: top
objectclass: person
objectClass: inetOrgPerson
uid: bob
cn: bobby
gn: Bob
sn: Roberts
mail: bob@example.org
homeDirectory: e:\\Users\\bob
userPassword: pass
userPrincipalName: bob@ad.example.org
"""

from anyldap import interfaces
from anyldap._encoder import to_bytes
from anyldap.deferred import succeed
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import distinguishedname, ldaperrors
from anyldap.protocols.ldap.ldapserver import LDAPServer


class LDAPServerWithUPNBind(LDAPServer):
    """
    An LDAP server which support BIND using UPN similar to AD.
    """

    _loginAttribute = b"userPrincipalName"

    def handle_LDAPBindRequest(self, request, controls, reply):
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError(
                "Version %u not supported" % request.version
            )

        self.checkControls(controls)

        if request.dn == b"":
            # anonymous bind
            self.boundUser = None
            return pureldap.LDAPBindResponse(resultCode=0)

        request_dn = to_bytes(request.dn)

        root = interfaces.IConnectedLDAPEntry(self.factory)

        def _gotUPNResult(results):
            if len(results) != 1:
                # Not exactly one result, so this might not be an UNP.
                return distinguishedname.DistinguishedName(request.dn)

            # A single result, so the UPN might exist.
            return results[0].dn

        if b"@" in request_dn and b"," not in request_dn:
            # This might be an UPN request.
            filterText = b"(" + self._loginAttribute + b"=" + request_dn + b")"
            d = root.search(filterText=filterText)
            d.addCallback(_gotUPNResult)
        else:
            d = succeed(distinguishedname.DistinguishedName(request_dn))

        # Once the BIND DN is known, search for the LDAP entry.
        d.addCallback(lambda dn: root.lookup(dn))

        def _noEntry(fail):
            """
            Called when the requested BIND DN was not found.
            """
            fail.trap(ldaperrors.LDAPNoSuchObject)

        d.addErrback(_noEntry)

        def _gotEntry(entry, auth):
            """
            Called when the requested BIND DN was found.
            """
            if entry is None:
                raise ldaperrors.LDAPInvalidCredentials()

            d = entry.bind(auth)

            def _cb(entry):
                """
                Called when BIND operation was successful.
                """
                self.boundUser = entry
                msg = pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.Success.resultCode,
                    matchedDN=entry.dn.getText(),
                )
                return msg

            d.addCallback(_cb)
            return d

        d.addCallback(_gotEntry, request.auth)

        return d
