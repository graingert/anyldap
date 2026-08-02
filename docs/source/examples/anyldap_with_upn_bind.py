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
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import distinguishedname, ldaperrors
from anyldap.protocols.ldap.ldapserver import LDAPServer


class LDAPServerWithUPNBind(LDAPServer):
    """
    An LDAP server which support BIND using UPN similar to AD.
    """

    _loginAttribute = b"userPrincipalName"

    async def handle_LDAPBindRequest(self, request, controls, reply):
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

        if b"@" in request_dn and b"," not in request_dn:
            # This might be an UPN request.
            filterText = b"(" + self._loginAttribute + b"=" + request_dn + b")"
            results = await root.search(filterText=filterText)
            if len(results) == 1:
                # A single result, so the UPN might exist.
                dn = results[0].dn
            else:
                # Not exactly one result, so this might not be an UPN.
                dn = distinguishedname.DistinguishedName(request.dn)
        else:
            dn = distinguishedname.DistinguishedName(request_dn)

        # Once the BIND DN is known, search for the LDAP entry.
        try:
            entry = await root.lookup(dn)
        except ldaperrors.LDAPNoSuchObject:
            raise ldaperrors.LDAPInvalidCredentials()

        entry = await entry.bind(request.auth)
        self.boundUser = entry
        return pureldap.LDAPBindResponse(
            resultCode=ldaperrors.Success.resultCode,
            matchedDN=entry.dn.getText(),
        )
