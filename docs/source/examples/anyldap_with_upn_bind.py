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

from collections.abc import Iterable, Sequence
from typing import cast

from anyldap import interfaces
from anyldap._encoder import to_bytes, to_unicode
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import distinguishedname, ldaperrors
from anyldap.protocols.ldap.ldapserver import LDAPServer, Reply


class LDAPServerWithUPNBind(LDAPServer):
    """
    An LDAP server which support BIND using UPN similar to AD.
    """

    _loginAttribute = b"userPrincipalName"

    async def handle_LDAPBindRequest(
        self,
        request: pureldap.LDAPBindRequest,
        controls: Iterable[pureldap.Control] | None,
        reply: Reply,
    ) -> pureldap.LDAPBindResponse:
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
            filterText = "({}={})".format(
                to_unicode(self._loginAttribute), to_unicode(request_dn)
            )
            # What a search hands back depends on how it was called, so the
            # interface says only that it hands something back; called this
            # way it is the entries that matched.
            found = cast(
                Sequence[interfaces.IConnectedLDAPEntry],
                await root.search(filterText=filterText),
            )
            dn: distinguishedname.DistinguishedName
            if len(found) == 1:
                # A single result, so the UPN might exist.
                dn = found[0].dn
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

        if isinstance(request.auth, tuple):
            # A SASL bind carries a mechanism and its credentials, which
            # this server does not do: it knows how to check a password.
            raise ldaperrors.LDAPAuthMethodNotSupported()

        bound = await entry.bind(request.auth)
        self.boundUser = bound
        return pureldap.LDAPBindResponse(
            resultCode=ldaperrors.Success.resultCode,
            matchedDN=bound.dn.getText(),
        )
