import outcome

from anyldap import numberalloc
from anyldap.protocols.ldap import autofill, ldapsyntax


class Autofill_posix:  # TODO baseclass
    def __init__(self, baseDN, freeNumberGetter=numberalloc.getFreeNumber):
        self.baseDN = baseDN
        self.freeNumberGetter = freeNumberGetter

    def _cb_gotNumbers(self, numbers, ldapObject):
        uid, gid = numbers
        ldapObject["uidNumber"] = [str(uid.unwrap())]
        ldapObject["gidNumber"] = [str(gid.unwrap())]

    async def start(self, ldapObject):
        assert "objectClass" in ldapObject
        if "posixAccount" not in ldapObject["objectClass"]:
            raise autofill.ObjectMissingObjectClassException(ldapObject)

        assert "loginShell" not in ldapObject
        ldapObject["loginShell"] = ["/bin/sh"]

        baseObject = ldapsyntax.LDAPEntry(client=ldapObject.client, dn=self.baseDN)
        # Both allocations are attempted even if the first one fails, so that
        # a caller inspecting the outcomes sees what each one did.
        numbers = [
            await outcome.acapture(
                self.freeNumberGetter, baseObject, numberType, min=1000
            )
            for numberType in ("uidNumber", "gidNumber")
        ]
        self._cb_gotNumbers(numbers, ldapObject)

    def notify(self, ldapObject, attributeType):
        pass
