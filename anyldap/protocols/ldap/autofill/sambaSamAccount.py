from anyldap import interfaces
from anyldap.protocols.ldap.autofill import ObjectMissingObjectClassException


class Autofill_samba:  # TODO baseclass
    def __init__(
        self, domainSID: str, fixedPrimaryGroupSID: int | None = None
    ) -> None:
        self.domainSID = domainSID
        self.fixedPrimaryGroupSID = fixedPrimaryGroupSID

    def start(self, ldapObject: interfaces.IEditableLDAPEntry) -> None:
        assert "objectClass" in ldapObject
        if "sambaSamAccount" not in ldapObject["objectClass"]:
            raise ObjectMissingObjectClassException(ldapObject)

        assert "sambaAcctFlags" not in ldapObject
        ldapObject["sambaAcctFlags"] = ["[UX         ]"]
        assert "sambaPwdLastSet" not in ldapObject
        ldapObject["sambaPwdLastSet"] = ["1"]
        assert "sambaLogonTime" not in ldapObject
        ldapObject["sambaLogonTime"] = ["0"]
        assert "sambaLogoffTime" not in ldapObject
        ldapObject["sambaLogoffTime"] = ["0"]
        assert "sambaPwdCanChange" not in ldapObject
        ldapObject["sambaPwdCanChange"] = ["0"]
        assert "sambaPwdMustChange" not in ldapObject
        ldapObject["sambaPwdMustChange"] = ["0"]

        if self.fixedPrimaryGroupSID is not None:
            assert "sambaPrimaryGroupSID" not in ldapObject
            ldapObject["sambaPrimaryGroupSID"] = [
                "%s-%d" % (self.domainSID, self.fixedPrimaryGroupSID)
            ]

        # Handle attributeTypes that were added before we got
        # started. We know we don't defer in notify, so we can do a
        # simple loop here.
        for attributeType in ldapObject.keys():
            self.notify(ldapObject, attributeType)

    def notify(
        self, ldapObject: interfaces.IEditableLDAPEntry, attributeType: str | bytes
    ) -> None:
        # sambaSID=2*uidNumber+1000
        if attributeType == "uidNumber":
            assert "uidNumber" in ldapObject
            assert len(ldapObject["uidNumber"]) == 1
            (uidNumber,) = ldapObject["uidNumber"]
            sid = "%s-%d" % (self.domainSID, int(uidNumber) * 2 + 1000)
            ldapObject["sambaSID"] = [str(sid)]
            return

        # sambaPrimaryGroupSID = fixed or 2*gidNumber+1001
        if self.fixedPrimaryGroupSID is None and attributeType == "gidNumber":
            assert "gidNumber" in ldapObject
            assert len(ldapObject["gidNumber"]) == 1
            (gidNumber,) = ldapObject["gidNumber"]
            sid = "%s-%d" % (self.domainSID, int(gidNumber) * 2 + 1001)
            ldapObject["sambaPrimaryGroupSID"] = [str(sid)]
            return
