from anyldap import numberalloc
from anyldap.deferred import DeferredSource
from anyldap.protocols.ldap import autofill, ldapsyntax


class Autofill_posix:  # TODO baseclass
    def __init__(self, baseDN, freeNumberGetter=numberalloc.getFreeNumber):
        self.baseDN = baseDN
        self.freeNumberGetter = freeNumberGetter

    def _cb_gotNumbers(self, r, ldapObject):
        uid, gid = r

        ok, val = uid
        if not ok:
            val.trap()
        ldapObject["uidNumber"] = [str(val)]

        ok, val = gid
        if not ok:
            val.trap()
        ldapObject["gidNumber"] = [str(val)]

    def _gather_numbers(self, uid_deferred, gid_deferred):
        result = DeferredSource()
        values = [None, None]
        done = [False, False]

        def maybe_finish():
            if all(done) and not result.called:
                result.callback(values)

        def cb(value, index):
            values[index] = (True, value)
            done[index] = True
            maybe_finish()
            return value

        def eb(failure, index):
            values[index] = (False, failure)
            done[index] = True
            if not result.called:
                result.errback(failure)

        uid_deferred.addCallback(cb, 0)
        uid_deferred.addErrback(eb, 0)
        gid_deferred.addCallback(cb, 1)
        gid_deferred.addErrback(eb, 1)
        return result.deferred

    def start(self, ldapObject):
        assert "objectClass" in ldapObject
        if "posixAccount" not in ldapObject["objectClass"]:
            raise autofill.ObjectMissingObjectClassException(ldapObject)

        assert "loginShell" not in ldapObject
        ldapObject["loginShell"] = ["/bin/sh"]

        baseObject = ldapsyntax.LDAPEntry(client=ldapObject.client, dn=self.baseDN)
        d1 = self.freeNumberGetter(baseObject, "uidNumber", min=1000)

        d2 = self.freeNumberGetter(baseObject, "gidNumber", min=1000)

        d = self._gather_numbers(d1, d2)
        d.addCallback(self._cb_gotNumbers, ldapObject)
        return d

    def notify(self, ldapObject, attributeType):
        pass
