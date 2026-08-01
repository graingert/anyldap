from zope.interface import implementer

from anyldap import entry, entryhelpers, interfaces
from anyldap._async import await_result
from anyldap.deferred import DeferredSource, maybeDeferred, succeed
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldifprotocol
from anyldap.runtime import ConnectionDone, Failure


class LDAPCannotRemoveRootError(ldaperrors.LDAPNamingViolation):
    """Cannot remove root of LDAP tree"""


@implementer(interfaces.IConnectedLDAPEntry)
class ReadOnlyInMemoryLDAPEntry(
    entry.EditableLDAPEntry,
    entryhelpers.DiffTreeMixin,
    entryhelpers.SubtreeFromChildrenMixin,
    entryhelpers.MatchMixin,
    entryhelpers.SearchByTreeWalkingMixin,
):
    def __init__(self, *a, **kw):
        entry.BaseLDAPEntry.__init__(self, *a, **kw)
        self._parent = None
        self._children = {}

    def parent(self):
        return self._parent

    def children(self, callback=None):
        if callback is None:
            return succeed(list(self._children.values()))
        else:
            for c in self._children.values():
                callback(c)
            return succeed(None)

    async def children_async(self, callback=None):
        return await await_result(self.children(callback=callback))

    def _lookup(self, dn):
        if not self.dn.contains(dn):
            raise ldaperrors.LDAPNoSuchObject(dn.getText())
        if dn == self.dn:
            return succeed(self)

        for c in self._children.values():
            if c.dn.contains(dn):
                return c.lookup(dn)

        raise ldaperrors.LDAPNoSuchObject(dn.getText())

    def lookup(self, dn):
        if not isinstance(dn, distinguishedname.DistinguishedName):
            dn = distinguishedname.DistinguishedName(stringValue=dn)
        return maybeDeferred(self._lookup, dn)

    async def lookup_async(self, dn):
        return await await_result(self.lookup(dn))

    def fetch(self, *attributes):
        return succeed(self)

    async def fetch_async(self, *attributes):
        return await await_result(self.fetch(*attributes))

    def addChild(self, rdn, attributes):
        """TODO ugly API. Returns the created entry."""
        rdn = distinguishedname.RelativeDistinguishedName(rdn)
        rdn_str = rdn.getText()
        if rdn_str in self._children:
            raise ldaperrors.LDAPEntryAlreadyExists(
                self._children[rdn_str].dn.getText()
            )
        dn = distinguishedname.DistinguishedName(listOfRDNs=(rdn,) + self.dn.split())
        e = self.__class__(dn, attributes)
        e._parent = self
        self._children[rdn_str] = e
        return e

    def _delete(self):
        if self._parent is None:
            raise LDAPCannotRemoveRootError()
        if self._children:
            raise ldaperrors.LDAPNotAllowedOnNonLeaf(self.dn)
        return self._parent.deleteChild(self.dn.split()[0])

    def delete(self):
        return maybeDeferred(self._delete)

    async def delete_async(self):
        return await await_result(self.delete())

    def _deleteChild(self, rdn):
        if not isinstance(rdn, distinguishedname.RelativeDistinguishedName):
            rdn = distinguishedname.RelativeDistinguishedName(stringValue=rdn)
        rdn_str = rdn.getText()
        try:
            return self._children.pop(rdn_str)
        except KeyError:
            raise ldaperrors.LDAPNoSuchObject(rdn.getText())

    def deleteChild(self, rdn):
        return maybeDeferred(self._deleteChild, rdn)

    async def deleteChild_async(self, rdn):
        return await await_result(self.deleteChild(rdn))

    def _move(self, newDN):
        if not isinstance(newDN, distinguishedname.DistinguishedName):
            newDN = distinguishedname.DistinguishedName(stringValue=newDN)
        if self._parent is not None and newDN.up() != self.dn.up():
            # climb up the tree to root
            root = self
            while root._parent is not None:
                root = root._parent
            d = maybeDeferred(root.lookup, newDN.up())
        else:
            d = succeed(self._parent)
        d.addCallback(self._move2, newDN)
        return d

    def _move2(self, newParent, newDN):
        if newParent is not None:
            del self._parent._children[self.dn.split()[0].getText()]
            newParent._children[newDN.split()[0].getText()] = self
            self._parent = newParent
        # remove old RDN attributes
        for attr in self.dn.split()[0].split():
            self[attr.attributeType].remove(attr.value)
        # add new RDN attributes
        for attr in newDN.split()[0].split():
            # TODO what if the key does not exist?
            self[attr.attributeType].add(attr.value)
        self.dn = newDN
        return self

    def move(self, newDN):
        return maybeDeferred(self._move, newDN)

    async def move_async(self, newDN):
        return await await_result(self.move(newDN))

    def commit(self):
        return succeed(True)

    async def commit_async(self):
        return await await_result(self.commit())


class InMemoryLDIFProtocol(ldifprotocol.LDIF):
    """
    Receive LDIF data and gather results into an ReadOnlyInMemoryLDAPEntry.

    You can override lookupFailed and addFailed to provide smarter
    error handling. They are called as Deferred errbacks; returning
    the reason causes error to pass onward and abort the whole
    operation. Returning None from lookupFailed skips that entry, but
    continues loading.

    When the full LDIF data has been read, the completed Deferred will
    trigger.
    """

    def __init__(self):
        super().__init__()
        # Do not access this via db, just to make sure you respect the ordering
        self.db = None
        self._deferred = DeferredSource()
        self.completed = DeferredSource().deferred

    def _addEntry(self, db, entry):
        d = db.lookup(entry.dn.up())
        d.addErrback(self.lookupFailed, entry)

        def _add(parent, entry):
            parent.addChild(rdn=entry.dn.split()[0], attributes=entry)

        d.addCallback(_add, entry)
        d.addErrback(self.addFailed, entry)

        def _passDB(_, db):
            return db

        d.addCallback(_passDB, db)
        return d

    def gotEntry(self, entry):
        if self.db is None:
            # first entry, create the db, prepare to process the rest
            self.db = ReadOnlyInMemoryLDAPEntry(dn=entry.dn, attributes=entry)
            self._deferred.callback(self.db)
        else:
            self._deferred.deferred.addCallback(self._addEntry, entry)

    def lookupFailed(self, reason, entry):
        return reason  # pass the error (abort) by default

    def addFailed(self, reason, entry):
        return reason  # pass the error (abort) by default

    def connectionLost(self, reason):
        super().connectionLost(reason)
        if not reason.check(ConnectionDone):
            self.completed._errback(reason)
        else:
            self._deferred.deferred.addCallbacks(
                self.completed._callback,
                self.completed._errback,
            )

        del self._deferred  # invalidate it to flush out bugs


def fromLDIFFile(f):
    """Read LDIF data from a file."""

    p = InMemoryLDIFProtocol()
    while 1:
        data = f.read()
        if not data:
            break
        p.dataReceived(data)
    p.connectionLost(Failure(ConnectionDone()))

    return p.completed
