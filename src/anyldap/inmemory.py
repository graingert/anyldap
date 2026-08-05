from collections.abc import Awaitable, Callable
from typing import Protocol as TypingProtocol

from zope.interface import implementer

from anyldap import entry, entryhelpers, interfaces
from anyldap._async import ResultSlot, await_result
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldifprotocol
from anyldap.runtime import ConnectionDone, Failure, Protocol, unwrap_failure


class LDAPCannotRemoveRootError(ldaperrors.LDAPNamingViolation):
    """Cannot remove root of LDAP tree"""


class ReadableFile(TypingProtocol):
    """A plain file-like or an anyio AsyncFile."""

    def read(self, size: int) -> bytes | Awaitable[bytes]: ...


@implementer(interfaces.IWalkableLDAPEntry)
class ReadOnlyInMemoryLDAPEntry(
    entry.EditableLDAPEntry,
    entryhelpers.DiffTreeMixin,
    entryhelpers.SubtreeFromChildrenMixin,
    entryhelpers.MatchMixin,
    entryhelpers.SearchByTreeWalkingMixin,
):
    def __init__(
        self,
        dn: interfaces.AnyDN,
        attributes: interfaces.Attributes = {},
    ) -> None:
        entry.BaseLDAPEntry.__init__(self, dn, attributes)
        self._parent: "ReadOnlyInMemoryLDAPEntry | None" = None
        self._children: dict[str, "ReadOnlyInMemoryLDAPEntry"] = {}

    def parent(self) -> "ReadOnlyInMemoryLDAPEntry | None":
        return self._parent

    async def children(
        self,
        callback: entryhelpers.EntryCallback | None = None,
    ) -> list[interfaces.IWalkableLDAPEntry] | None:
        if callback is None:
            return list(self._children.values())
        for c in self._children.values():
            await callback(c)
        return None

    children_async = children

    async def lookup(
        self, dn: interfaces.AnyDN
    ) -> interfaces.IConnectedLDAPEntry:
        if not isinstance(dn, distinguishedname.DistinguishedName):
            dn = distinguishedname.DistinguishedName(stringValue=dn)
        if not self.dn.contains(dn):
            raise ldaperrors.LDAPNoSuchObject(dn.getText())
        if dn == self.dn:
            return self

        for c in self._children.values():
            if c.dn.contains(dn):
                return await c.lookup(dn)

        raise ldaperrors.LDAPNoSuchObject(dn.getText())

    lookup_async = lookup

    async def fetch(self, *attributes: str | bytes) -> interfaces.ILDAPEntry:
        return self

    fetch_async = fetch

    def addChild(
        self,
        rdn: distinguishedname.RelativeDistinguishedName | str | bytes,
        attributes: interfaces.Attributes,
    ) -> "ReadOnlyInMemoryLDAPEntry":
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

    async def delete(self) -> "ReadOnlyInMemoryLDAPEntry":
        if self._parent is None:
            raise LDAPCannotRemoveRootError()
        if self._children:
            raise ldaperrors.LDAPNotAllowedOnNonLeaf(self.dn.getText())
        return await self._parent.deleteChild(self.dn.split()[0])

    delete_async = delete

    async def deleteChild(
        self, rdn: distinguishedname.RelativeDistinguishedName | str | bytes
    ) -> "ReadOnlyInMemoryLDAPEntry":
        if not isinstance(rdn, distinguishedname.RelativeDistinguishedName):
            rdn = distinguishedname.RelativeDistinguishedName(stringValue=rdn)
        rdn_str = rdn.getText()
        try:
            return self._children.pop(rdn_str)
        except KeyError:
            raise ldaperrors.LDAPNoSuchObject(rdn.getText())

    deleteChild_async = deleteChild

    async def move(self, newDN: interfaces.AnyDN) -> "ReadOnlyInMemoryLDAPEntry":
        if not isinstance(newDN, distinguishedname.DistinguishedName):
            newDN = distinguishedname.DistinguishedName(stringValue=newDN)
        if self._parent is not None and newDN.up() != self.dn.up():
            # climb up the tree to root
            root: ReadOnlyInMemoryLDAPEntry = self
            while (parent := root._parent) is not None:
                root = parent
            found = await root.lookup(newDN.up())
            assert isinstance(found, ReadOnlyInMemoryLDAPEntry)
            newParent: ReadOnlyInMemoryLDAPEntry | None = found
        else:
            newParent = self._parent
        return self._move2(newParent, newDN)

    move_async = move

    def _move2(
        self,
        newParent: "ReadOnlyInMemoryLDAPEntry | None",
        newDN: distinguishedname.DistinguishedName,
    ) -> "ReadOnlyInMemoryLDAPEntry":
        if newParent is not None:
            assert self._parent is not None
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

    async def commit(self) -> bool:
        return True

    commit_async = commit


class InMemoryLDIFProtocol(ldifprotocol.LDIF):
    """
    Receive LDIF data and gather results into an ReadOnlyInMemoryLDAPEntry.

    You can override lookupFailed and addFailed to provide smarter error
    handling. They are called with the `Failure` and the entry that provoked
    it; returning the reason causes the error to pass onward and abort the
    whole operation. Returning None skips that entry, but continues loading.

    Entries are gathered as they arrive and grafted onto the tree by
    `completed()`, which is where the database becomes available.
    """

    def __init__(self) -> None:
        super().__init__()
        # Do not access this via db, just to make sure you respect the ordering
        self.db: ReadOnlyInMemoryLDAPEntry | None = None
        self._pending: list[entry.BaseLDAPEntry] = []
        self._received: ResultSlot[None] = ResultSlot()

    async def _addEntry(
        self, db: ReadOnlyInMemoryLDAPEntry, entry: entry.BaseLDAPEntry
    ) -> None:
        try:
            parent = await db.lookup(entry.dn.up())
        except Exception as exc:
            if self._reportFailure(self.lookupFailed, exc, entry):
                return
            raise
        assert isinstance(parent, ReadOnlyInMemoryLDAPEntry)
        try:
            parent.addChild(rdn=entry.dn.split()[0], attributes=entry)
        except Exception as exc:
            if self._reportFailure(self.addFailed, exc, entry):
                return
            raise

    @staticmethod
    def _reportFailure(
        hook: Callable[[Failure, "entry.BaseLDAPEntry"], object],
        exc: BaseException,
        entry: "entry.BaseLDAPEntry",
    ) -> bool:
        """Call `hook`; report whether it swallowed the error."""
        return hook(Failure(exc), entry) is None

    def gotEntry(self, obj: object) -> None:
        assert isinstance(obj, entry.BaseLDAPEntry)
        entry_ = obj
        if self.db is None:
            # first entry, create the db, prepare to process the rest
            self.db = ReadOnlyInMemoryLDAPEntry(dn=entry_.dn, attributes=entry_)
        else:
            self._pending.append(entry_)

    def lookupFailed(
        self, reason: Failure, entry: "entry.BaseLDAPEntry"
    ) -> object:
        return reason  # pass the error (abort) by default

    def addFailed(self, reason: Failure, entry: "entry.BaseLDAPEntry") -> object:
        return reason  # pass the error (abort) by default

    def connectionLost(self, reason: BaseException = Protocol.connectionDone) -> None:
        super().connectionLost(reason)
        # A reason reaches us either bare or wrapped in a Failure.
        unwrapped = unwrap_failure(reason)
        if isinstance(unwrapped, ConnectionDone):
            self._received.set_value(None)
        else:
            self._received.set_exception(unwrapped)

    async def completed(self) -> ReadOnlyInMemoryLDAPEntry:
        """Wait for the LDIF stream, then return the assembled database."""
        await self._received.wait()
        assert self.db is not None
        while self._pending:
            await self._addEntry(self.db, self._pending.pop(0))
        return self.db


async def fromLDIFFile(f: ReadableFile) -> ReadOnlyInMemoryLDAPEntry:
    """Read LDIF data from a file."""

    p = InMemoryLDIFProtocol()
    while 1:
        # `f` may be a plain file-like or an anyio AsyncFile.
        data = await await_result(f.read(8192))
        if not data:
            break
        p.dataReceived(data)
    p.connectionLost(Failure(ConnectionDone()))

    return await p.completed()
