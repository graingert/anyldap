"""
Manage LDAP data as a tree of LDIF files.
"""
import errno
import os
import uuid
from collections.abc import Callable

import anyio
from zope.interface import implementer

from anyldap import attributeset, entry, entryhelpers, interfaces
from anyldap._encoder import to_unicode
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldifprotocol
from anyldap.runtime import ConnectionDone, Failure, Protocol, logger

# What a caller may name a place in the tree with.
AnyPath = str | bytes | os.PathLike[str]


class LDIFTreeEntryContainsMultipleEntries(Exception):
    """LDIFTree entry contains multiple LDIF entries."""


class LDIFTreeEntryContainsNoEntries(Exception):
    """LDIFTree entry does not contain a valid LDIF entry."""


class LDIFTreeNoSuchObject(Exception):
    """LDIFTree does not contain such entry."""


class LDAPCannotRemoveRootError(ldaperrors.LDAPNamingViolation):
    """Cannot remove root of LDAP tree"""


class StoreParsedLDIF(ldifprotocol.LDIF):
    def __init__(self) -> None:
        super().__init__()
        self.done = False
        self.seen: list[entry.BaseLDAPEntry] = []

    def gotEntry(self, obj: entry.BaseLDAPEntry) -> None:
        self.seen.append(obj)

    def connectionLost(
        self, reason: BaseException = Protocol.connectionDone
    ) -> None:
        self.done = True


async def get(path: AnyPath, dn: interfaces.AnyDN) -> entry.BaseLDAPEntry:
    return await _get(path, dn)


async def _get(path: AnyPath, dn: interfaces.AnyDN) -> entry.BaseLDAPEntry:
    path = anyio.Path(to_unicode(path))
    dn = distinguishedname.DistinguishedName(dn)
    l = list(dn.split())
    assert len(l) >= 1
    l.reverse()

    parser = StoreParsedLDIF()

    entry = path.joinpath(*("%s.dir" % rdn.getText() for rdn in l[:-1]))
    entry = entry / ("%s.ldif" % l[-1].getText())
    async with await anyio.Path(entry).open("rb") as f:
        while 1:
            data = await f.read(8192)
            if not data:
                break
            parser.dataReceived(data)
    parser.connectionLost(Failure(ConnectionDone()))

    assert parser.done
    entries = parser.seen
    if len(entries) == 0:
        raise LDIFTreeEntryContainsNoEntries()
    elif len(entries) > 1:
        raise LDIFTreeEntryContainsMultipleEntries(entries)
    else:
        return entries[0]


async def _putEntry(
    fileName: str | os.PathLike[str], entry: entry.BaseLDAPEntry
) -> bool:
    """fileName is without extension."""
    name = anyio.Path(fileName)
    tmp = name.with_name(f"{name.name}.{uuid.uuid4()!s}.tmp")
    await tmp.write_bytes(entry.toWire())
    await tmp.rename(name.with_name(name.name + ".ldif"))
    return True


async def _put(path: AnyPath, entry: entry.BaseLDAPEntry) -> bool:
    path = anyio.Path(to_unicode(path))
    l = list(entry.dn.split())
    assert len(l) >= 1
    l.reverse()

    entryRDN = l.pop()
    if l:
        grandParent = path.joinpath(*("%s.dir" % rdn.getText() for rdn in l[:-1]))
        parentEntry = grandParent / ("%s.ldif" % l[-1].getText())
        parentDir = grandParent / ("%s.dir" % l[-1].getText())
        if not await parentDir.exists():
            if not await parentEntry.exists():
                raise LDIFTreeNoSuchObject(entry.dn.up())
            await parentDir.mkdir(parents=True, exist_ok=True)
    else:
        parentDir = path
    return await _putEntry(parentDir / entryRDN.getText(), entry)


async def put(path: AnyPath, entry: entry.BaseLDAPEntry) -> bool:
    return await _put(path, entry)


@implementer(interfaces.IConnectedLDAPEntry)
class LDIFTreeEntry(
    entry.EditableLDAPEntry,
    entryhelpers.DiffTreeMixin,
    entryhelpers.SubtreeFromChildrenMixin,
    entryhelpers.MatchMixin,
    entryhelpers.SearchByTreeWalkingMixin,
):
    def __init__(
        self,
        path: AnyPath,
        dn: interfaces.AnyDN | None = None,
        attributes: interfaces.Attributes = {},
    ) -> None:
        """Build an entry without touching the filesystem.

        Reading an entry back off disk has to await, so a directly constructed
        entry starts out with no attributes; use :meth:`open` instead.
        """
        if dn is None:
            dn = ""
        entry.BaseLDAPEntry.__init__(self, dn, attributes)
        self.path = anyio.Path(to_unicode(path))

    @classmethod
    async def open(
        cls,
        path: AnyPath,
        dn: interfaces.AnyDN | None = None,
        attributes: interfaces.Attributes = {},
    ) -> "LDIFTreeEntry":
        """Build an entry and read its attributes from disk."""
        self = cls(path, dn, attributes)
        if self.dn != "":
            await self._load()
        return self

    async def _load(self) -> None:
        assert self.path.suffix == ".dir"
        entryPath = self.path.with_suffix(".ldif")

        parser = StoreParsedLDIF()

        try:
            f = await entryPath.open("rb")
        except OSError as e:
            if e.errno == errno.ENOENT:
                return
            else:
                raise
        async with f:
            while 1:
                data = await f.read(8192)
                if not data:
                    break
                parser.dataReceived(data)
        parser.connectionLost(Failure(ConnectionDone()))
        assert parser.done

        entries = parser.seen
        if len(entries) == 0:
            raise LDIFTreeEntryContainsNoEntries()
        elif len(entries) > 1:
            raise LDIFTreeEntryContainsMultipleEntries(entries)
        else:
            for k, v in entries[0].items():
                self._attributes[k] = attributeset.LDAPAttributeSet(k, v)

    async def parent(self) -> "LDIFTreeEntry | None":
        if self.dn == "":
            # root
            return None
        return await self.__class__.open(self.path.parent, self.dn.up())

    async def _child_entries(self) -> list["LDIFTreeEntry"]:
        children = []
        try:
            filenames = [item.name async for item in self.path.iterdir()]
        except OSError as e:
            if e.errno == errno.ENOENT:
                pass
            else:
                raise
        else:
            seen = set()
            for fn in filenames:
                base, ext = anyio.Path(fn).stem, anyio.Path(fn).suffix
                if ext not in [".dir", ".ldif"]:
                    continue
                if base in seen:
                    continue
                seen.add(base)

                dn = distinguishedname.DistinguishedName(
                    listOfRDNs=(
                        (distinguishedname.RelativeDistinguishedName(base),)
                        + self.dn.split()
                    )
                )
                child = await self.__class__.open(self.path / (base + ".dir"), dn)
                children.append(child)
        return children

    async def children(
        self,
        callback: Callable[[interfaces.IConnectedLDAPEntry], object] | None = None,
    ) -> list[interfaces.IConnectedLDAPEntry] | None:
        children = await self._child_entries()
        if callback is None:
            return list(children)
        for c in children:
            callback(c)
        return None

    children_async = children

    async def lookup(
        self, dn: interfaces.AnyDN
    ) -> interfaces.IConnectedLDAPEntry:
        dn = distinguishedname.DistinguishedName(dn)
        if not self.dn.contains(dn):
            raise ldaperrors.LDAPNoSuchObject(dn.getText())
        if dn == self.dn:
            return self

        it = dn.split()
        me = self.dn.split()
        assert len(it) > len(me)
        assert (len(me) == 0) or (it[-len(me) :] == me)
        rdn = it[-len(me) - 1]
        path = self.path / ("%s.dir" % rdn.getText())
        entry = self.path / ("%s.ldif" % rdn.getText())
        if not await path.is_dir() and not await entry.is_file():
            raise ldaperrors.LDAPNoSuchObject(dn.getText())
        childDN = distinguishedname.DistinguishedName(listOfRDNs=(rdn,) + me)
        c = await self.__class__.open(path, childDN)
        return await c.lookup(dn)

    lookup_async = lookup

    async def _addChild(
        self,
        rdn: distinguishedname.RelativeDistinguishedName | str | bytes,
        attributes: interfaces.Attributes,
    ) -> "LDIFTreeEntry":
        rdn = distinguishedname.RelativeDistinguishedName(rdn)
        for c in await self._child_entries():
            if c.dn.split()[0] == rdn:
                raise ldaperrors.LDAPEntryAlreadyExists(c.dn.getText())

        dn = distinguishedname.DistinguishedName(listOfRDNs=(rdn,) + self.dn.split())
        e = entry.BaseLDAPEntry(dn, attributes)
        if not await self.path.exists():
            await self.path.mkdir()
        fileName = self.path / rdn.getText()
        tmp = fileName.with_name(f"{fileName.name}.{uuid.uuid4()!s}.tmp")
        await tmp.write_bytes(e.toWire())
        await tmp.rename(fileName.with_name(fileName.name + ".ldif"))
        dirName = self.path / ("%s.dir" % rdn.getText())
        return await self.__class__.open(dirName, dn)

    async def addChild(
        self,
        rdn: distinguishedname.RelativeDistinguishedName | str | bytes,
        attributes: interfaces.Attributes,
    ) -> "LDIFTreeEntry":
        return await self._addChild(rdn, attributes)

    addChild_async = addChild

    async def delete(self) -> "LDIFTreeEntry":
        if self.dn == "":
            raise LDAPCannotRemoveRootError()
        if await self._child_entries():
            raise ldaperrors.LDAPNotAllowedOnNonLeaf(
                "Cannot remove entry with children: %s" % self.dn.getText()
            )
        assert self.path.suffix == ".dir"
        await self.path.with_suffix(".ldif").unlink()
        return self

    delete_async = delete

    async def deleteChild(
        self, rdn: distinguishedname.RelativeDistinguishedName | str | bytes
    ) -> "LDIFTreeEntry":
        if not isinstance(rdn, distinguishedname.RelativeDistinguishedName):
            rdn = distinguishedname.RelativeDistinguishedName(stringValue=rdn)
        for c in await self._child_entries():
            if c.dn.split()[0] == rdn:
                return await c.delete()
        raise ldaperrors.LDAPNoSuchObject(rdn.getText())

    deleteChild_async = deleteChild

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.path!r}, {self.dn.getText()!r})"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, LDIFTreeEntry):
            return NotImplemented
        return self.dn < other.dn

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, LDIFTreeEntry):
            return NotImplemented
        return self.dn > other.dn

    async def commit(self) -> bool:
        assert self.path.suffix == ".dir"
        entryPath = self.path.with_suffix("")
        try:
            return await _putEntry(entryPath, self)
        except Exception:
            logger.error("[ERROR] Could not commit entry: %s.", self.dn.getText())
            return False

    commit_async = commit

    async def move(self, newDN: interfaces.AnyDN) -> bool:
        if not isinstance(newDN, distinguishedname.DistinguishedName):
            newDN = distinguishedname.DistinguishedName(stringValue=newDN)
        if newDN.up() != self.dn.up():
            # climb up the tree to root
            rootDN = self.dn
            rootPath = self.path
            while rootDN != "":
                rootDN = rootDN.up()
                rootPath = rootPath.parent
            root = await self.__class__.open(path=rootPath, dn=rootDN)
            found = await root.lookup(newDN.up())
            assert isinstance(found, LDIFTreeEntry)
            newParent: LDIFTreeEntry | None = found
        else:
            newParent = None
        return await self._move2(newParent, newDN)

    move_async = move

    async def _move2(
        self,
        newParent: "LDIFTreeEntry | None",
        newDN: distinguishedname.DistinguishedName,
    ) -> bool:
        # remove old RDN attributes
        for attr in self.dn.split()[0].split():
            self[attr.attributeType].remove(attr.value)
        # add new RDN attributes
        for attr in newDN.split()[0].split():
            self[attr.attributeType].add(attr.value)
        newRDN = newDN.split()[0]
        srcdir = self.path.parent
        if newParent is None:
            dstdir = srcdir
        else:
            dstdir = newParent.path

        newpath = dstdir / ("%s.dir" % newRDN.getText())
        if await self.path.exists():
            await self.path.rename(newpath)
        assert self.path.suffix == ".dir"
        await self.path.with_suffix(".ldif").rename(
            dstdir / ("%s.ldif" % newRDN.getText())
        )
        self.dn = newDN
        self.path = newpath
        return await self.commit()


if __name__ == "__main__":
    raise SystemExit("Use the AnyIO server entrypoints instead of the legacy demo.")
