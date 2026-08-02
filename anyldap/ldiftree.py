"""
Manage LDAP data as a tree of LDIF files.
"""
import errno
import os
import uuid

import anyio
from zope.interface import implementer

from anyldap import attributeset, entry, entryhelpers, interfaces
from anyldap._encoder import to_unicode
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldifprotocol
from anyldap.runtime import ConnectionDone, Failure, logger


class LDIFTreeEntryContainsMultipleEntries(Exception):
    """LDIFTree entry contains multiple LDIF entries."""


class LDIFTreeEntryContainsNoEntries(Exception):
    """LDIFTree entry does not contain a valid LDIF entry."""


class LDIFTreeNoSuchObject(Exception):
    """LDIFTree does not contain such entry."""


class LDAPCannotRemoveRootError(ldaperrors.LDAPNamingViolation):
    """Cannot remove root of LDAP tree"""


class StoreParsedLDIF(ldifprotocol.LDIF):
    def __init__(self):
        super().__init__()
        self.done = False
        self.seen = []

    def gotEntry(self, obj):
        self.seen.append(obj)

    def connectionLost(self, reason):
        self.done = True


async def get(path, dn):
    return await _get(path, dn)


async def _get(path, dn):
    path = to_unicode(path)
    dn = distinguishedname.DistinguishedName(dn)
    l = list(dn.split())
    assert len(l) >= 1
    l.reverse()

    parser = StoreParsedLDIF()

    entry = os.path.join(path, *("%s.dir" % rdn.getText() for rdn in l[:-1]))
    entry = os.path.join(entry, "%s.ldif" % l[-1].getText())
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


async def _putEntry(fileName, entry):
    """fileName is without extension."""
    tmp = anyio.Path(f"{fileName}.{uuid.uuid4()!s}.tmp")
    await tmp.write_bytes(entry.toWire())
    await tmp.rename(fileName + ".ldif")
    return True


async def _put(path, entry):
    path = to_unicode(path)
    l = list(entry.dn.split())
    assert len(l) >= 1
    l.reverse()

    entryRDN = l.pop()
    if l:
        grandParent = os.path.join(path, *("%s.dir" % rdn.getText() for rdn in l[:-1]))
        parentEntry = os.path.join(grandParent, "%s.ldif" % l[-1].getText())
        parentDir = os.path.join(grandParent, "%s.dir" % l[-1].getText())
        if not await anyio.Path(parentDir).exists():
            if not await anyio.Path(parentEntry).exists():
                raise LDIFTreeNoSuchObject(entry.dn.up())
            await anyio.Path(parentDir).mkdir(parents=True, exist_ok=True)
    else:
        parentDir = path
    return await _putEntry(
        os.path.join(parentDir, "%s" % entryRDN.getText()), entry
    )


async def put(path, entry):
    return await _put(path, entry)


@implementer(interfaces.IConnectedLDAPEntry)
class LDIFTreeEntry(
    entry.EditableLDAPEntry,
    entryhelpers.DiffTreeMixin,
    entryhelpers.SubtreeFromChildrenMixin,
    entryhelpers.MatchMixin,
    entryhelpers.SearchByTreeWalkingMixin,
):
    def __init__(self, path, dn=None, *a, **kw):
        """Build an entry without touching the filesystem.

        Reading an entry back off disk has to await, so a directly constructed
        entry starts out with no attributes; use :meth:`open` instead.
        """
        if dn is None:
            dn = ""
        entry.BaseLDAPEntry.__init__(self, dn, *a, **kw)
        self.path = to_unicode(path)

    @classmethod
    async def open(cls, path, dn=None, *a, **kw):
        """Build an entry and read its attributes from disk."""
        self = cls(path, dn, *a, **kw)
        if self.dn != "":
            await self._load()
        return self

    async def _load(self):
        assert self.path.endswith(".dir")
        entryPath = "%s.ldif" % self.path[: -len(".dir")]

        parser = StoreParsedLDIF()

        try:
            f = await anyio.Path(entryPath).open("rb")
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

    async def parent(self):
        if self.dn == "":
            # root
            return None
        parentPath, _ = os.path.split(self.path)
        return await self.__class__.open(parentPath, self.dn.up())

    async def _child_entries(self):
        children = []
        try:
            filenames = [item.name async for item in anyio.Path(self.path).iterdir()]
        except OSError as e:
            if e.errno == errno.ENOENT:
                pass
            else:
                raise
        else:
            seen = set()
            for fn in filenames:
                base, ext = os.path.splitext(fn)
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
                e = await self.__class__.open(
                    os.path.join(self.path, base + ".dir"), dn
                )
                children.append(e)
        return children

    async def children(self, callback=None):
        children = await self._child_entries()
        if callback is None:
            return children
        for c in children:
            callback(c)
        return None

    children_async = children

    async def lookup(self, dn):
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
        path = os.path.join(self.path, "%s.dir" % rdn.getText())
        entry = os.path.join(self.path, "%s.ldif" % rdn.getText())
        if not await anyio.Path(path).is_dir() and not await anyio.Path(entry).is_file():
            raise ldaperrors.LDAPNoSuchObject(dn.getText())
        childDN = distinguishedname.DistinguishedName(listOfRDNs=(rdn,) + me)
        c = await self.__class__.open(path, childDN)
        return await c.lookup(dn)

    lookup_async = lookup

    async def _addChild(self, rdn, attributes):
        rdn = distinguishedname.RelativeDistinguishedName(rdn)
        for c in await self._child_entries():
            if c.dn.split()[0] == rdn:
                raise ldaperrors.LDAPEntryAlreadyExists(c.dn.getText())

        dn = distinguishedname.DistinguishedName(listOfRDNs=(rdn,) + self.dn.split())
        e = entry.BaseLDAPEntry(dn, attributes)
        if not await anyio.Path(self.path).exists():
            await anyio.Path(self.path).mkdir()
        fileName = os.path.join(self.path, "%s" % rdn.getText())
        tmp = anyio.Path(f"{fileName}.{uuid.uuid4()!s}.tmp")
        await tmp.write_bytes(e.toWire())
        await tmp.rename(fileName + ".ldif")
        dirName = os.path.join(self.path, "%s.dir" % rdn.getText())
        return await self.__class__.open(dirName, dn)

    async def addChild(self, rdn, attributes):
        return await self._addChild(rdn, attributes)

    addChild_async = addChild

    async def delete(self):
        if self.dn == "":
            raise LDAPCannotRemoveRootError()
        if await self._child_entries():
            raise ldaperrors.LDAPNotAllowedOnNonLeaf(
                "Cannot remove entry with children: %s" % self.dn.getText()
            )
        assert self.path.endswith(".dir")
        entryPath = "%s.ldif" % self.path[: -len(".dir")]
        await anyio.Path(entryPath).unlink()
        return self

    delete_async = delete

    async def deleteChild(self, rdn):
        if not isinstance(rdn, distinguishedname.RelativeDistinguishedName):
            rdn = distinguishedname.RelativeDistinguishedName(stringValue=rdn)
        for c in await self._child_entries():
            if c.dn.split()[0] == rdn:
                return await c.delete()
        raise ldaperrors.LDAPNoSuchObject(rdn.getText())

    deleteChild_async = deleteChild

    def __repr__(self):
        return f"{self.__class__.__name__}({self.path!r}, {self.dn.getText()!r})"

    def __lt__(self, other):
        if not isinstance(other, LDIFTreeEntry):
            return NotImplemented
        return self.dn < other.dn

    def __gt__(self, other):
        if not isinstance(other, LDIFTreeEntry):
            return NotImplemented
        return self.dn > other.dn

    async def commit(self):
        assert self.path.endswith(".dir")
        entryPath = self.path[: -len(".dir")]
        try:
            return await _putEntry(entryPath, self)
        except Exception:
            logger.error("[ERROR] Could not commit entry: %s.", self.dn.getText())
            return False

    commit_async = commit

    async def move(self, newDN):
        if not isinstance(newDN, distinguishedname.DistinguishedName):
            newDN = distinguishedname.DistinguishedName(stringValue=newDN)
        if newDN.up() != self.dn.up():
            # climb up the tree to root
            rootDN = self.dn
            rootPath = self.path
            while rootDN != "":
                rootDN = rootDN.up()
                rootPath = os.path.dirname(rootPath)
            root = await self.__class__.open(path=rootPath, dn=rootDN)
            newParent = await root.lookup(newDN.up())
        else:
            newParent = None
        return await self._move2(newParent, newDN)

    move_async = move

    async def _move2(self, newParent, newDN):
        # remove old RDN attributes
        for attr in self.dn.split()[0].split():
            self[attr.attributeType].remove(attr.value)
        # add new RDN attributes
        for attr in newDN.split()[0].split():
            self[attr.attributeType].add(attr.value)
        newRDN = newDN.split()[0]
        srcdir = os.path.dirname(self.path)
        if newParent is None:
            dstdir = srcdir
        else:
            dstdir = newParent.path

        newpath = os.path.join(dstdir, "%s.dir" % newRDN.getText())
        if await anyio.Path(self.path).exists():
            await anyio.Path(self.path).rename(newpath)
        basename, ext = os.path.splitext(self.path)
        assert ext == ".dir"
        await anyio.Path("%s.ldif" % basename).rename(
            os.path.join(dstdir, "%s.ldif" % newRDN.getText())
        )
        self.dn = newDN
        self.path = newpath
        return await self.commit()


if __name__ == "__main__":
    raise SystemExit("Use the AnyIO server entrypoints instead of the legacy demo.")
