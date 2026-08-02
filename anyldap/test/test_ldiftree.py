"""
Test cases for LDIF directory tree writing/reading.
"""
import errno
import logging
import os
import random
import shutil
import subprocess
import sys
import unittest as stdlib_unittest

import pytest

from anyldap import delta, entry, ldiftree
from anyldap.entry import BaseLDAPEntry
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldifprotocol
from anyldap.test import util
from anyldap.test._testing import capture_logs

pytestmark = pytest.mark.anyio


def writeFile(path, content):
    with open(path, "wb") as f:
        f.write(content)


def _readFile(path):
    with open(path, "rb") as f:
        return f.read()


def _moved(dn):
    """The entry a `ou=moved` rename is expected to produce."""
    return BaseLDAPEntry(
        dn=dn, attributes={b"objectClass": [b"a", b"b"], b"ou": [b"moved"]}
    )


skipIfWindowsOrRoot = stdlib_unittest.skipIf(
    sys.platform == "win32" or os.getuid() == 0,
    "Can't test on windows or as root",
)


skipIfWindows = stdlib_unittest.skipIf(
    sys.platform == "win32",
    "TODO: fails on windows",
)


class RandomizedListdir:
    """
    Base class that makes os.listdir return its members in a random order, so
    tests cannot quietly depend on directory ordering.
    """

    @pytest.fixture(autouse=True)
    def _randomize_listdir(self, monkeypatch):
        real_listdir = os.listdir

        def randomListdir(*args, **kwargs):
            r = real_listdir(*args, **kwargs)
            random.shuffle(r)
            return r

        monkeypatch.setattr(os, "listdir", randomListdir)
        self._restore_modes = []
        yield
        for path, mode in reversed(self._restore_modes):
            os.chmod(path, mode)

    def chmod(self, path, mode):
        self._restore_modes.append((path, os.stat(path).st_mode))
        os.chmod(path, mode)


class TestDir2LDIF(RandomizedListdir):
    @pytest.fixture(autouse=True)
    def _tree(self, tmp_path):
        self.tree = str(tmp_path / "tree")
        os.mkdir(self.tree)
        com = os.path.join(self.tree, "dc=com.dir")
        os.mkdir(com)
        example = os.path.join(com, "dc=example.dir")
        os.mkdir(example)
        writeFile(
            os.path.join(example, "cn=foo.ldif"),
            b"""\
dn: cn=foo,dc=example,dc=com
cn: foo
objectClass: top

""",
        )
        writeFile(
            os.path.join(example, "cn=bad-two-entries.ldif"),
            b"""\
dn: cn=bad-two-entries,dc=example,dc=com
cn: bad-two-entries
objectClass: top

dn: cn=more,dc=example,dc=com
cn: more
objectClass: top

""",
        )
        writeFile(
            os.path.join(example, "cn=bad-missing-end.ldif"),
            b"""\
dn: cn=bad-missing-end,dc=example,dc=com
cn: bad-missing-end
objectClass: top
""",
        )
        writeFile(os.path.join(example, "cn=bad-empty.ldif"), b"")
        writeFile(os.path.join(example, "cn=bad-only-newline.ldif"), b"\n")
        sales = os.path.join(example, "ou=Sales.dir")
        os.mkdir(sales)
        writeFile(
            os.path.join(sales, "cn=sales-thingie.ldif"),
            b"""\
dn: cn=sales-thingie,ou=Sales,dc=example,dc=com
cn: sales-thingie
objectClass: top

""",
        )

    async def testSimpleRead(self):
        want = BaseLDAPEntry(
            dn=b"cn=foo,dc=example,dc=com",
            attributes={
                b"objectClass": [b"top"],
                b"cn": [b"foo"],
            },
        )
        assert await ldiftree.get(self.tree, want.dn) == want

    @skipIfWindowsOrRoot
    async def testNoAccess(self):
        self.chmod(
            os.path.join(self.tree, "dc=com.dir", "dc=example.dir", "cn=foo.ldif"), 0
        )
        with pytest.raises(OSError) as excinfo:
            await ldiftree.get(self.tree, "cn=foo,dc=example,dc=com")
        assert excinfo.value.errno == errno.EACCES

    async def gettingDNRaises(self, dn, exceptionClass):
        with pytest.raises(exceptionClass):
            await ldiftree.get(self.tree, dn)

    async def testMultipleError(self):
        await self.gettingDNRaises(
            "cn=bad-two-entries,dc=example,dc=com",
            ldiftree.LDIFTreeEntryContainsMultipleEntries,
        )

    async def testMissingEndError(self):
        await self.gettingDNRaises(
            "cn=bad-missing-end,dc=example,dc=com",
            ldiftree.LDIFTreeEntryContainsNoEntries,
        )

    async def testEmptyError(self):
        await self.gettingDNRaises(
            "cn=bad-empty,dc=example,dc=com", ldiftree.LDIFTreeEntryContainsNoEntries
        )

    async def testOnlyNewlineError(self):
        await self.gettingDNRaises(
            "cn=bad-only-newline,dc=example,dc=com",
            ldifprotocol.LDIFLineWithoutSemicolonError,
        )

    async def testTreeBranches(self):
        want = BaseLDAPEntry(
            dn=b"cn=sales-thingie,ou=Sales,dc=example,dc=com",
            attributes={
                b"objectClass": [b"top"],
                b"cn": [b"sales-thingie"],
            },
        )
        assert await ldiftree.get(self.tree, want.dn) == want


class TestLDIF2Dir(RandomizedListdir):
    @pytest.fixture(autouse=True)
    def _tree(self, tmp_path):
        self.tree = str(tmp_path / "tree")
        os.mkdir(self.tree)
        com = os.path.join(self.tree, "dc=com.dir")
        os.mkdir(com)
        example = os.path.join(com, "dc=example.dir")
        os.mkdir(example)
        writeFile(
            os.path.join(example, "cn=pre-existing.ldif"),
            b"""\
dn: cn=pre-existing,dc=example,dc=com
cn: pre-existing
objectClass: top

""",
        )
        writeFile(
            os.path.join(example, "ou=OrgUnit.ldif"),
            b"""\
dn: ou=OrgUnit,dc=example,dc=com
ou: OrgUnit
objectClass: organizationalUnit

""",
        )

    async def testSimpleWrite(self):
        e = BaseLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["top"],
                "cn": ["foo"],
            },
        )
        await ldiftree.put(self.tree, e)
        self._cb_testSimpleWrite()

    def _cb_testSimpleWrite(self):
        path = os.path.join(self.tree, "dc=com.dir", "dc=example.dir", "cn=foo.ldif")
        assert os.path.isfile(path)
        assert _readFile(path) == (b"""\
dn: cn=foo,dc=example,dc=com
objectClass: top
cn: foo

""")

    async def testDirCreation(self):
        e = BaseLDAPEntry(
            dn="cn=create-me,ou=OrgUnit,dc=example,dc=com",
            attributes={
                "objectClass": ["top"],
                "cn": ["create-me"],
            },
        )
        await ldiftree.put(self.tree, e)
        self._cb_testDirCreation()

    def _cb_testDirCreation(self):
        path = os.path.join(
            self.tree,
            "dc=com.dir",
            "dc=example.dir",
            "ou=OrgUnit.dir",
            "cn=create-me.ldif",
        )
        assert os.path.isfile(path)
        assert _readFile(path) == (b"""\
dn: cn=create-me,ou=OrgUnit,dc=example,dc=com
objectClass: top
cn: create-me

""")

    async def testDirExists(self):
        e = BaseLDAPEntry(
            dn="cn=create-me,ou=OrgUnit,dc=example,dc=com",
            attributes={
                "objectClass": ["top"],
                "cn": ["create-me"],
            },
        )
        dirpath = os.path.join(
            self.tree, "dc=com.dir", "dc=example.dir", "ou=OrgUnit.dir"
        )
        os.mkdir(dirpath)
        await ldiftree.put(self.tree, e)
        self._cb_testDirExists(dirpath)

    def _cb_testDirExists(self, dirpath):
        path = os.path.join(dirpath, "cn=create-me.ldif")
        assert os.path.isfile(path)
        assert _readFile(path) == (b"""\
dn: cn=create-me,ou=OrgUnit,dc=example,dc=com
objectClass: top
cn: create-me

""")

    async def testMissingLinkError(self):
        e = BaseLDAPEntry(
            dn="cn=bad-create,ou=NoSuchOrgUnit,dc=example,dc=com",
            attributes={
                "objectClass": ["top"],
                "cn": ["bad-create"],
            },
        )

        with pytest.raises(ldiftree.LDIFTreeNoSuchObject):
            await ldiftree.put(self.tree, e)

    async def testAddTopLevel(self):
        e = BaseLDAPEntry(
            dn="dc=org",
            attributes={
                "objectClass": ["dcObject"],
                "dc": ["org"],
            },
        )
        await ldiftree.put(self.tree, e)
        self._cb_testAddTopLevel()

    def _cb_testAddTopLevel(self):
        path = os.path.join(self.tree, "dc=org.ldif")
        assert os.path.isfile(path)
        assert _readFile(path) == (b"""\
dn: dc=org
objectClass: dcObject
dc: org

""")


class TestLDIFTreeEntry(RandomizedListdir):
    """
    Tests for LDIFTreeEntry.
    """

    # TODO share the actual tests with inmemory and any other
    # implementations of the same interface
    @pytest.fixture(autouse=True)
    def _tree(self, tmp_path):
        self.tree = str(tmp_path / "tree")
        os.mkdir(self.tree)
        com = os.path.join(self.tree, "dc=com.dir")
        os.mkdir(com)
        example = os.path.join(com, "dc=example.dir")
        os.mkdir(example)
        meta = os.path.join(example, "ou=metasyntactic.dir")
        os.mkdir(meta)
        writeFile(
            os.path.join(example, "ou=metasyntactic.ldif"),
            b"""\
dn: ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
ou: metasyntactic

""",
        )
        foo = os.path.join(meta, "cn=foo.dir")
        writeFile(
            os.path.join(meta, "cn=foo.ldif"),
            b"""\
dn: cn=foo,ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
cn: foo

""",
        )
        bar = os.path.join(meta, "cn=bar.dir")
        writeFile(
            os.path.join(meta, "cn=bar.ldif"),
            b"""\
dn: cn=bar,ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
cn: bar

""",
        )
        empty = os.path.join(example, "ou=empty.dir")
        writeFile(
            os.path.join(example, "ou=empty.ldif"),
            b"""\
dn: ou=empty,dc=example,dc=com
objectClass: a
objectClass: b
ou: empty

""",
        )
        oneChild = os.path.join(example, "ou=oneChild.dir")
        os.mkdir(oneChild)
        writeFile(
            os.path.join(example, "ou=oneChild.ldif"),
            b"""\
dn: ou=oneChild,dc=example,dc=com
objectClass: a
objectClass: b
ou: oneChild

""",
        )
        theChild = os.path.join(oneChild, "cn=theChild.dir")
        writeFile(
            os.path.join(oneChild, "cn=theChild.ldif"),
            b"""\
dn: cn=theChild,ou=oneChild,dc=example,dc=com
objectClass: a
objectClass: b
cn: theChild

""",
        )
        # Invalid file
        writeFile(os.path.join(oneChild, "cn=invalidChild.lddd"), b"invalid data")

        self.root = ldiftree.LDIFTreeEntry(self.tree)
        self.example = ldiftree.LDIFTreeEntry(example, "dc=example,dc=com")
        self.empty = ldiftree.LDIFTreeEntry(empty, "ou=empty,dc=example,dc=com")
        self.meta = ldiftree.LDIFTreeEntry(meta, "ou=metasyntactic,dc=example,dc=com")
        self.foo = ldiftree.LDIFTreeEntry(
            foo, "cn=foo,ou=metasyntactic,dc=example,dc=com"
        )
        self.bar = ldiftree.LDIFTreeEntry(
            bar, "cn=bar,ou=metasyntactic,dc=example,dc=com"
        )
        self.oneChild = ldiftree.LDIFTreeEntry(
            oneChild, "ou=oneChild,dc=example,dc=com"
        )
        self.theChild = ldiftree.LDIFTreeEntry(
            theChild, "cn=theChild,ou=oneChild,dc=example,dc=com"
        )

    async def test_children_empty(self):
        assert await self.empty.children() == []

    async def test_children_oneChild(self):
        self._cb_test_children_oneChild(await self.oneChild.children())

    def _cb_test_children_oneChild(self, children):
        assert len(children) == 1
        got = [e.dn for e in children]
        want = ["cn=theChild,ou=oneChild,dc=example,dc=com"]
        got.sort()
        want.sort()
        assert got == want

    async def test_children_repeat(self):
        """Test that .children() returns a copy of the data so that modifying it does not affect behaviour."""
        children1 = await self.oneChild.children()
        assert len(children1) == 1

        children1.pop()

        assert len(await self.oneChild.children()) == 1

    async def test_children_twoChildren(self):
        self._cb_test_children_twoChildren(await self.meta.children())

    def _cb_test_children_twoChildren(self, children):
        assert len(children) == 2
        want = [
            "cn=foo,ou=metasyntactic,dc=example,dc=com",
            "cn=bar,ou=metasyntactic,dc=example,dc=com",
        ]
        got = [e.dn for e in children]
        got.sort()
        want.sort()
        assert got == want

    async def test_children_twoChildren_callback(self):
        children = []
        r = await self.meta.children(callback=children.append)
        self._cb_test_children_twoChildren_callback(r, children)

    def _cb_test_children_twoChildren_callback(self, r, children):
        assert r is None
        assert len(children) == 2
        want = [
            "cn=foo,ou=metasyntactic,dc=example,dc=com",
            "cn=bar,ou=metasyntactic,dc=example,dc=com",
        ]
        got = [e.dn for e in children]
        got.sort()
        want.sort()
        assert got == want

    @skipIfWindowsOrRoot
    async def test_children_noAccess_dir_noRead(self):
        self.chmod(self.meta.path, 0o300)
        with pytest.raises(OSError) as excinfo:
            await self.meta.children()
        assert excinfo.value.errno == errno.EACCES
        self.chmod(self.meta.path, 0o755)

    @skipIfWindowsOrRoot
    async def test_children_noAccess_dir_noExec(self):
        self.chmod(self.meta.path, 0o600)
        with pytest.raises(OSError) as excinfo:
            await self.meta.children()
        assert excinfo.value.errno == errno.EACCES
        self.chmod(self.meta.path, 0o755)

    @skipIfWindowsOrRoot
    async def test_children_noAccess_file(self):
        self.chmod(os.path.join(self.meta.path, "cn=foo.ldif"), 0)
        with pytest.raises(OSError) as excinfo:
            await self.meta.children()
        assert excinfo.value.errno == errno.EACCES

    async def test_addChild(self):
        self.empty.addChild(
            rdn="a=b",
            attributes={
                "objectClass": ["a", "b"],
                "a": "b",
            },
        )
        self._cb_test_addChild(await self.empty.children())

    def _cb_test_addChild(self, children):
        assert len(children) == 1
        got = [e.dn for e in children]
        want = [
            "a=b,ou=empty,dc=example,dc=com",
        ]
        got.sort()
        want.sort()
        assert got == want

    def test_addChild_Exists(self):
        with pytest.raises(ldaperrors.LDAPEntryAlreadyExists):
            self.meta.addChild(
                rdn="cn=foo",
                attributes={
                    "objectClass": ["a"],
                    "cn": "foo",
                },
            )

    def test_addChild_to_existing_directory(self):
        child = self.meta.addChild(
            rdn="cn=baz",
            attributes={"objectClass": ["a"], "cn": ["baz"]},
        )
        assert child.dn == "cn=baz,ou=metasyntactic,dc=example,dc=com"

    async def test_deleteChild_accepts_relative_distinguished_name(self):
        result = await self.meta.deleteChild(
            distinguishedname.RelativeDistinguishedName("cn=bar")
        )
        assert result == self.bar

    async def test_move_accepts_distinguished_name(self):
        result = await self.empty.move(
            distinguishedname.DistinguishedName("ou=moved,dc=example,dc=com")
        )
        assert result
        assert self.empty.dn == "ou=moved,dc=example,dc=com"

    def test_parent(self):
        assert self.foo.parent() == self.meta
        assert self.meta.parent() == self.example
        assert self.root.parent() is None

    async def test_subtree_empty(self):
        assert len(await self.empty.subtree()) == 1

    async def test_subtree_oneChild(self):
        self._cb_test_subtree_oneChild(await self.oneChild.subtree())

    def _cb_test_subtree_oneChild(self, results):
        got = results
        want = [
            self.oneChild,
            self.theChild,
        ]
        assert got == want

    async def test_subtree_oneChild_cb(self):
        got = []
        r = await self.oneChild.subtree(got.append)
        self._cb_test_subtree_oneChild_cb(r, got)

    def _cb_test_subtree_oneChild_cb(self, r, got):
        assert r is None

        want = [
            self.oneChild,
            self.theChild,
        ]
        assert got == want

    async def test_subtree_many(self):
        result = await self.example.subtree()

        expected = [
            self.example,
            self.oneChild,
            self.theChild,
            self.empty,
            self.meta,
            self.bar,
            self.foo,
        ]
        util.assert_permutation(expected, result)

    async def test_subtree_many_cb(self):
        got = []
        result = await self.example.subtree(callback=got.append)

        assert result is None
        expected = [
            self.example,
            self.oneChild,
            self.theChild,
            self.empty,
            self.meta,
            self.bar,
            self.foo,
        ]
        util.assert_permutation(expected, got)

    async def test_lookup_fail(self):
        dn = "cn=thud,ou=metasyntactic,dc=example,dc=com"
        with pytest.raises(ldaperrors.LDAPNoSuchObject) as excinfo:
            await self.root.lookup(dn)
        assert excinfo.value.message == dn

    async def test_lookup_fail_outOfTree(self):
        dn = "dc=invalid"
        with pytest.raises(ldaperrors.LDAPNoSuchObject) as excinfo:
            await self.root.lookup(dn)
        assert excinfo.value.message == dn

    async def test_lookup_fail_outOfTree_2(self):
        dn = "dc=invalid"
        with pytest.raises(ldaperrors.LDAPNoSuchObject) as excinfo:
            await self.example.lookup(dn)
        assert excinfo.value.message == dn

    async def test_lookup_fail_multipleError(self):
        writeFile(
            os.path.join(self.example.path, "cn=bad-two-entries.ldif"),
            b"""\
dn: cn=bad-two-entries,dc=example,dc=com
cn: bad-two-entries
objectClass: top

dn: cn=more,dc=example,dc=com
cn: more
objectClass: top

""",
        )
        with pytest.raises(ldiftree.LDIFTreeEntryContainsMultipleEntries):
            await self.example.lookup("cn=bad-two-entries,dc=example,dc=com")

    async def test_lookup_fail_emptyError(self):
        writeFile(os.path.join(self.example.path, "cn=bad-empty.ldif"), b"")
        with pytest.raises(ldiftree.LDIFTreeEntryContainsNoEntries):
            await self.example.lookup("cn=bad-empty,dc=example,dc=com")

    async def test_lookup_deep(self):
        dn = "cn=bar,ou=metasyntactic,dc=example,dc=com"
        assert await self.root.lookup(dn) == self.bar

    async def test_delete_root(self):
        with pytest.raises(ldiftree.LDAPCannotRemoveRootError):
            await self.root.delete()

    async def test_delete_nonLeaf(self):
        with pytest.raises(ldaperrors.LDAPNotAllowedOnNonLeaf):
            await self.meta.delete()

    async def test_delete(self):
        assert await self.foo.delete() == self.foo
        assert await self.meta.children() == [self.bar]

    async def test_deleteChild(self):
        assert await self.meta.deleteChild("cn=bar") == self.bar
        assert await self.meta.children() == [self.foo]

    async def test_deleteChild_NonExisting(self):
        with pytest.raises(ldaperrors.LDAPNoSuchObject):
            await self.root.deleteChild("cn=not-exist")

    def test_setPassword(self):
        self.foo.setPassword(b"s3krit", salt=b"\xf2\x4a")
        assert "userPassword" in self.foo
        assert self.foo["userPassword"] == [b"{SSHA}0n/Iw1NhUOKyaI9gm9v5YsO3ZInySg=="]

    async def test_setPassword_noSalt(self):
        self.foo.setPassword(b"s3krit")
        assert "userPassword" in self.foo
        assert await self.foo.bind("s3krit") is self.foo
        with pytest.raises(ldaperrors.LDAPInvalidCredentials):
            await self.foo.bind("s4krit")

    async def test_diffTree_self(self):
        assert await self.root.diffTree(self.root) == []

    async def test_diffTree_copy(self, tmp_path):
        otherDir = str(tmp_path / "other")
        shutil.copytree(self.tree, otherDir)
        other = ldiftree.LDIFTreeEntry(otherDir)
        assert await self.root.diffTree(other) == []

    async def test_diffTree_addChild(self, tmp_path):
        otherDir = str(tmp_path / "other")
        shutil.copytree(self.tree, otherDir)
        other = ldiftree.LDIFTreeEntry(otherDir)
        e = entry.BaseLDAPEntry(dn="cn=foo,dc=example,dc=com")
        await ldiftree.put(otherDir, e)

        added = await other.lookup("cn=foo,dc=example,dc=com")
        assert await self.root.diffTree(other) == [delta.AddOp(added)]

    async def test_diffTree_delChild(self, tmp_path):
        otherDir = str(tmp_path / "other")
        shutil.copytree(self.tree, otherDir)
        other = ldiftree.LDIFTreeEntry(otherDir)

        otherEmpty = await other.lookup("ou=empty,dc=example,dc=com")
        await otherEmpty.delete()

        assert await self.root.diffTree(other) == [delta.DeleteOp(self.empty)]

    async def test_diffTree_edit_failure(self, tmp_path):
        otherDir = str(tmp_path / "other")
        shutil.copytree(self.tree, otherDir)
        other = ldiftree.LDIFTreeEntry(otherDir)

        otherEmpty = await other.lookup("ou=empty,dc=example,dc=com")
        otherEmpty["foo"] = ["bar"]
        shutil.rmtree(otherDir)
        cleanups = []
        messages = capture_logs(cleanups, level=logging.ERROR)
        try:
            assert not (await otherEmpty.commit())
        finally:
            for cleanup in cleanups:
                cleanup()
        assert messages[0] == "[ERROR] Could not commit entry: ou=empty,dc=example,dc=com."

    @skipIfWindows
    async def test_diffTree_edit(self, tmp_path):
        otherDir = str(tmp_path / "other")
        shutil.copytree(self.tree, otherDir)
        other = ldiftree.LDIFTreeEntry(otherDir)

        otherEmpty = await other.lookup("ou=empty,dc=example,dc=com")
        otherEmpty["foo"] = ["bar"]
        await otherEmpty.commit()

        assert await self.root.diffTree(other) == [
            delta.ModifyOp(self.empty.dn, [delta.Add(b"foo", [b"bar"])]),
        ]

    @skipIfWindows
    async def test_move_noChildren_sameSuperior(self):
        await self.empty.move("ou=moved,dc=example,dc=com")

        assert set(await self.example.children()) == {
            self.meta,
            _moved("ou=moved,dc=example,dc=com"),
            self.oneChild,
        }

    @skipIfWindows
    async def test_move_children_sameSuperior(self):
        await self.meta.move("ou=moved,dc=example,dc=com")

        assert set(await self.example.children()) == {
            _moved("ou=moved,dc=example,dc=com"),
            self.empty,
            self.oneChild,
        }

    @skipIfWindows
    async def test_move_noChildren_newSuperior(self):
        await self.empty.move("ou=moved,ou=oneChild,dc=example,dc=com")

        assert set(await self.example.children()) == {self.meta, self.oneChild}
        assert set(await self.oneChild.children()) == {
            self.theChild,
            _moved("ou=moved,ou=oneChild,dc=example,dc=com"),
        }

    @skipIfWindows
    async def test_move_children_newSuperior(self):
        await self.meta.move("ou=moved,ou=oneChild,dc=example,dc=com")

        assert set(await self.example.children()) == {self.empty, self.oneChild}
        assert set(await self.oneChild.children()) == {
            self.theChild,
            _moved("ou=moved,ou=oneChild,dc=example,dc=com"),
        }

    def testCompareOtherTypes(self):
        """
        It can't be compared with other types.
        """
        with pytest.raises(TypeError):
            self.example < object()

        with pytest.raises(TypeError):
            self.example > object()

    def testCompareGreater(self):
        """
        It is compared with other entries based on DN, where child is
        greater than the parent.
        """
        assert self.oneChild > self.example
        assert not (self.example > self.oneChild)

    def testCompareLess(self):
        """
        It is compared with other entries based on DN, where parent is
        less than the child.
        """
        assert self.example < self.oneChild
        assert not (self.oneChild < self.example)

    def testRepresentation(self):
        assert self.example.dn.getText() in repr(self.example)


def test_module_entrypoint_explains_legacy_demo_removal():
    result = subprocess.run(
        [sys.executable, "-m", "anyldap.ldiftree"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "AnyIO server entrypoints" in result.stderr
