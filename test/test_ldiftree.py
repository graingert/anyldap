"""
Test cases for LDIF directory tree writing/reading.
"""
import contextlib
import errno
import logging
import os
import pathlib
import random
import shutil
import subprocess
import sys
import unittest as stdlib_unittest
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from unittest import mock

import anyio
import pytest

from anyldap import delta, entry, interfaces, ldiftree
from anyldap.entry import BaseLDAPEntry
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldifprotocol

from . import util
from ._testing import capture_logs

pytestmark = pytest.mark.anyio


async def writeFile(path: str | pathlib.Path, content: bytes) -> None:
    await anyio.Path(path).write_bytes(content)


async def _readFile(path: str | pathlib.Path) -> bytes:
    return await anyio.Path(path).read_bytes()


def _moved(dn: str) -> BaseLDAPEntry:
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


@contextlib.contextmanager
def randomizedListdir() -> Iterator[mock.MagicMock]:
    """Make directory listings come back in a random order.

    Patches anyio.Path.iterdir, which is what the tree walks; patching
    os.listdir instead would only bite on the CPython versions whose pathlib
    happens to be implemented in terms of it. Yields the mock, so a caller can
    assert the listing really went through it.
    """
    real_iterdir = anyio.Path.iterdir

    async def randomIterdir(path: anyio.Path) -> AsyncIterator[anyio.Path]:
        entries = [item async for item in real_iterdir(path)]
        random.shuffle(entries)
        for item in entries:
            yield item

    with mock.patch(
        "anyio.Path.iterdir", autospec=True, side_effect=randomIterdir
    ) as iterdir:
        yield iterdir


class RestoresModes:
    """Base class that puts back any file modes a test changed."""

    @pytest.fixture(autouse=True)
    def _restore_modes_after_chmod(self) -> Iterator[None]:
        self._restore_modes: list[tuple[str | os.PathLike[str], int]] = []
        yield
        for path, mode in reversed(self._restore_modes):
            os.chmod(path, mode)

    async def chmod(self, path: str | os.PathLike[str], mode: int) -> None:
        self._restore_modes.append((path, (await anyio.Path(path).stat()).st_mode))
        await anyio.Path(path).chmod(mode)


class TestDir2LDIF(RestoresModes):
    @pytest.fixture(autouse=True)
    async def _tree(self, tmp_path: pathlib.Path) -> None:
        self.tree = str(tmp_path / "tree")
        await anyio.Path(self.tree).mkdir()
        com = os.path.join(self.tree, "dc=com.dir")
        await anyio.Path(com).mkdir()
        example = os.path.join(com, "dc=example.dir")
        await anyio.Path(example).mkdir()
        await writeFile(
            os.path.join(example, "cn=foo.ldif"),
            b"""\
dn: cn=foo,dc=example,dc=com
cn: foo
objectClass: top

""",
        )
        await writeFile(
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
        await writeFile(
            os.path.join(example, "cn=bad-missing-end.ldif"),
            b"""\
dn: cn=bad-missing-end,dc=example,dc=com
cn: bad-missing-end
objectClass: top
""",
        )
        await writeFile(os.path.join(example, "cn=bad-empty.ldif"), b"")
        await writeFile(os.path.join(example, "cn=bad-only-newline.ldif"), b"\n")
        sales = os.path.join(example, "ou=Sales.dir")
        await anyio.Path(sales).mkdir()
        await writeFile(
            os.path.join(sales, "cn=sales-thingie.ldif"),
            b"""\
dn: cn=sales-thingie,ou=Sales,dc=example,dc=com
cn: sales-thingie
objectClass: top

""",
        )

    async def testSimpleRead(self) -> None:
        want = BaseLDAPEntry(
            dn=b"cn=foo,dc=example,dc=com",
            attributes={
                b"objectClass": [b"top"],
                b"cn": [b"foo"],
            },
        )
        assert await ldiftree.get(self.tree, want.dn) == want

    @skipIfWindowsOrRoot
    async def testNoAccess(self) -> None:
        await self.chmod(
            os.path.join(self.tree, "dc=com.dir", "dc=example.dir", "cn=foo.ldif"), 0
        )
        with pytest.raises(OSError) as excinfo:
            await ldiftree.get(self.tree, "cn=foo,dc=example,dc=com")
        assert excinfo.value.errno == errno.EACCES

    async def gettingDNRaises(
        self, dn: str, exceptionClass: type[BaseException]
    ) -> None:
        with pytest.raises(exceptionClass):
            await ldiftree.get(self.tree, dn)

    async def testMultipleError(self) -> None:
        await self.gettingDNRaises(
            "cn=bad-two-entries,dc=example,dc=com",
            ldiftree.LDIFTreeEntryContainsMultipleEntries,
        )

    async def testMissingEndError(self) -> None:
        await self.gettingDNRaises(
            "cn=bad-missing-end,dc=example,dc=com",
            ldiftree.LDIFTreeEntryContainsNoEntries,
        )

    async def testEmptyError(self) -> None:
        await self.gettingDNRaises(
            "cn=bad-empty,dc=example,dc=com", ldiftree.LDIFTreeEntryContainsNoEntries
        )

    async def testOnlyNewlineError(self) -> None:
        await self.gettingDNRaises(
            "cn=bad-only-newline,dc=example,dc=com",
            ldifprotocol.LDIFLineWithoutSemicolonError,
        )

    async def testTreeBranches(self) -> None:
        want = BaseLDAPEntry(
            dn=b"cn=sales-thingie,ou=Sales,dc=example,dc=com",
            attributes={
                b"objectClass": [b"top"],
                b"cn": [b"sales-thingie"],
            },
        )
        assert await ldiftree.get(self.tree, want.dn) == want


class TestLDIF2Dir(RestoresModes):
    @pytest.fixture(autouse=True)
    async def _tree(self, tmp_path: pathlib.Path) -> None:
        self.tree = str(tmp_path / "tree")
        await anyio.Path(self.tree).mkdir()
        com = os.path.join(self.tree, "dc=com.dir")
        await anyio.Path(com).mkdir()
        example = os.path.join(com, "dc=example.dir")
        await anyio.Path(example).mkdir()
        await writeFile(
            os.path.join(example, "cn=pre-existing.ldif"),
            b"""\
dn: cn=pre-existing,dc=example,dc=com
cn: pre-existing
objectClass: top

""",
        )
        await writeFile(
            os.path.join(example, "ou=OrgUnit.ldif"),
            b"""\
dn: ou=OrgUnit,dc=example,dc=com
ou: OrgUnit
objectClass: organizationalUnit

""",
        )

    async def testSimpleWrite(self) -> None:
        e = BaseLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["top"],
                "cn": ["foo"],
            },
        )
        await ldiftree.put(self.tree, e)
        await self._cb_testSimpleWrite()

    async def _cb_testSimpleWrite(self) -> None:
        path = os.path.join(self.tree, "dc=com.dir", "dc=example.dir", "cn=foo.ldif")
        assert os.path.isfile(path)
        assert await _readFile(path) == (b"""\
dn: cn=foo,dc=example,dc=com
objectClass: top
cn: foo

""")

    async def testDirCreation(self) -> None:
        e = BaseLDAPEntry(
            dn="cn=create-me,ou=OrgUnit,dc=example,dc=com",
            attributes={
                "objectClass": ["top"],
                "cn": ["create-me"],
            },
        )
        await ldiftree.put(self.tree, e)
        await self._cb_testDirCreation()

    async def _cb_testDirCreation(self) -> None:
        path = os.path.join(
            self.tree,
            "dc=com.dir",
            "dc=example.dir",
            "ou=OrgUnit.dir",
            "cn=create-me.ldif",
        )
        assert os.path.isfile(path)
        assert await _readFile(path) == (b"""\
dn: cn=create-me,ou=OrgUnit,dc=example,dc=com
objectClass: top
cn: create-me

""")

    async def testDirExists(self) -> None:
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
        await anyio.Path(dirpath).mkdir()
        await ldiftree.put(self.tree, e)
        await self._cb_testDirExists(dirpath)

    async def _cb_testDirExists(self, dirpath: str) -> None:
        path = os.path.join(dirpath, "cn=create-me.ldif")
        assert os.path.isfile(path)
        assert await _readFile(path) == (b"""\
dn: cn=create-me,ou=OrgUnit,dc=example,dc=com
objectClass: top
cn: create-me

""")

    async def testMissingLinkError(self) -> None:
        e = BaseLDAPEntry(
            dn="cn=bad-create,ou=NoSuchOrgUnit,dc=example,dc=com",
            attributes={
                "objectClass": ["top"],
                "cn": ["bad-create"],
            },
        )

        with pytest.raises(ldiftree.LDIFTreeNoSuchObject):
            await ldiftree.put(self.tree, e)

    async def testAddTopLevel(self) -> None:
        e = BaseLDAPEntry(
            dn="dc=org",
            attributes={
                "objectClass": ["dcObject"],
                "dc": ["org"],
            },
        )
        await ldiftree.put(self.tree, e)
        await self._cb_testAddTopLevel()

    async def _cb_testAddTopLevel(self) -> None:
        path = os.path.join(self.tree, "dc=org.ldif")
        assert os.path.isfile(path)
        assert await _readFile(path) == (b"""\
dn: dc=org
objectClass: dcObject
dc: org

""")


class TestLDIFTreeEntry(RestoresModes):
    """
    Tests for LDIFTreeEntry.
    """

    # TODO share the actual tests with inmemory and any other
    # implementations of the same interface
    @pytest.fixture(autouse=True)
    async def _tree(self, tmp_path: pathlib.Path) -> None:
        self.tree = str(tmp_path / "tree")
        await anyio.Path(self.tree).mkdir()
        com = os.path.join(self.tree, "dc=com.dir")
        await anyio.Path(com).mkdir()
        example = os.path.join(com, "dc=example.dir")
        await anyio.Path(example).mkdir()
        meta = os.path.join(example, "ou=metasyntactic.dir")
        await anyio.Path(meta).mkdir()
        await writeFile(
            os.path.join(example, "ou=metasyntactic.ldif"),
            b"""\
dn: ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
ou: metasyntactic

""",
        )
        foo = os.path.join(meta, "cn=foo.dir")
        await writeFile(
            os.path.join(meta, "cn=foo.ldif"),
            b"""\
dn: cn=foo,ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
cn: foo

""",
        )
        bar = os.path.join(meta, "cn=bar.dir")
        await writeFile(
            os.path.join(meta, "cn=bar.ldif"),
            b"""\
dn: cn=bar,ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
cn: bar

""",
        )
        empty = os.path.join(example, "ou=empty.dir")
        await writeFile(
            os.path.join(example, "ou=empty.ldif"),
            b"""\
dn: ou=empty,dc=example,dc=com
objectClass: a
objectClass: b
ou: empty

""",
        )
        oneChild = os.path.join(example, "ou=oneChild.dir")
        await anyio.Path(oneChild).mkdir()
        await writeFile(
            os.path.join(example, "ou=oneChild.ldif"),
            b"""\
dn: ou=oneChild,dc=example,dc=com
objectClass: a
objectClass: b
ou: oneChild

""",
        )
        theChild = os.path.join(oneChild, "cn=theChild.dir")
        await writeFile(
            os.path.join(oneChild, "cn=theChild.ldif"),
            b"""\
dn: cn=theChild,ou=oneChild,dc=example,dc=com
objectClass: a
objectClass: b
cn: theChild

""",
        )
        # Invalid file
        await writeFile(os.path.join(oneChild, "cn=invalidChild.lddd"), b"invalid data")

        self.root = await ldiftree.LDIFTreeEntry.open(self.tree)
        self.example = await ldiftree.LDIFTreeEntry.open(example, "dc=example,dc=com")
        self.empty = await ldiftree.LDIFTreeEntry.open(
            empty, "ou=empty,dc=example,dc=com"
        )
        self.meta = await ldiftree.LDIFTreeEntry.open(
            meta, "ou=metasyntactic,dc=example,dc=com"
        )
        self.foo = await ldiftree.LDIFTreeEntry.open(
            foo, "cn=foo,ou=metasyntactic,dc=example,dc=com"
        )
        self.bar = await ldiftree.LDIFTreeEntry.open(
            bar, "cn=bar,ou=metasyntactic,dc=example,dc=com"
        )
        self.oneChild = await ldiftree.LDIFTreeEntry.open(
            oneChild, "ou=oneChild,dc=example,dc=com"
        )
        self.theChild = await ldiftree.LDIFTreeEntry.open(
            theChild, "cn=theChild,ou=oneChild,dc=example,dc=com"
        )

    async def test_children_empty(self) -> None:
        with randomizedListdir() as iterdir:
            assert await self.empty.children() == []

        assert iterdir.mock_calls == [mock.call(self.empty.path)]

    async def test_children_oneChild(self) -> None:
        with randomizedListdir() as iterdir:
            children = await self.oneChild.children()
            assert children is not None

        assert iterdir.mock_calls == [mock.call(self.oneChild.path)]
        assert children is not None
        self._cb_test_children_oneChild(children)

    def _cb_test_children_oneChild(
        self, children: Sequence[interfaces.IWalkableLDAPEntry]
    ) -> None:
        assert len(children) == 1
        got = [e.dn for e in children]
        want = ["cn=theChild,ou=oneChild,dc=example,dc=com"]
        got.sort()
        want.sort()
        assert got == want

    async def test_children_repeat(self) -> None:
        """Test that .children() returns a copy of the data so that modifying it does not affect behaviour."""
        with randomizedListdir() as iterdir:
            children1 = await self.oneChild.children()
            assert children1 is not None
            assert children1 is not None
            assert len(children1) == 1

            children1.pop()

            again = await self.oneChild.children()
            assert again is not None
            assert again is not None
            assert len(again) == 1

        assert iterdir.mock_calls == [
            mock.call(self.oneChild.path),
            mock.call(self.oneChild.path),
        ]

    async def test_children_twoChildren(self) -> None:
        with randomizedListdir() as iterdir:
            children = await self.meta.children()
            assert children is not None

        assert iterdir.mock_calls == [mock.call(self.meta.path)]
        self._cb_test_children_twoChildren(children)

    def _cb_test_children_twoChildren(
        self, children: Sequence[interfaces.IWalkableLDAPEntry]
    ) -> None:
        assert len(children) == 2
        want = [
            "cn=foo,ou=metasyntactic,dc=example,dc=com",
            "cn=bar,ou=metasyntactic,dc=example,dc=com",
        ]
        got = [e.dn for e in children]
        got.sort()
        want.sort()
        assert got == want

    async def test_children_twoChildren_callback(self) -> None:
        children: list[interfaces.IWalkableLDAPEntry] = []
        with randomizedListdir() as iterdir:
            r = await self.meta.children(callback=util.appender(children))

        assert iterdir.mock_calls == [mock.call(self.meta.path)]
        self._cb_test_children_twoChildren_callback(r, children)

    def _cb_test_children_twoChildren_callback(
        self,
        r: object,
        children: Sequence[interfaces.IWalkableLDAPEntry],
    ) -> None:
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
    async def test_children_noAccess_dir_noRead(self) -> None:
        await self.chmod(self.meta.path, 0o300)
        with randomizedListdir() as iterdir, pytest.raises(OSError) as excinfo:
            await self.meta.children()
        assert excinfo.value.errno == errno.EACCES
        assert iterdir.mock_calls == [mock.call(self.meta.path)]
        await self.chmod(self.meta.path, 0o755)

    @skipIfWindowsOrRoot
    async def test_children_noAccess_dir_noExec(self) -> None:
        await self.chmod(self.meta.path, 0o600)
        with randomizedListdir() as iterdir, pytest.raises(OSError) as excinfo:
            await self.meta.children()
        assert excinfo.value.errno == errno.EACCES
        assert iterdir.mock_calls == [mock.call(self.meta.path)]
        await self.chmod(self.meta.path, 0o755)

    @skipIfWindowsOrRoot
    async def test_children_noAccess_file(self) -> None:
        await self.chmod(os.path.join(self.meta.path, "cn=foo.ldif"), 0)
        with randomizedListdir() as iterdir, pytest.raises(OSError) as excinfo:
            await self.meta.children()
        assert excinfo.value.errno == errno.EACCES
        assert iterdir.mock_calls == [mock.call(self.meta.path)]

    async def test_addChild(self) -> None:
        await self.empty.addChild(
            rdn="a=b",
            attributes={
                "objectClass": ["a", "b"],
                "a": "b",
            },
        )
        children = await self.empty.children()
        assert children is not None
        self._cb_test_addChild(children)

    def _cb_test_addChild(self, children: Sequence[interfaces.IWalkableLDAPEntry]) -> None:
        assert len(children) == 1
        got = [e.dn for e in children]
        want = [
            "a=b,ou=empty,dc=example,dc=com",
        ]
        got.sort()
        want.sort()
        assert got == want

    async def test_addChild_Exists(self) -> None:
        with pytest.raises(ldaperrors.LDAPEntryAlreadyExists):
            await self.meta.addChild(
                rdn="cn=foo",
                attributes={
                    "objectClass": ["a"],
                    "cn": "foo",
                },
            )

    async def test_addChild_to_existing_directory(self) -> None:
        child = await self.meta.addChild(
            rdn="cn=baz",
            attributes={"objectClass": ["a"], "cn": ["baz"]},
        )
        assert child.dn == "cn=baz,ou=metasyntactic,dc=example,dc=com"

    async def test_deleteChild_accepts_relative_distinguished_name(self) -> None:
        result = await self.meta.deleteChild(
            distinguishedname.RelativeDistinguishedName("cn=bar")
        )
        assert result == self.bar

    async def test_move_accepts_distinguished_name(self) -> None:
        result = await self.empty.move(
            distinguishedname.DistinguishedName("ou=moved,dc=example,dc=com")
        )
        assert result
        assert self.empty.dn == "ou=moved,dc=example,dc=com"

    async def test_parent(self) -> None:
        assert await self.foo.parent() == self.meta
        assert await self.meta.parent() == self.example
        assert await self.root.parent() is None

    async def test_subtree_empty(self) -> None:
        with randomizedListdir() as iterdir:
            entries = await self.empty.subtree()
            assert entries is not None
            assert len(entries) == 1

        assert iterdir.mock_calls == [mock.call(self.empty.path)]

    async def test_subtree_oneChild(self) -> None:
        with randomizedListdir() as iterdir:
            results = await self.oneChild.subtree()
            assert results is not None

        assert iterdir.mock_calls == [
            mock.call(self.oneChild.path),
            mock.call(self.theChild.path),
        ]
        self._cb_test_subtree_oneChild(results)

    def _cb_test_subtree_oneChild(self, results: Sequence[interfaces.IWalkableLDAPEntry]) -> None:
        got = results
        want = [
            self.oneChild,
            self.theChild,
        ]
        assert got == want

    async def test_subtree_oneChild_cb(self) -> None:
        got: list[interfaces.IWalkableLDAPEntry] = []
        with randomizedListdir() as iterdir:
            r = await self.oneChild.subtree(util.appender(got))

        assert iterdir.mock_calls == [
            mock.call(self.oneChild.path),
            mock.call(self.theChild.path),
        ]
        self._cb_test_subtree_oneChild_cb(r, got)

    def _cb_test_subtree_oneChild_cb(self, r: object, got: Sequence[interfaces.IWalkableLDAPEntry]) -> None:
        assert r is None

        want = [
            self.oneChild,
            self.theChild,
        ]
        assert got == want

    async def test_subtree_many(self) -> None:
        with randomizedListdir() as iterdir:
            result = await self.example.subtree()
            assert result is not None

        util.assert_permutation(
            iterdir.mock_calls,
            [
                mock.call(e.path)
                for e in (
                    self.example,
                    self.oneChild,
                    self.theChild,
                    self.empty,
                    self.meta,
                    self.bar,
                    self.foo,
                )
            ],
        )
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

    async def test_subtree_many_cb(self) -> None:
        got: list[interfaces.IWalkableLDAPEntry] = []
        with randomizedListdir() as iterdir:
            result = await self.example.subtree(callback=util.appender(got))

        util.assert_permutation(
            iterdir.mock_calls,
            [
                mock.call(e.path)
                for e in (
                    self.example,
                    self.oneChild,
                    self.theChild,
                    self.empty,
                    self.meta,
                    self.bar,
                    self.foo,
                )
            ],
        )
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

    async def test_lookup_fail(self) -> None:
        dn = "cn=thud,ou=metasyntactic,dc=example,dc=com"
        with pytest.raises(ldaperrors.LDAPNoSuchObject) as excinfo:
            await self.root.lookup(dn)
        assert excinfo.value.message == dn

    async def test_lookup_fail_outOfTree(self) -> None:
        dn = "dc=invalid"
        with pytest.raises(ldaperrors.LDAPNoSuchObject) as excinfo:
            await self.root.lookup(dn)
        assert excinfo.value.message == dn

    async def test_lookup_fail_outOfTree_2(self) -> None:
        dn = "dc=invalid"
        with pytest.raises(ldaperrors.LDAPNoSuchObject) as excinfo:
            await self.example.lookup(dn)
        assert excinfo.value.message == dn

    async def test_lookup_fail_multipleError(self) -> None:
        await writeFile(
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

    async def test_lookup_fail_emptyError(self) -> None:
        await writeFile(os.path.join(self.example.path, "cn=bad-empty.ldif"), b"")
        with pytest.raises(ldiftree.LDIFTreeEntryContainsNoEntries):
            await self.example.lookup("cn=bad-empty,dc=example,dc=com")

    async def test_lookup_deep(self) -> None:
        dn = "cn=bar,ou=metasyntactic,dc=example,dc=com"
        assert await self.root.lookup(dn) == self.bar

    async def test_delete_root(self) -> None:
        with pytest.raises(ldiftree.LDAPCannotRemoveRootError):
            await self.root.delete()

    async def test_delete_nonLeaf(self) -> None:
        with pytest.raises(ldaperrors.LDAPNotAllowedOnNonLeaf):
            await self.meta.delete()

    async def test_delete(self) -> None:
        assert await self.foo.delete() == self.foo
        assert await self.meta.children() == [self.bar]

    async def test_deleteChild(self) -> None:
        assert await self.meta.deleteChild("cn=bar") == self.bar
        assert await self.meta.children() == [self.foo]

    async def test_deleteChild_NonExisting(self) -> None:
        with pytest.raises(ldaperrors.LDAPNoSuchObject):
            await self.root.deleteChild("cn=not-exist")

    async def test_setPassword(self) -> None:
        self.foo.setPassword(b"s3krit", salt=b"\xf2\x4a")
        assert "userPassword" in self.foo
        assert self.foo["userPassword"] == [b"{SSHA}0n/Iw1NhUOKyaI9gm9v5YsO3ZInySg=="]

    async def test_setPassword_noSalt(self) -> None:
        self.foo.setPassword(b"s3krit")
        assert "userPassword" in self.foo
        assert await self.foo.bind("s3krit") is self.foo
        with pytest.raises(ldaperrors.LDAPInvalidCredentials):
            await self.foo.bind("s4krit")

    async def test_diffTree_self(self) -> None:
        assert await self.root.diffTree(self.root) == []

    async def test_diffTree_copy(self, tmp_path: pathlib.Path) -> None:
        otherDir = str(tmp_path / "other")
        await anyio.to_thread.run_sync(shutil.copytree, self.tree, otherDir)
        other = await ldiftree.LDIFTreeEntry.open(otherDir)
        assert await self.root.diffTree(other) == []

    async def test_diffTree_addChild(self, tmp_path: pathlib.Path) -> None:
        otherDir = str(tmp_path / "other")
        await anyio.to_thread.run_sync(shutil.copytree, self.tree, otherDir)
        other = await ldiftree.LDIFTreeEntry.open(otherDir)
        e = entry.BaseLDAPEntry(dn="cn=foo,dc=example,dc=com")
        await ldiftree.put(otherDir, e)

        added = await other.lookup("cn=foo,dc=example,dc=com")
        assert isinstance(added, ldiftree.LDIFTreeEntry)
        assert await self.root.diffTree(other) == [delta.AddOp(added)]

    async def test_diffTree_delChild(self, tmp_path: pathlib.Path) -> None:
        otherDir = str(tmp_path / "other")
        await anyio.to_thread.run_sync(shutil.copytree, self.tree, otherDir)
        other = await ldiftree.LDIFTreeEntry.open(otherDir)

        otherEmpty = await other.lookup("ou=empty,dc=example,dc=com")
        assert isinstance(otherEmpty, ldiftree.LDIFTreeEntry)
        await otherEmpty.delete()

        assert await self.root.diffTree(other) == [delta.DeleteOp(self.empty)]

    async def test_diffTree_edit_failure(self, tmp_path: pathlib.Path) -> None:
        otherDir = str(tmp_path / "other")
        await anyio.to_thread.run_sync(shutil.copytree, self.tree, otherDir)
        other = await ldiftree.LDIFTreeEntry.open(otherDir)

        otherEmpty = await other.lookup("ou=empty,dc=example,dc=com")
        assert isinstance(otherEmpty, ldiftree.LDIFTreeEntry)
        otherEmpty["foo"] = ["bar"]
        await anyio.to_thread.run_sync(shutil.rmtree, otherDir)
        cleanups: list[Callable[[], object]] = []
        messages = capture_logs(cleanups, level=logging.ERROR)
        try:
            assert not (await otherEmpty.commit())
        finally:
            for cleanup in cleanups:
                cleanup()
        assert messages[0] == "[ERROR] Could not commit entry: ou=empty,dc=example,dc=com."

    @skipIfWindows
    async def test_diffTree_edit(self, tmp_path: pathlib.Path) -> None:
        otherDir = str(tmp_path / "other")
        await anyio.to_thread.run_sync(shutil.copytree, self.tree, otherDir)
        other = await ldiftree.LDIFTreeEntry.open(otherDir)

        otherEmpty = await other.lookup("ou=empty,dc=example,dc=com")
        assert isinstance(otherEmpty, ldiftree.LDIFTreeEntry)
        otherEmpty["foo"] = ["bar"]
        await otherEmpty.commit()

        assert await self.root.diffTree(other) == [
            delta.ModifyOp(self.empty.dn, [delta.Add(b"foo", [b"bar"])]),
        ]

    @skipIfWindows
    async def test_move_noChildren_sameSuperior(self) -> None:
        await self.empty.move("ou=moved,dc=example,dc=com")

        children = await self.example.children()
        assert children is not None
        assert set(children) == {
            self.meta,
            _moved("ou=moved,dc=example,dc=com"),
            self.oneChild,
        }

    @skipIfWindows
    async def test_move_children_sameSuperior(self) -> None:
        await self.meta.move("ou=moved,dc=example,dc=com")

        children = await self.example.children()
        assert children is not None
        assert set(children) == {
            _moved("ou=moved,dc=example,dc=com"),
            self.empty,
            self.oneChild,
        }

    @skipIfWindows
    async def test_move_noChildren_newSuperior(self) -> None:
        await self.empty.move("ou=moved,ou=oneChild,dc=example,dc=com")

        top = await self.example.children()
        assert top is not None
        assert set(top) == {self.meta, self.oneChild}
        children = await self.oneChild.children()
        assert children is not None
        assert set(children) == {
            self.theChild,
            _moved("ou=moved,ou=oneChild,dc=example,dc=com"),
        }

    @skipIfWindows
    async def test_move_children_newSuperior(self) -> None:
        await self.meta.move("ou=moved,ou=oneChild,dc=example,dc=com")

        top = await self.example.children()
        assert top is not None
        assert set(top) == {self.empty, self.oneChild}
        children = await self.oneChild.children()
        assert children is not None
        assert set(children) == {
            self.theChild,
            _moved("ou=moved,ou=oneChild,dc=example,dc=com"),
        }

    async def testCompareOtherTypes(self) -> None:
        """
        It can't be compared with other types.
        """
        with pytest.raises(TypeError):
            self.example < object()

        with pytest.raises(TypeError):
            self.example > object()

    async def testCompareGreater(self) -> None:
        """
        It is compared with other entries based on DN, where child is
        greater than the parent.
        """
        assert self.oneChild > self.example
        assert not (self.example > self.oneChild)

    async def testCompareLess(self) -> None:
        """
        It is compared with other entries based on DN, where parent is
        less than the child.
        """
        assert self.example < self.oneChild
        assert not (self.oneChild < self.example)

    async def testRepresentation(self) -> None:
        assert self.example.dn.getText() in repr(self.example)


def test_module_entrypoint_explains_legacy_demo_removal() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "anyldap.ldiftree"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "AnyIO server entrypoints" in result.stderr
