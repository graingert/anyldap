"""
Test cases for anyldap.inmemory module.
"""
from io import BytesIO

import pytest

from anyldap import delta, inmemory
from anyldap.protocols.ldap import distinguishedname, ldaperrors
from anyldap.runtime import ConnectionDone, Failure
from anyldap.test import util

pytestmark = pytest.mark.anyio


async def test_async_entry_operations_use_the_in_memory_tree() -> None:
    root = inmemory.ReadOnlyInMemoryLDAPEntry(
        "dc=example,dc=com", {"dc": ["example"]}
    )
    child = root.addChild("cn=child", {"cn": ["child"]})
    leaf = root.addChild("cn=leaf", {"cn": ["leaf"]})

    assert await root.lookup_async(child.dn) is child
    assert await child.fetch_async("cn") is child
    assert await child.move_async("cn=moved,dc=example,dc=com") is child
    assert await child.commit_async() is True
    assert await leaf.delete_async() is leaf
    assert await root.deleteChild_async("cn=moved") is child
    assert await root.move_async("dc=renamed") is root


async def test_ldif_protocol_reports_abnormal_disconnect() -> None:
    protocol = inmemory.InMemoryLDIFProtocol()
    protocol.dataReceived(b"version: 1\n\n")
    protocol.connectionLost(Failure(RuntimeError("input failed")))

    with pytest.raises(RuntimeError, match="input failed"):
        await protocol.completed()


class SubclassEntry(inmemory.ReadOnlyInMemoryLDAPEntry):
    pass


class TestInMemoryDatabase:
    def setup_method(self) -> None:
        self.root = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )
        self.meta = self.root.addChild(
            rdn="ou=metasyntactic",
            attributes={
                "objectClass": ["a", "b"],
                "ou": ["metasyntactic"],
            },
        )
        self.foo = self.meta.addChild(
            rdn="cn=foo",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["foo"],
            },
        )
        self.bar = self.meta.addChild(
            rdn="cn=bar",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["bar"],
            },
        )

        self.empty = self.root.addChild(
            rdn="ou=empty",
            attributes={
                "objectClass": ["a", "b"],
                "ou": ["empty"],
            },
        )

        self.oneChild = self.root.addChild(
            rdn="ou=oneChild",
            attributes={
                "objectClass": ["a", "b"],
                "ou": ["oneChild"],
            },
        )
        self.theChild = self.oneChild.addChild(
            rdn="cn=theChild",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["theChild"],
            },
        )

    async def test_children_empty(self) -> None:
        _result = await self.empty.children()
        util.assert_permutation(_result, [])

    async def test_children_oneChild(self) -> None:


        children = await self.oneChild.children()
        assert len(children) == 1
        got = [e.dn for e in children]
        want = [
            distinguishedname.DistinguishedName(
                "cn=theChild,ou=oneChild,dc=example,dc=com"
            )
        ]
        got.sort()
        want.sort()
        util.assert_permutation(got, want)

    async def test_children_repeat(self) -> None:
        """Test that .children() returns a copy of the data so that modifying it does not affect behaviour."""
        children1 = await self.oneChild.children()
        assert len(children1) == 1

        children1.pop()

        assert len(await self.oneChild.children()) == 1

    async def test_children_twoChildren(self) -> None:


        children = await self.meta.children()
        assert len(children) == 2
        want = [
            distinguishedname.DistinguishedName(
                "cn=foo,ou=metasyntactic,dc=example,dc=com"
            ),
            distinguishedname.DistinguishedName(
                "cn=bar,ou=metasyntactic,dc=example,dc=com"
            ),
        ]
        got = [e.dn for e in children]
        util.assert_permutation(got, want)

    async def test_addChild(self) -> None:
        self.empty.addChild(
            rdn="a=b",
            attributes={
                "objectClass": ["a", "b"],
                "a": "b",
            },
        )


        children = await self.empty.children()
        assert len(children) == 1
        got = [e.dn for e in children]
        want = [
            distinguishedname.DistinguishedName("a=b,ou=empty,dc=example,dc=com"),
        ]
        got.sort()
        want.sort()
        util.assert_permutation(got, want)

    def test_addChild_Exists(self) -> None:
        with pytest.raises(ldaperrors.LDAPEntryAlreadyExists):
            self.meta.addChild(
                rdn="cn=foo",
                attributes={
                    "objectClass": ["a"],
                    "cn": "foo",
                },
            )

    def test_addChild_subclass(self) -> None:
        """
        Adding child to ReadOnlyInMemoryLDAPEntry subclass instance
        creates entry of the same class
        """
        entry = SubclassEntry(dn="dc=example,dc=com")
        child = entry.addChild(rdn="ou=empty", attributes={"objectClass": ["a"]})
        assert isinstance(child, SubclassEntry)

    def test_parent(self) -> None:
        assert self.foo.parent() == self.meta
        assert self.meta.parent() == self.root
        assert self.root.parent() is None

    async def test_subtree_empty(self) -> None:


        entries = await self.empty.subtree()
        assert len(entries) == 1

    async def test_subtree_oneChild(self) -> None:
        _result = await self.oneChild.subtree()
        util.assert_permutation(_result, [
                    self.oneChild,
                    self.theChild,
                ])

    async def test_subtree_oneChild_cb(self) -> None:
        got = []
        assert await self.oneChild.subtree(got.append) is None
        util.assert_permutation(
            got,
            [
                self.oneChild,
                self.theChild,
            ],
        )

    async def test_subtree_many(self) -> None:


        results = await self.root.subtree()
        got = results
        want = [
            self.root,
            self.oneChild,
            self.theChild,
            self.empty,
            self.meta,
            self.bar,
            self.foo,
        ]
        util.assert_permutation(got, want)

    async def test_subtree_many_cb(self) -> None:
        got = []


        r = await self.root.subtree(callback=got.append)
        assert r is None

        want = [
            self.root,
            self.oneChild,
            self.theChild,
            self.empty,
            self.meta,
            self.bar,
            self.foo,
        ]
        util.assert_permutation(got, want)

    async def test_lookup_fail(self) -> None:
        dn = distinguishedname.DistinguishedName(
            "cn=thud,ou=metasyntactic,dc=example,dc=com"
        )


        with pytest.raises(ldaperrors.LDAPNoSuchObject) as excinfo:
            await self.root.lookup(dn)
        assert excinfo.value.message == dn

    async def test_lookup_fail_outOfTree(self) -> None:
        dn = distinguishedname.DistinguishedName("dc=invalid")


        with pytest.raises(ldaperrors.LDAPNoSuchObject) as excinfo:
            await self.root.lookup(dn)
        assert excinfo.value.message == dn

    async def test_lookup_deep_dn(self) -> None:
        """Entry lookup with a DN instance returns entry instance with this DN"""
        dn = distinguishedname.DistinguishedName(
            "cn=bar,ou=metasyntactic,dc=example,dc=com"
        )
        _result = await self.root.lookup(dn)
        assert _result == self.bar

    async def test_lookup_deep_str(self) -> None:
        """Entry lookup with a DN as a string returns entry instance with this DN"""
        _result = await self.root.lookup("cn=bar,ou=metasyntactic,dc=example,dc=com")
        assert _result == self.bar

    async def test_delete_root(self) -> None:
        newRoot = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )


        with pytest.raises(inmemory.LDAPCannotRemoveRootError):
            await newRoot.delete()

    async def test_delete_nonLeaf(self) -> None:
        with pytest.raises(ldaperrors.LDAPNotAllowedOnNonLeaf) as excinfo:
            await self.meta.delete()

        # The error has to survive being rendered: it used to carry the DN
        # object itself, and encoding that raised TypeError instead of
        # reporting the LDAP failure.
        assert excinfo.value.toWire() == (
            b"notAllowedOnNonLeaf: ou=metasyntactic,dc=example,dc=com"
        )

    async def test_delete(self) -> None:
        _result = await self.foo.delete()
        assert _result == self.foo
        _result = await self.meta.children()
        util.assert_permutation(_result, [self.bar])

    async def test_deleteChild(self) -> None:
        _result = await self.meta.deleteChild("cn=bar")
        assert _result == self.bar
        _result = await self.meta.children()
        util.assert_permutation(_result, [self.foo])

    async def test_deleteChild_NonExisting(self) -> None:


        with pytest.raises(ldaperrors.LDAPNoSuchObject):
            await self.root.deleteChild("cn=not-exist")

    def test_setPassword(self) -> None:
        self.foo.setPassword(b"s3krit", salt=b"\xf2\x4a")
        assert self.foo["userPassword"] == [b"{SSHA}0n/Iw1NhUOKyaI9gm9v5YsO3ZInySg=="]

    async def test_setPassword_noSalt(self) -> None:
        self.foo.setPassword(b"s3krit")
        assert "userPassword" in self.foo
        assert await self.foo.bind(b"s3krit") is self.foo
        with pytest.raises(ldaperrors.LDAPInvalidCredentials):
            await self.foo.bind(b"s4krit")

    async def testSearch_withCallback(self) -> None:
        got = []


        r = await self.root.search(filterText="(|(cn=foo)(cn=bar))", callback=got.append)
        assert r is None

        want = [
            self.bar,
            self.foo,
        ]
        util.assert_permutation(got, want)

    async def testSearch_withoutCallback(self) -> None:
        _result = await self.root.search(filterText="(|(cn=foo)(cn=bar))")
        util.assert_permutation(_result, [
                    self.bar,
                    self.foo,
                ])

    async def test_move_noChildren_sameSuperior(self) -> None:


        _result = await self.empty.move("ou=moved,dc=example,dc=com")
        _result = await self.root.children()
        util.assert_permutation(_result, [
                    self.meta,
                    inmemory.ReadOnlyInMemoryLDAPEntry(
                        dn="ou=moved,dc=example,dc=com",
                        attributes={
                            "objectClass": ["a", "b"],
                            "ou": ["moved"],
                        },
                    ),
                    self.oneChild,
                ])

    async def test_move_children_sameSuperior(self) -> None:


        _result = await self.meta.move("ou=moved,dc=example,dc=com")
        _result = await self.root.children()
        util.assert_permutation(_result, [
                    inmemory.ReadOnlyInMemoryLDAPEntry(
                        dn="ou=moved,dc=example,dc=com",
                        attributes={
                            "objectClass": ["a", "b"],
                            "ou": ["moved"],
                        },
                    ),
                    self.empty,
                    self.oneChild,
                ])

    async def test_move_noChildren_newSuperior(self) -> None:




        _result = await self.empty.move("ou=moved,ou=oneChild,dc=example,dc=com")
        _result = await self.root.children()
        util.assert_permutation(_result, [
                    self.meta,
                    self.oneChild,
                ])
        _result = await self.oneChild.children()
        util.assert_permutation(_result, [
                    self.theChild,
                    inmemory.ReadOnlyInMemoryLDAPEntry(
                        dn="ou=moved,ou=oneChild,dc=example,dc=com",
                        attributes={
                            "objectClass": ["a", "b"],
                            "ou": ["moved"],
                        },
                    ),
                ])

    async def test_move_children_newSuperior(self) -> None:




        _result = await self.meta.move("ou=moved,ou=oneChild,dc=example,dc=com")
        _result = await self.root.children()
        util.assert_permutation(_result, [
                    self.empty,
                    self.oneChild,
                ])
        _result = await self.oneChild.children()
        util.assert_permutation(_result, [
                    self.theChild,
                    inmemory.ReadOnlyInMemoryLDAPEntry(
                        dn="ou=moved,ou=oneChild,dc=example,dc=com",
                        attributes={
                            "objectClass": ["a", "b"],
                            "ou": ["moved"],
                        },
                    ),
                ])

    async def test_commit(self) -> None:
        """ReadOnlyInMemoryLDAPEntry.commit() always reports success."""
        self.meta["foo"] = ["bar"]
        assert await self.meta.commit() is True


class TestLDIFLoadFailureHooks:
    """The lookupFailed/addFailed hooks decide whether a bad entry aborts."""

    orphan = b"""\
dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=foo,ou=nonexisting,dc=example,dc=com
objectClass: a
cn: foo

"""

    duplicate = b"""\
dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=foo,dc=example,dc=com
objectClass: a
cn: foo

dn: cn=foo,dc=example,dc=com
objectClass: a
cn: foo

"""

    async def _load(self, protocol, data):
        protocol.dataReceived(data)
        protocol.connectionLost(Failure(ConnectionDone()))
        return await protocol.completed()

    async def test_lookupFailed_can_skip_the_entry(self) -> None:
        skipped = []

        class SkipMissingParents(inmemory.InMemoryLDIFProtocol):
            def lookupFailed(self, reason, entry) -> None:
                skipped.append(entry.dn.getText())

        db = await self._load(SkipMissingParents(), self.orphan)

        assert skipped == ["cn=foo,ou=nonexisting,dc=example,dc=com"]
        assert await db.children() == []

    async def test_addFailed_aborts_by_default(self) -> None:
        with pytest.raises(ldaperrors.LDAPEntryAlreadyExists):
            await self._load(inmemory.InMemoryLDIFProtocol(), self.duplicate)

    async def test_addFailed_can_skip_the_entry(self) -> None:
        skipped = []

        class SkipDuplicates(inmemory.InMemoryLDIFProtocol):
            def addFailed(self, reason, entry) -> None:
                skipped.append(entry.dn.getText())

        db = await self._load(SkipDuplicates(), self.duplicate)

        assert skipped == ["cn=foo,dc=example,dc=com"]
        assert len(await db.children()) == 1


class TestFromLDIF:
    async def test_single(self) -> None:
        ldif = BytesIO(
            b"""\
dn: cn=foo,dc=example,dc=com
objectClass: a
objectClass: b
aValue: a
aValue: b
bValue: c

"""
        )
        db = await inmemory.fromLDIFFile(ldif)
        assert db.dn == distinguishedname.DistinguishedName("cn=foo,dc=example,dc=com")
        assert await db.children() == []

    async def test_two(self) -> None:
        ldif = BytesIO(
            b"""\
dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=foo,dc=example,dc=com
objectClass: a
cn: foo

"""
        )
        db = await inmemory.fromLDIFFile(ldif)
        assert db.dn == distinguishedname.DistinguishedName("dc=example,dc=com")

        children = await db.subtree()
        assert len(children) == 2
        util.assert_permutation(
            [e.dn for e in children],
            [
                distinguishedname.DistinguishedName("dc=example,dc=com"),
                distinguishedname.DistinguishedName("cn=foo,dc=example,dc=com"),
            ],
        )

    async def test_missingNode(self) -> None:
        ldif = BytesIO(
            b"""\
dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=foo,ou=nonexisting,dc=example,dc=com
objectClass: a
cn: foo

"""
        )


        with pytest.raises(ldaperrors.LDAPNoSuchObject) as excinfo:
            await inmemory.fromLDIFFile(ldif)
        assert excinfo.value.toWire() == b"noSuchObject: ou=nonexisting,dc=example,dc=com"


class TestDiff:
    async def testNoChange(self) -> None:
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            "dc=example,dc=com",
            {
                "dc": ["example"],
            },
        )
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            "dc=example,dc=com",
            {
                "dc": ["example"],
            },
        )
        _result = await a.diffTree(b)
        assert _result == []

    async def testRootChange_Add(self) -> None:
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            "dc=example,dc=com",
            {
                "dc": ["example"],
            },
        )
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            "dc=example,dc=com",
            {
                "dc": ["example"],
                "foo": ["bar"],
            },
        )
        _result = await a.diffTree(b)
        assert _result == [
                delta.ModifyOp(
                    "dc=example,dc=com",
                    [
                        delta.Add("foo", ["bar"]),
                    ],
                ),
            ]

    async def testChildChange_Add(self) -> None:
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            "dc=example,dc=com",
            {
                "dc": ["example"],
            },
        )
        a.addChild(
            "cn=foo",
            {
                "cn": ["foo"],
            },
        )
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            "dc=example,dc=com",
            {
                "dc": ["example"],
            },
        )
        b.addChild(
            "cn=foo",
            {
                "cn": ["foo"],
                "foo": ["bar"],
            },
        )
        _result = await a.diffTree(b)
        assert _result == [
                delta.ModifyOp(
                    "cn=foo,dc=example,dc=com",
                    [
                        delta.Add("foo", ["bar"]),
                    ],
                ),
            ]

    async def testAddChild(self) -> None:
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )

        foo = b.addChild(
            rdn="cn=foo",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["foo"],
            },
        )
        bar = b.addChild(
            rdn="cn=bar",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["bar"],
            },
        )

        _result = await a.diffTree(b)
        assert _result == [
                delta.AddOp(bar),
                delta.AddOp(foo),
            ]

    async def testAddSubtree(self) -> None:
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )

        foo = b.addChild(
            rdn="ou=foo",
            attributes={
                "objectClass": ["a", "b"],
                "ou": ["foo"],
            },
        )
        baz = foo.addChild(
            rdn="cn=baz",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["baz"],
            },
        )
        bar = b.addChild(
            rdn="cn=bar",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["bar"],
            },
        )

        _result = await a.diffTree(b)
        assert _result == [
                delta.AddOp(bar),
                delta.AddOp(foo),
                delta.AddOp(baz),
            ]

    async def testDeleteChild(self) -> None:
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )

        foo = a.addChild(
            rdn="cn=foo",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["foo"],
            },
        )
        bar = a.addChild(
            rdn="cn=bar",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["bar"],
            },
        )

        _result = await a.diffTree(b)
        assert _result == [
                delta.DeleteOp(bar),
                delta.DeleteOp(foo),
            ]

    async def testDeleteSubtree(self) -> None:
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )

        foo = a.addChild(
            rdn="ou=foo",
            attributes={
                "objectClass": ["a", "b"],
                "ou": ["foo"],
            },
        )
        baz = foo.addChild(
            rdn="cn=baz",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["baz"],
            },
        )
        bar = a.addChild(
            rdn="cn=bar",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["bar"],
            },
        )

        _result = await a.diffTree(b)
        assert _result == [
                delta.DeleteOp(bar),
                delta.DeleteOp(baz),
                delta.DeleteOp(foo),
            ]
