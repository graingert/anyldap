"""
Test cases for anyldap.protocols.ldap.delta
"""

import pytest

from anyldap import attributeset, delta, entry, inmemory, testutil
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldapsyntax

pytestmark = pytest.mark.anyio


async def test_delete_operation_uses_real_in_memory_entry() -> None:
    root = inmemory.ReadOnlyInMemoryLDAPEntry("dc=example,dc=com")
    child = root.addChild("cn=foo", {"cn": ["foo"]})
    operation = delta.DeleteOp(child)
    assert await operation.patch(root) is child
    with pytest.raises(ldaperrors.LDAPNoSuchObject):
        await root.lookup(child.dn)


def test_modify_op_survives_its_own_request() -> None:
    """fromLDAP reads back the request asLDAP built.

    Modification.asLDAP used to hand back encoded bytes while its sibling
    ModifyOp.asLDAP handed back an object, so the request came out holding
    pre-encoded members that fromLDAP could not unpack. It only ever worked
    because the members were on their way to the wire, where bytes pass
    straight through.
    """
    op = delta.ModifyOp(
        "cn=foo,dc=example,dc=com",
        [delta.Add("cn", ["bar"]), delta.Delete("sn", ["quux"])],
    )

    back = delta.ModifyOp.fromLDAP(op.asLDAP())

    # The values come back as the utf-8 they were sent as, so the operations
    # are equivalent rather than equal.
    assert back.dn == op.dn
    assert [type(m) for m in back.modifications] == [delta.Add, delta.Delete]
    assert back.asLDAP().toWire() == op.asLDAP().toWire()


class TestModifications:
    def setup_method(self) -> None:
        self.client = testutil.LDAPClientTestDriver()
        self.foo = ldapsyntax.LDAPEntry(
            # These modifications are journalled, never sent, which the
            # driver enforces: it has no responses to give.
            self.client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["foo", "thud"],
                "sn": ["bar"],
                "more": ["junk"],
            },
        )

    async def testAbstractOperation(self) -> None:
        """
        Operation.patch is awaited, like every operation that implements it.
        """
        with pytest.raises(NotImplementedError):
            await delta.Operation().patch(self.foo)
        with pytest.raises(NotImplementedError):
            delta.Operation().asLDIF()

    def testAbstractAndInvalidOperations(self) -> None:
        modification = delta.Modification("cn", ["value"])
        with pytest.raises(NotImplementedError):
            modification.patch(self.foo)
        with pytest.raises(NotImplementedError):
            modification.asLDAP()
        with pytest.raises(NotImplementedError):
            modification.asLDIF()
        assert delta.ModifyOp._getClassFromOp(999) is None
        with pytest.raises(RuntimeError):
            delta.ModifyOp.fromLDAP(object())
        request = pureldap.LDAPModifyRequest(
            object="cn=foo",
            modification=[
                pureber.BERSequence(
                    [
                        pureber.BEREnumerated(999),
                        pureber.BERSequence(
                            [
                                pureldap.LDAPAttributeDescription("cn"),
                                pureber.BERSet(
                                    [pureldap.LDAPAttributeValue("foo")]
                                ),
                            ]
                        ),
                    ]
                )
            ],
        )
        with pytest.raises(RuntimeError):
            delta.ModifyOp.fromLDAP(request)

    def testAddOld(self) -> None:
        mod = delta.Add("cn", ["quux"])
        mod.patch(self.foo)

        assert not ("stuff" in self.foo)
        assert self.foo["cn"] == ["foo", "thud", "quux"]

    def testAddNew(self) -> None:
        mod = delta.Add("stuff", ["val1", "val2"])
        mod.patch(self.foo)

        assert self.foo["stuff"] == ["val1", "val2"]
        assert self.foo["cn"] == ["foo", "thud"]

    def testDelete(self) -> None:
        mod = delta.Delete("cn", ["thud"])
        mod.patch(self.foo)

        assert not ("stuff" in self.foo)
        assert self.foo["cn"] == ["foo"]

    def testDeleteAll(self) -> None:
        mod = delta.Delete("more")
        mod.patch(self.foo)

        assert not ("stuff" in self.foo)
        assert self.foo["cn"] == ["foo", "thud"]

    def testDelete_FailOnNonExistingAttributeType_All(self) -> None:
        mod = delta.Delete("notexist", [])
        with pytest.raises(KeyError):
            mod.patch(self.foo)

    def testDelete_FailOnNonExistingAttributeType_OneValue(self) -> None:
        mod = delta.Delete("notexist", ["a"])
        with pytest.raises(KeyError):
            mod.patch(self.foo)

    def testDelete_FailOnNonExistingAttributeValue(self) -> None:
        mod = delta.Delete("cn", ["notexist"])
        with pytest.raises(LookupError):
            mod.patch(self.foo)

    def testReplace_Add(self) -> None:
        mod = delta.Replace("stuff", ["val1", "val2"])
        mod.patch(self.foo)

        assert self.foo["stuff"] == ["val1", "val2"]
        assert self.foo["sn"] == ["bar"]
        assert self.foo["more"] == ["junk"]

    def testReplace_Modify(self) -> None:
        mod = delta.Replace("sn", ["baz"])
        mod.patch(self.foo)

        assert not ("stuff" in self.foo)
        assert self.foo["sn"] == ["baz"]
        assert self.foo["more"] == ["junk"]

    def testReplace_Delete_Existing(self) -> None:
        mod = delta.Replace("more", [])
        mod.patch(self.foo)

        assert not ("stuff" in self.foo)
        assert self.foo["sn"] == ["bar"]
        assert not ("more" in self.foo)

    def testReplace_Delete_NonExisting(self) -> None:
        mod = delta.Replace("nonExisting", [])
        mod.patch(self.foo)

        assert not ("stuff" in self.foo)
        assert self.foo["sn"] == ["bar"]
        assert self.foo["more"] == ["junk"]


class TestModificationOpLDIF:
    def testAdd(self) -> None:
        m = delta.Add("foo", ["bar", "baz"])
        assert m.asLDIF() == (b"""\
add: foo
foo: bar
foo: baz
-
""")

    def testDelete(self) -> None:
        m = delta.Delete("foo", ["bar", "baz"])
        assert m.asLDIF() == (b"""\
delete: foo
foo: bar
foo: baz
-
""")

    def testDeleteAll(self) -> None:
        m = delta.Delete("foo")
        assert m.asLDIF() == (b"""\
delete: foo
-
""")

    def testReplace(self) -> None:
        m = delta.Replace("foo", ["bar", "baz"])
        assert m.asLDIF() == (b"""\
replace: foo
foo: bar
foo: baz
-
""")

    def testReplaceAll(self) -> None:
        m = delta.Replace("thud")
        assert m.asLDIF() == (b"""\
replace: thud
-
""")

    def testAddBase64(self) -> None:
        """
        LDIF attribute representation is base64 encoded
        if attribute value contains nonprintable characters
        or starts with reserved characters
        """
        m = delta.Add("attr", [":value1", "value\n\r2"])
        assert m.asLDIF() == (b"""\
add: attr
attr:: OnZhbHVlMQ==
attr:: dmFsdWUKDTI=
-
""")


class TestOperationTestCase:
    """
    Test case for operations on a LDAP tree.
    """

    def getRoot(self) -> inmemory.ReadOnlyInMemoryLDAPEntry:
        """
        Returns a new LDAP root for dc=example,dc=com.
        """
        return inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName("dc=example,dc=com")
        )


class TestAddOpLDIF(TestOperationTestCase):
    """
    Unit tests for `AddOp`.
    """

    def testAsLDIF(self) -> None:
        """
        It will return the LDIF representation of the operation.
        """
        sut = delta.AddOp(
            entry.BaseLDAPEntry(
                dn="dc=example,dc=com",
                attributes={
                    "foo": ["bar", "baz"],
                    "quux": ["thud"],
                },
            )
        )

        result = sut.asLDIF()

        assert (b"""dn: dc=example,dc=com
changetype: add
foo: bar
foo: baz
quux: thud

""") == result

    def testAddOpEqualitySameEntry(self) -> None:
        """
        Objects are equal when the have the same LDAP entry.
        """
        first_entry = entry.BaseLDAPEntry(
            dn="ou=Duplicate Team, dc=example,dc=com",
            attributes={"foo": ["same", "attributes"]},
        )
        second_entry = entry.BaseLDAPEntry(
            dn="ou=Duplicate Team, dc=example,dc=com",
            attributes={"foo": ["same", "attributes"]},
        )

        first = delta.AddOp(first_entry)
        second = delta.AddOp(second_entry)

        assert first == second

    def testAddOpInequalityDifferentEntry(self) -> None:
        """
        Objects are not equal when the have different LDAP entries.
        """
        first_entry = entry.BaseLDAPEntry(
            dn="ou=First Team, dc=example,dc=com",
            attributes={"foo": ["same", "attributes"]},
        )
        second_entry = entry.BaseLDAPEntry(
            dn="ou=First Team, dc=example,dc=com",
            attributes={"foo": ["other", "attributes"]},
        )

        first = delta.AddOp(first_entry)
        second = delta.AddOp(second_entry)

        assert first != second

    def testAddOpInequalityNoEntryObject(self) -> None:
        """
        Objects is not equal with random objects.
        """
        team_entry = entry.BaseLDAPEntry(
            dn="ou=Duplicate Team, dc=example,dc=com",
            attributes={"foo": ["same", "attributes"]},
        )
        sut = delta.AddOp(team_entry)

        assert sut != {"foo": ["same", "attributes"]}

    def testAddOpHashSimilar(self) -> None:
        """
        Objects which are equal have the same hash.
        """
        first_entry = entry.BaseLDAPEntry(
            dn="ou=Duplicate Team, dc=example,dc=com",
            attributes={"foo": ["same", "attributes"]},
        )
        second_entry = entry.BaseLDAPEntry(
            dn="ou=Duplicate Team, dc=example,dc=com",
            attributes={"foo": ["same", "attributes"]},
        )

        first = delta.AddOp(first_entry)
        second = delta.AddOp(second_entry)

        assert hash(first) == hash(second)

    def testAddOpHashDifferent(self) -> None:
        """
        Objects which are not equal have different hash.
        """
        first_entry = entry.BaseLDAPEntry(
            dn="ou=Duplicate Team, dc=example,dc=com",
            attributes={"foo": ["one", "attributes"]},
        )
        second_entry = entry.BaseLDAPEntry(
            dn="ou=Duplicate Team, dc=example,dc=com",
            attributes={"foo": ["other", "attributes"]},
        )

        first = delta.AddOp(first_entry)
        second = delta.AddOp(second_entry)

        assert hash(first) != hash(second)

    async def testAddOp_DNExists(self) -> None:
        """
        It fails to perform the `add` operation for an existing entry.
        """
        root = self.getRoot()
        root.addChild(
            rdn="ou=Existing Team",
            attributes={
                "objectClass": ["a", "b"],
                "ou": ["HR"],
            },
        )

        hr_entry = entry.BaseLDAPEntry(
            dn="ou=Existing Team, dc=example,dc=com",
            attributes={"foo": ["dont", "care"]},
        )
        sut = delta.AddOp(hr_entry)

        with pytest.raises(ldaperrors.LDAPEntryAlreadyExists):
            await sut.patch(root)

    def testRepr(self) -> None:
        """
        Getting string representation
        """
        sut = delta.AddOp(
            entry.BaseLDAPEntry(
                dn="dc=example,dc=com",
                attributes={
                    "bar": ["foo"],
                    "foo": ["bar"],
                },
            )
        )

        assert repr(sut) == ("AddOp(BaseLDAPEntry('dc=example,dc=com', "
            "{'bar': ['foo'], 'foo': ['bar']}))")


class TestDeleteOpLDIF(TestOperationTestCase):
    """
    Unit tests for DeleteOp.
    """

    def testAsLDIF(self) -> None:
        """
        It return the LDIF representation of the delete operation.
        """
        sut = delta.DeleteOp("dc=example,dc=com")

        result = sut.asLDIF()
        assert (b"""dn: dc=example,dc=com
changetype: delete

""") == result

    def testDeleteOpEqualitySameDN(self) -> None:
        """
        Objects are equal when the have the same DN.
        """
        first_entry = entry.BaseLDAPEntry(dn="ou=Team, dc=example,dc=com")
        second_entry = entry.BaseLDAPEntry(dn="ou=Team, dc=example,dc=com")

        first = delta.DeleteOp(first_entry)
        second = delta.DeleteOp(second_entry)

        assert first == second

    def testDeleteOpEqualityEqualDN(self) -> None:
        """
        DeleteOp objects are equal if their DNs are equal.
        """
        first_dn = distinguishedname.DistinguishedName(
            stringValue="ou=Team,dc=example,dc=com"
        )
        first = delta.DeleteOp(first_dn)

        second_entry = entry.BaseLDAPEntry(dn="ou=Team, dc=example, dc=com")
        second = delta.DeleteOp(second_entry)

        third = delta.DeleteOp("ou=Team, dc=example,dc=com")

        assert first == second
        assert first == third

    def testDeleteOpInequalityDifferentEntry(self) -> None:
        """
        DeleteOp objects are not equal when the have different LDAP entries.
        """
        first_entry = entry.BaseLDAPEntry(dn="ou=Team, dc=example,dc=com")
        second_entry = entry.BaseLDAPEntry(dn="ou=Cowboys, dc=example,dc=com")

        first = delta.DeleteOp(first_entry)
        second = delta.DeleteOp(second_entry)

        assert first != second

    def testDeleteOpInequalityNoEntryObject(self) -> None:
        """
        DeleteOp objects is not equal with random objects.
        """
        team_entry = entry.BaseLDAPEntry(dn="ou=Team, dc=example,dc=com")

        sut = delta.DeleteOp(team_entry)

        assert sut != "ou=Team, dc=example,dc=com"

    def testDeleteOpHashSimilar(self) -> None:
        """
        Objects which are equal have the same hash.
        """
        first_entry = entry.BaseLDAPEntry(dn="ou=Team, dc=example,dc=com")
        second_entry = entry.BaseLDAPEntry(dn="ou=Team, dc=example,dc=com")

        first = delta.DeleteOp(first_entry)
        second = delta.DeleteOp(second_entry)

        assert hash(first) == hash(second)

    def testDeleteOpHashDifferent(self) -> None:
        """
        Objects which are not equal have different hash.
        """
        first_entry = entry.BaseLDAPEntry(dn="ou=Team, dc=example,dc=com")
        second_entry = entry.BaseLDAPEntry(dn="ou=Cowboys, dc=example,dc=com")

        first = delta.DeleteOp(first_entry)
        second = delta.DeleteOp(second_entry)

        assert hash(first) != hash(second)

    async def testDeleteOp_DNNotFound(self) -> None:
        """
        If fail to delete when the RDN does not exists.
        """
        root = self.getRoot()
        sut = delta.DeleteOp("cn=nope,dc=example,dc=com")

        with pytest.raises(ldaperrors.LDAPNoSuchObject):
            await sut.patch(root)

    def testDeleteOpInvalidDN(self) -> None:
        """
        Invalid type of DN raises AssertionError
        """
        with pytest.raises(AssertionError):
            delta.DeleteOp(0)

    def testRepr(self) -> None:
        """
        Getting string representation
        """
        sut = delta.DeleteOp("dc=example,dc=com")

        assert repr(sut) == "DeleteOp('dc=example,dc=com')"


class TestModifyOp(TestOperationTestCase):
    """
    Unit tests for ModifyOp.
    """

    def testAsLDIF(self) -> None:
        """
        It will return a LDIF representation of the contained operations.
        """
        sut = delta.ModifyOp(
            "cn=Paula Jensen, ou=Dev Ops, dc=airius, dc=com",
            [
                delta.Add(
                    "postaladdress",
                    ["123 Anystreet $ Sunnyvale, CA $ 94086"],
                ),
                delta.Delete("description"),
                delta.Replace(
                    "telephonenumber",
                    ["+1 408 555 1234", "+1 408 555 5678"],
                ),
                delta.Delete("facsimiletelephonenumber", ["+1 408 555 9876"]),
            ],
        )

        result = sut.asLDIF()

        assert (b"""dn: cn=Paula Jensen,ou=Dev Ops,dc=airius,dc=com
changetype: modify
add: postaladdress
postaladdress: 123 Anystreet $ Sunnyvale, CA $ 94086
-
delete: description
-
replace: telephonenumber
telephonenumber: +1 408 555 1234
telephonenumber: +1 408 555 5678
-
delete: facsimiletelephonenumber
facsimiletelephonenumber: +1 408 555 9876
-

""") == result

    def testInequalityDiffertnDN(self) -> None:
        """
        Modify operations for different DN are not equal.
        """
        first = delta.ModifyOp(
            "cn=john,dc=example,dc=com", [delta.Delete("description")]
        )

        second = delta.ModifyOp(
            "cn=doe,dc=example,dc=com", [delta.Delete("description")]
        )

        assert first != second

    def testInequalityDifferentModifications(self) -> None:
        """
        Modify operations with different modifications are not equal
        """
        first = delta.ModifyOp("cn=john,dc=example,dc=com", [delta.Add("description")])

        second = delta.ModifyOp(
            "cn=john,dc=example,dc=com", [delta.Delete("description")]
        )

        assert first != second

    def testInequalityNotModifyOP(self) -> None:
        """
        Modify operations are not equal with other object types.
        """
        sut = delta.ModifyOp("cn=john,dc=example,dc=com", [delta.Delete("description")])

        assert "cn=john,dc=example,dc=com" != sut

    def testInequalityDiffertnOperations(self) -> None:
        """
        Modify operations for same DN but different operations are not equal.
        """
        first = delta.ModifyOp(
            "cn=john,dc=example,dc=com", [delta.Delete("description")]
        )
        second = delta.ModifyOp(
            "cn=doe,dc=example,dc=com", [delta.Delete("homeDirectory")]
        )

        assert first != second

    def testHashEquality(self) -> None:
        """
        Modify operations can be hashed and equal objects have the same
        hash.
        """
        first = delta.ModifyOp(
            "cn=john,dc=example,dc=com", [delta.Delete("description")]
        )

        second = delta.ModifyOp(
            "cn=john,dc=example,dc=com", [delta.Delete("description")]
        )

        assert first == second
        assert first.asLDIF() == second.asLDIF(), "LDIF equality is a precondition for valid hash values"
        assert hash(first) == hash(second)

    def testHashInequality(self) -> None:
        """
        Different modify operations have different hash values.
        """
        first = delta.ModifyOp(
            "cn=john,dc=example,dc=com", [delta.Delete("description")]
        )

        second = delta.ModifyOp(
            "cn=john,dc=example,dc=com", [delta.Delete("homeDirectory")]
        )

        assert first.asLDIF() != second.asLDIF()
        assert hash(first) != hash(second)

    async def testModifyOp_DNNotFound(self) -> None:
        """
        If fail to modify when the RDN does not exists.
        """
        root = self.getRoot()
        sut = delta.ModifyOp(
            "cn=nope,dc=example,dc=com",
            [delta.Add("foo", ["bar"])],
        )

        with pytest.raises(ldaperrors.LDAPNoSuchObject):
            await sut.patch(root)

    def testRepr(self) -> None:
        """
        Getting string representation
        """
        sut = delta.ModifyOp("cn=john,dc=example,dc=com", [delta.Delete("description")])

        assert repr(sut) == ("ModifyOp(dn='cn=john,dc=example,dc=com', "
            "modifications=[Delete('description', [])])")


class TestModificationComparison:
    def testEquality_Add_True(self) -> None:
        a = delta.Add("k", ["b", "c", "d"])
        b = delta.Add("k", ["b", "c", "d"])
        assert a == b

    def testEquality_AddVsDelete_False(self) -> None:
        a = delta.Add("k", ["b", "c", "d"])
        b = delta.Delete("k", ["b", "c", "d"])
        assert a != b

    def testEquality_AttributeSet_False(self) -> None:
        a = delta.Add("k", ["b", "c", "d"])
        b = attributeset.LDAPAttributeSet("k", ["b", "c", "d"])
        assert a != b

    def testEquality_List_False(self) -> None:
        a = delta.Add("k", ["b", "c", "d"])
        b = ["b", "c", "d"]
        assert a != b
