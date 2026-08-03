"""
Changes to the content of one single LDAP entry.

(This means these do not belong here: adding or deleting of entries,
changing of location in tree)
"""

from collections.abc import Sequence
from typing import ClassVar, Protocol, Self

from anyldap import attributeset, interfaces
from anyldap._async import await_result
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import distinguishedname, ldif


class EntryToAdd(Protocol):
    """What AddOp needs of the entry it is adding.

    anyldap.entry imports this module, so the concrete class cannot be named
    here.
    """

    @property
    def dn(self) -> distinguishedname.DistinguishedName: ...

    def toWire(self) -> bytes: ...


def _octetString(obj: pureber.BERBase) -> pureber.BEROctetString:
    """Narrow a decoded member to the string a modification is made of."""
    assert isinstance(obj, pureber.BEROctetString)
    return obj


class Modification(attributeset.LDAPAttributeSet[str | bytes]):
    def patch(self, entry: interfaces.IEditableLDAPEntry) -> None:
        raise NotImplementedError("%s.patch not implemented" % self.__class__.__name__)

    _LDAP_OP: ClassVar[int | None] = None

    def asLDIF(self) -> bytes:
        raise NotImplementedError("%s.asLDIF not implemented" % self.__class__.__name__)

    def asLDAP(self) -> pureber.BERSequence:
        if self._LDAP_OP is None:
            raise NotImplementedError(
                "%s.asLDAP not implemented" % self.__class__.__name__
            )
        newlist = [
            value.encode("utf-8") if isinstance(value, str) else value
            for value in self
        ]

        return pureber.BERSequence(
            [
                pureber.BEREnumerated(self._LDAP_OP),
                pureber.BERSequence(
                    [
                        pureldap.LDAPAttributeDescription(self.key),
                        pureber.BERSet(map(pureldap.LDAPString, newlist)),
                    ]
                ),
            ]
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return super().__eq__(other)


class Add(Modification):
    _LDAP_OP = 0

    def patch(self, entry: interfaces.IEditableLDAPEntry) -> None:
        if self.key in entry:
            entry[self.key].update(self)
        else:
            entry[self.key] = self

    def asLDIF(self) -> bytes:
        r = []
        values = list(self)
        values.sort()
        r.append(ldif.attributeAsLDIF("add", self.key))
        for v in values:
            r.append(ldif.attributeAsLDIF(self.key, v))
        r.append(b"-\n")
        return b"".join(r)


class Delete(Modification):
    _LDAP_OP = 1

    def patch(self, entry: interfaces.IEditableLDAPEntry) -> None:
        if not self:
            del entry[self.key]
        else:
            for v in self:
                entry[self.key].remove(v)

    def asLDIF(self) -> bytes:
        r = []
        values = list(self)
        values.sort()
        r.append(ldif.attributeAsLDIF("delete", self.key))
        for v in values:
            r.append(ldif.attributeAsLDIF(self.key, v))
        r.append(b"-\n")
        return b"".join(r)


class Replace(Modification):
    _LDAP_OP = 2

    def patch(self, entry: interfaces.IEditableLDAPEntry) -> None:
        if self:
            entry[self.key] = self
        else:
            try:
                del entry[self.key]
            except KeyError:
                pass

    def asLDIF(self) -> bytes:
        r = []
        values = list(self)
        values.sort()
        r.append(ldif.attributeAsLDIF("replace", self.key))
        for v in values:
            r.append(ldif.attributeAsLDIF(self.key, v))
        r.append(b"-\n")
        return b"".join(r)


class Operation:
    async def patch(self, root: interfaces.IConnectedLDAPEntry) -> object:
        """
        Find the correct entry in IConnectedLDAPEntry and patch it.

        @param root: IConnectedLDAPEntry that is at the root of the
        subtree the patch applies to.

        @returns: None, once the patch has been applied.
        """
        raise NotImplementedError("%s.patch not implemented" % self.__class__.__name__)


class ModifyOp(Operation):
    def __init__(
        self,
        dn: interfaces.AnyDN,
        modifications: Sequence[Modification] = (),
    ) -> None:
        if not isinstance(dn, distinguishedname.DistinguishedName):
            dn = distinguishedname.DistinguishedName(stringValue=dn)
        self.dn = dn
        self.modifications = list(modifications)

    def asLDIF(self) -> bytes:
        r = []
        r.append(ldif.attributeAsLDIF("dn", self.dn.getText()))
        r.append(ldif.attributeAsLDIF("changetype", "modify"))
        for m in self.modifications:
            r.append(m.asLDIF())
        r.append(b"\n")
        return b"".join(r)

    def asLDAP(self) -> pureldap.LDAPModifyRequest:
        return pureldap.LDAPModifyRequest(
            object=self.dn.getText(),
            modification=[x.asLDAP() for x in self.modifications],
        )

    @classmethod
    def _getClassFromOp(class_, op: int) -> type["Modification"] | None:
        for mod in [Add, Delete, Replace]:
            if op == mod._LDAP_OP:
                return mod
        return None

    @classmethod
    def fromLDAP(class_, request: object) -> Self:
        if not isinstance(request, pureldap.LDAPModifyRequest):
            raise RuntimeError(
                "%s.fromLDAP needs an LDAPModifyRequest" % class_.__name__
            )
        dn = request.object
        assert dn is not None
        assert request.modification is not None
        result = []
        for modification in request.modification:
            assert isinstance(modification, pureber.BERSequence)
            op_ber, mods = modification
            assert isinstance(op_ber, pureber.BERInteger)
            op = op_ber.value
            klass = class_._getClassFromOp(op)
            if klass is None:
                raise RuntimeError(
                    f"Unknown LDAP op number {op!r} in {class_.__name__}.fromLDAP"
                )

            assert isinstance(mods, pureber.BERSequence)
            key_ber, vals = mods
            assert isinstance(key_ber, pureber.BEROctetString)
            assert isinstance(vals, pureber.BERSequence)
            m = klass(key_ber.value, [_octetString(x).value for x in vals])
            result.append(m)
        return class_(dn, result)

    async def patch(self, root: interfaces.IConnectedLDAPEntry) -> interfaces.ILDAPEntry:
        entry = await root.lookup(self.dn)
        # A tree being patched has to hand back entries that can be written to.
        assert interfaces.IEditableLDAPEntry.providedBy(entry)
        for mod in self.modifications:
            mod.patch(entry)
        return entry

    def __repr__(self) -> str:
        dn = self.dn.getText()
        return (
            self.__class__.__name__
            + "("
            + "dn=%r" % dn
            + ", "
            + "modifications=%r" % self.modifications
            + ")"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        if self.dn != other.dn:
            return False
        if self.modifications != other.modifications:
            return False
        return True

    def __hash__(self) -> int:
        # We use the LDIF representation as similar objects
        # should have the same LDIF.
        return hash(self.asLDIF())

    def __ne__(self, other: object) -> bool:
        return not self == other


class AddOp(Operation):
    def __init__(self, entry: "EntryToAdd") -> None:
        self.entry = entry

    def asLDIF(self) -> bytes:
        l = self.entry.toWire().splitlines()
        assert l[0].startswith(b"dn:")
        l[1:1] = [ldif.attributeAsLDIF("changetype", "add").rstrip(b"\n")]
        return b"".join([x + b"\n" for x in l])

    async def patch(self, root: interfaces.IConnectedLDAPEntry) -> None:
        parent = await root.lookup(self.entry.dn.up())
        # ldiftree's addChild has to await; inmemory's does not.
        await await_result(parent.addChild(self.entry.dn.split()[0], self.entry))

    def __repr__(self) -> str:
        return self.__class__.__name__ + "(" + "%r" % self.entry + ")"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        if self.entry != other.entry:
            return False
        return True

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __hash__(self) -> int:
        # Use the LDIF representions as equal operations should
        # have the same LDIF.
        return hash(self.asLDIF())


class DeleteOp(Operation):
    def __init__(self, dn: object) -> None:
        """
        Instance can be initialized with different objects:

        * anyldap.entry.BaseLDAPEntry instance
        * anyldap.protocols.ldap.distinguishedname.DistinguishedName instance
        * unicode or byte string
        """
        if hasattr(dn, "dn") and isinstance(dn.dn, distinguishedname.DistinguishedName):
            self.dn = dn.dn
        elif isinstance(dn, distinguishedname.DistinguishedName):
            self.dn = dn
        elif isinstance(dn, (bytes, str)):
            self.dn = distinguishedname.DistinguishedName(stringValue=dn)
        else:
            raise AssertionError("Invalid type of object: %s" % dn.__class__.__name__)

    def asLDIF(self) -> bytes:
        r = []
        r.append(ldif.attributeAsLDIF("dn", self.dn.getText()))
        r.append(ldif.attributeAsLDIF("changetype", "delete"))
        r.append(b"\n")
        return b"".join(r)

    async def patch(self, root: interfaces.IConnectedLDAPEntry) -> object:
        entry = await root.lookup(self.dn)
        assert interfaces.IEditableLDAPEntry.providedBy(entry)
        return await entry.delete()

    def __repr__(self) -> str:
        dn = self.dn.getText()
        return self.__class__.__name__ + "(" + "%r" % dn + ")"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        if self.dn != other.dn:
            return False
        return True

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash(self.dn)
