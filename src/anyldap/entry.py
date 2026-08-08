import base64
import random
from collections.abc import Iterable, Iterator
from hashlib import sha1
from typing import ClassVar

from anyldap import attributeset, delta, interfaces
from anyldap._collections import InsensitiveDict
from anyldap._encoder import WireStrAlias, get_strings, to_bytes
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldif

# An attribute name, or one of its values: text on the way in, bytes off the
# wire.
AttributeText = str | bytes


def sshaDigest(passphrase: bytes, salt: bytes | None = None) -> bytes:
    """
    Return the salted SHA for `passphrase` which is passed as bytes.
    """
    if salt is None:
        text = ""
        for i in range(8):
            text += chr(random.randint(0, 127))
        salt = text.encode("ascii")

    s = sha1()
    s.update(passphrase)
    s.update(salt)
    encoded = base64.encodebytes(s.digest() + salt).rstrip()
    crypt = b"{SSHA}" + encoded
    return crypt


class BaseLDAPEntry(WireStrAlias, interfaces.ILDAPEntry):
    dn: distinguishedname.DistinguishedName
    _object_class_keys: ClassVar[set[AttributeText]] = set(get_strings("objectClass"))
    _object_class_lower_keys: ClassVar[set[AttributeText]] = set(
        get_strings("objectclass")
    )
    _user_password_keys: ClassVar[set[AttributeText]] = set(
        get_strings("userPassword")
    )

    def __init__(
        self,
        dn: interfaces.AnyDN,
        attributes: interfaces.Attributes = {},
    ) -> None:
        """

        Initialize the object.

        @param dn: Distinguished Name of the object, as a string.

        @param attributes: Attributes of the object. A dictionary of
        attribute types to list of attribute values.

        """
        self._attributes: InsensitiveDict[
            AttributeText, attributeset.LDAPAttributeSet[AttributeText]
        ] = InsensitiveDict()
        self.dn = distinguishedname.DistinguishedName(dn)

        # Collected case-insensitively first, so that an entry given both
        # "cn" and "CN" ends up with one attribute holding all the values.
        collected: InsensitiveDict[AttributeText, list[AttributeText]] = (
            InsensitiveDict()
        )
        for k, vs in attributes.items():
            if k not in collected:
                collected[k] = []
            collected[k].extend(vs)

        for k, vs in collected.items():
            self._attributes[k] = self.buildAttributeSet(k, vs)

    def buildAttributeSet(
        self, key: AttributeText, values: Iterable[AttributeText]
    ) -> attributeset.LDAPAttributeSet[AttributeText]:
        return attributeset.LDAPAttributeSet(key, values)

    def __getitem__(
        self, key: AttributeText
    ) -> attributeset.LDAPAttributeSet[AttributeText]:
        for k in get_strings(key):
            if k in self._attributes:
                return self._attributes[k]
        raise KeyError(key)

    def get(
        self,
        key: AttributeText,
        default: Iterable[AttributeText] | None = None,
    ) -> Iterable[AttributeText] | None:
        for k in get_strings(key):
            if k in self._attributes:
                return self._attributes[k]
        return default

    def has_key(self, key: AttributeText) -> bool:
        for k in get_strings(key):
            if k in self._attributes:
                return True
        return False

    def __contains__(self, key: AttributeText) -> bool:
        return self.has_key(key)

    def __iter__(self) -> Iterator[AttributeText]:
        yield from self._attributes.iterkeys()

    def keys(self) -> list[AttributeText]:
        a = []
        for key in self._object_class_keys:
            if key in self._attributes:
                a.append(key)
        l = list(self._attributes.keys())
        l.sort(key=to_bytes)
        for key in l:
            if key.lower() not in self._object_class_lower_keys:
                a.append(key)
        return a

    def items(self) -> list[tuple[AttributeText, list[AttributeText]]]:
        a = []

        for key in self._object_class_keys:
            objectClasses = list(self._attributes.get(key, []))
            objectClasses.sort(key=to_bytes)
            if objectClasses:
                a.append((key, objectClasses))

        l = list(self._attributes.items())
        l.sort(key=lambda x: to_bytes(x[0]))
        for key, values in l:
            if key.lower() not in self._object_class_lower_keys:
                vs = list(values)
                vs.sort()
                a.append((key, vs))

        return a

    def toWire(self) -> bytes:
        a = []

        for key in self._object_class_keys:
            objectClasses = list(self._attributes.get(key, []))
            objectClasses.sort(key=to_bytes)
            a.append((key, objectClasses))

        items_gen = ((key, self[key]) for key in self)
        items = sorted(items_gen, key=lambda x: to_bytes(x[0]))
        for key, values in items:
            if key.lower() not in self._object_class_lower_keys:
                vs = list(values)
                vs.sort()
                a.append((key, vs))
        return ldif.asLDIF(self.dn.getText(), a)

    def getLDIF(self) -> str:
        return self.toWire().decode("utf-8")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseLDAPEntry):
            return NotImplemented
        if self.dn != other.dn:
            return False

        my = sorted((key for key in self), key=to_bytes)
        its = sorted((key for key in other), key=to_bytes)
        if my != its:
            return False
        for key in my:
            myAttr = self[key]
            itsAttr = other[key]
            if myAttr != itsAttr:
                return False
        return True

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __len__(self) -> int:
        return len(self.keys())

    def __bool__(self) -> bool:
        return True

    def __nonzero__(self) -> bool:
        return self.__bool__()

    def __repr__(self) -> str:
        keys = sorted((key for key in self), key=to_bytes)
        a = []
        for key in keys:
            a.append(f"{key!r}: {list(self[key])!r}")
        attributes = ", ".join(a)
        dn = self.dn.getText()
        return f"{self.__class__.__name__}({dn!r}, {{{attributes}}})"

    def diff(self, other: "BaseLDAPEntry") -> delta.ModifyOp | None:
        """
        Compute differences between this and another LDAP entry.

        @param other: An LDAPEntry to compare to.

        @return: None if equal, otherwise a ModifyOp that would make
        this entry look like other.
        """
        assert self.dn == other.dn
        if self == other:
            return None

        r: list[delta.Modification] = []

        myKeys = {key for key in self}
        otherKeys = {key for key in other}

        addedKeys = list(otherKeys - myKeys)
        addedKeys.sort(key=to_bytes)  # for reproducability only
        for added in addedKeys:
            r.append(delta.Add(added, other[added]))

        deletedKeys = list(myKeys - otherKeys)
        deletedKeys.sort(key=to_bytes)  # for reproducability only
        for deleted in deletedKeys:
            r.append(delta.Delete(deleted, self[deleted]))

        sharedKeys = list(myKeys & otherKeys)
        sharedKeys.sort(key=to_bytes)  # for reproducability only
        for shared in sharedKeys:

            addedValues = list(other[shared] - self[shared])
            if addedValues:
                addedValues.sort(key=to_bytes)  # for reproducability only
                r.append(delta.Add(shared, addedValues))

            deletedValues = list(self[shared] - other[shared])
            if deletedValues:
                deletedValues.sort(key=to_bytes)  # for reproducability only
                r.append(delta.Delete(shared, deletedValues))

        return delta.ModifyOp(dn=self.dn, modifications=r)

    async def bind(self, password: AttributeText) -> "BaseLDAPEntry":
        return self._bind(password)

    bind_async = bind

    def _bind(self, password: AttributeText) -> "BaseLDAPEntry":
        secret = to_bytes(password)
        for key in self._user_password_keys:
            digests = self.get(key, ())
            assert digests is not None
            for value in digests:
                digest = to_bytes(value)
                if digest.startswith(b"{SSHA}"):
                    raw = base64.decodebytes(digest[len(b"{SSHA}") :])
                    salt = raw[20:]
                    got = sshaDigest(secret, salt)
                    if got == digest:
                        return self
                else:
                    # Plaintext
                    if digest == secret:
                        return self
        raise ldaperrors.LDAPInvalidCredentials()

    def hasMember(self, dn: object) -> bool:
        members = self.get("member", [])
        assert members is not None
        for memberDN in members:
            if memberDN == dn:
                return True
        return False

    def __hash__(self) -> int:
        # FIXME:https://github.com/graingert/anyldap/issues/101
        # The hash should take into consideration any attribute used to
        # decide the equality.
        return hash(self.dn)


class EditableLDAPEntry(BaseLDAPEntry, interfaces.IEditableLDAPEntry):
    def __setitem__(self, key: AttributeText, value: Iterable[AttributeText]) -> None:
        new = self.buildAttributeSet(key, value)
        self._attributes[key] = new

    def __delitem__(self, key: AttributeText) -> None:
        del self._attributes[key]

    def undo(self) -> None:
        raise NotImplementedError()

    async def commit(self) -> object:
        raise NotImplementedError()

    async def move(self, newDN: interfaces.AnyDN) -> object:
        raise NotImplementedError()

    async def delete(self) -> object:
        raise NotImplementedError()

    def setPassword(self, newPasswd: bytes, salt: bytes | None = None) -> None:
        """
        Update the password for the entry with a new password and salt passed
        as bytes.
        """
        crypt = sshaDigest(newPasswd, salt)
        for key in self._user_password_keys:
            if key in self:
                self[key] = [crypt]
        self[b"userPassword"] = [crypt]
