"""Pythonic API for LDAP operations."""
import functools
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Protocol

import outcome

from anyldap import attributeset, delta, entry, interfaces, ldapfilter
from anyldap._async import ResultSlot, await_result
from anyldap._encoder import to_bytes
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldif
from anyldap.runtime import Failure
from anyldap.samba import smbpassword

AttributeText = str | bytes


class LDAPSender(Protocol):
    """What an entry needs of its client: somewhere to send messages.

    An entry does not care which client it has, only that requests go out
    and answers come back, which is what lets a test drive one.
    """

    async def send(self, op: pureldap.LDAPProtocolRequest) -> object: ...

    async def send_multiResponse_ex(
        self,
        op: pureldap.LDAPProtocolRequest,
        controls: Iterable[pureldap.Control] | None,
        handler: Callable[..., bool | Awaitable[bool]] | None,
        *args: object,
        **kwargs: object,
    ) -> object: ...


class PasswordSetAggregateError(Exception):
    """Some of the password plugins failed"""

    def __init__(self, errors: Sequence[tuple[str, Failure]]) -> None:
        Exception.__init__(self)
        self.errors = errors

    def __str__(self) -> str:
        return "{}: {}.".format(
            self.__doc__,
            "; ".join(
                [
                    f"{name} failed with {fail.getErrorMessage()}"
                    for name, fail in self.errors
                ]
            ),
        )

    def __repr__(self) -> str:
        return "<" + self.__class__.__name__ + " errors=" + repr(self.errors) + ">"


class PasswordSetAborted(Exception):
    """Aborted"""

    def __str__(self) -> str:
        assert self.__doc__ is not None
        return self.__doc__


class DNNotPresentError(Exception):
    """The requested DN cannot be found by the server."""


class ObjectInBadStateError(Exception):
    """The LDAP object in in a bad state."""


class ObjectDeletedError(ObjectInBadStateError):
    """The LDAP object has already been removed, unable to perform operations on it."""


class ObjectDirtyError(ObjectInBadStateError):
    """The LDAP object has a journal which needs to be committed or undone before this operation."""


class NoContainingNamingContext(Exception):
    """The server contains to LDAP naming context that would contain this object."""


class CannotRemoveRDNError(Exception):
    """The attribute to be removed is the RDN for the object and cannot be removed."""

    def __init__(self, key: AttributeText, val: AttributeText | None = None) -> None:
        Exception.__init__(self)
        self.key = key
        self.val = val

    def __str__(self) -> str:
        if self.val is None:
            r = repr(self.key)
        else:
            r = f"{self.key!r}={self.val!r}"
        return (
            """The attribute to be removed, %s, is the RDN for the object and cannot be removed."""
            % r
        )


class MatchNotImplemented(NotImplementedError):
    """Match type not implemented"""

    def __init__(self, op: object) -> None:
        Exception.__init__(self)
        self.op = op

    def __str__(self) -> str:
        return f"{self.__doc__}: {self.op!r}"


class JournaledLDAPAttributeSet(attributeset.LDAPAttributeSet[AttributeText]):
    def __init__(
        self,
        ldapObject: "LDAPEntryWithClient",
        key: AttributeText,
        values: Iterable[AttributeText] = (),
    ) -> None:
        self.ldapObject = ldapObject
        super().__init__(key, values)

    def add(self, value: AttributeText) -> None:
        self.ldapObject.journal(delta.Add(self.key, [value]))
        super().add(value)

    def update(self, *sequences: Iterable[AttributeText]) -> None:
        for sequence in sequences:
            self.ldapObject.journal(delta.Add(self.key, sequence))
        super().update(*sequences)

    def remove(self, value: AttributeText) -> None:
        if value not in self:
            raise LookupError(value)
        self.ldapObject._canRemove(self.key, value)
        self.ldapObject.journal(delta.Delete(self.key, [value]))
        super().remove(value)

    def clear(self) -> None:
        self.ldapObject._canRemoveAll(self.key)
        super().clear()
        self.ldapObject.journal(delta.Delete(self.key))


class LDAPEntryWithClient(
    entry.EditableLDAPEntry, interfaces.IServerBackedLDAPEntry
):
    _state = "invalid"
    """

    State of an LDAPEntry is one of:

    invalid - object not initialized yet

    ready - normal

    deleted - object has been deleted

    """

    def __init__(
        self,
        client: LDAPSender,
        dn: interfaces.AnyDN,
        attributes: interfaces.Attributes = {},
        complete: int = 0,
    ) -> None:
        """

        Initialize the object.

        @param client: The LDAP client connection this object belongs
        to.

        @param dn: Distinguished Name of the object, as a string.

        @param attributes: Attributes of the object. A dictionary of
        attribute types to list of attribute values.

        """

        super().__init__(dn, attributes)
        self.client = client
        self.complete = complete

        self._journal: list[delta.Modification] = []

        self._remoteData = entry.EditableLDAPEntry(dn, attributes)
        self._state = "ready"

    def buildAttributeSet(
        self, key: AttributeText, values: Iterable[AttributeText]
    ) -> attributeset.LDAPAttributeSet[AttributeText]:
        return JournaledLDAPAttributeSet(self, key, values)

    def _canRemove(self, key: AttributeText, value: AttributeText) -> None:
        """

        Called by JournaledLDAPAttributeSet when it is about to remove a value
        of an attributeType.

        """
        self._checkState()
        for rdn in self.dn.split()[0].split():
            if rdn.attributeType == key and rdn.value == value:
                raise CannotRemoveRDNError(key, value)

    def _canRemoveAll(self, key: AttributeText) -> None:
        """

        Called by JournaledLDAPAttributeSet when it is about to remove all values
        of an attributeType.

        """
        self._checkState()
        assert not isinstance(self.dn, str)
        for keyval in self.dn.split()[0].split():
            if keyval.attributeType == key:
                raise CannotRemoveRDNError(key)

    def _checkState(self) -> None:
        if self._state != "ready":
            if self._state == "deleted":
                raise ObjectDeletedError
            else:
                raise ObjectInBadStateError(
                    "State is {} while expecting {}".format(
                        repr(self._state), repr("ready")
                    )
                )

    def journal(self, journalOperation: delta.Modification) -> None:
        """

        Add a Modification into the list of modifications
        that need to be flushed to the LDAP server.

        Normal callers should not use this, they should use the
        o['foo']=['bar', 'baz'] -style API that enforces schema,
        handles errors and updates the cached data.

        """
        self._journal.append(journalOperation)

    # start ILDAPEntry
    def __getitem__(
        self, key: AttributeText
    ) -> attributeset.LDAPAttributeSet[AttributeText]:
        self._checkState()
        return super().__getitem__(key)

    def get(
        self,
        key: AttributeText,
        default: Iterable[AttributeText] | None = None,
    ) -> Iterable[AttributeText] | None:
        self._checkState()
        return super().get(key, default)

    def has_key(self, key: AttributeText) -> bool:
        self._checkState()
        return super().has_key(key)

    def __contains__(self, key: AttributeText) -> bool:
        self._checkState()
        return self.has_key(key)

    def keys(self) -> list[AttributeText]:
        self._checkState()
        return super().keys()

    def items(self) -> list[tuple[AttributeText, list[AttributeText]]]:
        self._checkState()
        return super().items()

    def toWire(self) -> bytes:
        a: list[tuple[AttributeText, list[AttributeText]]] = []

        objectClasses = list(self.get("objectClass", []) or ())
        objectClasses.sort()
        a.append(("objectClass", objectClasses))

        lst = list(self.items())
        lst.sort()
        for key, values in lst:
            if key != "objectClass":
                a.append((key, values))
        return ldif.asLDIF(self.dn.getText(), a)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        if self.dn != other.dn:
            return False

        my = self.keys()
        my.sort()
        its = other.keys()
        its.sort()
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

    def __nonzero__(self) -> bool:
        return True

    def __hash__(self) -> int:
        return hash(self.toWire())

    async def bind(self, password: AttributeText) -> "LDAPEntryWithClient":
        r = pureldap.LDAPBindRequest(dn=self.dn.getText(), auth=password)
        return self._handle_bind_msg(await self.client.send(r))

    bind_async = bind

    def _handle_bind_msg(self, msg: object) -> "LDAPEntryWithClient":
        assert isinstance(msg, pureldap.LDAPBindResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get_exception(msg.resultCode, msg.errorMessage)
        return self

    # end ILDAPEntry

    # start IEditableLDAPEntry
    def __setitem__(
        self, key: AttributeText, value: Iterable[AttributeText]
    ) -> None:
        self._checkState()
        self._canRemoveAll(key)

        new = JournaledLDAPAttributeSet(self, key, value)
        super().__setitem__(key, new)
        self.journal(delta.Replace(key, value))

    def __delitem__(self, key: AttributeText) -> None:
        self._checkState()
        self._canRemoveAll(key)

        super().__delitem__(key)
        self.journal(delta.Delete(key))

    def undo(self) -> None:
        self._checkState()
        self._attributes.clear()
        for k, vs in self._remoteData.items():
            self._attributes[k] = self.buildAttributeSet(k, vs)
        self._journal = []

    def _assertMatchedDN(self, dn: AttributeText) -> None:
        assert dn == "" or dn == b""

    def _commit_success(self, msg: object) -> "LDAPEntryWithClient":
        assert isinstance(msg, pureldap.LDAPModifyResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get_exception(msg.resultCode, msg.errorMessage)

        self._assertMatchedDN(msg.matchedDN)

        self._remoteData = entry.EditableLDAPEntry(self.dn, self)
        self._journal = []
        return self

    async def commit(self) -> "LDAPEntryWithClient":
        self._checkState()
        if not self._journal:
            return self

        op = pureldap.LDAPModifyRequest(
            object=self.dn.getText(), modification=[x.asLDAP() for x in self._journal]
        )
        return self._commit_success(await self.client.send(op))

    commit_async = commit

    def _cbMoveDone(
        self, msg: object, newDN: distinguishedname.DistinguishedName
    ) -> "LDAPEntryWithClient":
        assert isinstance(msg, pureldap.LDAPModifyDNResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get_exception(msg.resultCode, msg.errorMessage)

        self._assertMatchedDN(msg.matchedDN)
        self.dn = newDN
        return self

    async def move(self, newDN: interfaces.AnyDN) -> "LDAPEntryWithClient":
        self._checkState()
        target = distinguishedname.DistinguishedName(newDN)

        newrdn = target.split()[0]
        newSuperior = distinguishedname.DistinguishedName(listOfRDNs=target.split()[1:])
        target = distinguishedname.DistinguishedName((newrdn,) + newSuperior.split())
        op = pureldap.LDAPModifyDNRequest(
            entry=self.dn.getText(),
            newrdn=newrdn.getText(),
            deleteoldrdn=1,
            newSuperior=newSuperior.getText(),
        )
        return self._cbMoveDone(await self.client.send(op), target)

    move_async = move

    def _cbDeleteDone(self, msg: object) -> "LDAPEntryWithClient":
        assert isinstance(msg, pureldap.LDAPResult)
        if not isinstance(msg, pureldap.LDAPDelResponse):
            raise ldaperrors.get_exception(msg.resultCode, msg.errorMessage)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get_exception(msg.resultCode, msg.errorMessage)

        self._assertMatchedDN(msg.matchedDN)
        return self

    async def delete(self) -> "LDAPEntryWithClient":
        self._checkState()

        op = pureldap.LDAPDelRequest(entry=self.dn.getText())
        self._state = "deleted"
        return self._cbDeleteDone(await self.client.send(op))

    delete_async = delete

    def _cbAddDone(
        self, msg: object, dn: distinguishedname.DistinguishedName
    ) -> "LDAPEntryWithClient":
        assert isinstance(msg, pureldap.LDAPAddResponse), (
            "LDAPRequest response was not an LDAPAddResponse: %r" % msg
        )
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get_exception(msg.resultCode, msg.errorMessage)

        self._assertMatchedDN(msg.matchedDN)
        e = self.__class__(dn=dn, client=self.client)
        return e

    async def addChild(
        self,
        rdn: distinguishedname.RelativeDistinguishedName | str | bytes,
        attributes: interfaces.Attributes,
    ) -> "LDAPEntryWithClient":
        self._checkState()

        # objectClass goes first; the rest follow in order. Read rather than
        # rearranged, so the caller's own attributes are left alone.
        items = list(attributes.items())
        ordered: list[tuple[AttributeText, Iterable[AttributeText]]] = [
            (key, values) for key, values in items if key == "objectClass" and values
        ]
        ordered += sorted(
            (key, values) for key, values in items if key != "objectClass"
        )
        newRDN = distinguishedname.RelativeDistinguishedName(rdn)
        dn = distinguishedname.DistinguishedName(
            listOfRDNs=(newRDN,) + self.dn.split()
        )

        ldapAttrs = []
        for attrType, values in ordered:
            ldapAttrType = pureldap.LDAPAttributeDescription(attrType)
            lst = []
            for value in values:
                raw = value.encode("utf-8") if isinstance(value, str) else value
                lst.append(pureldap.LDAPAttributeValue(raw))
            ldapValues = pureber.BERSet(lst)
            ldapAttrs.append((ldapAttrType, ldapValues))
        op = pureldap.LDAPAddRequest(entry=dn.getText(), attributes=ldapAttrs)
        return self._cbAddDone(await self.client.send(op), dn)

    addChild_async = addChild

    def _cbSetPassword_ExtendedOperation(
        self, msg: object
    ) -> "LDAPEntryWithClient":
        assert isinstance(msg, pureldap.LDAPExtendedResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get_exception(msg.resultCode, msg.errorMessage)

        self._assertMatchedDN(msg.matchedDN)
        return self

    async def setPassword_ExtendedOperation(
        self, newPasswd: bytes
    ) -> "LDAPEntryWithClient":
        """

        Set the password on this object.

        @param newPasswd: A string containing the new password.

        @return: self, once the operation is done.

        """

        self._checkState()

        op = pureldap.LDAPPasswordModifyRequest(
            userIdentity=self.dn.getText(), newPasswd=newPasswd
        )
        return self._cbSetPassword_ExtendedOperation(await self.client.send(op))

    setPassword_ExtendedOperation_async = setPassword_ExtendedOperation

    _setPasswordPriority_ExtendedOperation = 0
    setPasswordMaybe_ExtendedOperation = setPassword_ExtendedOperation

    async def setPassword_Samba(
        self, newPasswd: bytes, style: str | None = None
    ) -> "LDAPEntryWithClient":
        """

        Set the Samba password on this object.

        @param newPasswd: A string containing the new password.

        @param style: one of 'sambaSamAccount', 'sambaAccount' or
        None. Specifies the style of samba accounts used. None is
        default and is the same as 'sambaSamAccount'.

        @return: self, once the operation is done.

        """

        self._checkState()

        nthash = smbpassword.nthash(newPasswd)
        lmhash = smbpassword.lmhash(newPasswd)

        if style is None:
            style = "sambaSamAccount"
        if style == "sambaSamAccount":
            self["sambaNTPassword"] = [nthash]
            self["sambaLMPassword"] = [lmhash]
        elif style == "sambaAccount":
            self["ntPassword"] = [nthash]
            self["lmPassword"] = [lmhash]
        else:
            raise RuntimeError("Unknown samba password style %r" % style)
        return await self.commit()

    setPassword_Samba_async = setPassword_Samba

    _setPasswordPriority_Samba = 20

    async def setPasswordMaybe_Samba(
        self, newPasswd: bytes
    ) -> "LDAPEntryWithClient":
        """

        Set the Samba password on this object if it is a
        sambaSamAccount or sambaAccount.

        @param newPasswd: A string containing the new password.

        @return: self, once the operation is done.

        """
        if not self.complete and not self.has_key("objectClass"):
            await self.fetch("objectClass")
            return await self.setPasswordMaybe_Samba(newPasswd)

        objectClasses = [
            to_bytes(s.upper()) for s in self.get("objectClass", ()) or ()
        ]
        if b"SAMBAACCOUNT" in objectClasses:
            return await self.setPassword_Samba(newPasswd, style="sambaAccount")
        if b"SAMBASAMACCOUNT" in objectClasses:
            return await self.setPassword_Samba(newPasswd, style="sambaSamAccount")
        return self

    setPasswordMaybe_Samba_async = setPasswordMaybe_Samba

    def _cbSetPassword(
        self,
        dl: Sequence[tuple[bool | None, Failure | None]],
        names: Sequence[str],
    ) -> "LDAPEntryWithClient":
        assert len(dl) == len(names)
        lst = []
        for name, (ok, x) in zip(names, dl):
            if not ok:
                # Every changer that did not succeed recorded why.
                assert x is not None
                lst.append((name, x))
        if lst:
            raise PasswordSetAggregateError(lst)
        return self

    async def _setPasswordAll(
        self, newPasswd: bytes, prefix: str, names: Sequence[str]
    ) -> list[tuple[bool | None, Failure | None]]:
        """Run every password changer in turn, collecting per-name outcomes.

        A changer that fails aborts the ones after it, but every name still
        gets an entry so `_cbSetPassword` can report which one broke.
        """
        results: list[tuple[bool | None, Failure | None]] = []
        for name in names:
            if results and not results[-1][0]:
                # a previous changer failed, so this one never ran
                results.append((None, Failure(PasswordSetAborted())))
                continue
            fn = getattr(self, prefix + name)
            result = await outcome.acapture(fn, newPasswd)
            if isinstance(result, outcome.Error):
                fail = Failure(result.error)
                fail.trap(ldaperrors.LDAPException, DNNotPresentError)
                results.append((False, fail))
            else:
                results.append((True, None))
        return results

    # A local entry sets a password in place, with a salt it chooses; a
    # remote one negotiates with the server and has nowhere to put a salt.
    # The interface asks only for the password, which both honour.
    async def setPassword(  # type: ignore[override]
        self, newPasswd: bytes
    ) -> "LDAPEntryWithClient":
        def _passwordChangerPriorityComparison(me: str, other: str) -> int:
            mePri: int = getattr(self, "_setPasswordPriority_" + me)
            otherPri: int = getattr(self, "_setPasswordPriority_" + other)
            return (mePri > otherPri) - (mePri < otherPri)

        prefix = "setPasswordMaybe_"
        names = [
            name[len(prefix) :]
            for name in dir(self)
            if name.startswith(prefix) and not name.endswith("_async")
        ]
        names.sort(key=functools.cmp_to_key(_passwordChangerPriorityComparison))

        results = await self._setPasswordAll(newPasswd, prefix, names)
        return self._cbSetPassword(results, names)

    setPassword_async = setPassword

    # end IEditableLDAPEntry

    # start IConnectedLDAPEntry

    def _cbNamingContext_Entries(
        self, results: Iterable["LDAPEntryWithClient"]
    ) -> "LDAPEntryWithClient":
        for result in results:
            for namingContext in result.get("namingContexts", ()) or ():
                dn = distinguishedname.DistinguishedName(namingContext)
                if dn.contains(self.dn):
                    return LDAPEntry(self.client, dn)
        raise NoContainingNamingContext(self.dn.getText())

    async def namingContext(self) -> "LDAPEntryWithClient":
        o = LDAPEntry(client=self.client, dn="")
        results = await o.search(
            filterText="(objectClass=*)",
            scope=pureldap.LDAP_SCOPE_baseObject,
            attributes=["namingContexts"],
        )
        # No callback was given, so the search hands back its results.
        assert isinstance(results, Sequence)
        return self._cbNamingContext_Entries(results)

    namingContext_async = namingContext

    def _cbFetch(
        self,
        results: Sequence["LDAPEntryWithClient"],
        overWrite: Sequence[AttributeText],
    ) -> "LDAPEntryWithClient":
        if len(results) != 1:
            raise DNNotPresentError(self.dn.getText())
        o = results[0]

        assert not self._journal

        if not overWrite:
            for key in list(self._remoteData.keys()):
                del self._remoteData[key]
            overWrite = o.keys()
            self.complete = 1

        for k in overWrite:
            vs = o.get(k)
            if vs is not None:
                self._remoteData[k] = vs
        self.undo()
        return self

    async def fetch(self, *attributes: AttributeText) -> "LDAPEntryWithClient":
        self._checkState()
        if self._journal:
            raise ObjectDirtyError(
                "cannot fetch attributes of %s, it is dirty" % repr(self)
            )

        results = await self.search(
            scope=pureldap.LDAP_SCOPE_baseObject, attributes=attributes
        )
        assert isinstance(results, Sequence)
        return self._cbFetch(results, overWrite=attributes)

    fetch_async = fetch

    def _cbSearchEntry(
        self,
        callback: Callable[["LDAPEntryWithClient"], object],
        objectName: AttributeText,
        attributes: Iterable[tuple[AttributeText, Iterable[AttributeText]]],
        complete: int,
    ) -> None:
        attrib: dict[bytes, list[bytes]] = {}
        for key, values in attributes:
            attrib[to_bytes(key)] = [to_bytes(x) for x in values]
        o = LDAPEntry(
            client=self.client, dn=objectName, attributes=attrib, complete=complete
        )
        callback(o)

    def _cbSearchMsg(
        self,
        msg: object,
        controls: object,
        slot: ResultSlot[object],
        callback: Callable[["LDAPEntryWithClient"], object],
        complete: int,
        sizeLimitIsNonFatal: bool,
    ) -> bool:
        if isinstance(msg, pureldap.LDAPSearchResultDone):
            assert msg.referral is None  # TODO
            if msg.resultCode != ldaperrors.Success.resultCode:
                e = ldaperrors.get_exception(msg.resultCode, msg.errorMessage)
                try:
                    raise e
                except ldaperrors.LDAPSizeLimitExceeded:
                    if sizeLimitIsNonFatal:
                        pass
                except Exception:
                    slot.set_exception(e)
                    return True

            # search ended successfully
            self._assertMatchedDN(msg.matchedDN)
            slot.set_value(controls)
            return True
        elif isinstance(msg, pureldap.LDAPSearchResultEntry):
            self._cbSearchEntry(
                callback, msg.objectName, msg.attributes, complete=complete
            )
            return False
        elif isinstance(msg, pureldap.LDAPSearchResultReference):
            return False
        else:
            raise ldaperrors.LDAPProtocolError("bad search response: %r" % msg)

    async def search(
        self,
        filterText: str | None = None,
        filterObject: pureber.BERBase | None = None,
        attributes: Sequence[AttributeText] | None = (),
        scope: int | None = None,
        derefAliases: int | None = None,
        sizeLimit: int = 0,
        timeLimit: int = 0,
        typesOnly: int = 0,
        callback: Callable[["LDAPEntryWithClient"], object] | None = None,
        # Keyword-only, so that the arguments this shares with every other
        # entry stay in the positions they have there.
        *,
        sizeLimitIsNonFatal: bool = False,
        controls: Iterable[pureldap.Control] | None = None,
        return_controls: bool = False,
    ) -> object:
        self._checkState()
        slot: ResultSlot[object] = ResultSlot()
        if filterObject is None and filterText is None:
            filterObject = pureldap.LDAPFilterMatchAll
        elif filterObject is None and filterText is not None:
            filterObject = ldapfilter.parseFilter(filterText)
        elif filterObject is not None and filterText is None:
            pass
        else:
            assert filterText is not None
            assert filterObject is not None
            f = ldapfilter.parseFilter(filterText)
            filterObject = pureldap.LDAPFilter_and([f, filterObject])

        if scope is None:
            scope = pureldap.LDAP_SCOPE_wholeSubtree
        if derefAliases is None:
            derefAliases = pureldap.LDAP_DEREF_neverDerefAliases

        if attributes is None:
            attributes = ["1.1"]

        results: list[LDAPEntryWithClient] = []
        cb: Callable[[LDAPEntryWithClient], object]
        if callback is None:
            cb = results.append
        else:
            cb = callback
        op = pureldap.LDAPSearchRequest(
            baseObject=self.dn.getText(),
            scope=scope,
            derefAliases=derefAliases,
            sizeLimit=sizeLimit,
            timeLimit=timeLimit,
            typesOnly=typesOnly,
            filter=filterObject,
            attributes=attributes,
        )
        # `_cbSearchMsg` resolves `slot` with the response controls as soon as
        # the server signals the search is done; the send itself may also fail
        # before that ever happens.
        result = await outcome.acapture(
            self.client.send_multiResponse_ex,
            op,
            controls,
            self._cbSearchMsg,
            slot,
            cb,
            complete=not attributes,
            sizeLimitIsNonFatal=sizeLimitIsNonFatal,
        )
        if isinstance(result, outcome.Error) and not slot.is_set:
            raise result.error

        ctls = await slot.wait()
        if callback is not None:
            return ctls
        if return_controls:
            return results, ctls
        return results

    search_async = search

    async def lookup(self, dn: interfaces.AnyDN) -> "LDAPEntryWithClient":
        e = self.__class__(self.client, dn)
        return await e.fetch("1.1")

    lookup_async = lookup

    # end IConnectedLDAPEntry

    def __repr__(self) -> str:
        x = {}
        for key in super().keys():
            x[key] = self[key]
        keys = list(x.keys())
        keys.sort()
        a = []
        for key in keys:
            a.append(f"{key!r}: {self[key]!r}")
        attributes = ", ".join(a)
        return f"{self.__class__.__name__}(dn={self.dn!r}, attributes={{{attributes}}})"


# API backwards compatibility
LDAPEntry = LDAPEntryWithClient


class Autofiller(Protocol):
    """Something that fills in attributes as an entry is built.

    It is handed the entry it was added to, both when it starts and for
    every modification journalled afterwards.
    """

    def start(self, ldapObject: "LDAPEntryWithAutoFill") -> object: ...

    def notify(
        self, ldapObject: "LDAPEntryWithAutoFill", attributeType: AttributeText
    ) -> object: ...


class LDAPEntryWithAutoFill(LDAPEntry):
    def __init__(
        self,
        client: LDAPSender,
        dn: interfaces.AnyDN,
        attributes: interfaces.Attributes = {},
        complete: int = 0,
    ) -> None:
        LDAPEntry.__init__(self, client, dn, attributes, complete)
        self.autoFillers: list[Autofiller] = []

    async def addAutofiller(self, autoFiller: Autofiller) -> object:
        # Autofillers may be plain or async, depending on whether they need to
        # talk to the server to work out their values.
        r = await await_result(autoFiller.start(self))
        self.autoFillers.append(autoFiller)
        return r

    def journal(self, journalOperation: delta.Modification) -> None:
        LDAPEntry.journal(self, journalOperation)
        for autoFiller in self.autoFillers:
            autoFiller.notify(self, journalOperation.key)
