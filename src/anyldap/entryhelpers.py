from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any, Protocol

from anyldap import delta, interfaces, ldapfilter
from anyldap._encoder import get_strings, to_bytes
from anyldap.attributeset import LDAPAttributeSet
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import distinguishedname, ldaperrors, ldapsyntax

AttributeText = str | bytes


Entry = interfaces.IWalkableLDAPEntry


# What a walk hands each entry to. It is awaited, so a walk can be written
# out as it goes rather than collected first.
EntryCallback = Callable[[Entry], Awaitable[None]]


class Readable(Protocol):
    """What the matching mixin needs of the entry it is mixed into."""

    dn: distinguishedname.DistinguishedName

    def __contains__(self, key: AttributeText) -> bool: ...

    def __getitem__(self, key: AttributeText) -> LDAPAttributeSet[AttributeText]: ...

    def get(
        self, key: AttributeText, default: Iterable[AttributeText] | None = None
    ) -> Iterable[AttributeText] | None: ...

    def match(self, filter: pureber.BERBase) -> bool: ...


class Walkable(Protocol):
    """What the tree-walking mixins need of the entry they are mixed into."""

    dn: distinguishedname.DistinguishedName

    # The host compares against its own class, which each backend spells
    # differently, so this parameter is left to the host to constrain.
    def diff(self, other: Any) -> delta.ModifyOp | None: ...

    async def children(
        self, callback: EntryCallback | None = None
    ) -> list[Entry] | None: ...

    async def subtree(
        self, callback: EntryCallback | None = None
    ) -> list[Entry] | None: ...

    async def diffTree(
        self, other: Entry, result: list[delta.Operation] | None = None
    ) -> object: ...

    def match(self, filter: pureber.BERBase) -> bool: ...

    def toWire(self) -> bytes: ...


class DiffTreeHost(Walkable, Protocol):
    """A Walkable that DiffTreeMixin has been mixed into."""

    async def _diffTree_commonChildren(
        self,
        children: Iterable[tuple[Entry, Entry]],
        result: list[delta.Operation],
    ) -> list[delta.Operation]: ...

    async def _diffTree_addedChildren(
        self, children: Iterable[Entry], result: list[delta.Operation]
    ) -> list[delta.Operation]: ...

    async def _diffTree_deletedChildren(
        self, children: Iterable[Entry], result: list[delta.Operation]
    ) -> list[delta.Operation]: ...


def _folded(value: AttributeText) -> bytes:
    """An attribute or filter value in the one form matching compares in.

    An entry holds whichever of text or bytes it was given, and a filter off
    the wire always holds bytes, so a comparison between the two has to bring
    them together first. utf-8 sorts in code point order, so the ordering
    comparisons mean the same thing in either.
    """
    return to_bytes(value).lower()


def safelower(s: object) -> object:
    """
    As string.lower(), but return `s` if something goes wrong.
    """
    if hasattr(s, "lower"):
        return s.lower()
    return s


class DiffTreeMixin:
    async def _diffTree_commonChildren(
        self,
        children: Iterable[tuple[Entry, Entry]],
        result: list[delta.Operation],
    ) -> list[delta.Operation]:
        for a, b in children:
            await a.diffTree(b, result)
        return result

    async def _diffTree_addedChildren(
        self, children: Iterable[Entry], result: list[delta.Operation]
    ) -> list[delta.Operation]:
        for child in children:
            entries = await child.subtree()
            assert entries is not None
            for c in entries:
                result.append(delta.AddOp(c))
        return result

    async def _diffTree_deletedChildren(
        self, children: Iterable[Entry], result: list[delta.Operation]
    ) -> list[delta.Operation]:
        for child in children:
            entries = await child.subtree()
            assert entries is not None
            entries.reverse()  # remove children before their parent
            for c in entries:
                result.append(delta.DeleteOp(c))
        return result

    async def diffTree(
        self: DiffTreeHost,
        other: Entry,
        result: list[delta.Operation] | None = None,
    ) -> list[delta.Operation]:
        assert (
            self.dn == other.dn
        ), "diffTree arguments must refer to same LDAP tree:" "%r != %r" % (
            str(self.dn),
            str(other.dn),
        )
        if result is None:
            result = []

        # differences in root
        rootDiff = self.diff(other)
        if rootDiff is not None:
            result.append(rootDiff)

        myChildren = await self.children()
        otherChildren = await other.children()
        assert myChildren is not None
        assert otherChildren is not None

        def rdnToChild(
            rdn: distinguishedname.RelativeDistinguishedName,
            l: Iterable[Entry],
        ) -> Entry:
            r = [x for x in l if x.dn.split()[0] == rdn]
            assert len(r) == 1
            return r[0]

        my = {x.dn.split()[0] for x in myChildren}
        his = {x.dn.split()[0] for x in otherChildren}

        # differences in common children
        commonRDN = sorted(my & his)  # sorted for reproducability only
        await self._diffTree_commonChildren(
            [
                (rdnToChild(rdn, myChildren), rdnToChild(rdn, otherChildren))
                for rdn in commonRDN
            ],
            result,
        )

        # added children
        addedRDN = sorted(his - my)
        await self._diffTree_addedChildren(
            [rdnToChild(rdn, otherChildren) for rdn in addedRDN], result
        )

        # deleted children
        deletedRDN = sorted(my - his)
        return await self._diffTree_deletedChildren(
            [rdnToChild(rdn, myChildren) for rdn in deletedRDN], result
        )


class SubtreeFromChildrenMixin:
    async def subtree(
        self: Walkable, callback: EntryCallback | None = None
    ) -> list[Entry] | None:
        if callback is None:
            result: list[Entry] = []

            async def collect(entry: Entry) -> None:
                result.append(entry)

            await self.subtree(callback=collect)
            return result

        # self is the entry the mixin was mixed into; the callback is handed
        # entries, so say that the host is one.
        assert interfaces.IWalkableLDAPEntry.providedBy(self)
        await callback(self)
        children = await self.children()
        assert children is not None
        while children:
            await children.pop().subtree(callback)
        return None


class MatchMixin:
    def match(self: Readable, filter: pureber.BERBase) -> bool:
        if isinstance(filter, pureldap.LDAPFilter_present):
            for value in get_strings(filter.value):
                if value in self:
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_equalityMatch):
            # TODO case insensitivity depends on different attribute syntaxes
            assert filter.assertionValue is not None
            wanted = _folded(filter.assertionValue.value)
            for value in self.get(filter.attributeDesc.value, []) or ():
                if _folded(value) == wanted:
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_substrings):
            if filter.type not in self:
                return False
            possibleMatches = [_folded(x) for x in self[filter.type]]
            substrings = list(filter.substrings)

            if substrings and isinstance(
                substrings[0], pureldap.LDAPFilter_substrings_initial
            ):
                initial = _folded(substrings[0].value)
                possibleMatches = [
                    x[len(initial) :]
                    for x in possibleMatches
                    if x.startswith(initial)
                ]
                del substrings[0]

            if substrings and isinstance(
                substrings[-1], pureldap.LDAPFilter_substrings_final
            ):
                final = _folded(substrings[-1].value)
                possibleMatches = [
                    x[: -len(final)] for x in possibleMatches if x.endswith(final)
                ]
                del substrings[-1]

            while possibleMatches and substrings:
                assert isinstance(substrings[0], pureldap.LDAPFilter_substrings_any)
                any_ = _folded(substrings[0].value)
                r = []
                for possible in possibleMatches:
                    i = possible.find(any_)
                    if i >= 0:
                        r.append(possible[i:])
                possibleMatches = r
                del substrings[0]
            if possibleMatches and not substrings:
                return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_greaterOrEqual):
            if filter.attributeDesc.value not in self:
                return False
            assert filter.assertionValue is not None
            wanted = to_bytes(filter.assertionValue.value)
            for value in self[filter.attributeDesc.value]:
                if to_bytes(value) >= wanted:
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_lessOrEqual):
            if filter.attributeDesc.value not in self:
                return False
            assert filter.assertionValue is not None
            wanted = to_bytes(filter.assertionValue.value)
            for value in self[filter.attributeDesc.value]:
                if to_bytes(value) <= wanted:
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_and):
            for filt in filter:
                if not self.match(filt):
                    return False
            return True
        elif isinstance(filter, pureldap.LDAPFilter_or):
            for filt in filter:
                if self.match(filt):
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_not):
            return not self.match(filter.value)
        elif isinstance(filter, pureldap.LDAPFilter_extensibleMatch):
            if filter.matchingRule is None:
                attrib = filter.type.value if filter.type else None
                match_value_lower = _folded(filter.matchValue.value)
                if attrib is not None and any(
                    _folded(val) == match_value_lower
                    for val in self.get(attrib, []) or ()
                ):
                    return True
                for rdn in self.dn.listOfRDNs:
                    for av in rdn.attributeTypesAndValues:
                        if attrib is None or attrib == av.attributeType:
                            if match_value_lower == _folded(av.value):
                                return True
                return False
            else:
                raise ldapsyntax.MatchNotImplemented(filter)
        else:
            raise ldapsyntax.MatchNotImplemented(filter)


class SearchByTreeWalkingMixin:
    async def search(
        self: Walkable,
        filterText: str | None = None,
        filterObject: pureber.BERBase | None = None,
        attributes: Sequence[AttributeText] | None = (),
        scope: int | None = None,
        derefAliases: int | None = None,
        sizeLimit: int = 0,
        timeLimit: int = 0,
        typesOnly: int = 0,
        callback: EntryCallback | None = None,
    ) -> list[Entry] | None:
        if filterObject is None and filterText is None:
            filterObject = pureldap.LDAPFilterMatchAll
        elif filterObject is None and filterText is not None:
            filterObject = ldapfilter.parseFilter(filterText)
        elif filterObject is not None and filterText is None:
            pass
        else:
            assert filterObject is not None
            assert filterText is not None
            f = ldapfilter.parseFilter(filterText)
            filterObject = pureldap.LDAPFilter_and([f, filterObject])

        if scope is None:
            scope = pureldap.LDAP_SCOPE_wholeSubtree
        if derefAliases is None:
            derefAliases = pureldap.LDAP_DEREF_neverDerefAliases

        # choose iterator: base/children/subtree
        iterator: Callable[..., Awaitable[list[Entry] | None]]
        if scope == pureldap.LDAP_SCOPE_wholeSubtree:
            iterator = self.subtree
        elif scope == pureldap.LDAP_SCOPE_singleLevel:
            iterator = self.children
        elif scope == pureldap.LDAP_SCOPE_baseObject:

            async def iterateSelf(
                callback: EntryCallback,
            ) -> list[Entry] | None:
                assert interfaces.IWalkableLDAPEntry.providedBy(self)
                await callback(self)
                return None

            iterator = iterateSelf
        else:
            raise ldaperrors.LDAPProtocolError("unknown search scope: %r" % scope)

        results: list[Entry] = []
        matchCallback: EntryCallback
        if callback is None:

            async def collect(entry: Entry) -> None:
                results.append(entry)

            matchCallback = collect
        else:
            matchCallback = callback

        # gather results, send them
        async def _tryMatch(entry: Entry) -> None:
            assert filterObject is not None
            if entry.match(filterObject):
                await matchCallback(entry)

        await iterator(callback=_tryMatch)

        if callback is None:
            return results
        return None
