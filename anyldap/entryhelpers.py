from anyldap import delta, ldapfilter
from anyldap._encoder import get_strings
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors, ldapsyntax


def safelower(s):
    """
    As string.lower(), but return `s` if something goes wrong.
    """
    try:
        return s.lower()
    except AttributeError:
        return s


class DiffTreeMixin:
    async def _diffTree_commonChildren(self, children, result):
        for a, b in children:
            await a.diffTree(b, result)
        return result

    async def _diffTree_addedChildren(self, children, result):
        for child in children:
            for c in await child.subtree():
                result.append(delta.AddOp(c))
        return result

    async def _diffTree_deletedChildren(self, children, result):
        for child in children:
            entries = await child.subtree()
            entries.reverse()  # remove children before their parent
            for c in entries:
                result.append(delta.DeleteOp(c))
        return result

    async def diffTree(self, other, result=None):
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

        def rdnToChild(rdn, l):
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
    async def subtree(self, callback=None):
        if callback is None:
            result = []
            await self.subtree(callback=result.append)
            return result

        callback(self)
        children = await self.children()
        while children:
            await children.pop().subtree(callback)


class MatchMixin:
    def match(self, filter):
        if isinstance(filter, pureldap.LDAPFilter_present):
            for value in get_strings(filter.value):
                if value in self:
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_equalityMatch):
            # TODO case insensitivity depends on different attribute syntaxes
            for value in get_strings(filter.assertionValue.value.lower()):
                if value in [
                    val.lower() for val in self.get(filter.attributeDesc.value, [])
                ]:
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_substrings):
            if filter.type not in self:
                return False
            possibleMatches = self[filter.type]
            substrings = filter.substrings[:]

            if substrings and isinstance(
                filter.substrings[0], pureldap.LDAPFilter_substrings_initial
            ):
                possibleMatches = [
                    x[len(filter.substrings[0].value) :]
                    for x in possibleMatches
                    if x.lower().startswith(filter.substrings[0].value.lower())
                ]
                del substrings[0]

            if substrings and isinstance(
                filter.substrings[-1], pureldap.LDAPFilter_substrings_final
            ):
                possibleMatches = [
                    x[: -len(filter.substrings[0].value)]
                    for x in possibleMatches
                    if x.lower().endswith(filter.substrings[-1].value.lower())
                ]
                del substrings[-1]

            while possibleMatches and substrings:
                assert isinstance(substrings[0], pureldap.LDAPFilter_substrings_any)
                r = []
                for possible in possibleMatches:
                    i = possible.lower().find(substrings[0].value.lower())
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
            for value in self[filter.attributeDesc.value]:
                if value >= filter.assertionValue.value:
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_lessOrEqual):
            if filter.attributeDesc.value not in self:
                return False
            for value in self[filter.attributeDesc.value]:
                if value <= filter.assertionValue.value:
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
                attrib = filter.type.value
                match_value = filter.matchValue.value
                match_value_lower = safelower(match_value)
                if match_value_lower in [val.lower() for val in self.get(attrib, [])]:
                    return True
                for rdn in self.dn.listOfRDNs:
                    for av in rdn.attributeTypesAndValues:
                        if attrib is None or attrib == av.attributeType:
                            if match_value_lower == safelower(av.value):
                                return True
                return False
            else:
                raise ldapsyntax.MatchNotImplemented(filter)
        else:
            raise ldapsyntax.MatchNotImplemented(filter)


class SearchByTreeWalkingMixin:
    async def search(
        self,
        filterText=None,
        filterObject=None,
        attributes=(),
        scope=None,
        derefAliases=None,
        sizeLimit=0,
        timeLimit=0,
        typesOnly=0,
        callback=None,
    ):
        if filterObject is None and filterText is None:
            filterObject = pureldap.LDAPFilterMatchAll
        elif filterObject is None and filterText is not None:
            filterObject = ldapfilter.parseFilter(filterText)
        elif filterObject is not None and filterText is None:
            pass
        else:
            f = ldapfilter.parseFilter(filterText)
            filterObject = pureldap.LDAPFilter_and((f, filterObject))

        if scope is None:
            scope = pureldap.LDAP_SCOPE_wholeSubtree
        if derefAliases is None:
            derefAliases = pureldap.LDAP_DEREF_neverDerefAliases

        # choose iterator: base/children/subtree
        if scope == pureldap.LDAP_SCOPE_wholeSubtree:
            iterator = self.subtree
        elif scope == pureldap.LDAP_SCOPE_singleLevel:
            iterator = self.children
        elif scope == pureldap.LDAP_SCOPE_baseObject:

            async def iterateSelf(callback):
                callback(self)

            iterator = iterateSelf
        else:
            raise ldaperrors.LDAPProtocolError("unknown search scope: %r" % scope)

        results = []
        if callback is None:
            matchCallback = results.append
        else:
            matchCallback = callback

        # gather results, send them
        def _tryMatch(entry):
            if entry.match(filterObject):
                matchCallback(entry)

        await iterator(callback=_tryMatch)

        if callback is None:
            return results
        return None
