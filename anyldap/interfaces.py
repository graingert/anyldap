from collections.abc import Awaitable, Callable, Iterable

from zope.interface import Interface

from anyldap.attributeset import LDAPAttributeSet
from anyldap.protocols.ldap.distinguishedname import (
    DistinguishedName,
    RelativeDistinguishedName,
)
from anyldap.protocols.pureber import BERBase

# What a method takes where it will build a DistinguishedName out of it.
AnyDN = DistinguishedName | str | bytes


class ILDAPEntry(Interface):
    """

    Pythonic API for LDAP object access and modification.

    >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
    ...     dn='cn=foo,dc=example,dc=com',
    ...     attributes={'anAttribute': ['itsValue', 'secondValue'],
    ...     'onemore': ['aValue'],
    ...     })
    >>> o
    LDAPEntry(dn='cn=foo,dc=example,dc=com', attributes={'anAttribute': ['itsValue', 'secondValue'], 'onemore': ['aValue']})
    """

    def __getitem__(key: str | bytes) -> LDAPAttributeSet[str | bytes]:
        """

        Get all values of an attribute.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue']})
        >>> o['anAttribute']
        ['itsValue']

        """

    def get(
        key: str | bytes,
        default: Iterable[str | bytes] | None = None,
    ) -> Iterable[str | bytes] | None:
        """

        Get all values of an attribute.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue']})
        >>> o.get('anAttribute')
        ['itsValue']
        >>> o.get('foo')
        >>> o.get('foo', [])
        []

        """

    def has_key(key: str | bytes) -> bool:
        """TODO"""

    def __contains__(key: str | bytes) -> bool:
        """TODO"""

    def keys() -> list[str | bytes]:
        """TODO"""

    def items() -> list[tuple[str | bytes, list[str | bytes]]]:
        """TODO"""

    def __str__() -> str:
        """

        Stringify as LDIF.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue', 'secondValue'],
        ...     'onemore': ['aValue'],
        ...     })
        >>> # must use rstrip or doctests won't like it due to the empty line
        >>> # you can just say "print o"
        >>> print str(o).rstrip()
        dn: cn=foo,dc=example,dc=com
        anAttribute: itsValue
        anAttribute: secondValue
        onemore: aValue

        """

    def __eq__(other: object) -> bool:
        """

        Comparison. Only equality is supported.

        >>> client=ldapclient.LDAPClient()
        >>> a=LDAPEntry(client=client,
        ...             dn='dc=example,dc=com')
        >>> b=LDAPEntry(client=client,
        ...             dn='dc=example,dc=com')
        >>> a==b
        1
        >>> c=LDAPEntry(client=ldapclient.LDAPClient(),
        ...             dn='ou=different,dc=example,dc=com')
        >>> a==c
        0

        Comparison does not consider the client of the object.

        >>> anotherClient=ldapclient.LDAPClient()
        >>> d=LDAPEntry(client=anotherClient,
        ...             dn='dc=example,dc=com')
        >>> a==d
        1

        """

    def __ne__(other: object) -> bool:
        """

        Inequality comparison. See L{__eq__}.

        """

    def __len__() -> int:
        """TODO"""

    def __nonzero__() -> bool:
        """Always return True"""

    def bind(password: str | bytes) -> Awaitable["ILDAPEntry"]:
        """
        Try to authenticate with given secret.

        @return: ILDAPEntry (that is, self).

        @raise ldaperrors.LDAPInvalidCredentials: password was
        incorrect.
        """


class IEditableLDAPEntry(ILDAPEntry):
    """Interface definition for editable LDAP entries.

    Editing an entry means reading it too -- every modification asks what
    the entry already holds -- so this is an ILDAPEntry as well. Every
    implementer already provided both.
    """

    def __setitem__(key: str | bytes, value: Iterable[str | bytes]) -> None:
        """

        Set values of an attribute. Please use lists. Do not modify
        the lists in place, that's not supported _yet_.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue']})
        >>> o['anAttribute']=['foo', 'bar']
        >>> o['anAttribute']
        ['bar', 'foo']

        """

    def __delitem__(key: str | bytes) -> None:
        """

        Delete all values of an attribute.

        >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={
        ...     'anAttribute': ['itsValue', 'secondValue'],
        ...     'another': ['moreValues'],
        ...     })
        >>> del o['anAttribute']
        >>> o
        LDAPEntry(dn='cn=foo,dc=example,dc=com', attributes={'another': ['moreValues']})

        """

    def undo() -> None:
        """
        Forget all pending changes.
        """

    def commit() -> Awaitable[bool]:
        """
        Send all pending changes to the LDAP server.

        @returns: True (operation succeeded) or False (operation failed).
        """

    def move(newDN: AnyDN) -> Awaitable[object]:
        """

        Move the object to a new DN.

        @param newDN: the new DistinguishedName

        @return: Completes when the move is done.

        """

    def delete() -> Awaitable[object]:
        """

        Delete this object from the LDAP server.

        @return: Completes when the delete is done.

        """

    def setPassword(newPasswd: bytes) -> Awaitable[object]:
        """

        Set all applicable passwords for this object.

        @param newPasswd: A string containing the new password.

        @return: Completes when the operation is done.

        """


class IConnectedLDAPEntry(Interface):
    """
    Interface definition for LDAP entries that are part of a bigger
    whole.
    """

    def namingContext() -> Awaitable["ILDAPEntry"]:
        """
        Return an LDAPEntry for the naming context that contains this object.
        """

    def fetch(*attributes: str | bytes) -> Awaitable["ILDAPEntry"]:
        """
        Fetch the attributes of this object from the server.

        @param attributes: Attributes to fetch. If none, fetch all
        attributes. Fetched attributes are overwritten, and if
        fetching all attributes, attributes that are not on the server
        are removed.

        @return: Completes when the operation is done.
        """

    def search(
        filterText: str | None = None,
        filterObject: BERBase | None = None,
        attributes: Iterable[str | bytes] = (),
        scope: int | None = None,
        derefAliases: int | None = None,
        sizeLimit: int = 0,
        timeLimit: int = 0,
        typesOnly: int = 0,
        callback: Callable[["ILDAPEntry"], object] | None = None,
    ) -> Awaitable[list["ILDAPEntry"] | None]:
        """

        Perform an LDAP search with this object as the base.

        @param filterText: LDAP search filter as a string.

        @param filterObject: LDAP search filter as LDAPFilter.
        Note if both filterText and filterObject are given, they
        are combined with AND. If neither is given, the search is
        made with a filter that matches everything.

        @param attributes: List of attributes to retrieve for the
        result objects. An empty list and means all.

        @param scope: Whether to recurse into subtrees.

        @param derefAliases: Whether to deref LDAP aliases. TODO write
        better documentation.

        @param sizeLimit: At most how many entries to return. 0 means
        unlimited.

        @param timeLimit: At most how long to use for processing the
        search request. 0 means unlimited.

        @param typesOnly: Whether to return attribute types only, or
        also values.

        @param callback: Callback function to call for each resulting
        LDAPEntry. None means gather the results into a list and
        return it from here.

        @return: Completes when the search is done, giving None if
        callback was given and a list of the search results if callback
        is not given or is None.

        """

    def children(
        callback: Callable[["ILDAPEntry"], object] | None = None
    ) -> Awaitable[list["ILDAPEntry"] | None]:
        """

        List the direct children of this entry. Try to avoid using
        .search(), as this will be used later to implement .search()
        on LDAP backends.

        @param callback: Callback function to call for each resulting
        LDAPEntry. None means gather the results into a list and
        return it from here.

        @return: Completes when the list is over, giving None if
        callback was given and a list of the children if callback is
        not given or is None.

        """

    def subtree(
        callback: Callable[["ILDAPEntry"], object] | None = None
    ) -> Awaitable[list["ILDAPEntry"] | None]:
        """

        List the subtree rooted at this entry, including this
        entry. Try to avoid using .search(), as this will be used
        later to implement .search() on LDAP backends.

        @param callback: Callback function to call for each resulting
        LDAPEntry. None means gather the results into a list and
        return it from here.

        @return: Completes when the list is over, giving None if
        callback was given and a list of the children if callback is
        not given or is None.

        """

    def lookup(dn: AnyDN) -> Awaitable["IConnectedLDAPEntry"]:
        """
        Lookup the referred to by dn.

        @return: An entry from the same tree, or raises e.g. LDAPNoSuchObject.
        """

    def addChild(
        rdn: RelativeDistinguishedName | str | bytes, attributes: object
    ) -> "IConnectedLDAPEntry | Awaitable[IConnectedLDAPEntry]":
        """
        Add a child entry directly below this one.

        Backends that touch the filesystem have to await; the in-memory one
        does not, so callers pass the result through
        anyldap._async.await_result.

        @return: The new child entry.
        """

    def match(filter: BERBase) -> bool:
        """

        Does entry match filter.

        @param filter: An LDAPFilter (e.g. LDAPFilter_present,
        LDAPFilter_equalityMatch etc. TODO provide an interface or
        superclass for filters.)

        @return: Boolean.

        """


class ILDAPConfig(Interface):
    """Generic LDAP configuration retrieval."""

    def getBaseDN() -> DistinguishedName | str:
        """
        Get the LDAP base DN, as a DistinguishedName.

        Raises anyldap.config.MissingBaseDNError
        if configuration does not specify a base DN.
        """

    def getServiceLocationOverrides(
    ) -> dict[DistinguishedName, tuple[str | None, str | int | None]]:
        """
        Get the LDAP service location overrides, as a mapping of
        DistinguishedName to (host, port) tuples.
        """

    def copy(
        baseDN: AnyDN | None = None,
        serviceLocationOverrides: dict[
            DistinguishedName, tuple[str | None, str | int | None]
        ]
        | None = None,
    ) -> "ILDAPConfig":
        """
        Make a copy of this configuration, overriding certain aspects
        of it.
        """

    def getIdentityBaseDN() -> DistinguishedName | str:
        """TODO"""

    def getIdentitySearch(name: str) -> str:
        """TODO"""
