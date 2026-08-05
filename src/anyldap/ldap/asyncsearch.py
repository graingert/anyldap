"""``ldap.asyncsearch``: a search read result by result rather than all at once.

A search that would fill memory if it were all asked for at once is read
here as it arrives: ``startSearch()`` sends the request, and
``processResults()`` reads answers and hands each one to
``_processSingleResult()``, which a subclass overrides to do whatever it is
collecting or writing. The classes below are python-ldap's, and are used the
same way; only the two methods that touch the connection are awaited.

The hooks -- ``preProcessing()``, ``afterFirstResult()``,
``postProcessing()`` and ``_processSingleResult()`` -- are plain methods, as
they are in python-ldap: they are called while a result is being dispatched
and cannot await.
"""

from collections.abc import Mapping, Sequence
from typing import IO, TYPE_CHECKING, Any

from anyldap.ldap.constants import (
    RES_SEARCH_ENTRY,
    RES_SEARCH_REFERENCE,
    RES_SEARCH_RESULT,
)
from anyldap.ldap.ldapobject import Controls, Entry, Reference, SimpleLDAPObject
from anyldap.protocols.ldap import ldif as _ldif

if TYPE_CHECKING:  # pragma: no cover
    from _typeshed import SupportsWrite

__all__ = [
    "SEARCH_RESULT_TYPES",
    "ENTRY_RESULT_TYPES",
    "WrongResultType",
    "AsyncSearchHandler",
    "List",
    "Dict",
    "IndexedDict",
    "FileWriter",
    "LDIFWriter",
]

SEARCH_RESULT_TYPES = {
    RES_SEARCH_ENTRY,
    RES_SEARCH_RESULT,
    RES_SEARCH_REFERENCE,
}

ENTRY_RESULT_TYPES = {
    RES_SEARCH_ENTRY,
    RES_SEARCH_RESULT,
}

# One item of what a search answers with: an entry, or a reference somewhere
# else.
ResultItem = Entry | Reference


class WrongResultType(Exception):
    """A result arrived that a search cannot have answered with."""

    def __init__(
        self, receivedResultType: int, expectedResultTypes: set[int]
    ) -> None:
        self.receivedResultType = receivedResultType
        self.expectedResultTypes = expectedResultTypes
        Exception.__init__(self)

    def __str__(self) -> str:
        return "Received wrong result type {} (expected one of {}).".format(
            self.receivedResultType,
            ", ".join(str(result) for result in self.expectedResultTypes),
        )


class AsyncSearchHandler:
    """A search whose results are handled one at a time.

    ``l`` is the connection to search on.
    """

    def __init__(self, l: SimpleLDAPObject) -> None:  # noqa: E741
        self._l = l
        self._msgId: int | None = None
        self._afterFirstResult = 1
        self.beginResultsDropped = 0
        self.endResultBreak = 0

    async def startSearch(
        self,
        searchRoot: str,
        searchScope: int,
        filterStr: str,
        attrList: Sequence[str] | None = None,
        attrsOnly: int = 0,
        timeout: float = -1,
        sizelimit: int = 0,
        serverctrls: Controls = None,
        clientctrls: Controls = None,
    ) -> None:
        """Send the search, without waiting for what it answers.

        The arguments are ``search_ext()``'s, in the order python-ldap's
        ``startSearch()`` takes them.
        """
        self._msgId = await self._l.search_ext(
            searchRoot,
            searchScope,
            filterStr,
            attrList,
            attrsOnly,
            serverctrls,
            clientctrls,
            timeout,
            sizelimit,
        )
        self._afterFirstResult = 1

    def preProcessing(self) -> None:
        """Anything to do after starting the search, before reading it."""

    def afterFirstResult(self) -> None:
        """Anything to do once the first result has arrived."""

    def postProcessing(self) -> None:
        """Anything to do once every result has been read."""

    async def processResults(
        self,
        ignoreResultsNumber: int = 0,
        processResultsCount: int = 0,
        timeout: float = -1,
    ) -> int:
        """Read the results and hand each one on.

        The first ``ignoreResultsNumber`` are dropped, and at most
        ``processResultsCount`` are handled after that, or all of them if it
        is zero. Answers 1 if there are results left unread, which is when
        the search has been abandoned, and 0 if it ran out.
        """
        self.preProcessing()
        result_counter = 0
        end_result_counter = ignoreResultsNumber + processResultsCount
        go_ahead = 1
        partial = 0
        self.beginResultsDropped = 0
        self.endResultBreak = result_counter
        try:
            result_type: int | None = None
            result_list: Sequence[ResultItem] = []
            while go_ahead:
                while result_type is None and not result_list:
                    assert self._msgId is not None
                    (
                        result_type,
                        result_list,
                        _result_msgid,
                        _result_serverctrls,
                    ) = await self._l.result3(self._msgId, 0, timeout)
                    if self._afterFirstResult:
                        self.afterFirstResult()
                        self._afterFirstResult = 0
                if not result_list:
                    break
                # The two are read together, so a result list means a type.
                assert result_type is not None
                if result_type not in SEARCH_RESULT_TYPES:
                    raise WrongResultType(result_type, SEARCH_RESULT_TYPES)
                # Loop over list of search results
                for result_item in result_list:
                    if result_counter < ignoreResultsNumber:
                        self.beginResultsDropped = self.beginResultsDropped + 1
                    elif processResultsCount == 0 or result_counter < end_result_counter:
                        self._processSingleResult(result_type, result_item)
                    else:
                        go_ahead = 0  # break-out from while go_ahead
                        partial = 1
                        break  # break-out from this for-loop
                    result_counter = result_counter + 1
                result_type, result_list = None, []
                self.endResultBreak = result_counter
        finally:
            if partial and self._msgId is not None:
                await self._l.abandon(self._msgId)
        self.postProcessing()
        return partial

    def _processSingleResult(
        self, resultType: int, resultItem: ResultItem
    ) -> None:
        """One result, for a subclass to do something with."""


class List(AsyncSearchHandler):
    """Every result, kept as it came.

    Which looks pointless until only a certain part of a long search is
    wanted, which is what ``processResults()``'s arguments say.
    """

    def __init__(self, l: SimpleLDAPObject) -> None:  # noqa: E741
        AsyncSearchHandler.__init__(self, l)
        self.allResults: list[tuple[int, ResultItem]] = []

    def _processSingleResult(
        self, resultType: int, resultItem: ResultItem
    ) -> None:
        self.allResults.append((resultType, resultItem))


class Dict(AsyncSearchHandler):
    """Every entry, keyed by its distinguished name."""

    def __init__(self, l: SimpleLDAPObject) -> None:  # noqa: E741
        AsyncSearchHandler.__init__(self, l)
        self.allEntries: dict[str, Mapping[str, list[bytes]]] = {}

    def _processSingleResult(
        self, resultType: int, resultItem: ResultItem
    ) -> None:
        if resultType in ENTRY_RESULT_TYPES:
            # Search continuations are ignored
            dn, entry = resultItem
            assert dn is not None and isinstance(entry, dict)
            self.allEntries[dn] = entry


class IndexedDict(Dict):
    """Every entry, and an index of which names hold which values."""

    def __init__(
        self,
        l: SimpleLDAPObject,  # noqa: E741
        indexed_attrs: Sequence[str] | None = None,
    ) -> None:
        Dict.__init__(self, l)
        self.indexed_attrs = tuple(indexed_attrs or ())
        self.index: dict[str, dict[bytes, list[str]]] = {
            attribute: {} for attribute in self.indexed_attrs
        }

    def _processSingleResult(
        self, resultType: int, resultItem: ResultItem
    ) -> None:
        if resultType in ENTRY_RESULT_TYPES:
            # Search continuations are ignored
            dn, entry = resultItem
            assert dn is not None and isinstance(entry, dict)
            self.allEntries[dn] = entry
            for attribute in self.indexed_attrs:
                if attribute in entry:
                    for value in entry[attribute]:
                        self.index[attribute].setdefault(value, []).append(dn)


class FileWriter(AsyncSearchHandler):
    """Results written to a file as they arrive.

    ``headerStr`` goes in before the first one and ``footerStr`` after the
    last, which is what the two hooks are for.
    """

    def __init__(
        self,
        l: SimpleLDAPObject,  # noqa: E741
        f: "SupportsWrite[Any]",
        headerStr: str | bytes = "",
        footerStr: str | bytes = "",
    ) -> None:
        AsyncSearchHandler.__init__(self, l)
        self._f = f
        self.headerStr = headerStr
        self.footerStr = footerStr

    def preProcessing(self) -> None:
        """The header, written before any result has been read."""
        self._f.write(self.headerStr)

    def postProcessing(self) -> None:
        """The footer, written once every result has been read."""
        self._f.write(self.footerStr)


class LDIFWriter(FileWriter):
    """Results written out as LDIF.

    python-ldap takes either a file or one of its own ``ldif.LDIFWriter``
    objects here; this takes the file, and writes each entry with
    :func:`anyldap.protocols.ldap.ldif.asLDIF`, which is what the rest of
    anyldap writes LDIF with.
    """

    def __init__(
        self,
        l: SimpleLDAPObject,  # noqa: E741
        writer_obj: IO[bytes],
        headerStr: bytes = b"",
        footerStr: bytes = b"",
    ) -> None:
        FileWriter.__init__(self, l, writer_obj, headerStr, footerStr)

    def _processSingleResult(
        self, resultType: int, resultItem: ResultItem
    ) -> None:
        if resultType in ENTRY_RESULT_TYPES:
            # Search continuations are ignored
            dn, entry = resultItem
            assert dn is not None and isinstance(entry, dict)
            self._f.write(_ldif.asLDIF(dn, entry.items()))
