"""``ldap.controls.openldap``: the controls OpenLDAP has of its own."""

from typing import TYPE_CHECKING

from anyldap.ldap.constants import SCOPE_SUBTREE
from anyldap.ldap.controls import KNOWN_RESPONSE_CONTROLS, ResponseControl
from anyldap.ldap.controls.simple import ValueLessRequestControl
from anyldap.protocols import pureber

SEARCH_NOOP_OID = "1.3.6.1.4.1.4203.666.5.18"


class SearchNoOpControl(ValueLessRequestControl, ResponseControl):
    """Ask what a search would have found, without sending the entries.

    The result carries the numbers instead: how many entries the search
    matched, and how many references it would have followed. See
    https://www.openldap.org/its/index.cgi?findid=6598.
    """

    controlType = SEARCH_NOOP_OID

    def __init__(self, criticality: bool = False) -> None:
        ValueLessRequestControl.__init__(self, SEARCH_NOOP_OID, criticality)
        self.resultCode: int | None = None
        self.numSearchResults: int | None = None
        self.numSearchContinuations: int | None = None

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        value, _ = pureber.berDecodeObject(
            pureber.BERDecoderContext(), encodedControlValue
        )
        assert isinstance(value, pureber.BERSequence)
        code, results, continuations = value[0], value[1], value[2]
        assert isinstance(code, pureber.BERInteger)
        assert isinstance(results, pureber.BERInteger)
        assert isinstance(continuations, pureber.BERInteger)
        self.resultCode = code.value
        self.numSearchResults = results.value
        self.numSearchContinuations = continuations.value


KNOWN_RESPONSE_CONTROLS[SearchNoOpControl.controlType] = SearchNoOpControl


if TYPE_CHECKING:  # pragma: no cover
    # What the mixin is mixed into, so that the calls below are checked
    # against the connection that will really answer them.
    from anyldap.ldap.ldapobject import SimpleLDAPObject as _MixedInto
else:
    _MixedInto = object


class SearchNoOpMixIn(_MixedInto):
    """What a connection mixes in to count entries without reading them.

    python-ldap keeps ``noop_search_st`` here rather than on the connection
    itself, so that a caller who wants it says so::

        class Connection(SearchNoOpMixIn, ldap.SimpleLDAPObject):
            pass
    """

    async def noop_search_st(
        self,
        base: str,
        scope: int = SCOPE_SUBTREE,
        filterstr: str = "(objectClass=*)",
        timeout: float = -1,
    ) -> tuple[int | None, int | None]:
        """How many entries and references the search would have had."""
        from anyldap.ldap import errors

        msg_id = await self.search_ext(
            base,
            scope,
            filterstr=filterstr,
            attrlist=["1.1"],
            timeout=timeout,
            serverctrls=[SearchNoOpControl(criticality=True)],
        )
        try:
            _, _, _, response_controls = await self.result3(
                msg_id, all=1, timeout=timeout
            )
        except (
            errors.TIMEOUT,
            errors.TIMELIMIT_EXCEEDED,
            errors.SIZELIMIT_EXCEEDED,
            errors.ADMINLIMIT_EXCEEDED,
        ):
            # However it ended, the server is told to stop working on it.
            await self.abandon(msg_id)
            raise
        for control in response_controls:
            if control.controlType == SearchNoOpControl.controlType:
                assert isinstance(control, SearchNoOpControl)
                return control.numSearchResults, control.numSearchContinuations
        return (None, None)
