"""``ldap.controls.libldap``: the controls python-ldap encodes in its C library.

They are encoded here the same way everything else is, with the BER library
anyldap already has, so the module is only a place for the names to live.
"""

from anyldap.ldap.constants import CONTROL_ASSERT, CONTROL_VALUESRETURNFILTER
from anyldap.ldap.controls import RequestControl
from anyldap.ldap.controls.pagedresults import (
    SimplePagedResultsControl as SimplePagedResultsControl,
)
from anyldap.ldapfilter import parseFilter
from anyldap.protocols import pureber


class AssertionControl(RequestControl):
    """Do the operation only if the entry matches this filter (RFC 4528)."""

    controlType = CONTROL_ASSERT

    def __init__(
        self, criticality: bool = True, filterstr: str = "(objectClass=*)"
    ) -> None:
        self.controlType = CONTROL_ASSERT
        self.criticality = criticality
        self.filterstr = filterstr

    def encodeControlValue(self) -> bytes:
        return parseFilter(self.filterstr).toWire()


class MatchedValuesControl(RequestControl):
    """Send back only the values that match this filter (RFC 3876)."""

    controlType = CONTROL_VALUESRETURNFILTER

    def __init__(
        self, criticality: bool = False, filterstr: str = "(objectClass=*)"
    ) -> None:
        self.controlType = CONTROL_VALUESRETURNFILTER
        self.criticality = criticality
        self.filterstr = filterstr

    def encodeControlValue(self) -> bytes:
        return pureber.BERSequence([parseFilter(self.filterstr)]).toWire()
