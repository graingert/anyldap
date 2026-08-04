"""``ldap.functions``: the module-level helpers python-ldap keeps here."""

import calendar
import time
from collections.abc import Callable

from anyldap.ldap import ldapobject
from anyldap.ldap.dn import explode_dn as explode_dn
from anyldap.ldap.dn import explode_rdn as explode_rdn
from anyldap.ldap.errors import LDAPError as LDAPError
from anyldap.ldap.ldapobject import LDAPObject as LDAPObject
from anyldap.ldap.ldapobject import Value
from anyldap.ldap.ldapobject import initialize as initialize

# The time format LDAP writes, which is UTC to the second.
_GENERALIZED_TIME = "%Y%m%d%H%M%SZ"


def strf_secs(secs: float) -> str:
    """Seconds since the epoch, as the generalized time LDAP writes."""
    return time.strftime(_GENERALIZED_TIME, time.gmtime(secs))


def strp_secs(dt_str: str) -> int:
    """A generalized time, as seconds since the epoch."""
    return int(time.mktime(time.strptime(dt_str, _GENERALIZED_TIME)) - time.timezone)


def escape_str(escape_func: Callable[[Value], str], val: str, *args: Value) -> str:
    """A template filled in with values that were escaped first.

    ``escape_func`` is what to escape them with: ``escape_filter_chars`` for
    a filter, ``escape_dn_chars`` for a DN.
    """
    return val % tuple(escape_func(arg) for arg in args)


def timegm(t: tuple[int, ...]) -> int:
    """A UTC time tuple, as seconds since the epoch.

    python-ldap keeps its own because ``calendar.timegm()`` was once slow;
    this is that one.
    """
    return int(calendar.timegm(t))


# The options every connection opened after this is set starts with.
# python-ldap sets these on the C library, which has one set of them for the
# whole process; this keeps them here and hands them to each connection as
# it is made, which comes to the same thing for a caller.
_defaults: dict[int, object] = {}


def set_option(option: int, invalue: object) -> None:
    """Set an option on every connection opened from now on.

    A connection that is already open keeps what it has; set the option on
    the connection itself to change that one.
    """
    # Refused here if it would be refused on a connection, so that a bad
    # option is heard about now rather than at the next initialize().
    ldapobject.SimpleLDAPObject("ldap://").set_option(option, invalue)
    _defaults[option] = invalue


def get_option(option: int) -> object:
    """What a connection opened from now on would start with."""
    if option in _defaults:
        return _defaults[option]
    return ldapobject.SimpleLDAPObject("ldap://").get_option(option)
