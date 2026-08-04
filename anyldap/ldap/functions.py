"""``ldap.functions``: the module-level helpers python-ldap keeps here."""

import time
from collections.abc import Callable

from anyldap.ldap.ldapobject import Value

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
