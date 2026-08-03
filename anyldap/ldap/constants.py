"""The names and values python-ldap's ``ldap`` module defines.

Only the constants the client honours are here. An option python-ldap has
but this cannot act on is left out, so that setting it fails loudly rather
than being quietly ignored.
"""

from typing import Final

# Search scopes.
SCOPE_BASE: Final = 0
SCOPE_BASELEVEL: Final = 0
SCOPE_ONELEVEL: Final = 1
SCOPE_SUBTREE: Final = 2
SCOPE_SUBORDINATE: Final = 3

# What to do with aliases found along the way.
DEREF_NEVER: Final = 0
DEREF_SEARCHING: Final = 1
DEREF_FINDING: Final = 2
DEREF_ALWAYS: Final = 3

# Modification types, as they appear in a modify modlist.
MOD_ADD: Final = 0
MOD_DELETE: Final = 1
MOD_REPLACE: Final = 2
MOD_INCREMENT: Final = 3
# A flag python-ldap's own callers still set; values are always bytes here.
MOD_BVALUES: Final = 0x80

# Authentication methods bind_s takes.
AUTH_NONE: Final = 0
AUTH_SIMPLE: Final = 128

# Protocol versions. Only 3 is spoken.
VERSION1: Final = 1
VERSION2: Final = 2
VERSION3: Final = 3
VERSION_MIN: Final = 2
VERSION_MAX: Final = 3
# The version the constant names, as python-ldap spells it; connections
# speak version 3, which is what protocol_version is set to.
VERSION: Final = 2

# Result types, as returned in the first item of a result3() tuple.
RES_ANY: Final = -1
RES_UNSOLICITED: Final = 0
RES_BIND: Final = 0x61
RES_SEARCH_ENTRY: Final = 0x64
RES_SEARCH_RESULT: Final = 0x65
RES_SEARCH_REFERENCE: Final = 0x73
RES_MODIFY: Final = 0x67
RES_ADD: Final = 0x69
RES_DELETE: Final = 0x6B
RES_MODRDN: Final = 0x6D
RES_COMPARE: Final = 0x6F
RES_EXTENDED: Final = 0x78

# How much of an answer result3() waits for: one message at a time, or
# everything the operation produces.
MSG_ONE: Final = 0
MSG_ALL: Final = 1
MSG_RECEIVED: Final = 2

# Values an on/off option takes.
OPT_OFF: Final = 0
OPT_ON: Final = 1
OPT_SUCCESS: Final = 0

# Options set_option() and get_option() understand.
OPT_DEREF: Final = 0x02
OPT_SIZELIMIT: Final = 0x03
OPT_TIMELIMIT: Final = 0x04
OPT_REFERRALS: Final = 0x08
OPT_PROTOCOL_VERSION: Final = 0x11
OPT_TIMEOUT: Final = 0x5002
OPT_NETWORK_TIMEOUT: Final = 0x5005
OPT_URI: Final = 0x5006

# The port LDAP is served on, and the limit that is no limit.
PORT: Final = 389
NO_LIMIT: Final = 0

# OIDs of the controls python-ldap names. Controls are sent and received as
# (type, criticality, value) triples.
CONTROL_MANAGEDSAIT: Final = "2.16.840.1.113730.3.4.2"
CONTROL_PROXY_AUTHZ: Final = "2.16.840.1.113730.3.4.18"
CONTROL_SUBENTRIES: Final = "1.3.6.1.4.1.4203.1.10.1"
CONTROL_VALUESRETURNFILTER: Final = "1.2.826.0.1.3344810.2.3"
CONTROL_ASSERT: Final = "1.3.6.1.1.12"
CONTROL_PRE_READ: Final = "1.3.6.1.1.13.1"
CONTROL_POST_READ: Final = "1.3.6.1.1.13.2"
CONTROL_SORTREQUEST: Final = "1.2.840.113556.1.4.473"
CONTROL_SORTRESPONSE: Final = "1.2.840.113556.1.4.474"
CONTROL_PAGEDRESULTS: Final = "1.2.840.113556.1.4.319"
CONTROL_SYNC: Final = "1.3.6.1.4.1.4203.1.9.1.1"
CONTROL_SYNC_STATE: Final = "1.3.6.1.4.1.4203.1.9.1.2"
CONTROL_SYNC_DONE: Final = "1.3.6.1.4.1.4203.1.9.1.3"
CONTROL_PASSWORDPOLICYREQUEST: Final = "1.3.6.1.4.1.42.2.27.8.5.1"
CONTROL_PASSWORDPOLICYRESPONSE: Final = "1.3.6.1.4.1.42.2.27.8.5.1"
CONTROL_RELAX: Final = "1.3.6.1.4.1.4203.666.5.12"

# OIDs of the extended operations with their own method.
PASSMOD_OID: Final = "1.3.6.1.4.1.4203.1.11.1"
WHOAMI_OID: Final = "1.3.6.1.4.1.4203.1.11.3"
