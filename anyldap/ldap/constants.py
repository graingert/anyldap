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
RES_INTERMEDIATE: Final = 0x79

# What each kind of request is numbered, which is the tag it goes out under.
REQ_BIND: Final = 0x60
REQ_UNBIND: Final = 0x42
REQ_SEARCH: Final = 0x63
REQ_MODIFY: Final = 0x66
REQ_ADD: Final = 0x68
REQ_DELETE: Final = 0x4A
REQ_MODRDN: Final = 0x6C
REQ_COMPARE: Final = 0x6E
REQ_ABANDON: Final = 0x50
REQ_EXTENDED: Final = 0x77

# The BER tags of the parts of a message, for a caller reading the wire.
TAG_MESSAGE: Final = 0x30
TAG_MSGID: Final = 0x02
TAG_LDAPDN: Final = 0x04
TAG_LDAPCRED: Final = 0x04
TAG_CONTROLS: Final = 0xA0
TAG_REFERRAL: Final = 0xA3
TAG_NEWSUPERIOR: Final = 0x80
TAG_EXOP_REQ_OID: Final = 0x80
TAG_EXOP_REQ_VALUE: Final = 0x81
TAG_EXOP_RES_OID: Final = 0x8A
TAG_EXOP_RES_VALUE: Final = 0x8B
TAG_SASL_RES_CREDS: Final = 0x87

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
OPT_REFHOPLIMIT: Final = 0x5003
OPT_DEFBASE: Final = 0x5009
OPT_CONNECT_ASYNC: Final = 0x5010
OPT_TCP_USER_TIMEOUT: Final = 0x5015
OPT_DEBUG_LEVEL: Final = 0x5001
OPT_X_KEEPALIVE_IDLE: Final = 0x6300
OPT_X_KEEPALIVE_PROBES: Final = 0x6301
OPT_X_KEEPALIVE_INTERVAL: Final = 0x6302

# Options that describe the library or the connection underneath rather
# than saying how to talk to a server. They are named because python-ldap
# names them; asking for one of these says it is not an option here.
OPT_API_INFO: Final = 0x00
OPT_DESC: Final = 0x01
OPT_RESTART: Final = 0x09
OPT_SERVER_CONTROLS: Final = 0x12
OPT_CLIENT_CONTROLS: Final = 0x13
OPT_API_FEATURE_INFO: Final = 0x15
OPT_HOST_NAME: Final = 0x30
OPT_ERROR_NUMBER: Final = 0x31
OPT_RESULT_CODE: Final = 0x31
OPT_ERROR_STRING: Final = 0x32
OPT_DIAGNOSTIC_MESSAGE: Final = 0x32
OPT_MATCHED_DN: Final = 0x33

# How TLS is asked for. Setting any of these builds the ssl.SSLContext the
# connection is raised with, so they mean here what they mean to OpenLDAP.
OPT_X_TLS: Final = 0x6000
OPT_X_TLS_CTX: Final = 0x6001
OPT_X_TLS_CACERTFILE: Final = 0x6002
OPT_X_TLS_CACERTDIR: Final = 0x6003
OPT_X_TLS_CERTFILE: Final = 0x6004
OPT_X_TLS_KEYFILE: Final = 0x6005
OPT_X_TLS_REQUIRE_CERT: Final = 0x6006
OPT_X_TLS_CIPHER_SUITE: Final = 0x6008
OPT_X_TLS_PROTOCOL_MIN: Final = 0x6007
OPT_X_TLS_PROTOCOL_MAX: Final = 0x601B
OPT_X_TLS_NEWCTX: Final = 0x600F
OPT_X_TLS_PEERCERT: Final = 0x6015
OPT_X_TLS_VERSION: Final = 0x6013
OPT_X_TLS_CIPHER: Final = 0x6014
OPT_X_TLS_RANDOM_FILE: Final = 0x6009
OPT_X_TLS_CRLCHECK: Final = 0x600B
OPT_X_TLS_DHFILE: Final = 0x600E
OPT_X_TLS_CRLFILE: Final = 0x6010
OPT_X_TLS_PACKAGE: Final = 0x6011
OPT_X_TLS_ECNAME: Final = 0x6012
OPT_X_TLS_REQUIRE_SAN: Final = 0x601A

# Whose certificate revocation list to check, for OPT_X_TLS_CRLCHECK.
OPT_X_TLS_CRL_NONE: Final = 0
OPT_X_TLS_CRL_PEER: Final = 1
OPT_X_TLS_CRL_ALL: Final = 2

# What to make of the certificate the server sends.
OPT_X_TLS_NEVER: Final = 0
OPT_X_TLS_HARD: Final = 1
OPT_X_TLS_DEMAND: Final = 2
OPT_X_TLS_ALLOW: Final = 3
OPT_X_TLS_TRY: Final = 4

# The protocol versions OPT_X_TLS_PROTOCOL_MIN and _MAX are given in.
OPT_X_TLS_PROTOCOL_SSL3: Final = 0x300
OPT_X_TLS_PROTOCOL_TLS1_0: Final = 0x301
OPT_X_TLS_PROTOCOL_TLS1_1: Final = 0x302
OPT_X_TLS_PROTOCOL_TLS1_2: Final = 0x303
OPT_X_TLS_PROTOCOL_TLS1_3: Final = 0x304

# What a SASL bind is told about talking to the user, and what it says
# about the connection it ended up with.
SASL_AUTOMATIC: Final = 0
SASL_INTERACTIVE: Final = 1
SASL_QUIET: Final = 2
SASL_AVAIL: Final = 1
OPT_X_SASL_MECH: Final = 0x6100
OPT_X_SASL_REALM: Final = 0x6101
OPT_X_SASL_AUTHCID: Final = 0x6102
OPT_X_SASL_AUTHZID: Final = 0x6103
OPT_X_SASL_USERNAME: Final = 0x610C
OPT_X_SASL_SSF: Final = 0x6104
OPT_X_SASL_SSF_EXTERNAL: Final = 0x6105
OPT_X_SASL_SECPROPS: Final = 0x6106
OPT_X_SASL_SSF_MIN: Final = 0x6107
OPT_X_SASL_SSF_MAX: Final = 0x6108
OPT_X_SASL_MAXBUFSIZE: Final = 0x6109
OPT_X_SASL_NOCANON: Final = 0x610B

# The OID of syncrepl's Sync Info message, which python-ldap names here
# as well as in ldap.syncrepl.
SYNC_INFO: Final = "1.3.6.1.4.1.4203.1.9.1.4"

# What is wrong with a URL that could not be read.
URL_ERR_MEM: Final = 1
URL_ERR_BADSCOPE: Final = 8

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


# More than one name stands for some of the numbers below -- an option and
# a value an option takes can share one, and two spellings of the same
# option certainly do. This is the name python-ldap answers with for each of
# those, so that the two agree.
_SHARED_NUMBERS: Final[dict[int, str]] = {
    0: "OPT_SUCCESS",
    1: "OPT_X_TLS_CRL_PEER",
    2: "OPT_X_TLS_CRL_ALL",
    0x31: "OPT_ERROR_NUMBER",
    0x32: "OPT_ERROR_STRING",
}

# Every option, by the number it is known by. Built from what is above, so
# that a name and its number cannot drift apart: python-ldap builds its own
# from whatever its C library was compiled with, so which options are in it
# there depends on the build.
OPT_NAMES_DICT: Final[dict[int, str]] = {
    **{
        value: name
        for name, value in list(globals().items())
        if name.startswith("OPT_") and isinstance(value, int)
    },
    **_SHARED_NUMBERS,
}
