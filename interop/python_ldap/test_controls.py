"""python-ldap's tests for ldap.controls, run against anyldap.ldap.controls.

Ported from python-ldap 3.4.7: ``Tests/t_ldap_controls_libldap.py``,
``Tests/t_ldap_controls_readentry.py``, ``Tests/t_ldap_controls_ppolicy.py``
and ``Tests/t_ldap_controls_sss.py``. Copyright the python-ldap authors; see
LICENCE.python-ldap and LICENCE.python-ldap.MIT in this directory, and
README.rst for what was changed.
"""

from anyldap.ldap.controls import libldap, pagedresults, ppolicy, readentry, sss

# From t_ldap_controls_libldap.py: what a paged results control is written as.
PRC_BER = b"0\x0b\x02\x01\x05\x04\x06cookie"
SIZE = 5
COOKIE = b"cookie"

# From t_ldap_controls_readentry.py: a post-read control as a server sent it,
# and the request that asks for it.
PRC_ENC = (
    b"db\x04)uid=Administrator,cn=users,l=school,l=dev05"
    b"03\x04\tentryUUID1&\x04$5d96cc2c-8e13-103a-8ca5-2f74868e0e44"
)
PRC_DEC = b"0\x0b\x04\tentryUUID"

# From t_ldap_controls_ppolicy.py: what a server says about the password.
PP_GRACEAUTH = b"0\x84\x00\x00\x00\t\xa0\x84\x00\x00\x00\x03\x81\x01\x02"
PP_TIMEBEFORE = b"0\x84\x00\x00\x00\t\xa0\x84\x00\x00\x00\x03\x80\x012"


def test_pagedresults_encode() -> None:
    pr = pagedresults.SimplePagedResultsControl(size=SIZE, cookie=COOKIE)
    lib = libldap.SimplePagedResultsControl(size=SIZE, cookie=COOKIE)
    assert pr.encodeControlValue() == lib.encodeControlValue()
    assert pr.encodeControlValue() == PRC_BER


def test_pagedresults_decode() -> None:
    pr = pagedresults.SimplePagedResultsControl()
    pr.decodeControlValue(PRC_BER)
    assert pr.size == SIZE
    # LDAPString (OCTET STRING)
    assert isinstance(pr.cookie, bytes)
    assert pr.cookie == COOKIE

    lib = libldap.SimplePagedResultsControl()
    lib.decodeControlValue(PRC_BER)
    assert lib.size == SIZE
    assert isinstance(lib.cookie, bytes)
    assert lib.cookie == COOKIE


def test_matchedvalues() -> None:
    mvc = libldap.MatchedValuesControl()
    # unverified
    assert mvc.encodeControlValue() == b"0\r\x87\x0bobjectClass"


def test_assertioncontrol() -> None:
    ac = libldap.AssertionControl()
    # unverified
    assert ac.encodeControlValue() == b"\x87\x0bobjectClass"


def test_readentry_encode() -> None:
    pr = readentry.PostReadControl(True, ["entryUUID"])
    assert pr.encodeControlValue() == PRC_DEC


def test_readentry_decode() -> None:
    pr = readentry.PostReadControl(True, ["entryUUID"])
    pr.decodeControlValue(PRC_ENC)
    assert isinstance(pr.dn, str)
    assert pr.entry == {
        "entryUUID": [b"5d96cc2c-8e13-103a-8ca5-2f74868e0e44"]
    }


def assertPPolicy(
    pp: ppolicy.PasswordPolicyControl,
    timeBeforeExpiration: int | None = None,
    graceAuthNsRemaining: int | None = None,
    error: int | None = None,
) -> None:
    assert pp.timeBeforeExpiration == timeBeforeExpiration
    assert pp.graceAuthNsRemaining == graceAuthNsRemaining
    assert pp.error == error


def test_ppolicy_graceauth() -> None:
    pp = ppolicy.PasswordPolicyControl()
    pp.decodeControlValue(PP_GRACEAUTH)
    assertPPolicy(pp, graceAuthNsRemaining=2)


def test_ppolicy_timebefore() -> None:
    pp = ppolicy.PasswordPolicyControl()
    pp.decodeControlValue(PP_TIMEBEFORE)
    assertPPolicy(pp, timeBeforeExpiration=50)


def test_create_sss_request_control() -> None:
    control = sss.SSSRequestControl(ordering_rules=["-uidNumber"])
    assert control.ordering_rules == ["-uidNumber"]
