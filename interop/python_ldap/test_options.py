"""python-ldap's tests for the connection options, run against anyldap.ldap.

Ported from python-ldap 3.4.7, ``Tests/t_ldap_options.py``. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed.
"""

import os
from collections.abc import Iterator
from typing import Any

import pytest

from anyldap import ldap

python_ldap_slapdtest = pytest.importorskip(
    "slapdtest", reason="python-ldap's slapdtest is not installed"
)

if not any(
    os.path.exists(os.path.join(path, "slapd"))
    for path in ("/usr/sbin", "/usr/local/sbin", "/usr/lib/openldap", "/sbin")
):  # pragma: no cover - depends on what is installed
    pytest.skip("slapd is not installed", allow_module_level=True)

SENTINEL = object()


@pytest.fixture(scope="module")
def slapd() -> Iterator[Any]:
    server = python_ldap_slapdtest.SlapdObject()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def conn(slapd: Any) -> ldap.SimpleLDAPObject:
    # Upstream binds here; nothing is sent until an operation is awaited, so
    # the options can be asked of a connection that has not opened yet.
    return ldap.initialize(slapd.ldap_uri)


def check_option(
    conn: ldap.SimpleLDAPObject,
    option: int,
    value: object,
    expected: object = SENTINEL,
) -> None:
    old = conn.get_option(option)
    try:
        conn.set_option(option, value)
        new = conn.get_option(option)
        if expected is SENTINEL:
            assert new == value
        else:
            assert new == expected
    finally:
        conn.set_option(option, old)
        assert conn.get_option(option) == old


def test_invalid(conn: ldap.SimpleLDAPObject) -> None:
    with pytest.raises(ValueError):
        conn.get_option(-1)
    with pytest.raises(ValueError):
        conn.set_option(-1, "")


@pytest.mark.parametrize(
    "option", [ldap.OPT_TIMEOUT, ldap.OPT_NETWORK_TIMEOUT]
)
def test_timeout(conn: ldap.SimpleLDAPObject, option: int) -> None:
    check_option(conn, option, 10.5)
    check_option(conn, option, 0)
    with pytest.raises(ValueError):
        check_option(conn, option, -5)
    with pytest.raises(TypeError):
        conn.set_option(option, object)
    with pytest.raises(OverflowError):
        check_option(conn, option, 10**1000)
    old = conn.get_option(option)
    try:
        conn.set_option(option, None)
        assert conn.get_option(option) is None
        conn.set_option(option, -1)
        assert conn.get_option(option) is None
    finally:
        conn.set_option(option, old)


def test_uri(conn: ldap.SimpleLDAPObject) -> None:
    check_option(conn, ldap.OPT_URI, "ldapi:///path/to/socket")
    with pytest.raises(AssertionError):
        conn.set_option(ldap.OPT_URI, object)


def test_cafile(conn: ldap.SimpleLDAPObject) -> None:
    # None or a distribution or OS-specific path
    conn.get_option(ldap.OPT_X_TLS_CACERTFILE)


def test_network_timeout_attribute(conn: ldap.SimpleLDAPObject) -> None:
    option = ldap.OPT_NETWORK_TIMEOUT
    old = conn.get_option(option)
    try:
        assert conn.network_timeout == old

        conn.set_option(option, 5)
        assert conn.network_timeout == 5
        assert conn.get_option(option) == 5

        conn.set_option(option, -1)
        assert conn.network_timeout is None
        assert conn.get_option(option) is None

        conn.set_option(option, 10.5)
        assert conn.network_timeout == 10.5
        assert conn.get_option(option) == 10.5

        conn.set_option(option, None)
        assert conn.network_timeout is None
        assert conn.get_option(option) is None
    finally:
        conn.set_option(option, old)
