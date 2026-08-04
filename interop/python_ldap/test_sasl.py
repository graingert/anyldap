"""python-ldap's tests for ldap.sasl, run against anyldap.ldap.

Ported from python-ldap 3.4.7, ``Tests/t_ldap_sasl.py``. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed.

python-ldap's ``@requires_sasl()``, ``@requires_ldapi()`` and
``@requires_tls()`` are the skips below.
"""

import os
import ssl
from collections.abc import AsyncGenerator, Iterator
from typing import Any

import pytest

from anyldap import ldap
from anyldap.ldap import sasl

python_ldap_slapdtest = pytest.importorskip(
    "slapdtest", reason="python-ldap's slapdtest is not installed"
)

if not any(
    os.path.exists(os.path.join(path, "slapd"))
    for path in ("/usr/sbin", "/usr/local/sbin", "/usr/lib/openldap", "/sbin")
):  # pragma: no cover - depends on what is installed
    pytest.skip("slapd is not installed", allow_module_level=True)

pytestmark = pytest.mark.anyio

LDIF = """
dn: {suffix}
objectClass: dcObject
objectClass: organization
dc: {dc}
o: {dc}

dn: {rootdn}
objectClass: applicationProcess
objectClass: simpleSecurityObject
objectClass: uidObject
cn: {rootcn}
userPassword: {rootpw}
uid: {uid}

dn: cn={certuser},{suffix}
objectClass: applicationProcess
cn: {certuser}

"""

# from Tests/certs/client.pem
CERTUSER = "client"
CERTSUBJECT = "cn=client,ou=slapd-test,o=python-ldap,c=de"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def slapd() -> Iterator[Any]:
    server = python_ldap_slapdtest.SlapdObject()
    server.start()
    try:
        server.ldapadd(
            LDIF.format(
                suffix=server.suffix,
                rootdn=server.root_dn,
                rootcn=server.root_cn,
                rootpw=server.root_pw,
                dc=server.suffix.split(",")[0][3:],
                certuser=CERTUSER,
                uid=os.geteuid(),
            )
        )
        yield server
    finally:
        server.stop()


@pytest.fixture
async def ldap_conn(slapd: Any) -> AsyncGenerator[ldap.SimpleLDAPObject, None]:
    async with ldap.initialize(slapd.ldapi_uri) as connection:
        yield connection


async def test_external_ldapi(
    ldap_conn: ldap.SimpleLDAPObject, slapd: Any
) -> None:
    # EXTERNAL authentication with LDAPI (AF_UNIX)
    auth = sasl.external("some invalid user")
    with pytest.raises(ldap.INSUFFICIENT_ACCESS):
        await ldap_conn.sasl_interactive_bind_s("", auth)

    auth = sasl.external("")
    await ldap_conn.sasl_interactive_bind_s("", auth)
    assert await ldap_conn.whoami_s() == f"dn:{slapd.root_dn}".lower()


async def test_external_tlscert(slapd: Any) -> None:
    async with ldap.initialize(slapd.ldap_uri) as ldap_conn:
        ldap_conn.set_option(ldap.OPT_X_TLS_CACERTFILE, slapd.cafile)
        ldap_conn.set_option(ldap.OPT_X_TLS_CERTFILE, slapd.clientcert)
        ldap_conn.set_option(ldap.OPT_X_TLS_KEYFILE, slapd.clientkey)
        ldap_conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_HARD)
        ldap_conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        await ldap_conn.start_tls_s()

        auth = sasl.external()
        await ldap_conn.sasl_interactive_bind_s("", auth)
        assert await ldap_conn.whoami_s() == f"dn:{CERTSUBJECT}".lower()


def test_the_context_the_tls_options_describe_is_the_one_they_name(
    slapd: Any,
) -> None:
    """Not upstream: what the options above build, before anything is sent."""
    connection = ldap.initialize(slapd.ldap_uri)
    connection.set_option(ldap.OPT_X_TLS_CACERTFILE, slapd.cafile)
    connection.set_option(ldap.OPT_X_TLS_CERTFILE, slapd.clientcert)
    connection.set_option(ldap.OPT_X_TLS_KEYFILE, slapd.clientkey)
    connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_HARD)
    context = connection.get_option(ldap.OPT_X_TLS_CTX)
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    # The client certificate is the one that was named.
    assert context.get_ca_certs()
