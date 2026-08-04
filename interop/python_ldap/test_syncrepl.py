"""python-ldap's tests for ldap.syncrepl, run against anyldap.ldap.syncrepl.

Ported from python-ldap 3.4.7, ``Tests/t_ldap_syncrepl.py``. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed.

The slapd these run against is python-ldap's own, configured with the
syncprov overlay from python-ldap's ``SLAPD_CONF_PROVIDER_TEMPLATE``.
"""

import binascii
import os
from collections.abc import AsyncGenerator, Iterator
from typing import Any

import pytest

from anyldap import ldap
from anyldap.ldap.syncrepl import SyncInfoMessage, SyncreplConsumer

python_ldap_slapdtest = pytest.importorskip(
    "slapdtest", reason="python-ldap's slapdtest is not installed"
)

if not any(
    os.path.exists(os.path.join(path, "slapd"))
    for path in ("/usr/sbin", "/usr/local/sbin", "/usr/lib/openldap", "/sbin")
):  # pragma: no cover - depends on what is installed
    pytest.skip("slapd is not installed", allow_module_level=True)

pytestmark = pytest.mark.anyio

# a template string for generating simple slapd.conf file
SLAPD_CONF_PROVIDER_TEMPLATE = r"""dn: cn=config
objectClass: olcGlobal
cn: config
olcServerID: %(serverid)s
olcLogLevel: %(loglevel)s
olcAllows: bind_v2
olcAuthzRegexp: {0}"gidnumber=%(root_gid)s\+uidnumber=%(root_uid)s,cn=peercred,cn=external,cn=auth" "%(rootdn)s"
olcAuthzRegexp: {1}"C=DE, O=python-ldap, OU=slapd-test, CN=([A-Za-z]+)" "ldap://ou=people,dc=local???($1)"
olcTLSCACertificateFile: %(cafile)s
olcTLSCertificateFile: %(servercert)s
olcTLSCertificateKeyFile: %(serverkey)s
olcTLSVerifyClient: try

dn: cn=module,cn=config
objectClass: olcModuleList
cn: module
olcModuleLoad: back_%(database)s
olcModuleLoad: syncprov

dn: olcDatabase=%(database)s,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: %(database)s
olcSuffix: %(suffix)s
olcRootDN: %(rootdn)s
olcRootPW: %(rootpw)s
olcDbDirectory: %(directory)s
olcDbIndex: objectclass,entryCSN,entryUUID eq

dn: olcOverlay=syncprov,olcDatabase={1}%(database)s,cn=config
objectClass: olcOverlayConfig
objectClass: olcSyncProvConfig
olcOverlay: syncprov
olcSpCheckpoint: 100 10
olcSpSessionlog: 100
"""

# Define initial data load, both as an LDIF and as a dictionary.
LDIF_TEMPLATE = """dn: %(suffix)s
objectClass: dcObject
objectClass: organization
dc: %(dc)s
o: %(dc)s

dn: %(rootdn)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: %(rootcn)s
userPassword: %(rootpw)s

dn: cn=Foo1,%(suffix)s
objectClass: organizationalRole
cn: Foo1

dn: cn=Foo2,%(suffix)s
objectClass: organizationalRole
cn: Foo2

dn: cn=Foo3,%(suffix)s
objectClass: organizationalRole
cn: Foo3

dn: ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: Container

dn: cn=Foo4,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo4

"""

# NOTE: For the dict, it needs to be kept up-to-date as we make changes!
LDAP_ENTRIES = {
    "ou=Container,dc=slapd-test,dc=python-ldap,dc=org": {
        "objectClass": [b"organizationalUnit"],
        "ou": [b"Container"],
    },
    "cn=Foo2,dc=slapd-test,dc=python-ldap,dc=org": {
        "objectClass": [b"organizationalRole"],
        "cn": [b"Foo2"],
    },
    "cn=Foo4,ou=Container,dc=slapd-test,dc=python-ldap,dc=org": {
        "objectClass": [b"organizationalRole"],
        "cn": [b"Foo4"],
    },
    "cn=Manager,dc=slapd-test,dc=python-ldap,dc=org": {
        "objectClass": [b"applicationProcess", b"simpleSecurityObject"],
        "userPassword": [b"password"],
        "cn": [b"Manager"],
    },
    "cn=Foo3,dc=slapd-test,dc=python-ldap,dc=org": {
        "objectClass": [b"organizationalRole"],
        "cn": [b"Foo3"],
    },
    "cn=Foo1,dc=slapd-test,dc=python-ldap,dc=org": {
        "objectClass": [b"organizationalRole"],
        "cn": [b"Foo1"],
    },
    "dc=slapd-test,dc=python-ldap,dc=org": {
        "objectClass": [b"dcObject", b"organization"],
        "dc": [b"slapd-test"],
        "o": [b"slapd-test"],
    },
}


class SyncreplClient(SyncreplConsumer, ldap.SimpleLDAPObject):
    """
    This is a very simple class to start up the syncrepl search
    and handle callbacks that come in.

    Needs to be separate, because once an LDAP client starts a syncrepl
    search, it can't be used for anything else.
    """

    def __init__(self, uri: str) -> None:
        self.data: dict[str, Any] = {"cookie": None}
        self.uuid_dn: dict[str, str] = {}
        self.dn_attrs: dict[str, dict[str, list[bytes]]] = {}
        self.present: list[str] = []
        self.refresh_done = False
        ldap.SimpleLDAPObject.__init__(self, uri)

    async def search(self, search_base: str, search_mode: str) -> None:
        """
        Start a syncrepl search operation, given a base DN and search mode.
        """
        self.search_id = await self.syncrepl_search(
            search_base, ldap.SCOPE_SUBTREE, mode=search_mode
        )

    async def cancel(self) -> None:  # type: ignore[override]
        """
        A simple wrapper to call parent class with syncrepl search ID.
        """
        await ldap.SimpleLDAPObject.cancel(self, self.search_id)

    async def poll(self, timeout: float | None = None, all: int = 0) -> bool:
        """
        Take the params, add the syncrepl search ID, and call the proper poll.
        """
        return await self.syncrepl_poll(self.search_id, timeout=timeout, all=all)

    def syncrepl_get_cookie(self) -> str | None:
        """
        Pull cookie from storage, if one exists.
        """
        cookie = self.data["cookie"]
        assert cookie is None or isinstance(cookie, str)
        return cookie

    def syncrepl_set_cookie(self, cookie: str) -> None:
        """
        Update stored cookie.
        """
        self.data["cookie"] = cookie

    def syncrepl_refreshdone(self) -> None:
        """
        Just update a variable.
        """
        self.refresh_done = True

    def syncrepl_delete(self, uuids: list[str]) -> None:  # type: ignore[override]
        """
        Delete the given items from both maps.
        """
        for uuid in uuids:
            del self.dn_attrs[self.uuid_dn[uuid]]
            del self.uuid_dn[uuid]

    def syncrepl_entry(
        self, dn: str, attrs: dict[str, list[bytes]], uuid: str
    ) -> None:
        """
        Handles adds and changes (including DN changes).
        """
        if uuid in self.uuid_dn:
            # Catch changing DNs.
            if dn != self.uuid_dn[uuid]:
                # Delete data associated with old DN.
                del self.dn_attrs[self.uuid_dn[uuid]]

        # Update both maps.
        self.uuid_dn[uuid] = dn
        self.dn_attrs[dn] = attrs

    def syncrepl_present(
        self, uuids: list[str] | None, refreshDeletes: bool | None = False
    ) -> None:  # type: ignore[override]
        """
        The 'present' message from the LDAP server is the most complicated
        part of the refresh phase.  Suggest looking here for more info:
        https://syncrepl-client.readthedocs.io/en/latest/client.html
        """
        if (uuids is not None) and (refreshDeletes is False):
            self.present.extend(uuids)

        elif (uuids is None) and (refreshDeletes is False):
            deleted_uuids = []
            for uuid in self.uuid_dn:
                if uuid not in self.present:
                    deleted_uuids.append(uuid)

            if len(deleted_uuids) > 0:
                self.syncrepl_delete(deleted_uuids)

        elif (uuids is not None) and (refreshDeletes is True):
            self.syncrepl_delete(uuids)

        elif (uuids is None) and (refreshDeletes is True):
            pass


class SyncreplProvider(python_ldap_slapdtest.SlapdObject):  # type: ignore[misc]
    slapd_conf_template = SLAPD_CONF_PROVIDER_TEMPLATE


@pytest.fixture(scope="module")
def slapd() -> Iterator[Any]:
    server = SyncreplProvider()
    server.start()
    try:
        server.ldapadd(
            LDIF_TEMPLATE
            % {
                "suffix": server.suffix,
                "rootdn": server.root_dn,
                "rootcn": server.root_cn,
                "rootpw": server.root_pw,
                "dc": server.suffix.split(",")[0][3:],
            }
        )
        yield server
    finally:
        server.stop()


@pytest.fixture
async def tester(slapd: Any) -> AsyncGenerator[SyncreplClient, None]:
    client = SyncreplClient(slapd.ldap_uri)
    await client.simple_bind_s(slapd.root_dn, slapd.root_pw)
    try:
        yield client
    finally:
        await client.unbind_s()


async def test_refreshOnly_search(tester: SyncreplClient, slapd: Any) -> None:
    """Test to see if we can initialize a syncrepl search."""
    await tester.search(slapd.suffix, "refreshOnly")


async def test_refreshAndPersist_search(
    tester: SyncreplClient, slapd: Any
) -> None:
    await tester.search(slapd.suffix, "refreshAndPersist")


async def test_refreshOnly_poll_full(tester: SyncreplClient, slapd: Any) -> None:
    """Test doing a full refresh cycle, and check what we got."""
    await tester.search(slapd.suffix, "refreshOnly")
    poll_result = await tester.poll(all=1, timeout=None)
    assert not poll_result
    assert tester.dn_attrs == LDAP_ENTRIES


async def test_refreshAndPersist_poll_only(
    tester: SyncreplClient, slapd: Any
) -> None:
    """Test the refresh part of refresh-and-persist, and check what we got."""
    await tester.search(slapd.suffix, "refreshAndPersist")

    # Make sure to stop the test before going into persist mode.
    while tester.refresh_done is not True:
        poll_result = await tester.poll(all=0, timeout=None)
        assert poll_result

    assert tester.dn_attrs == LDAP_ENTRIES


async def test_refreshAndPersist_timeout(
    tester: SyncreplClient, slapd: Any
) -> None:
    """Make sure refreshAndPersist can handle a search with timeouts."""
    await tester.search(slapd.suffix, "refreshAndPersist")

    # Run a quick refresh, that shouldn't have any changes.
    while tester.refresh_done is not True:
        poll_result = await tester.poll(all=0, timeout=None)
        assert poll_result

    # Again, server data should not have changed.
    assert tester.dn_attrs == LDAP_ENTRIES

    # Run a search with timeout.
    # Nothing is changing the server, so it shoud timeout.
    with pytest.raises(ldap.TIMEOUT):
        await tester.poll(all=0, timeout=1)


async def test_refreshAndPersist_cancelled(
    tester: SyncreplClient, slapd: Any
) -> None:
    """Make sure refreshAndPersist can handle cancelling a syncrepl search."""
    await tester.search(slapd.suffix, "refreshAndPersist")

    # Run a quick refresh, that shouldn't have any changes.
    while tester.refresh_done is not True:
        poll_result = await tester.poll(all=0, timeout=None)
        assert poll_result

    # Again, server data should not have changed.
    assert tester.dn_attrs == LDAP_ENTRIES

    # Request cancellation.
    await tester.cancel()

    # Run another poll, without timeout, but which should cancel out.
    with pytest.raises(ldap.CANCELLED):
        await tester.poll(all=1, timeout=None)

    # Server data should still be intact.
    assert tester.dn_attrs == LDAP_ENTRIES


def test_syncidset_message() -> None:
    """
    A syncrepl server may send a sync info message, with a syncIdSet
    of uuids to delete. A regression was found in the original
    sync info message implementation due to how the choice was
    evaluated, because refreshPresent and refreshDelete were both
    able to be fully expressed as defaults, causing the parser
    to mistakenly catch a syncIdSet as a refreshPresent/refereshDelete.

    This tests that a syncIdSet request is properly decoded.

    reference: https://tools.ietf.org/html/rfc4533#section-2.5
    """
    # This is a dump of a syncidset message from wireshark + 389-ds
    msg = """
    a36b04526c6461706b64632e6578616d706c652e636f6d3a333839303123636e
    3d6469726563746f7279206d616e616765723a64633d6578616d706c652c6463
    3d636f6d3a286f626a656374436c6173733d2a2923330101ff311204108dc446
    01a93611ea8aaff248c5fa5780
    """.replace(" ", "").replace("\n", "")

    msgraw = binascii.unhexlify(msg)
    sim = SyncInfoMessage(msgraw)
    assert sim.refreshDelete is None
    assert sim.refreshPresent is None
    assert sim.newcookie is None
    assert sim.syncIdSet == {
        "cookie": (
            "ldapkdc.example.com:38901#cn=directory manager:"
            "dc=example,dc=com:(objectClass=*)#3"
        ),
        "syncUUIDs": ["8dc44601-a936-11ea-8aaf-f248c5fa5780"],
        "refreshDeletes": True,
    }
