"""
Tests for the code from docs/source/example.
"""
import os
import sys

from anyldap import inmemory, testutil
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors
from anyldap.test import unittest

# We inject the examples so that we can import them.
# There is no cleanup, so this is leaving side effects.
sys.path.append(os.path.abspath("docs/source/examples"))
import anyldap_with_upn_bind


class LDAPServerWithUPNBind(unittest.TestCase):
    """
    Tests for docs/source/examples/anyldap_with_upn_bind.py
    """

    def setUp(self):
        self.root = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="dc=example,dc=com", attributes={"dc": "example"}
        )
        self.user = self.root.addChild(
            rdn=b"cn=bob",
            attributes={
                "objectClass": ["a", "b"],
                # Hash is for "secret".
                "userPassword": [b"{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8="],
                "userPrincipalName": ["bob@ad.example.com"],
            },
        )

        server = anyldap_with_upn_bind.LDAPServerWithUPNBind()
        server.factory = self.root
        self.server = server

    async def checkSuccessfulBIND(self, bind_dn, password):
        """
        Do a BIND request and check that is succeeds.
        """
        response = await testutil.exchange_async(
            self.server,
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(dn=bind_dn, auth=password), id=4
            ).toWire(),
        )
        self.assertEqual(
            response,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=0, matchedDN="cn=bob,dc=example,dc=com"
                ),
                id=4,
            ).toWire(),
        )

    async def test_bindSuccessUPN(self):
        """
        It can authenticate based on the UPN.
        """
        await self.checkSuccessfulBIND("bob@ad.example.com", b"secret")

    async def test_bindSuccessDN(self):
        """
        It can still authenticate based on the normal DN.
        """
        await self.checkSuccessfulBIND("cn=bob,dc=example,dc=com", b"secret")

    async def test_bindBadPassword(self):
        """
        When password don't match the BIND fails.
        """
        response = await testutil.exchange_async(
            self.server,
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(dn="bob@ad.example.com", auth="invalid"),
                id=734,
            ).toWire(),
        )
        self.assertEqual(
            response,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                ),
                id=734,
            ).toWire(),
        )
