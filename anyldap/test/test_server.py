"""
Test cases for anyldap.protocols.ldap.ldapserver module.
"""
import base64
import logging
import types

from anyldap import delta, entry, inmemory, schema, testutil
from anyldap._encoder import to_bytes
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import fetchschema, ldaperrors, ldapserver
from anyldap.test import test_schema, unittest, util
from anyldap.test._testing import capture_logs


def observeCommits(entry):
    commits = []
    bound_commit = entry.commit

    def observe(v):
        commits.append(v)
        return v

    def commit(self):
        d = bound_commit()
        d.addBoth(observe)
        return d

    entry.commit = types.MethodType(commit, entry)
    return commits


class LDAPServerTest(unittest.TestCase):
    def setUp(self):
        self.root = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="dc=example,dc=com", attributes={"dc": "example"}
        )
        self.stuff = self.root.addChild(
            rdn="ou=stuff",
            attributes={
                b"objectClass": [b"a", b"b"],
                b"ou": [b"stuff"],
            },
        )
        self.thingie = self.stuff.addChild(
            rdn="cn=thingie",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["thingie"],
            },
        )
        self.another = self.stuff.addChild(
            rdn="cn=another",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["another"],
            },
        )

        # Add Users Subtree
        self.users = self.root.addChild(
            rdn="ou=People",
            attributes={"objectClass": ["top", "organizationalunit"], "ou": ["People"]},
        )

        self.users.addChild(
            rdn="uid=kthompson",
            attributes={"objectClass": ["top", "inetOrgPerson"], "uid": ["kthompson"]},
        )

        self.users.addChild(
            rdn="uid=bgates",
            attributes={"objectClass": ["top", "inetOrgPerson"], "uid": ["bgates"]},
        )

        # Add Groups Subtree
        self.groups = self.root.addChild(
            rdn="ou=Groups",
            attributes={"objectClass": ["top", "organizationalunit"], "ou": ["Groups"]},
        )

        self.groups.addChild(
            rdn="cn=unix",
            attributes={
                "uniquemember": ["uid=kthompson,ou=People,dc=example,dc=com"],
                "objectClass": ["top", "groupOfUniqueNames"],
                "cn": ["unix"],
            },
        )

        server = ldapserver.LDAPServer()
        server.factory = self.root
        self.server = server
        self.output = b""

    async def _send(self, wire_data):
        self.output += await testutil.exchange_async(self.server, wire_data)

    def _makeResultList(self, s):
        berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
            inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
                fallback=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
                inherit=pureldap.LDAPBERDecoderContext(
                    fallback=pureber.BERDecoderContext()
                ),
            )
        )
        buffer = s
        value = []
        while 1:
            o, bytes = pureber.berDecodeObject(berdecoder, buffer)
            buffer = buffer[bytes:]
            if not o:
                break
            value.append(o.toWire())
        return value

    async def makeSearch(
        self,
        baseObject=None,
        scope=None,
        derefAliases=None,
        sizeLimit=None,
        timeLimit=None,
        typesOnly=None,
        filter=None,
        attributes=None,
        tag=None,
    ):
        """Shortcut for sending LDAPSearchRequest to the test server"""
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPSearchRequest(
                    baseObject=baseObject,
                    scope=scope,
                    derefAliases=derefAliases,
                    sizeLimit=sizeLimit,
                    timeLimit=timeLimit,
                    typesOnly=typesOnly,
                    filter=filter,
                    attributes=attributes,
                    tag=tag,
                ),
                id=2,
            ).toWire()
        )

    def assertSearchResults(self, results=None, resultCode=0):
        """
        Shortcut for checking results returned by test server on LDAPSearchRequest.
        Results must be prepared as a list of dictionaries with 'objectName' and 'attributes' keys
        """
        if results is None:
            results = []

        messages = []

        for result in results:
            message = pureldap.LDAPMessage(
                pureldap.LDAPSearchResultEntry(
                    objectName=result["objectName"], attributes=result["attributes"]
                ),
                id=2,
            )
            messages.append(message)

        messages.append(
            pureldap.LDAPMessage(
                pureldap.LDAPSearchResultDone(resultCode=resultCode), id=2
            )
        )
        self.assertCountEqual(
            self._makeResultList(self.output),
            [msg.toWire() for msg in messages],
        )

    async def test_bind(self):
        await self._send(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=4
            ).toWire(),
        )

    async def test_bind_success(self):
        self.thingie["userPassword"] = [
            "{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8="
        ]  # "secret"
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn="cn=thingie,ou=stuff,dc=example,dc=com", auth=b"secret"
                ),
                id=4,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=0, matchedDN="cn=thingie,ou=stuff,dc=example,dc=com"
                ),
                id=4,
            ).toWire(),
        )

    async def test_bind_invalidCredentials_badPassword(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn="cn=thingie,ou=stuff,dc=example,dc=com", auth=b"invalid"
                ),
                id=734,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                ),
                id=734,
            ).toWire(),
        )

    async def test_bind_invalidCredentials_nonExisting(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn="cn=non-existing,dc=example,dc=com", auth=b"invalid"
                ),
                id=78,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                ),
                id=78,
            ).toWire(),
        )

    async def test_bind_badVersion_1_anonymous(self):
        await self._send(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(version=1), id=32).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage="Version 1 not supported",
                ),
                id=32,
            ).toWire(),
        )

    async def test_bind_badVersion_2_anonymous(self):
        await self._send(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(version=2), id=32).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage="Version 2 not supported",
                ),
                id=32,
            ).toWire(),
        )

    async def test_bind_badVersion_4_anonymous(self):
        await self._send(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(version=4), id=32).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage="Version 4 not supported",
                ),
                id=32,
            ).toWire(),
        )

    async def test_bind_badVersion_4_nonExisting(self):
        # TODO make a test just like this one that would pass authentication
        # if version was correct, to ensure we don't leak that info either.
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    version=4, dn="cn=non-existing,dc=example,dc=com", auth=b"invalid"
                ),
                id=11,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage="Version 4 not supported",
                ),
                id=11,
            ).toWire(),
        )

    async def test_unbind(self):
        await self._send(
            pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=7).toWire()
        )
        self.assertEqual(self.output, b"")

    async def test_compare_outOfTree(self):
        dn = "dc=invalid"
        attribute_desc = pureldap.LDAPString("objectClass")
        attribute_value = pureldap.LDAPString("groupOfUniqueNames")
        ava = pureldap.LDAPAttributeValueAssertion(attribute_desc, attribute_value)

        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPCompareRequest(entry=dn, ava=ava), id=2
            ).toWire()
        )

        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPCompareResponse(
                    resultCode=ldaperrors.LDAPNoSuchObject.resultCode
                ),
                id=2,
            ).toWire(),
        )

    async def test_compare_inGroup(self):
        dn = "cn=unix,ou=Groups,dc=example,dc=com"
        attribute_desc = pureldap.LDAPString("uniquemember")
        attribute_value = pureldap.LDAPString(
            "uid=kthompson,ou=People,dc=example,dc=com"
        )
        ava = pureldap.LDAPAttributeValueAssertion(attribute_desc, attribute_value)

        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPCompareRequest(entry=dn, ava=ava), id=2
            ).toWire()
        )

        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPCompareResponse(
                    resultCode=ldaperrors.LDAPCompareTrue.resultCode
                ),
                id=2,
            ).toWire(),
        )

    async def test_compare_notInGroup(self):
        dn = "cn=unix,ou=Groups,dc=example,dc=com"
        attribute_desc = pureldap.LDAPString("uniquemember")
        attribute_value = pureldap.LDAPString("uid=bgates,ou=People,dc=example,dc=com")
        ava = pureldap.LDAPAttributeValueAssertion(attribute_desc, attribute_value)

        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPCompareRequest(entry=dn, ava=ava), id=2
            ).toWire()
        )

        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPCompareResponse(
                    resultCode=ldaperrors.LDAPCompareFalse.resultCode
                ),
                id=2,
            ).toWire(),
        )

    async def test_compare_backend_type_error_becomes_other(self):
        self.stuff["broken"] = [object()]
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPCompareRequest(
                    entry=self.stuff.dn.getText(),
                    ava=pureldap.LDAPAttributeValueAssertion(
                        attributeDesc=pureldap.LDAPAttributeDescription("broken"),
                        assertionValue=pureldap.LDAPAssertionValue("value"),
                    ),
                ),
                id=2,
            ).toWire()
        )
        message, _ = pureber.berDecodeObject(
            self.server.berdecoder, self.output
        )
        self.assertEqual(message.value.resultCode, ldaperrors.other)
        self.assertIn(b"has no attribute", message.value.errorMessage)

    async def test_search_outOfTree(self):
        """Attempt to get nonexistent DN results in noSuchObject error response"""
        await self.makeSearch(baseObject="dc=invalid")
        self.assertSearchResults(resultCode=ldaperrors.LDAPNoSuchObject.resultCode)

    async def test_search_backend_matching_error_becomes_other(self):
        await self.makeSearch(
            baseObject=self.stuff.dn.getText(),
            filter=pureldap.LDAPFilter_extensibleMatch(
                matchingRule="caseIgnoreMatch", type="cn", matchValue="thingie"
            ),
        )
        message, _ = pureber.berDecodeObject(
            self.server.berdecoder, self.output
        )
        self.assertEqual(message.value.resultCode, ldaperrors.other)
        self.assertIn(b"Match type not implemented", message.value.errorMessage)

    async def test_search_matchAll_oneResult(self):
        """Searching for a single object with receiving all its attributes"""
        await self.makeSearch(baseObject="cn=thingie,ou=stuff,dc=example,dc=com")
        self.assertSearchResults(
            [
                {
                    "objectName": "cn=thingie,ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("cn", ["thingie"]),
                    ],
                }
            ]
        )

    async def test_search_matchAll_oneResult_filtered(self):
        """Searching for a single object with receiving a specified set of its attributes"""
        await self.makeSearch(
            baseObject="cn=thingie,ou=stuff,dc=example,dc=com", attributes=["cn"]
        )
        self.assertSearchResults(
            [
                {
                    "objectName": "cn=thingie,ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("cn", ["thingie"]),
                    ],
                }
            ]
        )

    async def test_search_matchAll_oneResult_filteredNoAttribsRemaining(self):
        """
        Attempt to search an existing object with a set of nonexistent attributes
        results in a successful response with no attributes
        """
        await self.makeSearch(
            baseObject="cn=thingie,ou=stuff,dc=example,dc=com", attributes=["xyzzy"]
        )
        self.assertSearchResults(
            [
                {
                    "objectName": "cn=thingie,ou=stuff,dc=example,dc=com",
                    "attributes": [],
                },
            ],
        )

    async def test_search_matchAll_manyResults(self):
        """Searching for a tree object with receiving it and all its children (default scope)"""
        await self.makeSearch(baseObject="ou=stuff,dc=example,dc=com")
        self.assertSearchResults(
            [
                {
                    "objectName": "ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("ou", ["stuff"]),
                    ],
                },
                {
                    "objectName": "cn=another,ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("cn", ["another"]),
                    ],
                },
                {
                    "objectName": "cn=thingie,ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("cn", ["thingie"]),
                    ],
                },
            ]
        )

    async def test_search_scope_oneLevel(self):
        """Searching for a tree object with receiving its children but without parent itself"""
        await self.makeSearch(
            baseObject="ou=stuff,dc=example,dc=com",
            scope=pureldap.LDAP_SCOPE_singleLevel,
        )
        self.assertSearchResults(
            [
                {
                    "objectName": "cn=thingie,ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("cn", ["thingie"]),
                    ],
                },
                {
                    "objectName": "cn=another,ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("cn", ["another"]),
                    ],
                },
            ]
        )

    async def test_search_scope_wholeSubtree(self):
        """
        Searching for a tree object with receiving it and all its children.
        This is a default behavior but here it is explicitly specified.
        """
        await self.makeSearch(
            baseObject="ou=stuff,dc=example,dc=com",
            scope=pureldap.LDAP_SCOPE_wholeSubtree,
        )
        self.assertSearchResults(
            [
                {
                    "objectName": "ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("ou", ["stuff"]),
                    ],
                },
                {
                    "objectName": "cn=another,ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("cn", ["another"]),
                    ],
                },
                {
                    "objectName": "cn=thingie,ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("cn", ["thingie"]),
                    ],
                },
            ]
        )

    async def test_search_scope_baseObject(self):
        """Searching for a tree object with receiving it without its children"""
        await self.makeSearch(
            baseObject="ou=stuff,dc=example,dc=com",
            scope=pureldap.LDAP_SCOPE_baseObject,
        )
        self.assertSearchResults(
            [
                {
                    "objectName": "ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("ou", ["stuff"]),
                    ],
                }
            ]
        )

    async def test_search_all_attributes(self):
        """
        Search request with the list of attributes passed as '*'
        returns objects with all their attributes
        """
        await self.makeSearch(
            baseObject="cn=thingie,ou=stuff,dc=example,dc=com", attributes=["*"]
        )
        self.assertSearchResults(
            [
                {
                    "objectName": "cn=thingie,ou=stuff,dc=example,dc=com",
                    "attributes": [
                        ("objectClass", ["a", "b"]),
                        ("cn", ["thingie"]),
                    ],
                }
            ]
        )

    async def test_rootDSE(self):
        """Searching for a root object"""
        await self.makeSearch(
            baseObject="",
            scope=pureldap.LDAP_SCOPE_baseObject,
            filter=pureldap.LDAPFilter_present("objectClass"),
        )
        self.assertSearchResults(
            [
                {
                    "objectName": "",
                    "attributes": [
                        ("supportedLDAPVersion", ["3"]),
                        ("namingContexts", ["dc=example,dc=com"]),
                        (
                            "supportedExtension",
                            [pureldap.LDAPPasswordModifyRequest.oid],
                        ),
                    ],
                }
            ]
        )

    async def test_delete(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPDelRequest(self.thingie.dn.getText()), id=2
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(pureldap.LDAPDelResponse(resultCode=0), id=2).toWire(),
        )
        d = self.stuff.children()
        d.addCallback(lambda actual: self.assertCountEqual(actual, [self.another]))
        return d

    async def test_add_success(self):
        dn = "cn=new,ou=stuff,dc=example,dc=com"
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPAddRequest(
                    entry=dn,
                    attributes=[
                        (
                            pureldap.LDAPAttributeDescription("objectClass"),
                            pureber.BERSet(
                                value=[pureldap.LDAPAttributeValue("something")]
                            ),
                        )
                    ],
                ),
                id=2,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPAddResponse(resultCode=ldaperrors.Success.resultCode), id=2
            ).toWire(),
        )
        # tree changed
        d = self.stuff.children()
        d.addCallback(
            lambda actual: self.assertCountEqual(
                actual,
                [
                    self.thingie,
                    self.another,
                    inmemory.ReadOnlyInMemoryLDAPEntry(
                        b"cn=new,ou=stuff,dc=example,dc=com",
                        {b"objectClass": [b"something"]},
                    ),
                ],
            )
        )
        return d

    async def test_add_fail_existsAlready(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPAddRequest(
                    entry=self.thingie.dn.getText(),
                    attributes=[
                        (
                            pureldap.LDAPAttributeDescription("objectClass"),
                            pureber.BERSet(
                                value=[
                                    pureldap.LDAPAttributeValue("something"),
                                ]
                            ),
                        )
                    ],
                ),
                id=2,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPAddResponse(
                    resultCode=ldaperrors.LDAPEntryAlreadyExists.resultCode,
                    errorMessage=self.thingie.dn.getText(),
                ),
                id=2,
            ).toWire(),
        )
        # tree did not change
        d = self.stuff.children()
        d.addCallback(
            lambda actual: self.assertCountEqual(actual, [self.thingie, self.another])
        )
        return d

    async def test_modifyDN_rdnOnly_deleteOldRDN_success(self):
        newrdn = "cn=thingamagic"
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPModifyDNRequest(
                    entry=self.thingie.dn.getText(), newrdn=newrdn, deleteoldrdn=True
                ),
                id=2,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPModifyDNResponse(resultCode=ldaperrors.Success.resultCode),
                id=2,
            ).toWire(),
        )
        # tree changed
        d = self.stuff.children()
        d.addCallback(
            lambda actual: self.assertCountEqual(
                actual,
                [
                    inmemory.ReadOnlyInMemoryLDAPEntry(
                        "%s,ou=stuff,dc=example,dc=com" % newrdn,
                        {"objectClass": ["a", "b"], "cn": ["thingamagic"]},
                    ),
                    self.another,
                ],
            )
        )
        return d

    async def test_modifyDN_rejects_preserving_old_rdn(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPModifyDNRequest(
                    entry=self.thingie.dn.getText(),
                    newrdn="cn=thingamagic",
                    deleteoldrdn=False,
                ),
                id=2,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPModifyDNResponse(
                    resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode,
                    errorMessage="Cannot handle preserving old RDN yet.",
                ),
                id=2,
            ).toWire(),
        )

    async def test_modifyDN_with_new_superior(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPModifyDNRequest(
                    entry=self.thingie.dn.getText(),
                    newrdn="cn=thingamagic",
                    deleteoldrdn=True,
                    newSuperior=self.groups.dn.getText(),
                ),
                id=2,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPModifyDNResponse(resultCode=ldaperrors.Success.resultCode),
                id=2,
            ).toWire(),
        )
        d = self.groups.lookup("cn=thingamagic,ou=Groups,dc=example,dc=com")
        d.addCallback(
            lambda result: self.assertEqual(
                result.dn.getText(), "cn=thingamagic,ou=Groups,dc=example,dc=com"
            )
        )
        return d

    async def test_modify(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPModifyRequest(
                    self.stuff.dn.getText(),
                    modification=[
                        delta.Add("foo", ["bar"]).asLDAP(),
                    ],
                ),
                id=2,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPModifyResponse(resultCode=ldaperrors.Success.resultCode),
                id=2,
            ).toWire(),
        )
        # tree changed
        self.assertEqual(
            self.stuff,
            inmemory.ReadOnlyInMemoryLDAPEntry(
                "ou=stuff,dc=example,dc=com",
                {b"objectClass": [b"a", b"b"], b"ou": [b"stuff"], b"foo": [b"bar"]},
            ),
        )

    async def test_extendedRequest_unknown(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedRequest(
                    requestName="42.42.42", requestValue="foo"
                ),
                id=2,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage="Unknown extended request: 42.42.42",
                ),
                id=2,
            ).toWire(),
        )

    async def test_passwordModify_notBound(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPPasswordModifyRequest(
                    userIdentity="cn=thingie,ou=stuff,dc=example,dc=com",
                    newPasswd="hushhush",
                ),
                id=2,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.LDAPStrongAuthRequired.resultCode,
                    responseName=pureldap.LDAPPasswordModifyRequest.oid,
                ),
                id=2,
            ).toWire(),
        )

    async def _send_raw_password_modify(self, *values):
        request = pureldap.LDAPExtendedRequest(
            requestName=pureldap.LDAPPasswordModifyRequest.oid,
            requestValue=pureber.BERSequence(values).toWire(),
        )
        await self._send(pureldap.LDAPMessage(request, id=2).toWire())

    def _assert_password_modify_protocol_error(self):
        message, used = pureber.berDecodeObject(
            self.server.berdecoder, self.output
        )
        self.assertEqual(used, len(self.output))
        self.assertEqual(message.value.resultCode, ldaperrors.LDAPProtocolError.resultCode)
        self.assertEqual(message.value.responseName, pureldap.LDAPPasswordModifyRequest.oid)

    async def test_passwordModify_rejects_duplicate_user_identity(self):
        value = pureldap.LDAPPasswordModifyRequest_userIdentity("cn=thingie")
        await self._send_raw_password_modify(value, value)
        self._assert_password_modify_protocol_error()

    async def test_passwordModify_rejects_duplicate_old_password(self):
        value = pureldap.LDAPPasswordModifyRequest_oldPasswd("old")
        await self._send_raw_password_modify(value, value)
        self._assert_password_modify_protocol_error()

    async def test_passwordModify_rejects_duplicate_new_password(self):
        value = pureldap.LDAPPasswordModifyRequest_newPasswd("new")
        await self._send_raw_password_modify(value, value)
        self._assert_password_modify_protocol_error()

    async def test_passwordModify_rejects_unknown_sequence_item(self):
        with self.assertRaises(ldaperrors.LDAPProtocolError):
            self.server.extendedRequest_LDAPPasswordModifyRequest(
                pureber.BERSequence([pureber.BERInteger(1)]), lambda response: None
            )

    async def test_passwordModify_rejects_non_sequence_value(self):
        request = pureldap.LDAPExtendedRequest(
            requestName=pureldap.LDAPPasswordModifyRequest.oid,
            requestValue=pureber.BERInteger(1).toWire(),
        )
        await self._send(pureldap.LDAPMessage(request, id=2).toWire())
        self._assert_password_modify_protocol_error()

    async def _bind_thingie_for_password_change(self):
        self.thingie["userPassword"] = [
            "{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8="
        ]
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(dn=self.thingie.dn.getText(), auth="secret"),
                id=1,
            ).toWire()
        )
        self.output = b""

    async def test_passwordModify_rejects_old_password_mode(self):
        await self._bind_thingie_for_password_change()
        await self._send_raw_password_modify(
            pureldap.LDAPPasswordModifyRequest_oldPasswd("secret"),
            pureldap.LDAPPasswordModifyRequest_newPasswd("new"),
        )
        message, _ = pureber.berDecodeObject(
            self.server.berdecoder, self.output
        )
        self.assertEqual(
            message.value.resultCode, ldaperrors.LDAPOperationsError.resultCode
        )

    async def test_passwordModify_requires_new_password(self):
        await self._bind_thingie_for_password_change()
        await self._send_raw_password_modify(
            pureldap.LDAPPasswordModifyRequest_userIdentity(self.thingie.dn.getText())
        )
        message, _ = pureber.berDecodeObject(
            self.server.berdecoder, self.output
        )
        self.assertEqual(
            message.value.resultCode, ldaperrors.LDAPOperationsError.resultCode
        )

    async def test_passwordModify_simple(self):
        commits = observeCommits(self.thingie)
        # first bind to some entry
        self.thingie["userPassword"] = [
            "{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8="
        ]  # "secret"
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn="cn=thingie,ou=stuff,dc=example,dc=com", auth=b"secret"
                ),
                id=4,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=0, matchedDN="cn=thingie,ou=stuff,dc=example,dc=com"
                ),
                id=4,
            ).toWire(),
        )
        self.output = b""
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPPasswordModifyRequest(
                    userIdentity="cn=thingie,ou=stuff,dc=example,dc=com",
                    newPasswd="hushhush",
                ),
                id=2,
            ).toWire()
        )
        self.assertListEqual(commits, [True], "Server never committed data.")
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.Success.resultCode,
                    responseName=pureldap.LDAPPasswordModifyRequest.oid,
                ),
                id=2,
            ).toWire(),
        )
        # tree changed
        secrets = self.thingie.get("userPassword", [])
        self.assertEqual(len(secrets), 1)
        for secret in secrets:
            self.assertEqual(secret[: len(b"{SSHA}")], b"{SSHA}")
            raw = base64.decodebytes(secret[len(b"{SSHA}") :])
            salt = raw[20:]
            self.assertEqual(entry.sshaDigest(b"hushhush", salt), secret)

    async def test_passwordModify_someoneElse(self):
        commits = observeCommits(self.thingie)
        # first bind to some entry
        userPassword = b"{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8="  # secret
        self.thingie["userPassword"] = [userPassword]
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn="cn=thingie,ou=stuff,dc=example,dc=com", auth=b"secret"
                ),
                id=4,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=0, matchedDN="cn=thingie,ou=stuff,dc=example,dc=com"
                ),
                id=4,
            ).toWire(),
        )
        self.output = b""
        messages = capture_logs(self, level=logging.INFO)
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPPasswordModifyRequest(
                    userIdentity="cn=another,ou=stuff,dc=example,dc=com",
                    newPasswd="hushhush",
                ),
                id=2,
            ).toWire()
        )
        self.assertEqual(
            messages[0],
            "User cn=thingie,ou=stuff,dc=example,dc=com "
            "tried to change password of "
            "b'cn=another,ou=stuff,dc=example,dc=com'",
        )
        self.assertListEqual(commits, [], "Server committed data.")
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.LDAPInsufficientAccessRights.resultCode,
                    responseName=pureldap.LDAPPasswordModifyRequest.oid,
                ),
                id=2,
            ).toWire(),
        )
        self.assertSequenceEqual(
            self.thingie.get("userPassword", []),
            [userPassword],
        )

    async def test_unknownRequest(self):
        # make server miss one of the handle_* attributes
        # without having to modify the LDAPServer class
        class MockServer(ldapserver.LDAPServer):
            handle_LDAPBindRequest = property()

        self.server.__class__ = MockServer
        await self._send(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    responseName="1.3.6.1.4.1.1466.20036",
                    errorMessage="Unknown request",
                ),
                id=2,
            ).toWire(),
        )

    async def test_control_unknown_critical(self):
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(),
                id=2,
                controls=[
                    ("42.42.42.42", True, None),
                ],
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPUnavailableCriticalExtension.resultCode,
                    errorMessage="Unknown control 42.42.42.42",
                ),
                id=2,
            ).toWire(),
        )

    async def test_control_unknown_nonCritical(self):
        self.thingie["userPassword"] = [
            "{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8="
        ]  # "secret"
        await self._send(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn="cn=thingie,ou=stuff,dc=example,dc=com", auth=b"secret"
                ),
                controls=[("42.42.42.42", False, None)],
                id=4,
            ).toWire()
        )
        self.assertEqual(
            self.output,
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=0, matchedDN="cn=thingie,ou=stuff,dc=example,dc=com"
                ),
                id=4,
            ).toWire(),
        )


class TestSchema(unittest.TestCase):
    def setUp(self):
        self.client = testutil.LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    "dc=example,dc=com",
                    [("subschemaSubentry", ["cn=schema"])],
                ),
                pureldap.LDAPSearchResultDone(resultCode=0, matchedDN="", errorMessage=""),
            ],
            [
                pureldap.LDAPSearchResultEntry(
                    "cn=schema",
                    [
                        (
                            "attributeTypes",
                            [test_schema.AttributeType_KnownValues.knownValues[0][0]],
                        ),
                        (
                            "objectClasses",
                            [
                                test_schema.OBJECTCLASSES["organization"],
                                test_schema.OBJECTCLASSES["organizationalUnit"],
                            ],
                        ),
                    ],
                ),
                pureldap.LDAPSearchResultDone(resultCode=0, matchedDN="", errorMessage=""),
            ],
        )

    def testSimple(self):
        d = fetchschema.fetch(self.client, "dc=example,dc=com")
        (attributeTypes, objectClasses) = util.pumpingDeferredResult(d)

        self.assertEqual(
            [to_bytes(x) for x in attributeTypes],
            [
                to_bytes(schema.AttributeTypeDescription(x))
                for x in [test_schema.AttributeType_KnownValues.knownValues[0][0]]
            ],
        )

        self.assertCountEqual(
            [to_bytes(x) for x in objectClasses],
            [
                to_bytes(schema.ObjectClassDescription(x))
                for x in [
                    test_schema.OBJECTCLASSES["organization"],
                    test_schema.OBJECTCLASSES["organizationalUnit"],
                ]
            ],
        )
