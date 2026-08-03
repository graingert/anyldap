"""
Test cases for anyldap.protocols.ldap.ldapsyntax module.
"""

import re

import pytest

from anyldap import config, delta
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldapclient, ldaperrors, ldapsyntax
from anyldap.runtime import ConnectionLost, Failure
from anyldap.testutil import LDAPClientTestDriver

pytestmark = pytest.mark.anyio


async def test_async_entry_methods_use_the_ldap_client_interface() -> None:
    client = LDAPClientTestDriver(
        [pureldap.LDAPModifyResponse(resultCode=0)],
        [pureldap.LDAPModifyDNResponse(resultCode=0)],
        [pureldap.LDAPAddResponse(resultCode=0)],
        [pureldap.LDAPExtendedResponse(resultCode=0)],
        [pureldap.LDAPModifyResponse(resultCode=0)],
        [pureldap.LDAPExtendedResponse(resultCode=0)],
        [
            pureldap.LDAPSearchResultEntry(
                "", [("namingContexts", ["dc=example,dc=com"])]
            ),
            pureldap.LDAPSearchResultDone(resultCode=0),
        ],
        [
            pureldap.LDAPSearchResultEntry(
                "cn=user,dc=example,dc=com", [("cn", ["user"])]
            ),
            pureldap.LDAPSearchResultDone(resultCode=0),
        ],
        [
            pureldap.LDAPSearchResultEntry(
                "cn=user,dc=example,dc=com", [("cn", ["user"])]
            ),
            pureldap.LDAPSearchResultDone(resultCode=0),
        ],
        [
            pureldap.LDAPSearchResultEntry(
                "cn=user,dc=example,dc=com", [("cn", ["user"])]
            ),
            pureldap.LDAPSearchResultDone(resultCode=0),
        ],
        [pureldap.LDAPDelResponse(resultCode=0)],
    )
    entry = ldapsyntax.LDAPEntry(
        client,
        "cn=user,dc=example,dc=com",
        {"objectClass": ["person"], "cn": ["user"]},
        complete=True,
    )

    assert len(entry) == 2
    assert entry.__nonzero__() is True
    assert await entry.commit_async() is entry
    entry["description"] = ["updated"]
    assert await entry.commit_async() is entry
    assert await entry.move_async("cn=moved,dc=example,dc=com") is entry
    child = await entry.addChild_async("cn=child", {"objectClass": ["person"]})
    assert child.dn.getText() == "cn=child,cn=moved,dc=example,dc=com"
    assert await entry.setPassword_ExtendedOperation_async("new-secret") is entry
    assert await entry.setPassword_Samba_async("new-secret", style="sambaSamAccount") is entry
    assert await entry.setPasswordMaybe_Samba_async("new-secret") is entry
    assert await entry.setPassword_async("new-secret") is entry
    context = await entry.namingContext_async()
    assert context.dn.getText() == "dc=example,dc=com"
    assert await entry.fetch_async("cn") is entry
    results = await entry.search_async(
        filterText="(cn=user)",
        filterObject=pureldap.LDAPFilter_present("cn"),
        derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
    )
    assert results[0].dn.getText() == "cn=user,dc=example,dc=com"
    found = await entry.lookup_async("cn=user,dc=example,dc=com")
    assert found.dn.getText() == "cn=user,dc=example,dc=com"
    assert await entry.delete_async() is entry


async def test_async_entry_operations_surface_real_ldap_errors() -> None:
    client = LDAPClientTestDriver(
        [pureldap.LDAPModifyResponse(resultCode=ldaperrors.LDAPNoSuchObject.resultCode)],
        [
            pureldap.LDAPModifyDNResponse(
                resultCode=ldaperrors.LDAPNoSuchObject.resultCode
            )
        ],
        [
            pureldap.LDAPAddResponse(
                resultCode=ldaperrors.LDAPEntryAlreadyExists.resultCode
            )
        ],
    )
    entry = ldapsyntax.LDAPEntry(
        client,
        "cn=missing,dc=example,dc=com",
        {"cn": ["missing"]},
        complete=True,
    )
    entry["description"] = ["dirty"]
    with pytest.raises(ldaperrors.LDAPNoSuchObject):
        await entry.commit_async()
    entry.undo()
    with pytest.raises(ldaperrors.LDAPNoSuchObject):
        await entry.move_async("cn=moved,dc=example,dc=com")
    with pytest.raises(ldaperrors.LDAPEntryAlreadyExists):
        await entry.addChild_async("cn=child", {"cn": ["child"]})


async def test_password_error_repr_and_non_ready_state() -> None:
    error = ldapsyntax.PasswordSetAggregateError(
        [("plugin", Failure(RuntimeError("failed")))]
    )
    assert repr(error).startswith("<PasswordSetAggregateError errors=")
    entry = ldapsyntax.LDAPEntry(LDAPClientTestDriver(), "cn=user")
    entry._state = "committing"
    with pytest.raises(ldapsyntax.ObjectInBadStateError, match="committing"):
        await entry.commit()


async def test_search_accepts_reference_and_nonfatal_size_limit_responses() -> None:
    client = LDAPClientTestDriver(
        [
            pureldap.LDAPSearchResultReference(["ldap://example"]),
            pureldap.LDAPSearchResultDone(
                resultCode=ldaperrors.LDAPSizeLimitExceeded.resultCode
            ),
        ]
    )
    entry = ldapsyntax.LDAPEntry(client, "dc=example,dc=com")
    assert await entry.search_async(sizeLimitIsNonFatal=True) == []


async def test_search_rejects_non_search_protocol_response() -> None:
    client = LDAPClientTestDriver([pureldap.LDAPBindResponse(resultCode=0)])
    entry = ldapsyntax.LDAPEntry(client, "dc=example,dc=com")
    with pytest.raises(ldaperrors.LDAPProtocolError, match="bad search response"):
        await entry.search_async()


class TestLDAPEntryTests:
    """
    Unit tests for LDAPEntry.
    """

    def testCreation(self) -> None:
        """Creating an LDAP object should succeed."""
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        assert o.dn.getText() == "cn=foo,dc=example,dc=com"
        assert o["objectClass"] == ["a", "b"]
        assert o["aValue"] == ["a"]
        assert o["bValue"] == ["b"]
        client.assertNothingSent()

    def testKeys(self) -> None:
        """Iterating over the keys of an LDAP object gives expected results."""
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        seen = {}
        for k in o.keys():
            assert k not in seen
            seen[k] = 1
        assert seen == {
            "objectClass": 1,
            "aValue": 1,
            "bValue": 1,
        }

    def testItems(self) -> None:
        """Iterating over the items of an LDAP object gives expected results."""
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        seen = {}
        for k, vs in o.items():
            assert k not in seen
            seen[k] = vs
        assert seen == {
            "objectClass": ["a", "b"],
            "aValue": ["a"],
            "bValue": ["b"],
        }

    def testIn(self) -> None:
        """Key in object gives expected results."""
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        assert "objectClass" in o
        assert "aValue" in o
        assert "bValue" in o
        assert "foo" not in o
        assert "" not in o
        assert None not in o

        assert "a" in o["objectClass"]
        assert "b" in o["objectClass"]
        assert "foo" not in o["objectClass"]
        assert "" not in o["objectClass"]
        assert None not in o["objectClass"]

        assert "a" in o["aValue"]
        assert "foo" not in o["aValue"]
        assert "" not in o["aValue"]
        assert None not in o["aValue"]

    def testInequalityOtherObject(self) -> None:
        """
        It is not equal with non LDAPEntry objects.
        """
        client = LDAPClientTestDriver()
        sut = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
        )

        assert "dc=example,dc=com" != sut

    def testInequalityDN(self) -> None:
        """
        Entries with different DN are not equal.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
        )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=org",
        )

        assert first != second

    def testInequalityAttributes(self) -> None:
        """
        Entries with same DN but different attributes are not equal.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={"attr_key1": ["some-value"]},
        )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={"attr_key2": ["some-value"]},
        )

        assert first != second

    def testInequalityValues(self) -> None:
        """
        Entries with same DN same attributes, but different
        values for attributes are not equal.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={"attr_key1": ["some-value"]},
        )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={"attr_key1": ["other-value"]},
        )

        assert first != second

    def testEquality(self) -> None:
        """
        Entries with same DN, same attributes, and same values for
        attributes equal, regardless of the order of the attributes.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={
                "attr_key1": ["some-value"],
                "attr_key2": ["second-value"],
            },
        )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={
                "attr_key2": ["second-value"],
                "attr_key1": ["some-value"],
            },
        )

        assert first == second

    def testHashEqual(self) -> None:
        """
        Entries which are equal have the same hash.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
        )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
        )

        assert first == second
        assert hash(first) == hash(second)

    def testHashNotEqual(self) -> None:
        """
        Entries which are not equal have different hash values.
        """
        client = LDAPClientTestDriver()
        first = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
        )
        second = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=org",
        )

        assert first != second
        assert hash(first) != hash(second)


class TestLDAPSyntaxAttributes:
    def testAttributeSetting(self) -> None:
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        o["aValue"] = ["foo", "bar"]
        assert o["aValue"] == ["foo", "bar"]
        o["aValue"] = ["quux"]
        assert o["aValue"] == ["quux"]
        assert o["bValue"] == ["b"]
        o["cValue"] = ["thud"]
        assert o["aValue"] == ["quux"]
        assert o["bValue"] == ["b"]
        assert o["cValue"] == ["thud"]

    def testAttributeDelete(self) -> None:
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        o["aValue"] = ["quux"]
        del o["aValue"]
        del o["bValue"]
        assert not ("aValue" in o)
        assert not ("bValue" in o)

    def testAttributeAdd(self) -> None:
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        o["aValue"].add("foo")
        assert o["aValue"] == ["a", "foo"]

    def testAttributeItemDelete(self) -> None:
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a", "b", "c"],
                "bValue": ["b"],
            },
        )
        o["aValue"].remove("b")
        assert o["aValue"] == ["a", "c"]

    def testUndo(self) -> None:
        """Undo should forget the modifications."""
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
                "cValue": ["c"],
            },
        )
        o["aValue"] = ["foo", "bar"]
        o["aValue"] = ["quux"]
        del o["cValue"]
        o.undo()
        assert o["aValue"] == ["a"]
        assert o["bValue"] == ["b"]
        assert o["cValue"] == ["c"]

    async def testUndoJournaling(self) -> None:
        """Journaling should still work after undo."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPModifyResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
                "cValue": ["c"],
            },
        )
        o["aValue"] = ["foo", "bar"]
        o["aValue"] = ["quux"]
        del o["cValue"]
        o.undo()
        o["aValue"].update(["newValue", "anotherNewValue"])


        await o.commit()
        assert o["aValue"] == ["a", "newValue", "anotherNewValue"]
        assert o["bValue"] == ["b"]
        assert o["cValue"] == ["c"]
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Add("aValue", ["newValue", "anotherNewValue"]),
                ],
            ).asLDAP()
        )

    async def testUndoAfterCommit(self) -> None:
        """Undo should not undo things that have been commited."""

        client = LDAPClientTestDriver(
            [
                pureldap.LDAPModifyResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
                "cValue": ["c"],
            },
        )
        o["aValue"] = ["foo", "bar"]
        o["bValue"] = ["quux"]
        del o["cValue"]



        await o.commit()
        o.undo()
        assert o["aValue"] == ["foo", "bar"]
        assert o["bValue"] == ["quux"]
        assert not ("cValue" in o)


class TestLDAPSyntaxAttributesModificationOnWire:
    async def testAdd(self) -> None:
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [
                pureldap.LDAPModifyResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
            },
        )
        o["aValue"].update(["newValue", "anotherNewValue"])



        await o.commit()
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Add("aValue", ["newValue", "anotherNewValue"]),
                ],
            ).asLDAP()
        )

    async def testAddSeparate(self) -> None:
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [
                pureldap.LDAPModifyResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
            },
        )
        o["aValue"].add("newValue")
        o["aValue"].add("anotherNewValue")



        await o.commit()
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Add("aValue", ["newValue"]),
                    delta.Add("aValue", ["anotherNewValue"]),
                ],
            ).asLDAP()
        )

    async def testDeleteAttribute(self) -> None:
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")]
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
            },
        )
        o["aValue"].remove("a")



        await o.commit()
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Delete("aValue", ["a"]),
                ],
            ).asLDAP()
        )

    async def testDeleteAllAttribute(self) -> None:
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [
                pureldap.LDAPModifyResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a1", "a2"],
                "bValue": ["b1", "b2"],
            },
        )
        del o["aValue"]
        o["bValue"].clear()



        await o.commit()
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Delete("aValue"),
                    delta.Delete("bValue"),
                ],
            ).asLDAP()
        )

    async def testReplaceAttributes(self) -> None:
        """Modify & commit should write the right data to the server."""

        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")]
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
            },
        )
        o["aValue"] = ["foo", "bar"]



        await o.commit()
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace("aValue", ["foo", "bar"]),
                ],
            ).asLDAP()
        )


class TestLDAPSyntaxSearch:
    timeout = 3

    async def _test_search(self, return_controls=False) -> None:
        """
        Create a test search.
        Return the response with no handler.
        """
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=foo,dc=example,dc=com",
                    attributes=(
                        ("foo", ["a"]),
                        ("bar", ["b", "c"]),
                    ),
                ),
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=bar,dc=example,dc=com",
                    attributes=(
                        ("foo", ["a"]),
                        ("bar", ["d", "e"]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={
                "objectClass": ["organizationalUnit"],
            },
        )


        val = await o.search(
            filterText="(foo=a)",
            attributes=["foo", "bar"],
            return_controls=return_controls,
        )
        if return_controls:
            val = val[0]
        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_wholeSubtree,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=0,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(value="foo"),
                    assertionValue=pureldap.LDAPAssertionValue(value="a"),
                ),
                attributes=["foo", "bar"],
            )
        )
        assert len(val) == 2
        assert val[0] == (ldapsyntax.LDAPEntry(
                client=client,
                dn="cn=foo,dc=example,dc=com",
                attributes={
                    b"foo": [b"a"],
                    b"bar": [b"b", b"c"],
                },
            ))
        assert val[1] == (ldapsyntax.LDAPEntry(
                client=client,
                dn="cn=bar,dc=example,dc=com",
                attributes={
                    b"foo": [b"a"],
                    b"bar": [b"d", b"e"],
                },
            ))

    async def testSearch(self) -> None:
        """Test searches."""
        await self._test_search()

    async def test_search_not_connected(self) -> None:
        client = ldapclient.LDAPClient()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={
                "objectClass": ["organizationalUnit"],
            },
        )
        with pytest.raises(ldapclient.LDAPClientConnectionLostException):
            await o.search(filterText="(foo=a)", attributes=["foo", "bar"])

    async def test_search_controls_returned(self) -> None:
        await self._test_search(return_controls=True)

    async def test_search_size_limit_exceeded(self) -> None:
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=foo,dc=example,dc=com",
                    attributes=(
                        ("foo", ["a"]),
                        ("bar", ["b", "c"]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=ldaperrors.LDAPSizeLimitExceeded.resultCode,
                    matchedDN="",
                    errorMessage="Size limit exceeded.",
                ),
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={
                "objectClass": ["organizationalUnit"],
            },
        )
        results = await o.search(
            filterText="(foo=a)",
            attributes=["foo", "bar"],
            sizeLimit=1,
            return_controls=False,
        )

        assert len(results) == 1

    async def testSearch_defaultAttributes(self) -> None:
        """Search without explicit list of attributes returns all attributes."""

        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=foo,dc=example,dc=com",
                    attributes=(
                        ("foo", ["a"]),
                        ("bar", ["b", "c"]),
                    ),
                ),
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=bar,dc=example,dc=com",
                    attributes=(
                        ("foo", ["a"]),
                        ("bar", ["d", "e"]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={
                "objectClass": ["organizationalUnit"],
            },
        )



        val = await o.search(filterText="(foo=a)")
        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_wholeSubtree,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=0,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(value="foo"),
                    assertionValue=pureldap.LDAPAssertionValue(value="a"),
                ),
                attributes=[],
            )
        )
        assert len(val) == 2

        assert val[0] == (ldapsyntax.LDAPEntry(
                client=client,
                dn="cn=foo,dc=example,dc=com",
                attributes={
                    b"foo": [b"a"],
                    b"bar": [b"b", b"c"],
                },
            ))
        assert val[0].complete

        assert val[1] == (ldapsyntax.LDAPEntry(
                client=client,
                dn="cn=bar,dc=example,dc=com",
                attributes={
                    b"foo": [b"a"],
                    b"bar": [b"d", b"e"],
                },
            ))
        assert val[1].complete

    async def testSearch_noAttributes(self) -> None:
        """Search with attributes=None returns no attributes."""

        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    "cn=foo,dc=example,dc=com", attributes=()
                ),
                pureldap.LDAPSearchResultEntry(
                    "cn=bar,dc=example,dc=com", attributes=()
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={
                "objectClass": ["organizationalUnit"],
            },
        )



        val = await o.search(filterText="(foo=a)", attributes=None)
        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_wholeSubtree,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=0,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(value="foo"),
                    assertionValue=pureldap.LDAPAssertionValue(value="a"),
                ),
                attributes=["1.1"],
            )
        )
        assert len(val) == 2

        assert val[0] == ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")
        assert not (val[0].complete)

        assert val[1] == ldapsyntax.LDAPEntry(client=client, dn="cn=bar,dc=example,dc=com")
        assert not (val[1].complete)

    async def testSearch_ImmediateProcessing(self) -> None:
        """Test searches with the immediate processing feature."""

        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=foo,dc=example,dc=com",
                    attributes=(("bar", ["b", "c"]),),
                ),
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=bar,dc=example,dc=com",
                    attributes=(("bar", ["b", "c"]),),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="dc=example,dc=com",
            attributes={
                "objectClass": ["organizationalUnit"],
            },
        )

        seen = []

        def process(o) -> None:
            seen.append(o)



        val = await o.search(filterText="(foo=a)", attributes=["bar"], callback=process)
        assert val is None

        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_wholeSubtree,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=0,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(value="foo"),
                    assertionValue=pureldap.LDAPAssertionValue(value="a"),
                ),
                attributes=["bar"],
            )
        )

        assert seen == ([
                ldapsyntax.LDAPEntry(
                    client=client,
                    dn="cn=foo,dc=example,dc=com",
                    attributes={
                        b"bar": [b"b", b"c"],
                    },
                ),
                ldapsyntax.LDAPEntry(
                    client=client,
                    dn="cn=bar,dc=example,dc=com",
                    attributes={
                        b"bar": [b"b", b"c"],
                    },
                ),
            ])

    async def testSearch_fail(self) -> None:
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultDone(
                    resultCode=ldaperrors.LDAPBusy.resultCode,
                    matchedDN="",
                    errorMessage="Go away",
                )
            ]
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="dc=example,dc=com")


        with pytest.raises(ldaperrors.LDAPBusy) as excinfo:
            await o.search(filterText="(foo=a)")
        assert excinfo.value.message == "Go away"

        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_wholeSubtree,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=0,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(value="foo"),
                    assertionValue=pureldap.LDAPAssertionValue(value="a"),
                ),
            )
        )

    async def testSearch_err(self) -> None:
        client = LDAPClientTestDriver([Failure(ConnectionLost())])
        o = ldapsyntax.LDAPEntry(client=client, dn="dc=example,dc=com")


        with pytest.raises(ConnectionLost):
            await o.search(filterText="(foo=a)")


class TestLDAPSyntaxDNs:
    def testDNKeyExistenceSuccess(self) -> None:
        client = LDAPClientTestDriver()
        ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "cn": ["foo"],
            },
        )


class TestLDAPSyntaxLDIF:
    def testLDIFConversion(self) -> None:
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a", "b"],
                "bValue": ["c"],
            },
        )
        assert o.toWire() == (b"""dn: cn=foo,dc=example,dc=com
objectClass: a
objectClass: b
aValue: a
aValue: b
bValue: c

""")


class TestLDAPSyntaxDelete:
    async def testDeleteInvalidates(self) -> None:
        """Deleting an LDAPEntry invalidates it."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPDelResponse(resultCode=0, matchedDN="", errorMessage=""),
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a"],
            },
        )


        await o.delete()
        with pytest.raises(ldapsyntax.ObjectDeletedError):
            await o.search(filterText="(foo=a)")
        with pytest.raises(ldapsyntax.ObjectDeletedError):
            o.get("objectClass")

    async def testDeleteOnWire(self) -> None:
        """LDAPEntry.delete should write the right data to the server."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPDelResponse(resultCode=0, matchedDN="", errorMessage=""),
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a"],
            },
        )


        await o.delete()
        client.assertSent(
            pureldap.LDAPDelRequest(
                entry="cn=foo,dc=example,dc=com",
            )
        )

    async def testErrorHandling(self) -> None:
        """LDAPEntry.delete should raise LDAP errors to its caller."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPDelResponse(
                    resultCode=ldaperrors.LDAPBusy.resultCode,
                    matchedDN="",
                    errorMessage="Go away",
                ),
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a"],
            },
        )


        with pytest.raises(ldaperrors.LDAPBusy) as excinfo:
            await o.delete()
        assert excinfo.value.message == "Go away"

        client.assertSent(
            pureldap.LDAPDelRequest(
                entry="cn=foo,dc=example,dc=com",
            )
        )

    async def testErrorHandling_extended(self) -> None:
        """LDAPEntry.delete should raise even non-LDAPDelResponse errors."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    responseName="1.3.6.1.4.1.1466.20036",
                    errorMessage="Unknown request",
                )
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a"],
            },
        )


        with pytest.raises(ldaperrors.LDAPProtocolError) as excinfo:
            await o.delete()
        assert excinfo.value.message == "Unknown request"

        client.assertSent(
            pureldap.LDAPDelRequest(
                entry="cn=foo,dc=example,dc=com",
            )
        )


class TestLDAPSyntaxAddChild:
    async def testAddChildOnWire(self) -> None:
        """LDAPEntry.addChild should write the right data to the server."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPAddResponse(resultCode=0, matchedDN="", errorMessage=""),
            ]
        )
        sut = ldapsyntax.LDAPEntry(
            client=client,
            dn="ou=things,dc=example,dc=com",
            attributes={
                "objectClass": ["organizationalUnit"],
                "ou": ["things"],
            },
        )
        await sut.addChild(
            rdn="givenName=Firstname+surname=Lastname",
            attributes={
                "objectClass": ["person", b"otherStuff"],
                "givenName": ["Firstname"],
                "surname": ["Lastname"],
            },
        )

        client.assertSent(
            pureldap.LDAPAddRequest(
                entry="givenName=Firstname+surname=Lastname,ou=things,dc=example,dc=com",
                attributes=[
                    (
                        pureldap.LDAPAttributeDescription("objectClass"),
                        pureber.BERSet(
                            [
                                pureldap.LDAPAttributeValue("person"),
                                pureldap.LDAPAttributeValue("otherStuff"),
                            ]
                        ),
                    ),
                    (
                        pureldap.LDAPAttributeDescription("givenName"),
                        pureber.BERSet([pureldap.LDAPAttributeValue("Firstname")]),
                    ),
                    (
                        pureldap.LDAPAttributeDescription("surname"),
                        pureber.BERSet(
                            [pureldap.LDAPAttributeValue("Lastname")],
                        ),
                    ),
                ],
            )
        )


class TestLDAPSyntaxContainingNamingContext:
    def setup_method(self) -> None:
        attributes = [
            (
                "namingContexts",
                (
                    "dc=foo,dc=example",
                    "dc=example,dc=com",
                    "dc=bar,dc=example",
                ),
            )
        ]
        self.client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(objectName="", attributes=attributes),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )

    async def testNamingContext(self) -> None:
        """LDAPEntry.namingContext returns the naming context that contains this object."""
        o = ldapsyntax.LDAPEntry(
            client=self.client,
            dn="cn=foo,ou=bar,dc=example,dc=com",
            attributes={"objectClass": ["a"]},
        )


        p = await o.namingContext()
        assert isinstance(p, ldapsyntax.LDAPEntry)
        assert p.client == o.client
        assert p.dn.getText() == "dc=example,dc=com"

        self.client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="",
                scope=pureldap.LDAP_SCOPE_baseObject,
                filter=pureldap.LDAPFilter_present("objectClass"),
                attributes=["namingContexts"],
            )
        )

    async def testNoContainingNamingContext(self) -> None:
        """LDAPEntry.namingContext raises exception if there are no naming contexts with it"""
        o = ldapsyntax.LDAPEntry(
            client=self.client,
            dn="cn=foo,dc=foo,dc=com",
            attributes={"objectClass": ["a"]},
        )
        with pytest.raises(ldapsyntax.NoContainingNamingContext):
            await o.namingContext()


class TestLDAPSyntaxPasswords:
    def setup_method(self) -> None:
        cfg = config.loadConfig()
        cfg.set("samba", "use-lmhash", "no")

    async def testPasswordSetting_ExtendedOperation(self) -> None:
        """LDAPEntry.setPassword_ExtendedOperation(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                )
            ],
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        await o.setPassword_ExtendedOperation(newPasswd=b"new")
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
        )

    async def testPasswordSetting_Samba_sambaAccount(self) -> None:
        """LDAPEntry.setPassword_Samba(newPasswd=...,
        style='sambaAccount') changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        await o.setPassword_Samba(newPasswd=b"new", style="sambaAccount")
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace(
                        "ntPassword", ["89963F5042E5041A59C249282387A622"]
                    ),
                    delta.Replace(
                        "lmPassword", ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"]
                    ),
                ],
            ).asLDAP()
        )

    async def testPasswordSetting_Samba_sambaSamAccount(self) -> None:
        """LDAPEntry.setPassword_Samba(newPasswd=..., style='sambaSamAccount') changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        await o.setPassword_Samba(newPasswd=b"new", style="sambaSamAccount")
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace(
                        "sambaNTPassword", ["89963F5042E5041A59C249282387A622"]
                    ),
                    delta.Replace(
                        "sambaLMPassword", ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"]
                    ),
                ],
            ).asLDAP()
        )

    async def testPasswordSetting_Samba_defaultStyle(self) -> None:
        """LDAPEntry.setPassword_Samba(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        await o.setPassword_Samba(newPasswd=b"new")
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace(
                        "sambaNTPassword", ["89963F5042E5041A59C249282387A622"]
                    ),
                    delta.Replace(
                        "sambaLMPassword", ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"]
                    ),
                ],
            ).asLDAP()
        )

    async def testPasswordSetting_Samba_badStyle(self) -> None:
        """LDAPEntry.setPassword_Samba(..., style='foo') fails."""
        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        with pytest.raises(RuntimeError) as excinfo:
            await o.setPassword_Samba(newPasswd=b"new", style="foo")
        assert str(excinfo.value) == "Unknown samba password style 'foo'"
        client.assertNothingSent()

    async def testPasswordSettingAll_noSamba(self) -> None:
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                )
            ],
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["foo"],
            },
            complete=1,
        )


        await o.setPassword(newPasswd=b"new")
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
        )

    async def testPasswordSettingAll_hasSamba(self) -> None:
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                )
            ],
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["foo", "sambaAccount"],
            },
            complete=1,
        )


        await o.setPassword(newPasswd=b"new")
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace(
                        "ntPassword", ["89963F5042E5041A59C249282387A622"]
                    ),
                    delta.Replace(
                        "lmPassword", ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"]
                    ),
                ],
            ).asLDAP(),
        )

    async def testPasswordSettingAll_hasSambaSam(self) -> None:
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                )
            ],
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["foo", "sambaSamAccount"],
            },
            complete=1,
        )


        await o.setPassword(newPasswd=b"new")
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace(
                        "sambaNTPassword", ["89963F5042E5041A59C249282387A622"]
                    ),
                    delta.Replace(
                        "sambaLMPassword", ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"]
                    ),
                ],
            ).asLDAP(),
        )

    async def testPasswordSettingAll_hasSamba_differentCase(self) -> None:
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                )
            ],
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["foo", "saMBaAccOuNT"],
            },
            complete=1,
        )


        await o.setPassword(newPasswd=b"new")
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace(
                        "ntPassword", ["89963F5042E5041A59C249282387A622"]
                    ),
                    delta.Replace(
                        "lmPassword", ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"]
                    ),
                ],
            ).asLDAP(),
        )

    async def testPasswordSettingAll_hasSambaSam_differentCase(self) -> None:
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                )
            ],
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["foo", "sAmbASAmaccoUnt"],
            },
            complete=1,
        )


        await o.setPassword(newPasswd=b"new")
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace(
                        "sambaNTPassword", ["89963F5042E5041A59C249282387A622"]
                    ),
                    delta.Replace(
                        "sambaLMPassword", ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"]
                    ),
                ],
            ).asLDAP(),
        )

    async def testPasswordSettingAll_maybeSamba_WillFind(self) -> None:
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                )
            ],
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="",
                    attributes=[("objectClass", ("foo", "sambaAccount", "bar"))],
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        await o.setPassword(newPasswd=b"new")
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
            pureldap.LDAPSearchRequest(
                baseObject="cn=foo,dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_baseObject,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=0,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilterMatchAll,
                attributes=("objectClass",),
            ),
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace(
                        "ntPassword", ["89963F5042E5041A59C249282387A622"]
                    ),
                    delta.Replace(
                        "lmPassword", ["XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"]
                    ),
                ],
            ).asLDAP(),
        )

    async def testPasswordSettingAll_maybeSamba_WillNotFind(self) -> None:
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                )
            ],
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="", attributes=[("objectClass", ("foo", "bar"))]
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        await o.setPassword(newPasswd=b"new")
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
            pureldap.LDAPSearchRequest(
                baseObject="cn=foo,dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_baseObject,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=0,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilterMatchAll,
                attributes=("objectClass",),
            ),
        )

    async def testPasswordSettingAll_maybeSamba_WillNotFindAnything(self) -> None:
        """LDAPEntry.setPassword(newPasswd=...) changes the password."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                )
            ],
            [
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")
        with pytest.raises(ldapsyntax.PasswordSetAggregateError) as excinfo:
            await o.setPassword(newPasswd=b"new")

        value = excinfo.value
        assert str(value) == ("Some of the password plugins failed: "
            "Samba failed with cn=foo,dc=example,dc=com.")
        l = value.errors
        assert len(l) == 1
        assert len(l[0]) == 2
        assert l[0][0] == "Samba"
        assert isinstance(l[0][1], Failure)
        l[0][1].trap(ldapsyntax.DNNotPresentError)
        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
            pureldap.LDAPSearchRequest(
                baseObject="cn=foo,dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_baseObject,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=0,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilterMatchAll,
                attributes=("objectClass",),
            ),
        )

    async def testPasswordSetting_abortsOnFirstError(self) -> None:
        """LDAPEntry.setPassword() aborts on first error (does not parallelize, as it used to)."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.LDAPInsufficientAccessRights.resultCode,
                    matchedDN="",
                    errorMessage="",
                )
            ],
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["foo", "sambaAccount"],
            },
            complete=1,
        )


        with pytest.raises(ldapsyntax.PasswordSetAggregateError) as excinfo:
            await o.setPassword(newPasswd=b"new")
        value = excinfo.value
        assert str(value) == ("Some of the password plugins failed: "
            "ExtendedOperation failed with insufficientAccessRights; "
            "Samba failed with Aborted.")
        l = value.errors
        assert len(l) == 2

        assert len(l[0]) == 2
        assert l[0][0] == "ExtendedOperation"
        assert isinstance(l[0][1], Failure)
        l[0][1].trap(ldaperrors.LDAPInsufficientAccessRights)

        assert len(l[1]) == 2
        assert l[1][0] == "Samba"
        assert isinstance(l[1][1], Failure)
        l[1][1].trap(ldapsyntax.PasswordSetAborted)

        client.assertSent(
            pureldap.LDAPPasswordModifyRequest(
                userIdentity="cn=foo,dc=example,dc=com", newPasswd=b"new"
            ),
        )


class TestLDAPSyntaxFetch:
    async def testFetch_WithDirtyJournal(self) -> None:
        """Trying to fetch attributes with a dirty journal fails."""
        client = LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")
        o["x"] = ["foo"]

        with pytest.raises(ldapsyntax.ObjectDirtyError):
            await o.fetch()

    async def testFetch_Empty(self) -> None:
        """Fetching attributes for a newly-created object works."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=foo,dc=example,dc=com",
                    attributes=(
                        ("foo", ["a"]),
                        ("bar", ["b", "c"]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )
        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        await o.fetch()
        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="cn=foo,dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_baseObject,
            )
        )

        has = o.keys()
        has.sort()
        want = [b"foo", b"bar"]
        want.sort()
        assert has == want
        assert o["foo"] == [b"a"]
        assert o["bar"] == [b"b", b"c"]

    async def testFetch_Prefilled(self) -> None:
        """Fetching attributes for a (partially) known object overwrites the old attributes."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=foo,dc=example,dc=com",
                    attributes=(
                        ("foo", ["a"]),
                        ("bar", ["b", "c"]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={"foo": ["x"], "quux": ["baz", "xyzzy"]},
        )


        await o.fetch()
        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="cn=foo,dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_baseObject,
            )
        )

        has = o.keys()
        has.sort()
        want = [b"foo", b"bar"]
        want.sort()
        assert has == want
        assert o["foo"] == [b"a"]
        assert o["bar"] == [b"b", b"c"]

    async def testFetch_Partial(self) -> None:
        """Fetching only some of the attributes does not overwrite existing values of different attribute types."""
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=foo,dc=example,dc=com",
                    attributes=(
                        (b"foo", [b"a"]),
                        (b"bar", [b"b", b"c"]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={b"foo": [b"x"], b"quux": [b"baz", b"xyzzy"]},
        )


        await o.fetch(b"foo", b"bar", b"thud")
        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="cn=foo,dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_baseObject,
                attributes=(b"foo", b"bar", b"thud"),
            )
        )

        has = o.keys()
        has.sort()
        want = [b"foo", b"bar", b"quux"]
        want.sort()
        assert has == want
        assert o[b"foo"] == [b"a"]
        assert o[b"bar"] == [b"b", b"c"]
        assert o[b"quux"] == [b"baz", b"xyzzy"]

    async def testCommitAndFetch(self) -> None:
        """Fetching after a commit works."""

        client = LDAPClientTestDriver(
            [pureldap.LDAPModifyResponse(resultCode=0, matchedDN="", errorMessage="")],
            [
                pureldap.LDAPSearchResultEntry(
                    "cn=foo,dc=example,dc=com",
                    [("aValue", ["foo", "bar"])],
                ),
                pureldap.LDAPSearchResultDone(resultCode=0),
            ],
        )
        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
            },
        )

        o["aValue"] = ["foo", "bar"]
        assert await o.commit() is o
        assert await o.fetch("aValue") is o
        client.assertSent(
            delta.ModifyOp(
                "cn=foo,dc=example,dc=com",
                [
                    delta.Replace("aValue", ["foo", "bar"]),
                ],
            ).asLDAP(),
            pureldap.LDAPSearchRequest(
                baseObject="cn=foo,dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_baseObject,
                attributes=["aValue"],
            ),
        )


class TestLDAPSyntaxRDNHandling:
    def testRemovingRDNFails(self) -> None:
        """Removing RDN fails with CannotRemoveRDNError."""
        o = ldapsyntax.LDAPEntry(
            client=None,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["someObjectClass"],
                "cn": ["foo", "bar", "baz"],
                "a": ["aValue"],
            },
        )
        o["cn"].remove("bar")
        del o["a"]
        with pytest.raises(ldapsyntax.CannotRemoveRDNError, match=re.escape(
                "The attribute to be removed, 'cn'='foo', "
                "is the RDN for the object and cannot be removed."
            )):
            o["cn"].remove("foo")

        def f() -> None:
            del o["cn"]

        with pytest.raises(ldapsyntax.CannotRemoveRDNError, match=re.escape(
                "The attribute to be removed, 'cn', "
                "is the RDN for the object and cannot be removed."
            )):
            f()

        def f() -> None:
            o["cn"] = ["thud"]

        with pytest.raises(ldapsyntax.CannotRemoveRDNError, match=re.escape(
                "The attribute to be removed, 'cn', "
                "is the RDN for the object and cannot be removed."
            )):
            f()

        # TODO maybe this should be ok, it preserves the RDN.
        # For now, disallow it.
        def f() -> None:
            o["cn"] = ["foo"]

        with pytest.raises(ldapsyntax.CannotRemoveRDNError, match=re.escape(
                "The attribute to be removed, 'cn', "
                "is the RDN for the object and cannot be removed."
            )):
            f()


class TestLDAPSyntaxMove:
    async def test_move(self) -> None:
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPModifyDNResponse(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ]
        )

        o = ldapsyntax.LDAPEntry(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "cn": ["foo"],
                "aValue": ["a"],
            },
        )


        await o.move("cn=bar,ou=somewhere,dc=example,dc=com")
        client.assertSent(
            pureldap.LDAPModifyDNRequest(
                entry="cn=foo,dc=example,dc=com",
                newrdn="cn=bar",
                deleteoldrdn=1,
                newSuperior="ou=somewhere,dc=example,dc=com",
            )
        )

        assert o.dn == "cn=bar,ou=somewhere,dc=example,dc=com"


class TestBind:
    async def test_ok(self) -> None:
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPBindResponse(resultCode=0, matchedDN=""),
            ]
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")
        assert await o.bind("s3krit") is o
        client.assertSent(
            pureldap.LDAPBindRequest(dn="cn=foo,dc=example,dc=com", auth="s3krit")
        )

    async def test_fail(self) -> None:
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPInvalidCredentials.resultCode,
                    matchedDN="",
                ),
            ]
        )

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        with pytest.raises(ldaperrors.LDAPInvalidCredentials):
            await o.bind("s3krit")

    async def test_err(self) -> None:
        client = LDAPClientTestDriver([Failure(ConnectionLost())])

        o = ldapsyntax.LDAPEntry(client=client, dn="cn=foo,dc=example,dc=com")


        with pytest.raises(ConnectionLost):
            await o.bind("whatever")
