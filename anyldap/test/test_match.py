"""
Test cases for anyldap.protocols.ldap.ldapserver module.
"""
import re

import attr
import pytest

from anyldap import entryhelpers, inmemory
from anyldap.protocols import pureber, pureldap
from anyldap.protocols.ldap import ldaperrors, ldapsyntax

pytestmark = pytest.mark.anyio


class TestEntryMatch:
    def test_safelower_preserves_values_without_lower(self) -> None:
        marker = object()
        assert entryhelpers.safelower(marker) is marker

    def test_safelower_folds_values_with_lower(self) -> None:
        assert entryhelpers.safelower("Foo") == "foo"
        assert entryhelpers.safelower(b"Foo") == b"foo"

    def test_matchAll(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(pureldap.LDAPFilterMatchAll)
        assert result is True

    def test_present_match(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(pureldap.LDAPFilter_present("aValue"))
        assert result is True

    def test_present_noMatch(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(pureldap.LDAPFilter_present("noSuchValue"))
        assert result is False

    def test_and_match(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_and(
                [
                    pureldap.LDAPFilter_present("aValue"),
                    pureldap.LDAPFilter_present("bValue"),
                ]
            )
        )
        assert result is True

    def test_and_noMatch(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_and(
                [
                    pureldap.LDAPFilter_present("cValue"),
                    pureldap.LDAPFilter_present("dValue"),
                ]
            )
        )
        assert result is False

    def test_or_match(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_or(
                [
                    pureldap.LDAPFilter_present("cValue"),
                    pureldap.LDAPFilter_present("bValue"),
                ]
            )
        )
        assert result is True

    def test_or_noMatch(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_or(
                [
                    pureldap.LDAPFilter_present("cValue"),
                    pureldap.LDAPFilter_present("dValue"),
                ]
            )
        )
        assert result is False

    def test_not(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_not(
                pureldap.LDAPFilter_or(
                    [
                        pureldap.LDAPFilter_present("cValue"),
                        pureldap.LDAPFilter_present("dValue"),
                    ]
                )
            )
        )
        assert result is True

    def test_equality_match(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureber.BEROctetString("aValue"),
                assertionValue=pureber.BEROctetString("a"),
            )
        )
        assert result is True

    def test_equality_match_caseInsensitive(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureber.BEROctetString("avaLUe"),
                assertionValue=pureber.BEROctetString("A"),
            )
        )
        assert result is True

    def test_equality_noMatch(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureber.BEROctetString("aValue"),
                assertionValue=pureber.BEROctetString("b"),
            )
        )
        assert result is False

    def test_substrings_match(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                ],
            )
        )
        assert result is True

    def test_substrings_match2(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["abcde"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        assert result is True

    def test_substrings_match3(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["abcde"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_any("c"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        assert result is True

    def test_substrings_match4(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["abcde"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_any("b"),
                    pureldap.LDAPFilter_substrings_any("c"),
                    pureldap.LDAPFilter_substrings_any("d"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        assert result is True

    def test_substrings_match5(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["aoeuboeucoeudoeue"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_any("b"),
                    pureldap.LDAPFilter_substrings_any("c"),
                    pureldap.LDAPFilter_substrings_any("d"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        assert result is True

    def test_substrings_match6(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["aBCdE"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("A"),
                    pureldap.LDAPFilter_substrings_any("b"),
                    pureldap.LDAPFilter_substrings_any("C"),
                    pureldap.LDAPFilter_substrings_any("D"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        assert result is True

    def test_substrings_match7(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["Foo"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("f"),
                ],
            )
        )
        assert result is True

    def test_substrings_noMatch(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["a"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("bad"),
                    pureldap.LDAPFilter_substrings_any("dog"),
                    pureldap.LDAPFilter_substrings_any("no"),
                    pureldap.LDAPFilter_substrings_final("bone"),
                ],
            )
        )
        assert result is False

    def test_substrings_noMatch2(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["aoeuboeucoeudoeue"],
                "bValue": ["b"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_substrings(
                type="aValue",
                substrings=[
                    pureldap.LDAPFilter_substrings_initial("a"),
                    pureldap.LDAPFilter_substrings_any("b"),
                    pureldap.LDAPFilter_substrings_any("Z"),
                    pureldap.LDAPFilter_substrings_any("d"),
                    pureldap.LDAPFilter_substrings_final("e"),
                ],
            )
        )
        assert result is False

    def test_greaterOrEqual_noMatch_nosuchattr(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_greaterOrEqual(
                pureber.BEROctetString("foo"), pureber.BEROctetString("42")
            )
        )
        assert result is False

    def test_greaterOrEqual_match_greater(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_greaterOrEqual(
                pureber.BEROctetString("num"), pureber.BEROctetString("3")
            )
        )
        assert result is True

    def test_greaterOrEqual_match_equal(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_greaterOrEqual(
                pureber.BEROctetString("num"), pureber.BEROctetString("4")
            )
        )
        assert result is True

    def test_greaterOrEqual_noMatch(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "bValue": ["4"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_greaterOrEqual(
                pureber.BEROctetString("num"), pureber.BEROctetString("5")
            )
        )
        assert result is False

    def test_lessOrEqual_noMatch_nosuchattr(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_lessOrEqual(
                pureber.BEROctetString("foo"), pureber.BEROctetString("42")
            )
        )
        assert result is False

    def test_lessOrEqual_match_less(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_lessOrEqual(
                pureber.BEROctetString("num"), pureber.BEROctetString("5")
            )
        )
        assert result is True

    def test_lessOrEqual_match_equal(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_lessOrEqual(
                pureber.BEROctetString("num"), pureber.BEROctetString("4")
            )
        )
        assert result is True

    def test_lessOrEqual_noMatch(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )
        result = o.match(
            pureldap.LDAPFilter_lessOrEqual(
                pureber.BEROctetString("num"), pureber.BEROctetString("3")
            )
        )
        assert result is False

    def test_extensibleMatch4(self) -> None:
        """
        An extensibleMatch filter that uses DN attributes matches an entry
        based on its OU.
        See RFC4511 section 4.5.1.
        """
        m = pureldap.LDAPFilter_extensibleMatch(
            matchingRule=None,
            type=pureldap.LDAPMatchingRuleAssertion_type(value="ou"),
            matchValue=pureldap.LDAPMatchingRuleAssertion_matchValue(value="fings"),
            dnAttributes=pureldap.LDAPMatchingRuleAssertion_dnAttributes(value=255),
        )
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,ou=fings,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )
        result = o.match(m)
        assert result is True

    def test_extensibleMatch4_noMatch(self) -> None:
        """
        An extensibleMatch filter that uses DN attributes does not match an entry
        based on its OU.
        See RFC4511 section 4.5.1.
        """
        m = pureldap.LDAPFilter_extensibleMatch(
            matchingRule=None,
            type=pureldap.LDAPMatchingRuleAssertion_type(value="ou"),
            matchValue=pureldap.LDAPMatchingRuleAssertion_matchValue(value="fings"),
            dnAttributes=pureldap.LDAPMatchingRuleAssertion_dnAttributes(value=255),
        )
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,ou=uvvers,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )
        result = o.match(m)
        assert result is False

    def test_notImplemented(self) -> None:
        o = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["a", "b"],
                "aValue": ["b"],
                "num": ["4"],
            },
        )

        @attr.s
        class UnknownMatch:
            pass

        unknownMatch = UnknownMatch()
        with pytest.raises(ldapsyntax.MatchNotImplemented, match=re.escape("Match type not implemented: UnknownMatch()")):
            # Not a filter at all, which is what the entry refuses to match.
            o.match(unknownMatch)  # type: ignore[arg-type]

    def test_substring_attribute_absent(self) -> None:
        entry = inmemory.ReadOnlyInMemoryLDAPEntry("cn=foo", {"cn": ["foo"]})
        filter_object = pureldap.LDAPFilter_substrings(
            type="missing", substrings=[pureldap.LDAPFilter_substrings_any("x")]
        )
        assert not (entry.match(filter_object))

    def test_substring_without_initial_component(self) -> None:
        entry = inmemory.ReadOnlyInMemoryLDAPEntry(
            "cn=foo", {"cn": ["prefix-middle-suffix"]}
        )
        filter_object = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any("middle"),
                pureldap.LDAPFilter_substrings_final("suffix"),
            ],
        )
        assert entry.match(filter_object)

    def test_greater_or_equal_checks_multiple_values_without_match(self) -> None:
        entry = inmemory.ReadOnlyInMemoryLDAPEntry("cn=foo", {"rank": ["1", "2"]})
        filter_object = pureldap.LDAPFilter_greaterOrEqual(
            attributeDesc=pureldap.LDAPAttributeDescription("rank"),
            assertionValue=pureldap.LDAPAssertionValue("3"),
        )
        assert not (entry.match(filter_object))

    def test_extensible_match_uses_entry_attribute(self) -> None:
        entry = inmemory.ReadOnlyInMemoryLDAPEntry("cn=foo", {"uid": ["Alice"]})
        filter_object = pureldap.LDAPFilter_extensibleMatch(
            type="uid", matchValue="alice"
        )
        assert entry.match(filter_object)

    def test_extensible_matching_rule_is_explicitly_unsupported(self) -> None:
        entry = inmemory.ReadOnlyInMemoryLDAPEntry("cn=foo", {"uid": ["Alice"]})
        filter_object = pureldap.LDAPFilter_extensibleMatch(
            matchingRule="caseIgnoreMatch", type="uid", matchValue="alice"
        )
        with pytest.raises(ldapsyntax.MatchNotImplemented):
            entry.match(filter_object)

    async def test_search_combines_text_and_object_filters(self) -> None:
        entry = inmemory.ReadOnlyInMemoryLDAPEntry("cn=foo", {"cn": ["foo"]})
        _result = await entry.search(
            filterText="(cn=foo)",
            filterObject=pureldap.LDAPFilter_present("cn"),
            scope=pureldap.LDAP_SCOPE_baseObject,
        )
        assert _result == [entry]

    async def test_search_accepts_object_filter_without_text(self) -> None:
        entry = inmemory.ReadOnlyInMemoryLDAPEntry("cn=foo", {"cn": ["foo"]})
        _result = await entry.search(
            filterObject=pureldap.LDAPFilter_present("cn"),
            scope=pureldap.LDAP_SCOPE_baseObject,
        )
        assert _result == [entry]

    async def test_search_rejects_unknown_scope(self) -> None:
        entry = inmemory.ReadOnlyInMemoryLDAPEntry("cn=foo", {"cn": ["foo"]})
        with pytest.raises(ldaperrors.LDAPProtocolError):
            await entry.search(scope=999)


# TODO LDAPFilter_approxMatch
# TODO LDAPFilter_extensibleMatch


def _from_the_wire(filt: pureber.BERBase) -> pureber.BERBase:
    """The filter as a server receives it, rather than as it was built."""
    request = pureldap.LDAPSearchRequest(baseObject="dc=example,dc=com", filter=filt)
    decoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
            fallback=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext()
            ),
            inherit=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext()
            ),
        )
    )
    message, used = pureber.berDecodeObject(
        decoder, pureldap.LDAPMessage(request, id=1).toWire()
    )
    assert used == len(pureldap.LDAPMessage(request, id=1).toWire())
    assert isinstance(message, pureldap.LDAPMessage)
    assert isinstance(message.value, pureldap.LDAPSearchRequest)
    return message.value.filter


_KEY = pureldap.LDAPAttributeDescription("cn")
_VALUE = pureldap.LDAPAssertionValue("alice")


@pytest.mark.parametrize(
    "filt",
    [
        pureldap.LDAPFilter_present("cn"),
        pureldap.LDAPFilter_equalityMatch(attributeDesc=_KEY, assertionValue=_VALUE),
        pureldap.LDAPFilter_greaterOrEqual(attributeDesc=_KEY, assertionValue=_VALUE),
        pureldap.LDAPFilter_lessOrEqual(attributeDesc=_KEY, assertionValue=_VALUE),
        pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("al"),
                pureldap.LDAPFilter_substrings_any("ic"),
                pureldap.LDAPFilter_substrings_final("e"),
            ],
        ),
        pureldap.LDAPFilter_extensibleMatch(
            matchingRule=None, type="cn", matchValue="alice"
        ),
    ],
    ids=lambda f: type(f).__name__,
)
def test_match_survives_the_wire(filt: pureber.BERBase) -> None:
    """An entry matches a filter the same whether it was built or decoded.

    A filter off the wire holds its values as bytes while an entry loaded
    from LDIF holds text, and matching used to compare the two directly:
    substring and ordering filters raised TypeError, which is what a real
    client's (cn=al*) reached on the server's search path.
    """
    o = inmemory.ReadOnlyInMemoryLDAPEntry(
        dn="cn=alice,dc=example,dc=com",
        attributes={"objectClass": ["person"], "cn": ["alice"]},
    )

    assert o.match(filt) is True
    assert o.match(_from_the_wire(filt)) is True
