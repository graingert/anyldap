"""
Test cases for anyldap.protocols.ldap.ldapfilter module.
"""
import subprocess
import sys

import pytest

from anyldap import ldapfilter
from anyldap.protocols import pureldap


def test_filter_errors_and_legacy_extensible_parser():
    error = ldapfilter.InvalidLDAPFilter("bad", 2, "text")
    assert str(error) == "Invalid LDAP filter: bad at point 2 in 'text'"
    with pytest.raises(NotImplementedError):
        ldapfilter.parseExtensible("cn", "value")
    with pytest.raises(ldapfilter.InvalidLDAPFilter):
        ldapfilter.parseMaybeSubstring("cn", "\\")


def test_filter_module_entrypoint():
    result = subprocess.run(
        [sys.executable, "-m", ldapfilter.__name__, "(cn=alice)"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "LDAPFilter_equalityMatch" in result.stdout


class TestRFC2254Examples:
    def test_cn(self):
        text = "(cn=Babs Jensen)"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
            assertionValue=pureldap.LDAPAssertionValue(value="Babs Jensen"),
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_not_cn(self):
        text = "(!(cn=Tim Howes))"
        filt = pureldap.LDAPFilter_not(
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
                assertionValue=pureldap.LDAPAssertionValue(value="Tim Howes"),
            )
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_and_or(self):
        text = "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))"
        filt = pureldap.LDAPFilter_and(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(
                        value="objectClass"
                    ),
                    assertionValue=pureldap.LDAPAssertionValue(value="Person"),
                ),
                pureldap.LDAPFilter_or(
                    [
                        pureldap.LDAPFilter_equalityMatch(
                            attributeDesc=pureldap.LDAPAttributeDescription(value="sn"),
                            assertionValue=pureldap.LDAPAssertionValue(value="Jensen"),
                        ),
                        pureldap.LDAPFilter_substrings(
                            type="cn",
                            substrings=[
                                pureldap.LDAPFilter_substrings_initial(value="Babs J")
                            ],
                        ),
                    ]
                ),
            ]
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_substrings(self):
        text = "(o=univ*of*mich*)"
        filt = pureldap.LDAPFilter_substrings(
            type="o",
            substrings=[
                pureldap.LDAPFilter_substrings_initial(value="univ"),
                pureldap.LDAPFilter_substrings_any(value="of"),
                pureldap.LDAPFilter_substrings_any(value="mich"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_extensible_1(self):
        text = "(cn:1.2.3.4.5:=Fred Flintstone)"
        filt = pureldap.LDAPFilter_extensibleMatch(
            type="cn",
            dnAttributes=False,
            matchingRule="1.2.3.4.5",
            matchValue="Fred Flintstone",
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_extensible_2(self):
        text = "(sn:dn:2.4.6.8.10:=Barney Rubble)"
        filt = pureldap.LDAPFilter_extensibleMatch(
            type="sn",
            dnAttributes=True,
            matchingRule="2.4.6.8.10",
            matchValue="Barney Rubble",
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_extensible_3(self):
        text = "(o:dn:=Ace Industry)"
        filt = pureldap.LDAPFilter_extensibleMatch(
            type="o",
            dnAttributes=True,
            matchingRule=None,
            matchValue="Ace Industry",
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_extensible_4(self):
        text = "(:dn:2.4.6.8.10:=Dino)"
        filt = pureldap.LDAPFilter_extensibleMatch(
            type=None,
            dnAttributes=True,
            matchingRule="2.4.6.8.10",
            matchValue="Dino",
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_extensible_5(self):
        text = "(cn:1.2.3.4.5:=Fred Flintstone)"
        filt = pureldap.LDAPFilter_extensibleMatch(
            type="cn",
            dnAttributes=None,
            matchingRule="1.2.3.4.5",
            matchValue="Fred Flintstone",
        )
        assert filt.asText() == text

    def test_escape_parens(self):
        text = r"(o=Parens R Us \28for all your parenthetical needs\29)"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="o"),
            assertionValue=pureldap.LDAPAssertionValue(
                value="Parens R Us (for all your parenthetical needs)"
            ),
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_escape_asterisk(self):
        text = r"(cn=*\2A*)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any(value="*"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text.lower()

    def test_escape_backslash(self):
        text = r"(filename=C:\5cMyFile)"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="filename"),
            assertionValue=pureldap.LDAPAssertionValue(value=r"C:\MyFile"),
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_escape_binary(self):
        text = r"(bin=\00\00\00\04)"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="bin"),
            assertionValue=pureldap.LDAPAssertionValue(value="\00\00\00\04"),
        )
        assert ldapfilter.parseFilter(text) == filt

    def test_escape_utf8(self):
        text = r"(sn=Lu\c4\8di\c4\87)"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="sn"),
            assertionValue=pureldap.LDAPAssertionValue(value="Lu\xc4\x8di\xc4\x87"),
        )
        assert ldapfilter.parseFilter(text) == filt
        # self.assertEqual(filt.asText(), text)


class TestValid:
    def test_item_present(self):
        text = r"(cn=*)"
        filt = pureldap.LDAPFilter_present(value="cn")
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_simple(self):
        text = r"(cn=foo)"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
            assertionValue=pureldap.LDAPAssertionValue(value="foo"),
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_init(self):
        text = r"(cn=foo*)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_final(self):
        text = r"(cn=*foo)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_final("foo"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_any(self):
        text = r"(cn=*foo*)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any("foo"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_aa(self):
        text = r"(cn=*foo*bar*)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_ia(self):
        text = r"(cn=foo*bar*)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_iaa(self):
        text = r"(cn=foo*bar*baz*)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
                pureldap.LDAPFilter_substrings_any("baz"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_if(self):
        text = r"(cn=foo*bar)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_final("bar"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_iaf(self):
        text = r"(cn=foo*bar*baz)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
                pureldap.LDAPFilter_substrings_final("baz"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_iaaf(self):
        text = r"(cn=foo*bar*baz*quux)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
                pureldap.LDAPFilter_substrings_any("baz"),
                pureldap.LDAPFilter_substrings_final("quux"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_af(self):
        text = r"(cn=*foo*bar)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any("foo"),
                pureldap.LDAPFilter_substrings_final("bar"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_item_substring_aaf(self):
        text = r"(cn=*foo*bar*baz)"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
                pureldap.LDAPFilter_substrings_final("baz"),
            ],
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_not_item(self):
        text = r"(!(cn=foo))"
        filt = pureldap.LDAPFilter_not(
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
                assertionValue=pureldap.LDAPAssertionValue(value="foo"),
            )
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_or_item(self):
        text = r"(|(cn=foo)(cn=bar))"
        filt = pureldap.LDAPFilter_or(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
                    assertionValue=pureldap.LDAPAssertionValue(value="foo"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
                    assertionValue=pureldap.LDAPAssertionValue(value="bar"),
                ),
            ]
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_and_item(self):
        text = r"(&(cn=foo)(cn=bar))"
        filt = pureldap.LDAPFilter_and(
            [
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
                    assertionValue=pureldap.LDAPAssertionValue(value="foo"),
                ),
                pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
                    assertionValue=pureldap.LDAPAssertionValue(value="bar"),
                ),
            ]
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_andornot(self):
        text = r"(&(!(|(cn=foo)(cn=bar)))(sn=a*b*c*d))"
        filt = pureldap.LDAPFilter_and(
            [
                pureldap.LDAPFilter_not(
                    pureldap.LDAPFilter_or(
                        [
                            pureldap.LDAPFilter_equalityMatch(
                                attributeDesc=pureldap.LDAPAttributeDescription(
                                    value="cn"
                                ),
                                assertionValue=pureldap.LDAPAssertionValue(value="foo"),
                            ),
                            pureldap.LDAPFilter_equalityMatch(
                                attributeDesc=pureldap.LDAPAttributeDescription(
                                    value="cn"
                                ),
                                assertionValue=pureldap.LDAPAssertionValue(value="bar"),
                            ),
                        ]
                    )
                ),
                pureldap.LDAPFilter_substrings(
                    type="sn",
                    substrings=[
                        pureldap.LDAPFilter_substrings_initial("a"),
                        pureldap.LDAPFilter_substrings_any("b"),
                        pureldap.LDAPFilter_substrings_any("c"),
                        pureldap.LDAPFilter_substrings_final("d"),
                    ],
                ),
            ]
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_whitespace_beforeCloseParen(self):
        text = r"(cn=foo )"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
            assertionValue=pureldap.LDAPAssertionValue(value="foo "),
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text

    def test_whitespace_afterEq(self):
        text = r"(cn= foo)"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
            assertionValue=pureldap.LDAPAssertionValue(value=" foo"),
        )
        assert ldapfilter.parseFilter(text) == filt
        assert filt.asText() == text


class TestInvalid:
    def test_closeParen_1(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter("(&(|(mail=)@*)(uid=)))(mail=*))")

    def test_closeParen_2(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter("(|(mail=)@*)(uid=)))")

    def test_closeParen_3(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter("(mail=)@*)")

    def test_closeParen_4(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter("(uid=))")

    def test_openParen_1(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter("(&(|(mail=(@*)(uid=())(mail=*))")

    def test_openParen_2(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter("(|(mail=(@*)(uid=())")

    def test_openParen_3(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter("(mail=(@*)")

    def test_openParen_4(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter("(uid=()")

    def test_whitespace_leading(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter(r" (cn=foo)")

    def test_whitespace_trailing(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter(r"(cn=foo) ")

    def test_whitespace_afterOpenParen(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter(r"( cn=foo)")

    def test_whitespace_beforeEq(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter(r"(cn =foo)")


class TestMaybeSubstring:
    def test_item_present(self):
        text = r"*"
        filt = pureldap.LDAPFilter_present(value="cn")
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_simple(self):
        text = r"foo"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
            assertionValue=pureldap.LDAPAssertionValue(value="foo"),
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_init(self):
        text = r"foo*"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_final(self):
        text = r"*foo"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_final("foo"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_any(self):
        text = r"*foo*"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any("foo"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_aa(self):
        text = r"*foo*bar*"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_ia(self):
        text = r"foo*bar*"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_iaa(self):
        text = r"foo*bar*baz*"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
                pureldap.LDAPFilter_substrings_any("baz"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_if(self):
        text = r"foo*bar"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_final("bar"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_iaf(self):
        text = r"foo*bar*baz"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
                pureldap.LDAPFilter_substrings_final("baz"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_iaaf(self):
        text = r"foo*bar*baz*quux"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_initial("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
                pureldap.LDAPFilter_substrings_any("baz"),
                pureldap.LDAPFilter_substrings_final("quux"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_af(self):
        text = r"*foo*bar"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any("foo"),
                pureldap.LDAPFilter_substrings_final("bar"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_item_substring_aaf(self):
        text = r"*foo*bar*baz"
        filt = pureldap.LDAPFilter_substrings(
            type="cn",
            substrings=[
                pureldap.LDAPFilter_substrings_any("foo"),
                pureldap.LDAPFilter_substrings_any("bar"),
                pureldap.LDAPFilter_substrings_final("baz"),
            ],
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt

    def test_escape_simple(self):
        text = r"f\2aoo(bar"
        filt = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value="cn"),
            assertionValue=pureldap.LDAPAssertionValue(value="f*oo(bar"),
        )
        assert ldapfilter.parseMaybeSubstring("cn", text) == filt


class TestWhitespace:
    def test_escape(self):
        with pytest.raises(ldapfilter.InvalidLDAPFilter):
            ldapfilter.parseFilter(r"(cn=\ 61)")
