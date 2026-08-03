"""
Test cases for anyldap.protocols.ldap.distinguishedname module.
"""

import pytest

from anyldap.protocols.ldap import distinguishedname as dn


def test_attribute_value_and_rdn_comparison_edges() -> None:
    first = dn.LDAPAttributeTypeAndValue(attributeType="cn", value="a")
    second = dn.LDAPAttributeTypeAndValue(attributeType="cn", value="b")
    other_type = dn.LDAPAttributeTypeAndValue(attributeType="sn", value="a")
    assert first.__eq__(object()) is NotImplemented
    assert first != second
    assert not first.__lt__(object())
    assert first < second
    assert other_type > first
    assert first <= second
    assert second >= first

    first_rdn = dn.RelativeDistinguishedName([first])
    second_rdn = dn.RelativeDistinguishedName([second])
    assert first_rdn.__eq__(object()) is NotImplemented
    assert first_rdn != second_rdn
    assert not first_rdn.__lt__(object())
    assert first_rdn < second_rdn
    assert second_rdn > first_rdn
    assert first_rdn <= second_rdn
    assert second_rdn >= first_rdn


def test_distinguished_name_comparison_and_domain_edges() -> None:
    value = dn.DistinguishedName("dc=example,dc=com")
    assert value.__eq__(object()) is NotImplemented
    assert value.__lt__(object()) is NotImplemented
    assert value != object()
    assert dn.DistinguishedName("cn=user,dc=example,dc=com").getDomainName() == (
        "example.com"
    )
    assert dn.DistinguishedName("cn=user").getDomainName() is None
    assert dn.DistinguishedName("cn=user+uid=1,dc=example").getDomainName() == "example"
    assert value.contains("cn=user,dc=example,dc=com")


class KnownValuesBase:
    knownValues = ()

    def testKnownValues(self) -> None:
        for s, l in self.knownValues:
            fromString = dn.DistinguishedName(s)
            listOfRDNs = []
            for av in l:
                listOfAttributeTypesAndValues = []
                for a, v in av:
                    listOfAttributeTypesAndValues.append(
                        dn.LDAPAttributeTypeAndValue(attributeType=a, value=v)
                    )
                r = dn.RelativeDistinguishedName(listOfAttributeTypesAndValues)
                listOfRDNs.append(r)
            fromList = dn.DistinguishedName(listOfRDNs)

            assert fromString == fromList

            fromStringToText = fromString.getText()
            fromListToText = fromList.getText()

            assert fromStringToText == fromListToText

            canon = fromStringToText
            # DNs equal their byte string representation. Note this does
            # not mean they equal all the possible string
            # representations -- just the canonical one.
            assert fromString == canon
            assert fromList == canon
            assert canon == fromString
            assert canon == fromList

            # DNs can be used interchangeably with their canonical
            # string representation as hash keys.
            assert hash(fromString) == hash(canon)
            assert hash(fromList) == hash(canon)
            assert hash(canon) == hash(fromString)
            assert hash(canon) == hash(fromList)


class TestLDAPDistinguishedName_Escaping(KnownValuesBase):
    knownValues = (
        ("", []),
        ("cn=foo", [[("cn", "foo")]]),
        (r"cn=\,bar", [[("cn", r",bar")]]),
        (r"cn=foo\,bar", [[("cn", r"foo,bar")]]),
        (r"cn=foo\,", [[("cn", r"foo,")]]),
        (r"cn=\+bar", [[("cn", r"+bar")]]),
        (r"cn=foo\+bar", [[("cn", r"foo+bar")]]),
        (r"cn=foo\+", [[("cn", r"foo+")]]),
        (r"cn=\"bar", [[("cn", r'"bar')]]),
        (r"cn=foo\"bar", [[("cn", r'foo"bar')]]),
        (r"cn=foo\"", [[("cn", r'foo"')]]),
        (r"cn=\\bar", [[("cn", r"\bar")]]),
        (r"cn=foo\\bar", [[("cn", r"foo\bar")]]),
        (r"cn=foo\\", [[("cn", "foo\\")]]),
        (r"cn=\<bar", [[("cn", r"<bar")]]),
        (r"cn=foo\<bar", [[("cn", r"foo<bar")]]),
        (r"cn=foo\<", [[("cn", r"foo<")]]),
        (r"cn=\>bar", [[("cn", r">bar")]]),
        (r"cn=foo\>bar", [[("cn", r"foo>bar")]]),
        (r"cn=foo\>", [[("cn", r"foo>")]]),
        (r"cn=\;bar", [[("cn", r";bar")]]),
        (r"cn=foo\;bar", [[("cn", r"foo;bar")]]),
        (r"cn=foo\;", [[("cn", r"foo;")]]),
        (r"cn=\#bar", [[("cn", r"#bar")]]),
        (r"cn=\ bar", [[("cn", r" bar")]]),
        (r"cn=bar\ ", [[("cn", r"bar ")]]),
        (
            r"cn=test+owner=uid\=foo\,ou\=depar"
            + r"tment\,dc\=example\,dc\=com,dc=ex"
            + r"ample,dc=com",
            [
                [
                    ("cn", r"test"),
                    ("owner", r"uid=foo,ou=depart" + r"ment,dc=example,dc=com"),
                ],
                [("dc", r"example")],
                [("dc", r"com")],
            ],
        ),
        (
            r"cn=bar,dc=example,dc=com",
            [[("cn", "bar")], [("dc", "example")], [("dc", "com")]],
        ),
        (
            r"cn=bar, dc=example, dc=com",
            [[("cn", "bar")], [("dc", "example")], [("dc", "com")]],
        ),
        (
            r"cn=bar,  dc=example,dc=com",
            [[("cn", "bar")], [("dc", "example")], [("dc", "com")]],
        ),
    )

    def testOpenLDAPEqualsEscape(self) -> None:
        """Slapd wants = to be escaped in RDN attributeValues."""
        got = dn.DistinguishedName(
            listOfRDNs=[
                dn.RelativeDistinguishedName(
                    attributeTypesAndValues=[
                        dn.LDAPAttributeTypeAndValue(attributeType="cn", value=r"test"),
                        dn.LDAPAttributeTypeAndValue(
                            attributeType="owner",
                            value=r"uid=foo,ou=depart" + r"ment,dc=example,dc=com",
                        ),
                    ]
                ),
                dn.RelativeDistinguishedName("dc=example"),
                dn.RelativeDistinguishedName("dc=com"),
            ]
        )
        got = got.getText()
        assert got == (r"cn=test+owner=uid\=foo\,ou\=depar"
            + r"tment\,dc\=example\,dc\=com,dc=ex"
            + "ample,dc=com")


class TestLDAPDistinguishedName_RFC2253_ExamplesBytes(KnownValuesBase):
    """
    It can be initialized from text/Unicode input as long as they contain
    ASCII only characters.
    """

    knownValues = (
        (
            "CN=Steve Kille,O=Isode Limited,C=GB",
            [[("CN", "Steve Kille")], [("O", "Isode Limited")], [("C", "GB")]],
        ),
        (
            "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US",
            [
                [("OU", "Sales"), ("CN", "J. Smith")],
                [("O", "Widget Inc.")],
                [("C", "US")],
            ],
        ),
        (
            r"CN=L. Eagle,O=Sue\, Grabbit and Runn,C=GB",
            [[("CN", "L. Eagle")], [("O", "Sue, Grabbit and Runn")], [("C", "GB")]],
        ),
        (
            r"CN=Before\0DAfter,O=Test,C=GB",
            [[("CN", "Before\x0dAfter")], [("O", "Test")], [("C", "GB")]],
        ),
        (
            r"1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB",
            [[("1.3.6.1.4.1.1466.0", "#04024869")], [("O", "Test")], [("C", "GB")]],
        ),
    )


class TestLDAPDistinguishedName_UTF8_Init(KnownValuesBase):
    """
    It can be initialized from an UTF-8 encoded data and it will
    keep the representation as UTF-8.
    """

    knownValues = (
        ("SN=Lu\u010di\u0107".encode(), [[(b"SN", "Lu\u010di\u0107".encode())]]),
    )


class TestLDAPDistinguishedName_InitialSpaces(KnownValuesBase):
    """
    The spaces which are not escapes are stripped.
    """

    knownValues = (
        (
            r"cn=foo, ou=bar,  dc=quux, \ attributeThatStartsWithSpace=Value",
            [
                [("cn", "foo")],
                [("ou", "bar")],
                [("dc", "quux")],
                [(" attributeThatStartsWithSpace", "Value")],
            ],
        ),
    )


class TestLDAPDistinguishedName_DomainName:
    def testNonDc(self) -> None:
        d = dn.DistinguishedName("cn=foo,o=bar,c=us")
        assert d.getDomainName() is None

    def testNonTrailingDc(self) -> None:
        d = dn.DistinguishedName("cn=foo,o=bar,dc=foo,c=us")
        assert d.getDomainName() is None

    def testSimple_ExampleCom(self) -> None:
        d = dn.DistinguishedName("dc=example,dc=com")
        assert d.getDomainName() == "example.com"

    def testSimple_SubExampleCom(self) -> None:
        d = dn.DistinguishedName("dc=sub,dc=example,dc=com")
        assert d.getDomainName() == "sub.example.com"

    def testSimple_HostSubExampleCom(self) -> None:
        d = dn.DistinguishedName("cn=host,dc=sub,dc=example,dc=com")
        assert d.getDomainName() == "sub.example.com"

    def testInterleaved_SubHostSubExampleCom(self) -> None:
        d = dn.DistinguishedName("dc=sub2,cn=host,dc=sub,dc=example,dc=com")
        assert d.getDomainName() == "sub.example.com"


class TestLDAPDistinguishedName_contains:
    shsec = dn.DistinguishedName("dc=sub2,cn=host,dc=sub,dc=example,dc=com")
    hsec = dn.DistinguishedName("cn=host,dc=sub,dc=example,dc=com")
    sec = dn.DistinguishedName("dc=sub,dc=example,dc=com")
    ec = dn.DistinguishedName("dc=example,dc=com")
    c = dn.DistinguishedName("dc=com")

    soc = dn.DistinguishedName("dc=sub,dc=other,dc=com")
    oc = dn.DistinguishedName("dc=other,dc=com")

    other = dn.DistinguishedName("o=foo,c=US")

    root = dn.DistinguishedName("")

    def test_selfContainment(self) -> None:
        assert self.c.contains(self.c)
        assert self.ec.contains(self.ec)
        assert self.sec.contains(self.sec)
        assert self.hsec.contains(self.hsec)
        assert self.shsec.contains(self.shsec)

        assert self.soc.contains(self.soc)
        assert self.oc.contains(self.oc)

        assert self.root.contains(self.root)

        assert self.other.contains(self.other)

    def test_realContainment(self) -> None:
        assert self.c.contains(self.ec)
        assert self.c.contains(self.sec)
        assert self.c.contains(self.hsec)
        assert self.c.contains(self.shsec)

        assert self.ec.contains(self.sec)
        assert self.ec.contains(self.hsec)
        assert self.ec.contains(self.shsec)

        assert self.sec.contains(self.hsec)
        assert self.sec.contains(self.shsec)

        assert self.hsec.contains(self.shsec)

        assert self.c.contains(self.oc)
        assert self.c.contains(self.soc)
        assert self.oc.contains(self.soc)

        for x in (
            self.shsec,
            self.hsec,
            self.sec,
            self.ec,
            self.c,
            self.soc,
            self.oc,
            self.other,
        ):
            assert self.root.contains(x)

    def test_nonContainment_parents(self) -> None:
        assert not self.shsec.contains(self.hsec)
        assert not self.shsec.contains(self.sec)
        assert not self.shsec.contains(self.ec)
        assert not self.shsec.contains(self.c)

        assert not self.hsec.contains(self.sec)
        assert not self.hsec.contains(self.ec)
        assert not self.hsec.contains(self.c)

        assert not self.sec.contains(self.ec)
        assert not self.sec.contains(self.c)

        assert not self.ec.contains(self.c)
        assert not self.soc.contains(self.oc)

        for x in (
            self.shsec,
            self.hsec,
            self.sec,
            self.ec,
            self.c,
            self.soc,
            self.oc,
            self.other,
        ):
            assert not x.contains(self.root)

    def test_nonContainment_nonParents(self) -> None:
        groups = (
            [self.shsec, self.hsec, self.sec, self.ec],
            [self.soc, self.oc],
            [self.other],
        )
        for g1 in groups:
            for g2 in groups:
                if g1 != g2:
                    for i1 in g1:
                        for i2 in g2:
                            assert not i1.contains(i2)
        assert not self.c.contains(self.other)
        assert not self.other.contains(self.c)


class TestLDAPDistinguishedName_Malformed:
    def testMalformed(self) -> None:
        with pytest.raises(dn.InvalidRelativeDistinguishedName):
            dn.DistinguishedName("foo")
        with pytest.raises(dn.InvalidRelativeDistinguishedName):
            dn.DistinguishedName("foo,dc=com")
        with pytest.raises(dn.InvalidRelativeDistinguishedName):
            dn.DistinguishedName("ou=something,foo")
        with pytest.raises(dn.InvalidRelativeDistinguishedName):
            dn.DistinguishedName("foo,foo")


class TestLDAPDistinguishedName_Prettify:
    def testPrettifySpaces(self) -> None:
        """DistinguishedName(...).getText() prettifies the DN by removing extra whitespace."""
        d = dn.DistinguishedName("cn=foo, o=bar,  c=us")
        assert d.getText() == "cn=foo,o=bar,c=us"


class TestDistinguishedName_Init:
    def testGetText(self) -> None:
        d = dn.DistinguishedName("dc=example,dc=com")
        assert d.getText() == "dc=example,dc=com"

    def testDN(self) -> None:
        proto = dn.DistinguishedName("dc=example,dc=com")
        d = dn.DistinguishedName(proto)
        assert d.getText() == "dc=example,dc=com"

    def testEqualToByteString(self) -> None:
        """
        DistinguishedName is equal to its bytes representation
        """
        d = dn.DistinguishedName("dc=example,dc=com")
        assert d == b"dc=example,dc=com"

    def testEqualToString(self) -> None:
        """
        DistinguishedName is equal to its unicode representation
        """
        d = dn.DistinguishedName("dc=example,dc=com")
        assert d == "dc=example,dc=com"


class TestRelativeDistinguishedName_Init:
    def testGetText(self) -> None:
        rdn = dn.RelativeDistinguishedName("dc=example")
        assert rdn.getText() == "dc=example"

    def testRDN(self) -> None:
        proto = dn.RelativeDistinguishedName("dc=example")
        rdn = dn.RelativeDistinguishedName(proto)
        assert rdn.getText() == "dc=example"


class TestDistinguishedName_Comparison:
    """
    Tests for comparing DistinguishedName.
    """

    def test_parent_child(self) -> None:
        """
        The parent is greater than the child.
        """
        dn1 = dn.DistinguishedName("dc=example,dc=com")
        dn2 = dn.DistinguishedName("dc=and,dc=example,dc=com")

        assert dn2 < dn1
        assert dn1 > dn2
