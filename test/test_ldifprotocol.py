"""
Test cases for anyldap.protocols.ldap.ldif module.
"""

import pytest

from anyldap import entry
from anyldap.protocols.ldap import distinguishedname, ldifprotocol


def test_base_parser_accepts_entry_hook() -> None:
    """The base parser's hook takes whatever it is handed and does nothing."""
    parser = ldifprotocol.LDIF()
    parser.gotEntry(object())


def test_line_receiver_is_abstract() -> None:
    """Splitting the stream into lines is all _LineReceiver does with it."""
    receiver = ldifprotocol._LineReceiver()
    with pytest.raises(NotImplementedError):
        receiver.dataReceived(b"a line\n")


class FixStringRepresentation:
    """
    A simple object which has a fix string representation.
    """

    def __str__(self) -> str:
        return "Here I am!"


class TestLDIFParseError:
    """
    Unit tests for LDIFParseError which is hte base for all the other
    LDIF errors.
    """

    def testInitNoArgs(self) -> None:
        """
        It can be initialized without arguments and will have the
        docstring as the string representation.
        """
        sut = ldifprotocol.LDIFParseError()

        result = str(sut)

        assert "Error parsing LDIF." == result

    def testInitWithArgs(self) -> None:
        """
        When initialized with arguments it will use the docstring as
        base and include all the arguments.
        """
        sut = ldifprotocol.LDIFParseError(1, "test", True, FixStringRepresentation())

        result = str(sut)

        assert "Error parsing LDIF: 1: test: True: Here I am!." == result


class LDIFDriver(ldifprotocol.LDIF):
    def __init__(self) -> None:
        super().__init__()
        self.listOfCompleted: list[entry.BaseLDAPEntry] = []

    def gotEntry(self, obj: object) -> None:
        assert isinstance(obj, entry.BaseLDAPEntry)
        self.listOfCompleted.append(obj)


class TestLDIFParsing:
    def testFromLDIF(self) -> None:
        proto = LDIFDriver()
        for line in (
            "dn: cn=foo,dc=example,dc=com",
            "objectClass: a",
            "objectClass: b",
            "aValue: a",
            "aValue: b",
            "bValue: c",
            "",
            "dn: cn=bar,dc=example,dc=com",
            "objectClass: c",
            "aValue:: IEZPTyE=",
            "aValue: b",
            "bValue: C",
            "",
        ):
            proto.lineReceived(line.encode("ascii"))

        assert len(proto.listOfCompleted) == 2

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=foo,dc=example,dc=com"
        assert o[b"objectClass"] == [b"a", b"b"]
        assert o[b"aValue"] == [b"a", b"b"]
        assert o[b"bValue"] == [b"c"]

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=bar,dc=example,dc=com"
        assert o[b"objectClass"] == [b"c"]
        assert o[b"aValue"] == [b" FOO!", b"b"]
        assert o[b"bValue"] == [b"C"]

        assert proto.listOfCompleted == []

    def testSplitLines(self) -> None:
        """
        Input can be split on multiple lines as long as the line starts with
        a space.
        """
        proto = LDIFDriver()
        for line in (
            "dn: cn=foo,dc=ex",
            " ample,dc=com",
            "objectClass: a",
            "ob",
            " jectClass: b",
            "",
        ):
            proto.lineReceived(line.encode("ascii"))

        assert len(proto.listOfCompleted) == 1

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=foo,dc=example,dc=com"
        assert o[b"objectClass"] == [b"a", b"b"]
        assert proto.listOfCompleted == []

    def testCaseInsensitiveDN(self) -> None:
        """
        DN is case insensitive.
        """
        proto = LDIFDriver()
        proto.dataReceived(
            b"""version: 1
dN: cn=foo, dc=example, dc=com
cn: foo

DN: cn=bar, dc=example, dc=com
cn: bar

"""
        )

        assert len(proto.listOfCompleted) == 2

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=foo,dc=example,dc=com"
        assert o[b"CN"] == [b"foo"]

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=bar,dc=example,dc=com"
        assert o[b"CN"] == [b"bar"]

        assert proto.listOfCompleted == []

    def testCaseInsensitiveAttributeTypes(self) -> None:
        """
        The attribute description (name/types) is case insensitive, while
        values are case sensitives.
        """
        proto = LDIFDriver()
        proto.dataReceived(
            b"""\
dn: cn=foo,dc=example,dc=com
objectClass: a
obJeCtClass: b
cn: foo
avalue: a
aValUe: B

"""
        )

        assert len(proto.listOfCompleted) == 1

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=foo,dc=example,dc=com"
        assert o[b"objectClass"] == [b"a", b"b"]
        assert o[b"CN"] == [b"foo"]
        assert o[b"aValue"] == [b"a", b"B"]

        assert proto.listOfCompleted == []

    def testVersion1(self) -> None:
        proto = LDIFDriver()
        proto.dataReceived(
            b"""\
version: 1
dn: cn=foo,dc=example,dc=com
objectClass: a
objectClass: b
aValue: a
aValue: b
bValue: c

"""
        )

        assert len(proto.listOfCompleted) == 1

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=foo,dc=example,dc=com"
        assert o[b"objectClass"] == [b"a", b"b"]
        assert o[b"aValue"] == [b"a", b"b"]
        assert o[b"bValue"] == [b"c"]

    def testVersionInvalid(self) -> None:
        proto = LDIFDriver()
        with pytest.raises(ldifprotocol.LDIFVersionNotANumberError):
            proto.dataReceived(b"""\
version: junk
dn: cn=foo,dc=example,dc=com
objectClass: a
objectClass: b
aValue: a
aValue: b
bValue: c

""")

    def testVersion2(self) -> None:
        proto = LDIFDriver()
        with pytest.raises(ldifprotocol.LDIFUnsupportedVersionError):
            proto.dataReceived(b"""\
version: 2
dn: cn=foo,dc=example,dc=com
objectClass: a
objectClass: b
aValue: a
aValue: b
bValue: c

""")

    def testNoSpaces(self) -> None:
        proto = LDIFDriver()
        proto.dataReceived(
            b"""\
dn:cn=foo,dc=example,dc=com
objectClass:a
obJeCtClass:b
cn:foo
avalue:a
aValUe:b

"""
        )

        assert len(proto.listOfCompleted) == 1

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=foo,dc=example,dc=com"
        assert o[b"objectClass"] == [b"a", b"b"]
        assert o[b"CN"] == [b"foo"]
        assert o[b"aValue"] == [b"a", b"b"]

        assert proto.listOfCompleted == []

    def testTruncatedFailure(self) -> None:
        proto = LDIFDriver()
        proto.dataReceived(
            b"""\
version: 1
dn: cn=foo,dc=example,dc=com
objectClass: a
objectClass: b
aValue: a
aValue: b
bValue: c
"""
        )

        assert len(proto.listOfCompleted) == 0

        with pytest.raises(ldifprotocol.LDIFTruncatedError):
            proto.connectionLost()

    def testComments(self) -> None:
        """
        Comments can be placed anywhere.
        """
        proto = LDIFDriver()
        proto.dataReceived(
            b"""# One comment here.
version: 1
# After comment.
dn: cn=foo, dc=example, dc=com
# Another one comment here.
cn: foo

# More comments
dn: cn=bar, dc=example, dc=com
cn: bar

"""
        )

        assert len(proto.listOfCompleted) == 2

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=foo,dc=example,dc=com"
        assert o[b"CN"] == [b"foo"]

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=bar,dc=example,dc=com"
        assert o[b"CN"] == [b"bar"]

        assert proto.listOfCompleted == []

    def testMoreEmptyLinesBetweenEntries(self) -> None:
        """
        It accept multiple lines between entries.
        """
        proto = LDIFDriver()
        proto.dataReceived(
            b"""version: 1
dn: cn=foo, dc=example, dc=com
cn: foo



dn: cn=bar, dc=example, dc=com
cn: bar

"""
        )

        assert len(proto.listOfCompleted) == 2

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=foo,dc=example,dc=com"
        assert o[b"CN"] == [b"foo"]

        o = proto.listOfCompleted.pop(0)
        assert o.dn.getText() == "cn=bar,dc=example,dc=com"
        assert o[b"CN"] == [b"bar"]

        assert proto.listOfCompleted == []

    def testStartWithSpace(self) -> None:
        """
        It fails to parse if a line start with a space but is not a
        continuation of a previous line.
        """
        proto = LDIFDriver()
        with pytest.raises(ldifprotocol.LDIFEntryStartsWithSpaceError):
            proto.dataReceived(
                b"""version: 1
dn: cn=foo, dc=example, dc=com
cn: foo

 dn: cn=bar, dc=example, dc=com
cn: bar

"""
            )

    def testEntryStartWithoutDN(self) -> None:
        """
        It fails to parse the entry does not start with DN.
        """
        proto = LDIFDriver()
        with pytest.raises(ldifprotocol.LDIFEntryStartsWithNonDNError):
            proto.dataReceived(
                b"""version: 1
cn: cn=foo, dc=example, dc=com
other: foo

"""
            )

    def testAttributeValueFromURL(self) -> None:
        """
        Getting attribute values from URL is not supported.
        """
        proto = LDIFDriver()
        with pytest.raises(NotImplementedError):
            proto.dataReceived(
                b"""version: 1
dn: cn=foo, dc=example, dc=com
cn:< file:///path/to/data 

"""
            )


class TestRFC2849_Examples:
    examples = [
        (
            b"""Example 1: An simple LDAP file with two entries""",
            b"""\
version: 1
dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Barbara Jensen
cn: Barbara J Jensen
cn: Babs Jensen
sn: Jensen
uid: bjensen
telephonenumber: +1 408 555 1212
description: A big sailing fan.

dn: cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Bjorn Jensen
sn: Jensen
telephonenumber: +1 408 555 1212

""",
            [
                (
                    b"cn=Barbara Jensen,ou=Product Development,dc=airius,dc=com",
                    {
                        b"objectClass": [b"top", b"person", b"organizationalPerson"],
                        b"cn": [b"Barbara Jensen", b"Barbara J Jensen", b"Babs Jensen"],
                        b"sn": [b"Jensen"],
                        b"uid": [b"bjensen"],
                        b"telephonenumber": [b"+1 408 555 1212"],
                        b"description": [b"A big sailing fan."],
                    },
                ),
                (
                    b"cn=Bjorn Jensen,ou=Accounting,dc=airius,dc=com",
                    {
                        b"objectClass": [b"top", b"person", b"organizationalPerson"],
                        b"cn": [b"Bjorn Jensen"],
                        b"sn": [b"Jensen"],
                        b"telephonenumber": [b"+1 408 555 1212"],
                    },
                ),
            ],
        ),
        (
            b"""Example 2: A file containing an entry with a folded attribute value""",
            b"""\
version: 1
dn:cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
objectclass:top
objectclass:person
objectclass:organizationalPerson
cn:Barbara Jensen
cn:Barbara J Jensen
cn:Babs Jensen
sn:Jensen
uid:bjensen
telephonenumber:+1 408 555 1212
description:Babs is a big sailing fan, and travels extensively in sea
 rch of perfect sailing conditions.
title:Product Manager, Rod and Reel Division

""",
            [
                (
                    b"cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com",
                    {
                        b"objectclass": [b"top", b"person", b"organizationalPerson"],
                        b"cn": [b"Barbara Jensen", b"Barbara J Jensen", b"Babs Jensen"],
                        b"sn": [b"Jensen"],
                        b"uid": [b"bjensen"],
                        b"telephonenumber": [b"+1 408 555 1212"],
                        b"description": [
                            b"Babs is a big sailing fan, and travels extensively in search of perfect sailing conditions."
                        ],
                        b"title": [b"Product Manager, Rod and Reel Division"],
                    },
                ),
            ],
        ),
        (
            b"""Example 3: A file containing a base-64-encoded value""",
            b"""\
version: 1
dn: cn=Gern Jensen, ou=Product Testing, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Gern Jensen
cn: Gern O Jensen
sn: Jensen
uid: gernj
telephonenumber: +1 408 555 1212
description:: V2hhdCBhIGNhcmVmdWwgcmVhZGVyIHlvdSBhcmUhICBUaGlzIHZhbHVlIGlzIGJhc2UtNjQtZW5jb2RlZCBiZWNhdXNlIGl0IGhhcyBhIGNvbnRyb2wgY2hhcmFjdGVyIGluIGl0IChhIENSKS4NICBCeSB0aGUgd2F5LCB5b3Ugc2hvdWxkIHJlYWxseSBnZXQgb3V0IG1vcmUu

""",
            [
                (
                    b"cn=Gern Jensen, ou=Product Testing, dc=airius, dc=com",
                    {
                        b"objectclass": [b"top", b"person", b"organizationalPerson"],
                        b"cn": [b"Gern Jensen", b"Gern O Jensen"],
                        b"sn": [b"Jensen"],
                        b"uid": [b"gernj"],
                        b"telephonenumber": [b"+1 408 555 1212"],
                        b"description": [
                            b"What a careful reader you are!  This value is base-64-encoded because it has a control character in it (a CR).\r  By the way, you should really get out more."
                        ],
                    },
                ),
            ],
        ),
    ]

    def testExamples(self) -> None:
        for name, data, expected in self.examples:
            proto = LDIFDriver()
            proto.dataReceived(data)

            assert len(proto.listOfCompleted) == len(expected)

            for dn, attr in expected:
                o = proto.listOfCompleted.pop(0)
                assert o.dn == distinguishedname.DistinguishedName(dn)

                got = {x.lower() for x in o.keys()}
                want = {x.lower() for x in attr.keys()}
                assert got == want

                for k, v in attr.items():
                    assert o[k] == v

            assert proto.listOfCompleted == []


"""
TODO more tests from RFC2849:

Example 4: A file containing an entries with UTF-8-encoded attribute
values, including language tags.  Comments indicate the contents
of UTF-8-encoded attributes and distinguished names.

version: 1
dn:: b3U95Za25qWt6YOoLG89QWlyaXVz
# dn:: ou=<JapaneseOU>,o=Airius
objectclass: top
objectclass: organizationalUnit
ou:: 5Za25qWt6YOo
# ou:: <JapaneseOU>
ou;lang-ja:: 5Za25qWt6YOo
# ou;lang-ja:: <JapaneseOU>
ou;lang-ja;phonetic:: 44GI44GE44GO44KH44GG44G2

# ou;lang-ja:: <JapaneseOU_in_phonetic_representation>
ou;lang-en: Sales
description: Japanese office

dn:: dWlkPXJvZ2FzYXdhcmEsb3U95Za25qWt6YOoLG89QWlyaXVz
# dn:: uid=<uid>,ou=<JapaneseOU>,o=Airius
userpassword: {SHA}O3HSv1MusyL4kTjP+HKI5uxuNoM=
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
uid: rogasawara
mail: rogasawara@airius.co.jp
givenname;lang-ja:: 44Ot44OJ44OL44O8
# givenname;lang-ja:: <JapaneseGivenname>
sn;lang-ja:: 5bCP56yg5Y6f
# sn;lang-ja:: <JapaneseSn>
cn;lang-ja:: 5bCP56yg5Y6fIOODreODieODi+ODvA==
# cn;lang-ja:: <JapaneseCn>
title;lang-ja:: 5Za25qWt6YOoIOmDqOmVtw==
# title;lang-ja:: <JapaneseTitle>
preferredlanguage: ja
givenname:: 44Ot44OJ44OL44O8
# givenname:: <JapaneseGivenname>
sn:: 5bCP56yg5Y6f
# sn:: <JapaneseSn>
cn:: 5bCP56yg5Y6fIOODreODieODi+ODvA==
# cn:: <JapaneseCn>
title:: 5Za25qWt6YOoIOmDqOmVtw==
# title:: <JapaneseTitle>
givenname;lang-ja;phonetic:: 44KN44Gp44Gr44O8
# givenname;lang-ja;phonetic::
<JapaneseGivenname_in_phonetic_representation_kana>
sn;lang-ja;phonetic:: 44GK44GM44GV44KP44KJ
# sn;lang-ja;phonetic:: <JapaneseSn_in_phonetic_representation_kana>
cn;lang-ja;phonetic:: 44GK44GM44GV44KP44KJIOOCjeOBqeOBq+ODvA==
# cn;lang-ja;phonetic:: <JapaneseCn_in_phonetic_representation_kana>
title;lang-ja;phonetic:: 44GI44GE44GO44KH44GG44G2IOOBtuOBoeOCh+OBhg==
# title;lang-ja;phonetic::
# <JapaneseTitle_in_phonetic_representation_kana>
givenname;lang-en: Rodney
sn;lang-en: Ogasawara
cn;lang-en: Rodney Ogasawara
title;lang-en: Sales, Director
"""

"""
Example 5: A file containing a reference to an external file

version: 1
dn: cn=Horatio Jensen, ou=Product Testing, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Horatio Jensen

cn: Horatio N Jensen
sn: Jensen
uid: hjensen
telephonenumber: +1 408 555 1212
jpegphoto:< file:///usr/local/directory/photos/hjensen.jpg
"""

"""
Example 6: A file containing a series of change records and comments

version: 1
# Add a new entry
dn: cn=Fiona Jensen, ou=Marketing, dc=airius, dc=com
changetype: add
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Fiona Jensen
sn: Jensen
uid: fiona
telephonenumber: +1 408 555 1212
jpegphoto:< file:///usr/local/directory/photos/fiona.jpg

# Delete an existing entry
dn: cn=Robert Jensen, ou=Marketing, dc=airius, dc=com
changetype: delete

# Modify an entry's relative distinguished name
dn: cn=Paul Jensen, ou=Product Development, dc=airius, dc=com
changetype: modrdn
newrdn: cn=Paula Jensen
deleteoldrdn: 1

# Rename an entry and move all of its children to a new location in
# the directory tree (only implemented by LDAPv3 servers).
dn: ou=PD Accountants, ou=Product Development, dc=airius, dc=com
changetype: modrdn
newrdn: ou=Product Development Accountants
deleteoldrdn: 0
newsuperior: ou=Accounting, dc=airius, dc=com

# Modify an entry: add an additional value to the postaladdress
# attribute, completely delete the description attribute, replace
# the telephonenumber attribute with two values, and delete a specific
# value from the facsimiletelephonenumber attribute
dn: cn=Paula Jensen, ou=Product Development, dc=airius, dc=com
changetype: modify
add: postaladdress
postaladdress: 123 Anystreet $ Sunnyvale, CA $ 94086
-
delete: description
-
replace: telephonenumber
telephonenumber: +1 408 555 1234
telephonenumber: +1 408 555 5678
-
delete: facsimiletelephonenumber
facsimiletelephonenumber: +1 408 555 9876
-

# Modify an entry: replace the postaladdress attribute with an empty
# set of values (which will cause the attribute to be removed), and
# delete the entire description attribute. Note that the first will
# always succeed, while the second will only succeed if at least
# one value for the description attribute is present.
dn: cn=Ingrid Jensen, ou=Product Support, dc=airius, dc=com
changetype: modify
replace: postaladdress
-
delete: description
-
"""

"""
Example 7: An LDIF file containing a change record with a control
version: 1
# Delete an entry. The operation will attach the LDAPv3
# Tree Delete Control defined in [9]. The criticality
# field is "true" and the controlValue field is
# absent, as required by [9].
dn: ou=Product Development, dc=airius, dc=com
control: 1.2.840.113556.1.4.805 true
changetype: delete

"""
