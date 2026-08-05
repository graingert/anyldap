"""python-ldap's tests for the ldif module, run against anyldap.ldap.ldif.

Ported from python-ldap 3.4.7, ``Tests/t_ldif.py``. Copyright the python-ldap
authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in this
directory, and README.rst for what was changed.

python-ldap's two ``TestCase`` classes differ only in which kind of record
they read, so ``record_type`` is a fixture here and each test is written
once against whichever the class it was in used.
"""

import textwrap
from collections.abc import Callable
from io import StringIO
from typing import Any

import pytest

from anyldap.ldap import ldif

Records = list[Any]
CheckRecords = Callable[..., None]


def _parse_records(
    record_type: str,
    ldif_string: str,
    ignored_attr_types: list[str] | None = None,
    max_entries: int = 0,
) -> Records:
    """Parse LDIF data in `ldif_string' into list of records"""
    ldif_file = StringIO(ldif_string)
    ldif_parser = ldif.LDIFRecordList(
        ldif_file,
        ignored_attr_types=ignored_attr_types,
        max_entries=max_entries,
    )
    parser_method = getattr(ldif_parser, "parse_%s_records" % record_type)
    parser_method()
    if record_type == "entry":
        return list(ldif_parser.all_records)
    return list(ldif_parser.all_modify_changes)


def _unparse_records(record_type: str, records: Records) -> str:
    """Returns LDIF string with entry records from list `records'"""
    ldif_file = StringIO()
    ldif_writer = ldif.LDIFWriter(ldif_file)
    if record_type == "entry":
        for dn, entry in records:
            ldif_writer.unparse(dn, entry)
    else:
        for dn, modops, _controls in records:
            ldif_writer.unparse(dn, modops)
    return ldif_file.getvalue()


@pytest.fixture
def check_records(record_type: str) -> CheckRecords:
    """Whether LDIF is parsed into the records it describes, and back again."""

    def check(
        ldif_string: str,
        records: Records,
        ignored_attr_types: list[str] | None = None,
        max_entries: int = 0,
    ) -> None:
        ldif_string = textwrap.dedent(ldif_string).lstrip()
        parsed_records = _parse_records(
            record_type,
            ldif_string,
            ignored_attr_types=ignored_attr_types,
            max_entries=max_entries,
        )
        generated_ldif = _unparse_records(record_type, records)
        parsed_records2 = _parse_records(
            record_type,
            generated_ldif,
            ignored_attr_types=ignored_attr_types,
            max_entries=max_entries,
        )
        assert records == parsed_records
        assert records == parsed_records2

    return check


# Entry records.

entry_records = pytest.mark.parametrize("record_type", ["entry"])
change_records = pytest.mark.parametrize("record_type", ["change"])


@entry_records
def test_empty(check_records: CheckRecords) -> None:
    check_records(
        """
        version: 1

        """,
        [],
    )


@entry_records
def test_simple(check_records: CheckRecords) -> None:
    check_records(
        """
        version: 1

        dn: cn=x,cn=y,cn=z
        attrib: value
        attrib: value2

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                {
                    "attrib": [b"value", b"value2"],
                },
            ),
        ],
    )


@entry_records
def test_simple2(check_records: CheckRecords) -> None:
    check_records(
        """
        dn:cn=x,cn=y,cn=z
        attrib:value
        attrib:value2

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                {
                    "attrib": [b"value", b"value2"],
                },
            ),
        ],
    )


@entry_records
def test_multiple(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x,cn=y,cn=z
        a: v
        attrib: value
        attrib: value2

        dn: cn=a,cn=b,cn=c
        attrib: value2
        attrib: value3
        b: v

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                {
                    "attrib": [b"value", b"value2"],
                    "a": [b"v"],
                },
            ),
            (
                "cn=a,cn=b,cn=c",
                {
                    "attrib": [b"value2", b"value3"],
                    "b": [b"v"],
                },
            ),
        ],
    )


@entry_records
def test_folded(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x,cn=y,cn=z
        attrib: very\x20
         long
          line-folded\x20
         value
        attrib2: %s

        """
        % ("asdf." * 20),
        [
            (
                "cn=x,cn=y,cn=z",
                {
                    "attrib": [b"very long line-folded value"],
                    "attrib2": [b"asdf." * 20],
                },
            ),
        ],
    )


@entry_records
def test_empty_attr_values(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x,cn=y,cn=z
        attrib1:
        attrib1: foo
        attrib2:
        attrib2: foo

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                {
                    "attrib1": [b"", b"foo"],
                    "attrib2": [b"", b"foo"],
                },
            ),
        ],
    )


@entry_records
def test_binary(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x,cn=y,cn=z
        attrib:: CQAKOiVA

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                {
                    "attrib": [b"\t\0\n:%@"],
                },
            ),
        ],
    )


@entry_records
def test_binary2(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x,cn=y,cn=z
        attrib::CQAKOiVA

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                {"attrib": [b"\t\0\n:%@"]},
            ),
        ],
    )


@entry_records
def test_big_binary(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x,cn=y,cn=z
        attrib:: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         =

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                {"attrib": [500 * b"\0"]},
            ),
        ],
    )


@entry_records
def test_unicode(check_records: CheckRecords) -> None:
    # Encode "Ströder" as UTF-8+Base64
    # Putting "Ströder" in a single line would be an invalid LDIF file
    # per https://tools.ietf.org/html/rfc2849 (only safe ascii is allowed
    # in a file)
    check_records(
        """
        dn: cn=Michael Stroeder,dc=stroeder,dc=com
        lastname:: U3Ryw7ZkZXI=

        """,
        [
            (
                "cn=Michael Stroeder,dc=stroeder,dc=com",
                {"lastname": [b"Str\303\266der"]},
            ),
        ],
    )


@entry_records
def test_unencoded_unicode(check_records: CheckRecords) -> None:
    # Encode "Ströder" as UTF-8, without base64
    # This is an invalid LDIF file, but such files are often found in the wild.
    check_records(
        """
        dn: cn=Michael Stroeder,dc=stroeder,dc=com
        lastname: Ströder

        """,
        [
            (
                "cn=Michael Stroeder,dc=stroeder,dc=com",
                {"lastname": [b"Str\303\266der"]},
            ),
        ],
    )


@entry_records
def test_sorted(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x,cn=y,cn=z
        b: value_b
        c: value_c
        a: value_a

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                {
                    "a": [b"value_a"],
                    "b": [b"value_b"],
                    "c": [b"value_c"],
                },
            ),
        ],
    )


@entry_records
def test_ignored_attr_types(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x,cn=y,cn=z
        a: value_a
        b: value_b
        c: value_c

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                {
                    "a": [b"value_a"],
                    "c": [b"value_c"],
                },
            ),
        ],
        ignored_attr_types=["b"],
    )


@entry_records
def test_comments(check_records: CheckRecords) -> None:
    check_records(
        """
        # comment #1
         with line-folding
        dn: cn=x1,cn=y1,cn=z1
        b1: value_b1
        c1: value_c1
        a1: value_a1

        # comment #2.1
        # comment #2.2
        dn: cn=x2,cn=y2,cn=z2
        b2: value_b2
        c2: value_c2
        a2: value_a2

        """,
        [
            (
                "cn=x1,cn=y1,cn=z1",
                {
                    "a1": [b"value_a1"],
                    "b1": [b"value_b1"],
                    "c1": [b"value_c1"],
                },
            ),
            (
                "cn=x2,cn=y2,cn=z2",
                {
                    "a2": [b"value_a2"],
                    "b2": [b"value_b2"],
                    "c2": [b"value_c2"],
                },
            ),
        ],
    )


@entry_records
def test_max_entries(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x1,cn=y1,cn=z1
        b1: value_b1
        a1: value_a1

        dn: cn=x2,cn=y2,cn=z2
        b2: value_b2
        a2: value_a2

        dn: cn=x3,cn=y3,cn=z3
        b3: value_b3
        a3: value_a3

        dn: cn=x4,cn=y4,cn=z4
        b2: value_b4
        a2: value_a4

        """,
        [
            (
                "cn=x1,cn=y1,cn=z1",
                {
                    "a1": [b"value_a1"],
                    "b1": [b"value_b1"],
                },
            ),
            (
                "cn=x2,cn=y2,cn=z2",
                {
                    "a2": [b"value_a2"],
                    "b2": [b"value_b2"],
                },
            ),
        ],
        max_entries=2,
    )


@entry_records
def test_missing_trailing_line_separator(check_records: CheckRecords) -> None:
    check_records(
        """
        dn: cn=x1,cn=y1,cn=z1
        first: value_a1
        middle: value_b1
        last: value_c1

        dn: cn=x2,cn=y2,cn=z2
        first: value_a2
        middle: value_b2
        last: value_c2""",
        [
            (
                "cn=x1,cn=y1,cn=z1",
                {
                    "first": [b"value_a1"],
                    "middle": [b"value_b1"],
                    "last": [b"value_c1"],
                },
            ),
            (
                "cn=x2,cn=y2,cn=z2",
                {
                    "first": [b"value_a2"],
                    "middle": [b"value_b2"],
                    "last": [b"value_c2"],
                },
            ),
        ],
    )


@entry_records
def test_weird_empty_lines(check_records: CheckRecords) -> None:
    check_records(
        """

        # comment before version

        version: 1


        dn: cn=x1,cn=y1,cn=z1
        first: value_a1
        middle: value_b1
        last: value_c1


        dn: cn=x2,cn=y2,cn=z2
        first: value_a2
        middle: value_b2
        last: value_c2""",
        [
            (
                "cn=x1,cn=y1,cn=z1",
                {
                    "first": [b"value_a1"],
                    "middle": [b"value_b1"],
                    "last": [b"value_c1"],
                },
            ),
            (
                "cn=x2,cn=y2,cn=z2",
                {
                    "first": [b"value_a2"],
                    "middle": [b"value_b2"],
                    "last": [b"value_c2"],
                },
            ),
        ],
    )


@entry_records
def test_multiple_empty_lines(check_records: CheckRecords) -> None:
    """test malformed LDIF with multiple empty lines"""
    check_records(
        """
        # normal
        dn: uid=one,dc=tld
        uid: one



        # after extra empty line
        dn: uid=two,dc=tld
        uid: two

        """,
        [
            ("uid=one,dc=tld", {"uid": [b"one"]}),
            ("uid=two,dc=tld", {"uid": [b"two"]}),
        ],
    )


# Change records.


@change_records
def test_change_empty(check_records: CheckRecords) -> None:
    check_records(
        """
        version: 1
        """,
        [],
    )


@change_records
def test_change_simple(check_records: CheckRecords) -> None:
    check_records(
        """
        version: 1

        dn: cn=x,cn=y,cn=z
        changetype: modify
        replace: attrib
        attrib: value
        attrib: value2
        -
        add: attrib2
        attrib2: value
        attrib2: value2
        -
        delete: attrib3
        attrib3: value
        -
        delete: attrib4
        -

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                [
                    (ldif.MOD_OP_INTEGER["replace"], "attrib", [b"value", b"value2"]),
                    (ldif.MOD_OP_INTEGER["add"], "attrib2", [b"value", b"value2"]),
                    (ldif.MOD_OP_INTEGER["delete"], "attrib3", [b"value"]),
                    (ldif.MOD_OP_INTEGER["delete"], "attrib4", None),
                ],
                None,
            ),
        ],
    )


@change_records
def test_change_weird_empty_lines(check_records: CheckRecords) -> None:
    check_records(
        """

        # comment before version

        version: 1


        dn: cn=x,cn=y,cn=z
        changetype: modify
        replace: attrib
        attrib: value
        attrib: value2
        -
        add: attrib2
        attrib2: value
        attrib2: value2
        -
        delete: attrib3
        attrib3: value
        -
        delete: attrib4
        -


        dn: cn=foo,cn=bar
        changetype: modify
        replace: attrib
        attrib: value
        attrib: value2
        -
        add: attrib2
        attrib2: value
        attrib2: value2
        -
        delete: attrib3
        attrib3: value
        -
        delete: attrib4""",
        [
            (
                "cn=x,cn=y,cn=z",
                [
                    (ldif.MOD_OP_INTEGER["replace"], "attrib", [b"value", b"value2"]),
                    (ldif.MOD_OP_INTEGER["add"], "attrib2", [b"value", b"value2"]),
                    (ldif.MOD_OP_INTEGER["delete"], "attrib3", [b"value"]),
                    (ldif.MOD_OP_INTEGER["delete"], "attrib4", None),
                ],
                None,
            ),
            (
                "cn=foo,cn=bar",
                [
                    (ldif.MOD_OP_INTEGER["replace"], "attrib", [b"value", b"value2"]),
                    (ldif.MOD_OP_INTEGER["add"], "attrib2", [b"value", b"value2"]),
                    (ldif.MOD_OP_INTEGER["delete"], "attrib3", [b"value"]),
                    (ldif.MOD_OP_INTEGER["delete"], "attrib4", None),
                ],
                None,
            ),
        ],
    )


@change_records
def test_change_missing_trailing_dash_separator(check_records: CheckRecords) -> None:
    check_records(
        """
        version: 1

        dn: cn=x,cn=y,cn=z
        changetype: modify
        replace: attrib
        attrib: value
        attrib: value2
        -
        add: attrib2
        attrib2: value
        attrib2: value2

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                [
                    (ldif.MOD_OP_INTEGER["replace"], "attrib", [b"value", b"value2"]),
                    (ldif.MOD_OP_INTEGER["add"], "attrib2", [b"value", b"value2"]),
                ],
                None,
            ),
        ],
    )


@change_records
def test_bad_change_records(record_type: str) -> None:
    for bad_ldif_string in (
        """
        changetype: modify
        replace: attrib
        attrib: value
        attrib: value2

        """,
    ):
        ldif_string = textwrap.dedent(bad_ldif_string).lstrip() + "\n"
        with pytest.raises(ValueError):
            _parse_records(record_type, ldif_string)


@change_records
def test_change_mod_increment(check_records: CheckRecords) -> None:
    check_records(
        """
        version: 1

        dn: cn=x,cn=y,cn=z
        changetype: modify
        increment: gidNumber
        gidNumber: 1
        -

        """,
        [
            (
                "cn=x,cn=y,cn=z",
                [
                    (ldif.MOD_OP_INTEGER["increment"], "gidNumber", [b"1"]),
                ],
                None,
            ),
        ],
    )
