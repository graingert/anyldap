"""python-ldap's tests for ldap.modlist, run against anyldap.ldap.modlist.

Ported from python-ldap 3.4.7, ``Tests/t_ldap_modlist.py``. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed.
"""

from typing import Any

import pytest

from anyldap import ldap
from anyldap.ldap.modlist import addModlist, modifyModlist

addModlist_tests: list[tuple[dict[str, Any], list[Any]]] = [
    (
        {
            "objectClass": [b"person", b"pilotPerson"],
            "cn": [b"Michael Str\303\266der", b"Michael Stroeder"],
            "sn": [b"Str\303\266der"],
            "dummy1": [],
            "dummy2": [b"2"],
            "dummy3": [b""],
        },
        [
            ("objectClass", [b"person", b"pilotPerson"]),
            ("cn", [b"Michael Str\303\266der", b"Michael Stroeder"]),
            ("sn", [b"Str\303\266der"]),
            ("dummy2", [b"2"]),
            ("dummy3", [b""]),
        ],
    ),
]


@pytest.mark.parametrize(("entry", "test_modlist"), addModlist_tests)
def test_addModlist(entry: dict[str, Any], test_modlist: list[Any]) -> None:
    test_modlist.sort()
    result_modlist = sorted(addModlist(entry))
    assert test_modlist == result_modlist


modifyModlist_tests: list[tuple[dict[str, Any], dict[str, Any], list[str], list[Any]]]
modifyModlist_tests = [
    (
        {
            "objectClass": [b"person", b"pilotPerson"],
            "cn": [b"Michael Str\303\266der", b"Michael Stroeder"],
            "sn": [b"Str\303\266der"],
            "enum": [b"a", b"b", b"c"],
            "c": [b"DE"],
        },
        {
            "objectClass": [b"person", b"inetOrgPerson"],
            "cn": [b"Michael Str\303\266der", b"Michael Stroeder"],
            "sn": [],
            "enum": [b"a", b"b", b"d"],
            "mail": [b"michael@stroeder.com"],
        },
        [],
        [
            (ldap.MOD_DELETE, "objectClass", None),
            (ldap.MOD_ADD, "objectClass", [b"person", b"inetOrgPerson"]),
            (ldap.MOD_DELETE, "c", None),
            (ldap.MOD_DELETE, "sn", None),
            (ldap.MOD_ADD, "mail", [b"michael@stroeder.com"]),
            (ldap.MOD_DELETE, "enum", None),
            (ldap.MOD_ADD, "enum", [b"a", b"b", b"d"]),
        ],
    ),
    (
        {"c": [b"DE"]},
        {"c": [b"FR"]},
        [],
        [
            (ldap.MOD_DELETE, "c", None),
            (ldap.MOD_ADD, "c", [b"FR"]),
        ],
    ),
    # Now a weird test-case for catching all possibilities
    # of removing an attribute with MOD_DELETE,attr_type,None
    (
        {
            "objectClass": [b"person"],
            "cn": [None],
            "sn": [b""],
            "c": [b"DE"],
        },
        {
            "objectClass": [],
            "cn": [],
            "sn": [None],
        },
        [],
        [
            (ldap.MOD_DELETE, "c", None),
            (ldap.MOD_DELETE, "objectClass", None),
            (ldap.MOD_DELETE, "sn", None),
        ],
    ),
    (
        {
            "objectClass": [b"person"],
            "cn": [b"Michael Str\303\266der", b"Michael Stroeder"],
            "sn": [b"Str\303\266der"],
            "enum": [b"a", b"b", b"C"],
        },
        {
            "objectClass": [b"Person"],
            "cn": [b"Michael Str\303\266der", b"Michael Stroeder"],
            "sn": [],
            "enum": [b"a", b"b", b"c"],
        },
        ["objectClass"],
        [
            (ldap.MOD_DELETE, "sn", None),
            (ldap.MOD_DELETE, "enum", None),
            (ldap.MOD_ADD, "enum", [b"a", b"b", b"c"]),
        ],
    ),
]


@pytest.mark.parametrize(
    ("old_entry", "new_entry", "case_ignore_attr_types", "test_modlist"),
    modifyModlist_tests,
)
def test_modifyModlist(
    old_entry: dict[str, Any],
    new_entry: dict[str, Any],
    case_ignore_attr_types: list[str],
    test_modlist: list[Any],
) -> None:
    test_modlist.sort(key=repr)
    result_modlist = sorted(
        modifyModlist(
            old_entry, new_entry, case_ignore_attr_types=case_ignore_attr_types
        ),
        key=repr,
    )
    assert test_modlist == result_modlist
