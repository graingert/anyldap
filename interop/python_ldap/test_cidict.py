"""python-ldap's tests for ldap.cidict, run against anyldap.ldap.cidict.

Ported from python-ldap 3.4.7, ``Tests/t_cidict.py``. Copyright the
python-ldap authors; see LICENCE.python-ldap and LICENCE.python-ldap.MIT in
this directory, and README.rst for what was changed.
"""

from anyldap import ldap
from anyldap.ldap import cidict


def test_cidict() -> None:
    assert ldap.dn.is_dn("foobar,ou=ae-dir") is False
    data = {"AbCDeF": 123}
    cix: cidict.cidict[int] = cidict.cidict(data)
    assert cix["ABCDEF"] == 123
    assert cix.get("ABCDEF", None) == 123
    assert cix.get("not existent", None) is None
    cix["xYZ"] = 987
    assert cix["XyZ"] == 987
    assert cix.get("xyz", None) == 987
    assert sorted(cix.keys()) == ["AbCDeF", "xYZ"]
    assert sorted(cix) == ["AbCDeF", "xYZ"]
    assert sorted(cix.items()) == [("AbCDeF", 123), ("xYZ", 987)]
    del cix["abcdEF"]
    # python-ldap looks in cix._keys here; the question it is asking is
    # whether the key is gone, whichever way it is spelled.
    assert ("abcdef" in cix) is False
    assert ("AbCDef" in cix) is False
    assert cix.has_key("abcdef") is False
    assert cix.has_key("AbCDef") is False


def test_copy() -> None:
    cix1: cidict.cidict[int] = cidict.cidict({"a": 1, "B": 2})
    cix2 = cix1.copy()
    assert cix1 == cix2
    cix1["c"] = 3
    assert "c" not in cix2
    cix2["C"] = 4
    assert cix1 != cix2
    assert list(cix1.keys()) == ["a", "B", "c"]
    assert list(cix2.keys()) == ["a", "B", "C"]
