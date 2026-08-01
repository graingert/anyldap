from anyldap._collections import InsensitiveDict


def test_insensitive_dict_preserves_keys_and_normalizes_lookup():
    values = InsensitiveDict({"Content-Type": "text/plain"})

    assert values["content-type"] == "text/plain"
    assert "CONTENT-TYPE" in values
    assert values.get("CONTENT-type") == "text/plain"
    assert values.get("missing", "fallback") == "fallback"
    assert list(values) == ["Content-Type"]
    assert values.keys() == ["Content-Type"]
    assert values.values() == ["text/plain"]
    assert values.items() == [("Content-Type", "text/plain")]
    assert len(values) == 1

    values["CONTENT-TYPE"] = "application/json"
    assert values.items() == [("CONTENT-TYPE", "application/json")]
    del values["content-type"]
    assert not values


def test_insensitive_dict_supports_non_string_keys():
    values = InsensitiveDict()
    values[1] = "one"

    assert values[1] == "one"
    assert 1 in values
