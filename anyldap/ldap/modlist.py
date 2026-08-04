"""``ldap.modlist``: turning entries into the modlists add and modify take."""

from collections.abc import Iterable, Mapping, Sequence

from anyldap._encoder import to_bytes
from anyldap.ldap.constants import MOD_ADD, MOD_DELETE
from anyldap.ldap.ldapobject import AddModlist, ModifyModlist, Value

# An entry as an application holds it. A value the caller has not filled
# in is None, which is not a value and does not reach the server.
Entry = Mapping[str, Sequence[Value | None] | Value | None]


def _values(values: Sequence[Value | None] | Value | None) -> list[bytes]:
    """The values of one attribute, with the empty ones left out."""
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        return [to_bytes(values)]
    return [to_bytes(value) for value in values if value is not None]


def addModlist(entry: Entry, ignore_attr_types: Iterable[str] = ()) -> AddModlist:
    """The modlist that adds an entry, skipping attributes with no values."""
    ignored = {attribute.lower() for attribute in ignore_attr_types}
    modlist: list[tuple[str, Sequence[Value] | Value]] = []
    for attribute, values in entry.items():
        if attribute.lower() in ignored:
            continue
        present = _values(values)
        if present:
            modlist.append((attribute, present))
    return modlist


def modifyModlist(
    old_entry: Entry,
    new_entry: Entry,
    ignore_attr_types: Iterable[str] = (),
    ignore_oldexistent: int = 0,
    case_ignore_attr_types: Iterable[str] = (),
) -> ModifyModlist:
    """The modlist that turns one entry into another.

    An attribute whose values changed is deleted and added again rather than
    replaced, which is what python-ldap's own does: the server then rejects
    the change if the entry moved underneath, instead of overwriting it.
    """
    ignored = {attribute.lower() for attribute in ignore_attr_types}
    case_ignored = {attribute.lower() for attribute in case_ignore_attr_types}
    modlist: list[tuple[int, str, Sequence[Value] | Value | None]] = []
    # The attributes of the old entry that the new one has not accounted
    # for yet, keyed by the spelling that matches whatever case is used.
    remaining = {attribute.lower(): attribute for attribute in old_entry}

    for attribute, values in new_entry.items():
        lowered = attribute.lower()
        if lowered in ignored:
            continue
        new_values = _values(values)
        if lowered in remaining:
            old_values = _values(old_entry[remaining.pop(lowered)])
        else:
            old_values = []

        if not old_values and new_values:
            modlist.append((MOD_ADD, attribute, new_values))
        elif old_values and new_values:
            if _differs(old_values, new_values, lowered in case_ignored):
                modlist.append((MOD_DELETE, attribute, None))
                modlist.append((MOD_ADD, attribute, new_values))
        elif old_values:
            modlist.append((MOD_DELETE, attribute, None))

    if not ignore_oldexistent:
        for lowered, attribute in remaining.items():
            if lowered in ignored:
                continue
            modlist.append((MOD_DELETE, attribute, None))

    return modlist


def _differs(
    old_values: Sequence[bytes], new_values: Sequence[bytes], case_ignore: bool
) -> bool:
    if len(old_values) != len(new_values):
        return True
    if case_ignore:
        return {value.lower() for value in old_values} != {
            value.lower() for value in new_values
        }
    return set(old_values) != set(new_values)
