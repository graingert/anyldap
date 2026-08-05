"""``ldap.schema.subentry``: the schema a server publishes, read into objects."""

import io
from collections.abc import Iterable, Mapping, Sequence
from typing import cast

from anyldap._encoder import to_unicode
from anyldap.ldap import _fetch, cidict
from anyldap.ldap.schema.models import (
    NOT_HUMAN_READABLE_LDAP_SYNTAXES as NOT_HUMAN_READABLE_LDAP_SYNTAXES,
)
from anyldap.ldap.schema.models import (
    SCHEMA_ATTR_MAPPING as SCHEMA_ATTR_MAPPING,
)
from anyldap.ldap.schema.models import (
    SCHEMA_ATTRS,
    SCHEMA_CLASS_MAPPING,
    AttributeType,
    ObjectClass,
    SchemaElement,
)

# What an object class of each kind is numbered, as python-ldap numbers them.
STRUCTURAL, ABSTRACT, AUXILIARY = 0, 1, 2


class SubschemaError(ValueError):
    """Something is wrong with the schema a server published."""


class OIDNotUnique(SubschemaError):
    """Two definitions of the same kind claim one OID."""

    def __init__(self, desc: str) -> None:
        self.desc = desc

    def __str__(self) -> str:
        return "OID not unique for %s" % (self.desc)


class NameNotUnique(SubschemaError):
    """Two definitions of the same kind claim one name."""

    def __init__(self, desc: str) -> None:
        self.desc = desc

    def __str__(self) -> str:
        return "NAME not unique for %s" % (self.desc)


class SubSchema:
    """The schema of one server, looked up by name or by OID.

    Built from the entry a server publishes at its subschema subentry: the
    dictionary of attributes a search of it hands back.
    """

    def __init__(
        self,
        sub_schema_sub_entry: Mapping[str, Iterable[bytes | str]],
        check_uniqueness: int = 1,
    ) -> None:
        """Read what a server published into the definitions it describes.

        ``check_uniqueness`` says what to do about a schema that describes
        one thing twice: 0 lets the second definition replace the first, 1
        keeps both by giving the second a suffix and records the OID in
        ``non_unique_oids``, and 2 or more refuses the schema outright. A
        name claimed twice is refused whichever of those it is.
        """
        # Every element read, by its OID, and where its names point.
        self.sed: dict[type[SchemaElement], dict[str, SchemaElement]] = {
            cls: {} for cls in SCHEMA_CLASS_MAPPING.values()
        }
        self.name2oid: dict[type[SchemaElement], cidict.cidict[str]] = {
            cls: cidict.cidict() for cls in SCHEMA_CLASS_MAPPING.values()
        }
        self.non_unique_names: dict[type[SchemaElement], cidict.cidict[None]] = {
            cls: cidict.cidict() for cls in SCHEMA_CLASS_MAPPING.values()
        }
        seen_twice: dict[str, None] = {}

        published = {
            _attribute_name(attribute): definitions
            for attribute, definitions in sub_schema_sub_entry.items()
        }
        for attribute in SCHEMA_ATTRS:
            cls = SCHEMA_CLASS_MAPPING[attribute]
            for definition in published.get(attribute, []):
                if not definition:
                    continue
                element = cls(definition)
                element_id = element.get_id()
                assert element_id is not None

                if check_uniqueness and element_id in self.sed[cls]:
                    seen_twice[element_id] = None
                    if check_uniqueness == 1:
                        # Keep both, by giving this one a suffix.
                        suffix = 1
                        unique = element_id
                        while unique in self.sed[cls]:
                            unique = ";".join((element_id, str(suffix)))
                            suffix += 1
                        element_id = unique
                    else:
                        raise OIDNotUnique(to_unicode(definition))

                self.sed[cls][element_id] = element

                for name in element.names:
                    if check_uniqueness and name in self.name2oid[cls]:
                        self.non_unique_names[cls][element_id] = None
                        raise NameNotUnique(to_unicode(definition))
                    self.name2oid[cls][name] = element_id

        # Turn dict into list maybe more handy for applications
        self.non_unique_oids = list(seen_twice)

    def ldap_entry(self) -> dict[str, list[str]]:
        """The entry this schema was read from, written out again.

        Each element as the definition it would be published as, keyed by
        the attribute it is published in.
        """
        entry: dict[str, list[str]] = {}
        for cls, elements in self.sed.items():
            for element in elements.values():
                entry.setdefault(cls.schema_attribute, []).append(str(element))
        return entry

    def listall(
        self,
        schema_element_class: type[SchemaElement],
        schema_element_filters: object = None,
    ) -> list[str]:
        """The OIDs of everything of this kind that the server published."""
        return list(self.sed[schema_element_class])

    def get_obj(
        self,
        se_class: type[SchemaElement],
        nameoroid: str,
        default: SchemaElement | None = None,
        raise_keyerror: int = 0,
    ) -> SchemaElement | None:
        """What the server said about this name, or about this OID."""
        oid = self.getoid(se_class, nameoroid)
        try:
            return self.sed[se_class][oid]
        except KeyError:
            if raise_keyerror:
                raise KeyError(
                    f"No {se_class.__name__} named {nameoroid!r}"
                ) from None
            return default

    def getoid(
        self,
        se_class: type[SchemaElement],
        nameoroid: str,
        raise_keyerror: int = 0,
    ) -> str:
        """The OID a name stands for, or the OID itself.

        Sub-types are dropped first, so ``cn;lang-en`` is asked about as
        ``cn``. A name the schema does not describe comes back as it was
        given unless ``raise_keyerror`` says to make something of it.
        """
        stripped = to_unicode(nameoroid).split(";")[0].strip()
        if stripped in self.sed[se_class]:
            # name_or_oid is already a registered OID
            return stripped
        try:
            return self.name2oid[se_class][stripped]
        except KeyError:
            if raise_keyerror:
                raise KeyError(
                    "No registered {}-OID for nameoroid {}".format(
                        se_class.__name__, repr(stripped)
                    )
                ) from None
            return stripped

    def attribute_types(
        self,
        object_class_list: Sequence[str],
        attr_type_filter: object = None,
        raise_keyerror: int = 1,
        ignore_dit_content_rule: int = 0,
    ) -> tuple[dict[str, AttributeType], dict[str, AttributeType]]:
        """What entries of these object classes must and may have.

        Two dictionaries of attribute types by OID: the ones that are
        required, and the ones that are allowed.
        """
        must: dict[str, AttributeType] = {}
        may: dict[str, AttributeType] = {}
        for name in self._with_superiors(object_class_list, raise_keyerror):
            object_class = self.get_obj(
                ObjectClass, name, raise_keyerror=raise_keyerror
            )
            if object_class is None:
                continue
            assert isinstance(object_class, ObjectClass)
            for attribute, into in (
                (object_class.must, must),
                (object_class.may, may),
            ):
                for attribute_name in attribute:
                    attribute_type = self.get_obj(
                        AttributeType, attribute_name, raise_keyerror=raise_keyerror
                    )
                    if attribute_type is not None:
                        assert isinstance(attribute_type, AttributeType)
                        assert attribute_type.oid is not None
                        into[attribute_type.oid] = attribute_type
        # An attribute that is required is not merely allowed.
        for oid in must:
            may.pop(oid, None)
        return must, may

    def _with_superiors(
        self, object_class_list: Sequence[str], raise_keyerror: int
    ) -> list[str]:
        """These object classes, and the ones they are built on."""
        seen: list[str] = []
        pending = list(object_class_list)
        while pending:
            name = pending.pop(0)
            oid = self.getoid(ObjectClass, name)
            if oid in seen:
                continue
            seen.append(oid)
            object_class = self.get_obj(ObjectClass, name, raise_keyerror=0)
            if object_class is not None:
                assert isinstance(object_class, ObjectClass)
                pending.extend(object_class.sup)
        return seen

    def get_structural_oc(self, oc_list: Sequence[str]) -> str | None:
        """The one object class of these that says what the entry is."""
        for name in oc_list:
            object_class = self.get_obj(ObjectClass, name)
            if isinstance(object_class, ObjectClass) and object_class.kind == STRUCTURAL:
                return object_class.oid
        return None


def _attribute_name(attribute: str) -> str:
    """The attribute an entry was keyed by, without its options."""
    for known in SCHEMA_ATTRS:
        if to_unicode(attribute).split(";")[0].lower() == known.lower():
            return known
    return to_unicode(attribute)


def _read_ldif(read: bytes) -> tuple[str | None, Mapping[str, list[bytes]]]:
    """The first record of some LDIF."""
    from anyldap.ldap import ldif

    records = ldif.LDIFRecordList(io.BytesIO(read), max_entries=1)
    records.parse()
    dn, entry = records.all_records[0]
    # Only a value the LDIF names by URL is ever None, and none are fetched.
    return dn, cast(Mapping[str, list[bytes]], entry)


async def urlfetch(uri: str, trace_level: int = 0) -> tuple[str | None, "SubSchema | None"]:
    """The schema an LDAP URL, or an LDIF file, says a server publishes.

    An ``ldap://``, ``ldaps://`` or ``ldapi://`` URL is asked: a connection
    is opened, bound as the URL says to bind, asked where its schema is and
    then for the schema itself, and closed again -- which is what makes this
    different from ``read_schema_s()`` on a connection that is already open.
    Anything else is the address of an LDIF file, and its first record is
    the schema, which is what python-ldap makes of one too. Unlike
    python-ldap's, which hands the address to ``urlopen``, only ``file:``,
    ``http:`` and ``https:`` are read.
    """
    from anyldap.ldap import cidict, ldapobject
    from anyldap.ldap.ldapurl import LDAPUrl

    uri = uri.strip()
    published: Mapping[str, list[bytes]] | None
    if not uri.startswith(("ldap:", "ldaps:", "ldapi:")):
        subschemasubentry_dn, published = _read_ldif(await _fetch.read_async(uri))
    else:
        url = LDAPUrl(uri)
        async with ldapobject.SimpleLDAPObject(
            url.initializeUrl(), trace_level
        ) as conn:
            await conn.simple_bind_s(url.who or "", url.cred or "")
            subschemasubentry_dn = await conn.search_subschemasubentry_s(url.dn)
            if subschemasubentry_dn is None:
                return None, None
            published = await conn.read_subschemasubentry_s(
                subschemasubentry_dn, attrs=url.attrs if url.attrs else SCHEMA_ATTRS
            )

    # Work-around for mixed-cased attribute names
    entry: cidict.cidict[list[bytes]] = cidict.cidict()
    for attribute, definitions in (published or {}).items():
        if attribute in SCHEMA_CLASS_MAPPING:
            entry.setdefault(attribute, []).extend(definitions)
    return subschemasubentry_dn, SubSchema(entry)
