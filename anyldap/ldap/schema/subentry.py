"""``ldap.schema.subentry``: the schema a server publishes, read into objects."""

from collections.abc import Iterable, Mapping, Sequence

from anyldap._encoder import to_unicode
from anyldap.ldap.schema.models import (
    SCHEMA_ATTRS,
    SCHEMA_CLASS_MAPPING,
    AttributeType,
    ObjectClass,
    SchemaElement,
)

# What an object class of each kind is numbered, as python-ldap numbers them.
STRUCTURAL, ABSTRACT, AUXILIARY = 0, 1, 2


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
        # Every element read, by its OID, and where its names point.
        self.sed: dict[type[SchemaElement], dict[str, SchemaElement]] = {
            cls: {} for cls in SCHEMA_CLASS_MAPPING.values()
        }
        self.name2oid: dict[type[SchemaElement], dict[str, str]] = {
            cls: {} for cls in SCHEMA_CLASS_MAPPING.values()
        }
        for attribute, definitions in sub_schema_sub_entry.items():
            cls = SCHEMA_CLASS_MAPPING.get(_attribute_name(attribute))
            if cls is None:
                continue
            for definition in definitions:
                element = cls(definition)
                assert element.oid is not None
                self.sed[cls][element.oid] = element
                for name in element.names:
                    self.name2oid[cls][name.lower()] = element.oid
                self.name2oid[cls][element.oid] = element.oid

    def listall(
        self,
        schema_element_class: type[SchemaElement],
        schema_element_filters: object = None,
    ) -> list[str]:
        """The OIDs of everything of this kind that the server published."""
        return list(self.sed[schema_element_class])

    def get_obj(
        self,
        schema_element_class: type[SchemaElement],
        name_or_oid: str,
        default: SchemaElement | None = None,
        raise_keyerror: int = 0,
    ) -> SchemaElement | None:
        """What the server said about this name, or about this OID."""
        oid = self.getoid(schema_element_class, name_or_oid)
        try:
            return self.sed[schema_element_class][oid]
        except KeyError:
            if raise_keyerror:
                raise KeyError(
                    f"No {schema_element_class.__name__} named {name_or_oid!r}"
                ) from None
            return default

    def getoid(
        self, schema_element_class: type[SchemaElement], name_or_oid: str
    ) -> str:
        """The OID a name stands for, or the OID itself."""
        return self.name2oid[schema_element_class].get(
            to_unicode(name_or_oid).lower(), to_unicode(name_or_oid)
        )

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

    def get_structural_oc(self, object_class_list: Sequence[str]) -> str | None:
        """The one object class of these that says what the entry is."""
        for name in object_class_list:
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
