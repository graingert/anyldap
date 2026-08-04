"""``ldap.schema.models``: what a server says its schema is made of.

Each class reads one schema definition -- the text a server publishes in its
subschema subentry -- and answers with the fields python-ldap's own model
classes answer with. The reading itself is :mod:`anyldap.schema`, which the
rest of anyldap already parses schema with.
"""

from collections.abc import Sequence
from typing import ClassVar

from anyldap import schema as _schema
from anyldap._encoder import to_bytes, to_unicode


def _text(value: bytes | str | None) -> str | None:
    return None if value is None else to_unicode(value)


def _texts(values: Sequence[bytes | str] | None) -> tuple[str, ...]:
    return tuple(to_unicode(value) for value in values or ())


class SchemaElement:
    """One definition out of a schema, whatever kind it is."""

    schema_attribute: ClassVar[str] = ""

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.oid: str | None = None
        self.names: tuple[str, ...] = ()
        self.desc: str | None = None
        self.obsolete: int = 0
        if schema_element_str is not None:
            self._parse(to_bytes(schema_element_str))

    def _parse(self, definition: bytes) -> None:
        raise NotImplementedError

    def get_id(self) -> str | None:
        return self.oid

    def __str__(self) -> str:
        return self.names[0] if self.names else (self.oid or "")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self}, oid={self.oid!r})"


class ObjectClass(SchemaElement):
    """An object class: what an entry of it must and may have."""

    schema_attribute = "objectClasses"

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.kind = 0
        self.sup: tuple[str, ...] = ()
        self.must: tuple[str, ...] = ()
        self.may: tuple[str, ...] = ()
        SchemaElement.__init__(self, schema_element_str)

    def _parse(self, definition: bytes) -> None:
        parsed = _schema.ObjectClassDescription(definition)
        self.oid = _text(parsed.oid)
        self.names = _texts(parsed.name)
        self.desc = _text(parsed.desc)
        self.obsolete = int(parsed.obsolete)
        self.sup = _texts(parsed.sup)
        self.must = _texts(parsed.must)
        self.may = _texts(parsed.may)
        # python-ldap numbers the kinds: structural, abstract, auxiliary.
        kind = (_text(parsed.type) or "STRUCTURAL").upper()
        self.kind = {"STRUCTURAL": 0, "ABSTRACT": 1, "AUXILIARY": 2}[kind]


class AttributeType(SchemaElement):
    """An attribute type: how its values are written and compared."""

    schema_attribute = "attributeTypes"

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.sup: tuple[str, ...] = ()
        self.equality: str | None = None
        self.ordering: str | None = None
        self.substr: str | None = None
        self.syntax: str | None = None
        self.syntax_len: int | None = None
        self.single_value = 0
        self.collective = 0
        self.no_user_mod = 0
        self.usage = 0
        SchemaElement.__init__(self, schema_element_str)

    def _parse(self, definition: bytes) -> None:
        parsed = _schema.AttributeTypeDescription(definition)
        self.oid = _text(parsed.oid)
        self.names = _texts(parsed.name)
        self.desc = _text(parsed.desc)
        self.obsolete = int(parsed.obsolete)
        self.sup = _texts([parsed.sup] if parsed.sup else [])
        self.equality = _text(parsed.equality)
        self.ordering = _text(parsed.ordering)
        self.substr = _text(parsed.substr)
        syntax = _text(parsed.syntax)
        if syntax is not None and syntax.endswith("}") and "{" in syntax:
            syntax, _, length = syntax[:-1].partition("{")
            self.syntax_len = int(length)
        self.syntax = syntax
        self.single_value = int(bool(parsed.single_value))
        self.collective = int(bool(parsed.collective))
        self.no_user_mod = int(bool(parsed.no_user_modification))
        usage = (_text(parsed.usage) or "userApplications").lower()
        self.usage = {
            "userapplications": 0,
            "directoryoperation": 1,
            "distributedoperation": 2,
            "dsaoperation": 3,
        }.get(usage, 0)


class MatchingRule(SchemaElement):
    """A matching rule: how two values of a syntax are compared."""

    schema_attribute = "matchingRules"

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.syntax: str | None = None
        SchemaElement.__init__(self, schema_element_str)

    def _parse(self, definition: bytes) -> None:
        parsed = _schema.MatchingRuleDescription(definition)
        self.oid = _text(parsed.oid)
        self.names = _texts(parsed.name)
        self.desc = _text(parsed.desc)
        self.obsolete = int(bool(parsed.obsolete))
        self.syntax = _text(parsed.syntax)


class LDAPSyntax(SchemaElement):
    """A syntax: what a value of it looks like."""

    schema_attribute = "ldapSyntaxes"

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.not_human_readable = 0
        self.x_binary_transfer_required = 0
        SchemaElement.__init__(self, schema_element_str)

    def _parse(self, definition: bytes) -> None:
        parsed = _schema.SyntaxDescription(definition)
        self.oid = _text(parsed.oid)
        self.desc = _text(parsed.desc)
        self.not_human_readable = int(not parsed.human_readable)
        self.x_binary_transfer_required = int(bool(parsed.binary_transfer_required))


# What python-ldap calls the classes it knows how to read, keyed by the
# attribute of the subschema subentry they are published in.
SCHEMA_CLASS_MAPPING: dict[str, type[SchemaElement]] = {
    cls.schema_attribute: cls
    for cls in (ObjectClass, AttributeType, MatchingRule, LDAPSyntax)
}
SCHEMA_ATTRS = list(SCHEMA_CLASS_MAPPING)
