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


def _extensions(
    parsed: Sequence[tuple[bytes, bytes | tuple[bytes, ...]]],
) -> dict[str, tuple[str, ...]]:
    """The ``X-`` fields of a definition, each as a tuple of its values."""
    read: dict[str, tuple[str, ...]] = {}
    for name, value in parsed:
        read[to_unicode(name)] = (
            (to_unicode(value),) if isinstance(value, bytes) else _texts(value)
        )
    return read


class SchemaElement:
    """One definition out of a schema, whatever kind it is."""

    schema_attribute: ClassVar[str] = ""

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.oid: str | None = None
        self.names: tuple[str, ...] = ()
        self.desc: str | None = None
        self.obsolete: int = 0
        self.x_origin: tuple[str, ...] = ()
        self.extensions: dict[str, tuple[str, ...]] = {}
        if schema_element_str is not None:
            self._parse(to_bytes(schema_element_str))

    def _parse(self, definition: bytes) -> None:
        raise NotImplementedError

    def _read_extensions(
        self, parsed: Sequence[tuple[bytes, bytes | tuple[bytes, ...]]]
    ) -> None:
        self.extensions = _extensions(parsed)
        self.x_origin = self.extensions.get("X-ORIGIN", ())

    def set_id(self, element_id: str) -> None:
        self.oid = element_id

    def get_id(self) -> str | None:
        return self.oid

    def key_attr(self, key: str, value: str | None, quoted: int = 0) -> str:
        """One field of a definition, written the way python-ldap writes it."""
        assert value is None or isinstance(value, str), TypeError(
            "value has to be of str, was %r" % value
        )
        if not value:
            return ""
        if quoted:
            return " {} '{}'".format(key, value.replace("'", "\\'"))
        return f" {key} {value}"

    def key_list(
        self, key: str, values: tuple[str, ...], sep: str = " ", quoted: int = 0
    ) -> str:
        """A field with several values, written the way python-ldap writes it."""
        assert isinstance(values, tuple), TypeError(
            "values has to be a tuple, was %r" % values
        )
        if not values:
            return ""
        if quoted:
            written = ["'%s'" % value.replace("'", "\\'") for value in values]
        else:
            written = list(values)
        if len(values) == 1:
            return f" {key} {written[0]}"
        return f" {key} ( {sep.join(written)} )"

    def __str__(self) -> str:
        return "( %s )" % "".join(
            [str(self.oid), self.key_attr("DESC", self.desc, quoted=1)]
        )

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
        # An object class with no SUP is under top, which is what
        # python-ldap fills in when the definition does not say.
        self.sup = _texts(parsed.sup) or ("top",)
        self.must = _texts(parsed.must)
        self.may = _texts(parsed.may)
        # python-ldap numbers the kinds: structural, abstract, auxiliary.
        kind = (_text(parsed.type) or "STRUCTURAL").upper()
        self.kind = {"STRUCTURAL": 0, "ABSTRACT": 1, "AUXILIARY": 2}[kind]
        self._read_extensions(parsed.x_attrs)

    def __str__(self) -> str:
        return "( %s )" % "".join(
            [
                str(self.oid),
                self.key_list("NAME", self.names, quoted=1),
                self.key_attr("DESC", self.desc, quoted=1),
                self.key_list("SUP", self.sup, sep=" $ "),
                " OBSOLETE" if self.obsolete else "",
                {0: " STRUCTURAL", 1: " ABSTRACT", 2: " AUXILIARY"}[self.kind],
                self.key_list("MUST", self.must, sep=" $ "),
                self.key_list("MAY", self.may, sep=" $ "),
                self.key_list("X-ORIGIN", self.x_origin, quoted=1),
            ]
        )


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
        self._read_extensions(parsed.x_attrs)

    def __str__(self) -> str:
        return "( %s )" % "".join(
            [
                str(self.oid),
                self.key_list("NAME", self.names, quoted=1),
                self.key_attr("DESC", self.desc, quoted=1),
                self.key_list("SUP", self.sup, sep=" $ "),
                " OBSOLETE" if self.obsolete else "",
                self.key_attr("EQUALITY", self.equality),
                self.key_attr("ORDERING", self.ordering),
                self.key_attr("SUBSTR", self.substr),
                self.key_attr("SYNTAX", self.syntax),
                ""
                if not self.syntax_len
                else "{%d}" % self.syntax_len,
                " SINGLE-VALUE" if self.single_value else "",
                " COLLECTIVE" if self.collective else "",
                " NO-USER-MODIFICATION" if self.no_user_mod else "",
                {
                    0: "",
                    1: " USAGE directoryOperation",
                    2: " USAGE distributedOperation",
                    3: " USAGE dSAOperation",
                }[self.usage],
                self.key_list("X-ORIGIN", self.x_origin, quoted=1),
            ]
        )


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
        self._read_extensions(parsed.x_attrs)

    def __str__(self) -> str:
        return "( %s )" % "".join(
            [
                str(self.oid),
                self.key_list("NAME", self.names, quoted=1),
                self.key_attr("DESC", self.desc, quoted=1),
                " OBSOLETE" if self.obsolete else "",
                self.key_attr("SYNTAX", self.syntax),
            ]
        )


class LDAPSyntax(SchemaElement):
    """A syntax: what a value of it looks like."""

    schema_attribute = "ldapSyntaxes"

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.not_human_readable = 0
        self.x_binary_transfer_required = 0
        self.x_subst: str | None = None
        SchemaElement.__init__(self, schema_element_str)

    def _parse(self, definition: bytes) -> None:
        parsed = _schema.SyntaxDescription(definition)
        self.oid = _text(parsed.oid)
        self.desc = _text(parsed.desc)
        self.not_human_readable = int(not parsed.human_readable)
        self.x_binary_transfer_required = int(bool(parsed.binary_transfer_required))
        self._read_extensions(parsed.x_attrs)
        self.x_subst = self.extensions.get("X-SUBST", (None,))[0]

    def __str__(self) -> str:
        return "( %s )" % "".join(
            [
                str(self.oid),
                self.key_attr("DESC", self.desc, quoted=1),
                self.key_attr("X-SUBST", self.x_subst, quoted=1),
                " X-NOT-HUMAN-READABLE 'TRUE'" if self.not_human_readable else "",
            ]
        )


# What python-ldap calls the classes it knows how to read, keyed by the
# attribute of the subschema subentry they are published in.
SCHEMA_CLASS_MAPPING: dict[str, type[SchemaElement]] = {
    cls.schema_attribute: cls
    for cls in (ObjectClass, AttributeType, MatchingRule, LDAPSyntax)
}
SCHEMA_ATTRS = list(SCHEMA_CLASS_MAPPING)
