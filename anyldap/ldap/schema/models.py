"""``ldap.schema.models``: what a server says its schema is made of.

Each class reads one schema definition -- the text a server publishes in its
subschema subentry -- and answers with the fields python-ldap's own model
classes answer with. The reading itself is :mod:`anyldap.schema`, which the
rest of anyldap already parses schema with.
"""

from collections import UserDict
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, ClassVar

from anyldap import schema as _schema
from anyldap._encoder import to_bytes, to_unicode
from anyldap.ldap import cidict
from anyldap.ldap.schema.tokenizer import Tokens, extract_tokens, split_tokens

if TYPE_CHECKING:  # pragma: no cover
    from anyldap.ldap.schema import subentry


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
SCHEMA_CLASS_MAPPING: dict[str, type[SchemaElement]] = {}
SCHEMA_ATTR_MAPPING: dict[type[SchemaElement], str] = {}
SCHEMA_ATTRS: list[str] = []

# What a value of an attribute type is used for, as python-ldap numbers it.
# The names are looked up whichever way they are spelled, and a schema that
# says "userApplication" is taken to mean "userApplications".
AttributeUsage = cidict.cidict(
    {
        "userApplication": 0,
        "userApplications": 0,
        "directoryOperation": 1,
        "distributedOperation": 2,
        "dSAOperation": 3,
    }
)

# The syntaxes whose values are not text, whatever a server says of them.
NOT_HUMAN_READABLE_LDAP_SYNTAXES = {
    "1.3.6.1.4.1.1466.115.121.1.4",  # Audio
    "1.3.6.1.4.1.1466.115.121.1.5",  # Binary
    "1.3.6.1.4.1.1466.115.121.1.8",  # Certificate
    "1.3.6.1.4.1.1466.115.121.1.9",  # Certificate List
    "1.3.6.1.4.1.1466.115.121.1.10",  # Certificate Pair
    "1.3.6.1.4.1.1466.115.121.1.23",  # G3 FAX
    "1.3.6.1.4.1.1466.115.121.1.28",  # JPEG
    "1.3.6.1.4.1.1466.115.121.1.40",  # Octet String
    "1.3.6.1.4.1.1466.115.121.1.49",  # Supported Algorithm
}


class _TokenisedElement(SchemaElement):
    """A definition read word by word rather than by a parser of its own.

    The four kinds below have no parser in :mod:`anyldap.schema`, because
    nothing else in anyldap reads them: what they say is read here with the
    tokenizer, which is how python-ldap reads every kind.
    """

    token_defaults: ClassVar[Tokens] = {
        "DESC": (None,),
    }

    def _parse(self, definition: bytes) -> None:
        read = split_tokens(to_unicode(definition))
        self.set_id(read[1])
        self._set_attrs(read, extract_tokens(read, self.token_defaults))

    def _set_attrs(self, read: list[str], said: Tokens) -> None:
        raise NotImplementedError

    @staticmethod
    def _one(said: Tokens, key: str) -> str | None:
        value = said[key]
        return value[0] if value else None

    @staticmethod
    def _many(said: Tokens, key: str) -> tuple[str, ...]:
        return tuple(value for value in said[key] or () if value is not None)


class MatchingRuleUse(_TokenisedElement):
    """Which attributes a matching rule may be used with."""

    schema_attribute = "matchingRuleUse"

    token_defaults: ClassVar[Tokens] = {
        "NAME": (),
        "DESC": (None,),
        "OBSOLETE": None,
        "APPLIES": (),
    }

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.applies: tuple[str, ...] = ()
        SchemaElement.__init__(self, schema_element_str)

    def _set_attrs(self, read: list[str], said: Tokens) -> None:
        self.names = self._many(said, "NAME")
        self.desc = self._one(said, "DESC")
        self.obsolete = int(said["OBSOLETE"] is not None)
        self.applies = self._many(said, "APPLIES")

    def __str__(self) -> str:
        return "( %s )" % "".join(
            [
                str(self.oid),
                self.key_list("NAME", self.names, quoted=1),
                self.key_attr("DESC", self.desc, quoted=1),
                " OBSOLETE" if self.obsolete else "",
                self.key_list("APPLIES", self.applies, sep=" $ "),
            ]
        )


class DITContentRule(_TokenisedElement):
    """What an entry of a structural class may hold on top of it."""

    schema_attribute = "dITContentRules"

    token_defaults: ClassVar[Tokens] = {
        "NAME": (),
        "DESC": (None,),
        "OBSOLETE": None,
        "AUX": (),
        "MUST": (),
        "MAY": (),
        "NOT": (),
    }

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.aux: tuple[str, ...] = ()
        self.must: tuple[str, ...] = ()
        self.may: tuple[str, ...] = ()
        self.nots: tuple[str, ...] = ()
        SchemaElement.__init__(self, schema_element_str)

    def _set_attrs(self, read: list[str], said: Tokens) -> None:
        self.names = self._many(said, "NAME")
        self.desc = self._one(said, "DESC")
        self.obsolete = int(said["OBSOLETE"] is not None)
        self.aux = self._many(said, "AUX")
        self.must = self._many(said, "MUST")
        self.may = self._many(said, "MAY")
        self.nots = self._many(said, "NOT")

    def __str__(self) -> str:
        return "( %s )" % "".join(
            [
                str(self.oid),
                self.key_list("NAME", self.names, quoted=1),
                self.key_attr("DESC", self.desc, quoted=1),
                " OBSOLETE" if self.obsolete else "",
                self.key_list("AUX", self.aux, sep=" $ "),
                self.key_list("MUST", self.must, sep=" $ "),
                self.key_list("MAY", self.may, sep=" $ "),
                self.key_list("NOT", self.nots, sep=" $ "),
            ]
        )


class DITStructureRule(_TokenisedElement):
    """Where in the tree an entry of a name form may be put.

    A structure rule is numbered rather than named by an OID, which is what
    ``ruleid`` is; ``get_id()`` answers with it.
    """

    schema_attribute = "dITStructureRules"

    token_defaults: ClassVar[Tokens] = {
        "NAME": (),
        "DESC": (None,),
        "OBSOLETE": None,
        "FORM": (None,),
        "SUP": (),
    }

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.ruleid: str | None = None
        self.form: str | None = None
        self.sup: tuple[str, ...] = ()
        SchemaElement.__init__(self, schema_element_str)

    def set_id(self, element_id: str) -> None:
        self.ruleid = element_id

    def get_id(self) -> str | None:
        return self.ruleid

    def _set_attrs(self, read: list[str], said: Tokens) -> None:
        self.names = self._many(said, "NAME")
        self.desc = self._one(said, "DESC")
        self.obsolete = int(said["OBSOLETE"] is not None)
        self.form = self._one(said, "FORM")
        self.sup = self._many(said, "SUP")

    def __str__(self) -> str:
        return "( %s )" % "".join(
            [
                str(self.ruleid),
                self.key_list("NAME", self.names, quoted=1),
                self.key_attr("DESC", self.desc, quoted=1),
                " OBSOLETE" if self.obsolete else "",
                self.key_attr("FORM", self.form, quoted=0),
                self.key_list("SUP", self.sup, sep=" $ "),
            ]
        )


class NameForm(_TokenisedElement):
    """Which attributes name an entry of an object class."""

    schema_attribute = "nameForms"

    token_defaults: ClassVar[Tokens] = {
        "NAME": (),
        "DESC": (None,),
        "OBSOLETE": None,
        "OC": (None,),
        "MUST": (),
        "MAY": (),
    }

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        self.oc: str | None = None
        self.must: tuple[str, ...] = ()
        self.may: tuple[str, ...] = ()
        SchemaElement.__init__(self, schema_element_str)

    def _set_attrs(self, read: list[str], said: Tokens) -> None:
        self.names = self._many(said, "NAME")
        self.desc = self._one(said, "DESC")
        self.obsolete = int(said["OBSOLETE"] is not None)
        self.oc = self._one(said, "OC")
        self.must = self._many(said, "MUST")
        self.may = self._many(said, "MAY")

    def __str__(self) -> str:
        return "( %s )" % "".join(
            [
                str(self.oid),
                self.key_list("NAME", self.names, quoted=1),
                self.key_attr("DESC", self.desc, quoted=1),
                " OBSOLETE" if self.obsolete else "",
                self.key_attr("OC", self.oc),
                self.key_list("MUST", self.must, sep=" $ "),
                self.key_list("MAY", self.may, sep=" $ "),
            ]
        )


# Every kind of definition, keyed by the attribute it is published in and
# the other way round.
for _cls in (
    ObjectClass,
    AttributeType,
    MatchingRule,
    MatchingRuleUse,
    LDAPSyntax,
    DITContentRule,
    DITStructureRule,
    NameForm,
):
    SCHEMA_CLASS_MAPPING[_cls.schema_attribute] = _cls
    SCHEMA_ATTR_MAPPING[_cls] = _cls.schema_attribute
SCHEMA_ATTRS = list(SCHEMA_CLASS_MAPPING)
del _cls


# What an entry is keyed by is a name on the way in and the tuple of the
# attribute's OID and its sub-types on the way through, so the keys are not
# one type from both sides.
class Entry(UserDict[Any, list[bytes]]):
    """An entry that knows the schema its attributes are described by.

    An attribute is looked up by whichever of its names or its OID the
    caller has, so ``entry["cn"]``, ``entry["commonName"]`` and
    ``entry["2.5.4.3"]`` are all the same attribute; sub-types are kept
    apart, so ``cn;lang-en`` is not ``cn``.
    """

    def __init__(
        self,
        schema: "subentry.SubSchema",
        dn: str,
        entry: Mapping[str, list[bytes]],
    ) -> None:
        self._keytuple2attrtype: dict[tuple[str, ...], str] = {}
        self._attrtype2keytuple: dict[str, tuple[str, ...]] = {}
        self._s = schema
        self.dn = dn
        super().__init__()
        self.update(entry)

    def _at2key(self, nameoroid: str) -> tuple[str, ...]:
        """The OID of an attribute and the sub-types asked for with it."""
        try:
            # Mapping already in cache
            return self._attrtype2keytuple[nameoroid]
        except KeyError:
            # Mapping has to be constructed
            oid = self._s.getoid(AttributeType, nameoroid)
            parts = nameoroid.lower().split(";")
            parts[0] = oid or nameoroid
            key = tuple(parts)
            self._attrtype2keytuple[nameoroid] = key
            return key

    def update(self, other: Mapping[str, list[bytes]]) -> None:  # type: ignore[override]
        for key, value in other.items():
            self[key] = value

    def __contains__(self, nameoroid: object) -> bool:
        assert isinstance(nameoroid, str)
        return self._at2key(nameoroid) in self.data

    def __getitem__(self, nameoroid: str) -> list[bytes]:
        return self.data[self._at2key(nameoroid)]

    def __setitem__(self, nameoroid: str, attr_values: list[bytes]) -> None:
        key = self._at2key(nameoroid)
        self._keytuple2attrtype[key] = nameoroid
        self.data[key] = attr_values

    def __delitem__(self, nameoroid: str) -> None:
        key = self._at2key(nameoroid)
        del self.data[key]
        del self._attrtype2keytuple[nameoroid]
        del self._keytuple2attrtype[key]

    def has_key(self, nameoroid: str) -> bool:
        return self._at2key(nameoroid) in self.data

    def keys(self) -> Any:
        return self._keytuple2attrtype.values()

    def items(self) -> Any:
        return [(key, self[key]) for key in self.keys()]

    def attribute_types(
        self, attr_type_filter: object = None, raise_keyerror: int = 1
    ) -> tuple[dict[str, AttributeType], dict[str, AttributeType]]:
        """What an entry of this one's object classes must and may have."""
        classes = self.data.get(self._at2key("objectClass"), [])
        return self._s.attribute_types(
            [to_unicode(name) for name in classes], attr_type_filter, raise_keyerror
        )
