from collections.abc import Sequence

from anyldap._encoder import WireStrAlias, to_bytes

# Schema descriptions are parsed and rendered as the bytes they arrive as.
Wire = str | bytes


def extractWord(text: bytes) -> tuple[bytes, bytes]:
    if not text:
        return b"", b""
    l = text.split(None, 1)
    word = l[0]
    try:
        text = l[1]
    except IndexError:
        text = b""
    return word, text


def peekWord(text: bytes) -> bytes | None:
    if not text:
        return None
    return text.split(None, 1)[0]


class ASN1ParserThingie:
    def _check_oid(self, oid: bytes) -> None:
        """An OID is a string of numbers, or a name standing for one.

        RFC 4512 section 1.4 lets an ``oid`` be a ``descr`` as well as a
        ``numericoid``, and directory servers take it up: a 389-DS schema
        names object classes ``nsEncryptionConfig-oid`` and the like. What
        is refused is a name that could not be either.
        """
        assert oid
        if all(c in b"0123456789." for c in oid):
            return
        assert oid[:1].isalpha(), "Not an OID: %s" % repr(oid)
        for c in oid[1:]:
            assert (
                bytes((c,)).isalnum() or c in b"-;"
            ), "Not an OID: %s" % repr(oid)

    def _to_list(self, text: bytes) -> tuple[bytes, ...]:
        """Split text into $-separated list."""
        r = []
        for x in text.split(b"$"):
            x = x.strip()
            assert x
            r.append(x)
        return tuple(r)

    def _strings_to_list(self, text: bytes) -> tuple[bytes, ...]:
        """Split ''-quoted strings into list."""
        r = []
        while text:
            text = text.lstrip()
            if not text:
                break
            assert text[:1] == b"'", "Text %s must start with a single quote." % repr(
                text
            )
            text = text[1:]
            end = text.index(b"'")
            r.append(text[:end])
            text = text[end + 1 :]
        return tuple(r)

    def _parse_extensions(
        self, text: bytes
    ) -> tuple[list[tuple[bytes, bytes | tuple[bytes, ...]]], bytes]:
        """The ``X-`` fields at the end of a definition, and what is left.

        A schema definition may end with any number of extensions -- RFC 4512
        section 4.1 lets a server define its own, and ``X-ORIGIN`` saying
        where a definition came from is on nearly everything OpenLDAP and
        389-ds publish. Each is a name and either one string or several.
        """
        extensions: list[tuple[bytes, bytes | tuple[bytes, ...]]] = []
        while True:
            text = text.lstrip()
            word = peekWord(text)
            if word is None or not word.startswith(b"X-"):
                break
            value: bytes | tuple[bytes, ...]
            text = text[len(word) :].lstrip()
            if text[:1] == b"'":
                text = text[1:]
                end = text.index(b"'")
                value = text[:end]
                text = text[end + 1 :]
            elif text[:1] == b"(":
                text = text[1:].lstrip()
                end = text.index(b")")
                value = self._strings_to_list(text[:end])
                text = text[end + 1 :]
            else:
                raise AssertionError(f"extension {word!r} has no value")
            extensions.append((word, value))
        return extensions, text

    def _extensions_to_wire(
        self, extensions: Sequence[tuple[bytes, bytes | tuple[bytes, ...]]]
    ) -> list[bytes]:
        """The extensions, written out again as they were read."""
        written = []
        for name, value in extensions:
            if isinstance(value, bytes):
                written.append(b"%s '%s'" % (name, value))
            else:
                written.append(
                    b"%s ( %s )" % (name, b" ".join(b"'%s'" % s for s in value))
                )
        return written

    def _str_list(self, l: Sequence[bytes]) -> bytes:
        s = b" ".join([self._str(x) for x in l])
        if len(l) > 1:
            s = b"( %s )" % s
        return s

    def _list(self, l: Sequence[bytes]) -> bytes:
        s = b" $ ".join([x for x in l])
        if len(l) > 1:
            s = b"( %s )" % s
        return s

    def _str(self, s: bytes) -> bytes:
        return b"'%s'" % s


class ObjectClassDescription(ASN1ParserThingie, WireStrAlias):
    """
    ASN Syntax::

        d               = "0" / "1" / "2" / "3" / "4" /
                          "5" / "6" / "7" / "8" / "9"

        numericstring   = 1*d

        numericoid      = numericstring *( "." numericstring )

        space           = 1*" "

        whsp            = [ space ]

        descr           = keystring

        qdescr          = whsp "'" descr "'" whsp

        qdescrlist      = [ qdescr *( qdescr ) ]

        ; object descriptors used as schema element names
        qdescrs         = qdescr / ( whsp "(" qdescrlist ")" whsp )

        dstring         = 1*utf8

        qdstring        = whsp "'" dstring "'" whsp

        descr           = keystring

        oid             = descr / numericoid

        woid            = whsp oid whsp

        ; set of oids of either form
        oids            = woid / ( "(" oidlist ")" )

        ObjectClassDescription = "(" whsp
                numericoid whsp      ; ObjectClass identifier
                [ "NAME" qdescrs ]
                [ "DESC" qdstring ]
                [ "OBSOLETE" whsp ]
                [ "SUP" oids ]       ; Superior ObjectClasses
                [ ( "ABSTRACT" / "STRUCTURAL" / "AUXILIARY" ) whsp ]
                                     ; default structural
                [ "MUST" oids ]      ; AttributeTypes
                [ "MAY" oids ]       ; AttributeTypes
                whsp ")"
    """

    def __init__(self, text: Wire | None) -> None:
        self.oid: bytes | None = None
        self.name: tuple[bytes, ...] | None = None
        self.desc: bytes | None = None
        self.obsolete: int = 0
        self.sup: Sequence[bytes] = []
        self.type: bytes | None = None
        self.must: list[bytes] = []
        self.may: list[bytes] = []
        self.x_attrs: list[tuple[bytes, bytes | tuple[bytes, ...]]] = []

        if text is not None:
            self._parse(to_bytes(text))

    def _parse(self, text: bytes) -> None:
        assert text[:1] == b"(", "Text %s must be in parentheses." % repr(text)
        assert text[-1:] == b")", "Text %s must be in parentheses." % repr(text)
        text = text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"NAME":
            text = text[len(b"NAME ") :]
            text = text.lstrip()
            if text[:1] == b"'":
                text = text[1:]
                end = text.index(b"'")
                self.name = (text[:end],)
                text = text[end + 1 :]
            elif text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.name = self._strings_to_list(text[:end])
                text = text[end + 1 :]
            else:
                raise AssertionError()

        text = text.lstrip()

        if peekWord(text) == b"DESC":
            text = text[len(b"DESC ") :]
            text = text.lstrip()
            assert text[:1] == b"'"
            text = text[1:]
            end = text.index(b"'")
            self.desc = text[:end]
            text = text[end + 1 :]

        text = text.lstrip()

        if peekWord(text) == b"OBSOLETE":
            self.obsolete = 1
            text = text[len(b"OBSOLETE ") :]

        text = text.lstrip()

        if peekWord(text) == b"SUP":
            text = text[len(b"SUP ") :]
            text = text.lstrip()
            if text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.sup = self._to_list(text[:end])
                text = text[end + 1 :]
            else:
                s, text = extractWord(text)
                self.sup = [s]

        text = text.lstrip()

        if peekWord(text) == b"ABSTRACT":
            assert self.type is None
            self.type = b"ABSTRACT"
            text = text[len(b"ABSTRACT ") :]

        text = text.lstrip()

        if peekWord(text) == b"STRUCTURAL":
            assert self.type is None
            self.type = b"STRUCTURAL"
            text = text[len(b"STRUCTURAL ") :]

        text = text.lstrip()

        if peekWord(text) == b"AUXILIARY":
            assert self.type is None
            self.type = b"AUXILIARY"
            text = text[len(b"AUXILIARY ") :]

        text = text.lstrip()

        if peekWord(text) == b"MUST":
            text = text[len(b"MUST ") :]
            text = text.lstrip()
            if text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.must.extend(self._to_list(text[:end]))
                text = text[end + 1 :]
            else:
                s, text = extractWord(text)
                self.must.append(s)

        text = text.lstrip()

        if peekWord(text) == b"MAY":
            text = text[len(b"MAY ") :]
            text = text.lstrip()
            if text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.may.extend(self._to_list(text[:end]))
                text = text[end + 1 :]
            else:
                s, text = extractWord(text)
                self.may.append(s)

        text = text.lstrip()

        self.x_attrs, text = self._parse_extensions(text)

        assert text == b"", "Text was not empty: %s" % repr(text)

        if not self.type:
            self.type = b"STRUCTURAL"

        self._check_oid(self.oid)
        assert self.name is None or self.name
        assert self.type in (b"ABSTRACT", b"STRUCTURAL", b"AUXILIARY")

    def __repr__(self) -> str:
        nice = {}
        for k, v in self.__dict__.items():
            nice[k] = repr(v)
        return (
            f"<{self.__class__.__name__} instance at 0x{id(self):x}"
            + (
                " oid=%(oid)s name=%(name)s desc=%(desc)s"
                + " obsolete=%(obsolete)s sup=%(sup)s type=%(type)s"
                + " must=%(must)s may=%(may)s>"
            )
            % nice
        )

    def toWire(self) -> bytes:
        r = []
        if self.name is not None:
            r.append(b"NAME %s" % self._str_list(self.name))
        if self.desc is not None:
            r.append(b"DESC %s" % self._str(self.desc))
        if self.obsolete:
            r.append(b"OBSOLETE")
        if self.sup:
            r.append(b"SUP %s" % self._list(self.sup))
        r.append(b"%s" % self.type)
        if self.must:
            r.append(b"MUST %s" % self._list(self.must))
        if self.may:
            r.append(b"MAY %s" % self._list(self.may))
        r.extend(self._extensions_to_wire(self.x_attrs))
        return b"( %s " % self.oid + b"\n        ".join(r) + b" )"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, ObjectClassDescription):
            raise NotImplementedError()
        if self.name is not None and other.name is not None:
            return self.name[0].upper() < other.name[0].upper()
        else:
            # A description that has been parsed always has an oid; _parse
            # asserts it before returning.
            assert self.oid is not None and other.oid is not None
            return self.oid < other.oid

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, ObjectClassDescription):
            raise NotImplementedError()
        if self.name is not None and other.name is not None:
            return self.name[0].upper() > other.name[0].upper()
        else:
            assert self.oid is not None and other.oid is not None
            return self.oid > other.oid

    def __le__(self, other: object) -> bool:
        return self == other or self < other

    def __ge__(self, other: object) -> bool:
        return self == other or self > other

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ObjectClassDescription):
            raise NotImplementedError()
        return (
            self.oid == other.oid
            and self.name == other.name
            and self.desc == other.desc
            and self.obsolete == other.obsolete
            and self.sup == other.sup
            and self.type == other.type
            and self.must == other.must
            and self.may == other.may
        )

    def __ne__(self, other: object) -> bool:
        return not (self == other)


class AttributeTypeDescription(ASN1ParserThingie, WireStrAlias):
    """
    ASN Syntax::

        AttributeTypeDescription = "(" whsp
                numericoid whsp                ; AttributeType identifier
                [ "NAME" qdescrs ]             ; name used in AttributeType
                [ "DESC" qdstring ]            ; description
                [ "OBSOLETE" whsp ]
                [ "SUP" woid ]                 ; derived from this other AttributeType
                [ "EQUALITY" woid              ; Matching Rule name
                [ "ORDERING" woid              ; Matching Rule name
                [ "SUBSTR" woid ]              ; Matching Rule name
                [ "SYNTAX" whsp noidlen whsp ] ; see section 4.3
                [ "SINGLE-VALUE" whsp ]        ; default multi-valued
                [ "COLLECTIVE" whsp ]          ; default not collective
                [ "NO-USER-MODIFICATION" whsp ]; default user modifiable
                [ "USAGE" whsp AttributeUsage ]; default userApplications
                whsp ")"

        AttributeUsage =
                "userApplications"     /
                "directoryOperation"   /
                "distributedOperation" / ; DSA-shared
                "dSAOperation"          ; DSA-specific, value depends on server

        noidlen = numericoid [ "{" len "}" ]

        len     = numericstring
    """

    def __init__(self, text: Wire | None) -> None:
        self.oid: bytes | None = None
        self.name: tuple[bytes, ...] | None = None
        self.desc: bytes | None = None
        self.obsolete: int = 0
        self.sup: bytes | None = None
        self.equality: bytes | None = None
        self.ordering: bytes | None = None
        self.substr: bytes | None = None
        self.syntax: bytes | None = None
        self.single_value: int | None = None
        self.collective: int | None = None
        self.no_user_modification: int | None = None
        self.usage: bytes | None = None

        # storage for experimental terms ("X-SOMETHING"), so we can
        # output them when stringifying.
        # An experimental term's value is a string, or a list of them.
        self.x_attrs: list[tuple[bytes, bytes | tuple[bytes, ...]]] = []

        if text is not None:
            self._parse(to_bytes(text))

    def _parse(self, text: bytes) -> None:
        assert text[:1] == b"(", "Text %s must be in parentheses." % repr(text)
        assert text[-1:] == b")", "Text %s must be in parentheses." % repr(text)
        text = text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"NAME":
            text = text[len(b"NAME ") :]
            text = text.lstrip()
            if text[:1] == b"'":
                text = text[1:]
                end = text.index(b"'")
                self.name = (text[:end],)
                text = text[end + 1 :]
            elif text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.name = self._strings_to_list(text[:end])
                text = text[end + 1 :]
            else:
                raise AssertionError()

        text = text.lstrip()

        if peekWord(text) == b"DESC":
            text = text[len(b"DESC ") :]
            text = text.lstrip()
            assert text[:1] == b"'"
            text = text[1:]
            end = text.index(b"'")
            self.desc = text[:end]
            text = text[end + 1 :]

        text = text.lstrip()

        if peekWord(text) == b"OBSOLETE":
            self.obsolete = 1
            text = text[len(b"OBSOLETE ") :]

        text = text.lstrip()

        if peekWord(text) == b"SUP":
            text = text[len(b"SUP ") :]
            text = text.lstrip()
            self.sup, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"EQUALITY":
            text = text[len(b"EQUALITY ") :]
            text = text.lstrip()
            self.equality, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"ORDERING":
            text = text[len(b"ORDERING ") :]
            text = text.lstrip()
            self.ordering, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"SUBSTR":
            text = text[len(b"SUBSTR ") :]
            text = text.lstrip()
            self.substr, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"SYNTAX":
            text = text[len(b"SYNTAX ") :]
            text = text.lstrip()
            self.syntax, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"SINGLE-VALUE":
            assert self.single_value is None
            self.single_value = 1
            text = text[len(b"SINGLE-VALUE ") :]

        text = text.lstrip()

        if peekWord(text) == b"COLLECTIVE":
            assert self.collective is None
            self.collective = 1
            text = text[len(b"COLLECTIVE ") :]

        text = text.lstrip()

        if peekWord(text) == b"NO-USER-MODIFICATION":
            assert self.no_user_modification is None
            self.no_user_modification = 1
            text = text[len(b"NO-USER-MODIFICATION ") :]

        text = text.lstrip()

        if peekWord(text) == b"USAGE":
            assert self.usage is None
            text = text[len(b"USAGE ") :]
            text = text.lstrip()
            self.usage, text = extractWord(text)

        self.x_attrs, text = self._parse_extensions(text)

        assert text == b"", "Text was not empty: %s" % repr(text)

        if self.single_value is None:
            self.single_value = 0

        if self.collective is None:
            self.collective = 0

        if self.no_user_modification is None:
            self.no_user_modification = 0

        self._check_oid(self.oid)
        assert self.name is None or self.name
        assert self.usage is None or self.usage in (
            b"userApplications",
            b"directoryOperation",
            b"distributedOperation",
            b"dSAOperation",
        )

    def __repr__(self) -> str:
        nice = {}
        for k, v in self.__dict__.items():
            nice[k] = repr(v)
        return (
            f"<{self.__class__.__name__} instance at 0x{id(self):x}"
            + (
                " oid=%(oid)s name=%(name)s desc=%(desc)s"
                + " obsolete=%(obsolete)s sup=%(sup)s"
                + " equality=%(equality)s ordering=%(ordering)s"
                + " substr=%(substr)s syntax=%(syntax)s"
                + " single_value=%(single_value)s"
                + " collective=%(collective)s"
                + " no_user_modification=%(no_user_modification)s"
                + " usage=%(usage)s>"
            )
            % nice
        )

    def toWire(self) -> bytes:
        r = []
        if self.name is not None:
            r.append(b"NAME %s" % self._str_list(self.name))
        if self.desc is not None:
            r.append(b"DESC %s" % self._str(self.desc))
        if self.obsolete:
            r.append(b"OBSOLETE")
        if self.sup is not None:
            r.append(b"SUP %s" % self.sup)
        if self.equality is not None:
            r.append(b"EQUALITY %s" % self.equality)
        if self.ordering is not None:
            r.append(b"ORDERING %s" % self.ordering)
        if self.substr is not None:
            r.append(b"SUBSTR %s" % self.substr)
        if self.syntax is not None:
            r.append(b"SYNTAX %s" % self.syntax)
        if self.single_value:
            r.append(b"SINGLE-VALUE")
        if self.collective:
            r.append(b"COLLECTIVE")
        if self.no_user_modification:
            r.append(b"NO-USER-MODIFICATION")
        if self.usage is not None:
            r.append(b"USAGE %s" % self.usage)
        r.extend(self._extensions_to_wire(self.x_attrs))
        return b"( %s " % self.oid + b"\n        ".join(r) + b" )"


class SyntaxDescription(ASN1ParserThingie, WireStrAlias):
    """
    ASN Syntax::

        SyntaxDescription = "(" whsp
                numericoid whsp
                [ "DESC" qdstring ]
                whsp ")"
    """

    def __init__(self, text: Wire | None) -> None:
        self.oid: bytes | None = None
        self.desc: bytes | None = None
        self.binary_transfer_required: bool | None = False
        self.human_readable: bool | None = True
        self.x_attrs: list[tuple[bytes, bytes | tuple[bytes, ...]]] = []

        if text is not None:
            self._parse(to_bytes(text))

    def _parse(self, text: bytes) -> None:

        assert text[:1] == b"("
        assert text[-1:] == b")"
        text = text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"DESC":
            text = text[len(b"DESC ") :]
            text = text.lstrip()
            assert text[:1] == b"'"
            text = text[1:]
            end = text.index(b"'")
            self.desc = text[:end]
            text = text[end + 1 :]

        text = text.lstrip()

        if peekWord(text) == b"X-BINARY-TRANSFER-REQUIRED":
            self.binary_transfer_required = True
            text = text[len(b"X-BINARY-TRANSFER-REQUIRED 'TRUE' ") :]
            text = text.lstrip()

        text = text.lstrip()

        if peekWord(text) == b"X-NOT-HUMAN-READABLE":
            self.human_readable = False
            text = text[len(b"X-NOT-HUMAN-READABLE 'TRUE' ") :]
            text = text.lstrip()

        text = text.lstrip()

        self.x_attrs, text = self._parse_extensions(text)

        assert text == b"", "Text was not empty: %s" % repr(text)

        self._check_oid(self.oid)

    def toWire(self) -> bytes:
        assert self.oid is not None
        r = [self.oid]

        if self.desc is not None:
            r.append(b"DESC %s" % self._str(self.desc))
        if self.binary_transfer_required is True:
            r.append(b"X-BINARY-TRANSFER-REQUIRED 'TRUE'")
        if self.human_readable is False:
            r.append(b"X-NOT-HUMAN-READABLE 'TRUE'")
        r.extend(self._extensions_to_wire(self.x_attrs))

        return b"( " + b" ".join(r) + b" )"

    def __repr__(self) -> str:
        nice = {}
        for k, v in self.__dict__.items():
            nice[k] = repr(v)
        return (
            f"<{self.__class__.__name__} instance at 0x{id(self):x}"
            + (" oid=%(oid)s desc=%(desc)s>") % nice
        )


class MatchingRuleDescription(ASN1ParserThingie, WireStrAlias):
    """
    ASN Syntax::

        MatchingRuleDescription = "(" whsp
                numericoid whsp  ; MatchingRule identifier
                [ "NAME" qdescrs ]
                [ "DESC" qdstring ]
                [ "OBSOLETE" whsp ]
                "SYNTAX" numericoid
                whsp ")"
    """

    def __init__(self, text: Wire | None) -> None:
        self.oid: bytes | None = None
        self.name: tuple[bytes, ...] | None = None
        self.desc: bytes | None = None
        self.obsolete: int | None = None
        self.syntax: bytes | None = None
        self.x_attrs: list[tuple[bytes, bytes | tuple[bytes, ...]]] = []

        if text is not None:
            self._parse(to_bytes(text))

    def _parse(self, text: bytes) -> None:

        assert text[:1] == b"("
        assert text[-1:] == b")"
        text = text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"NAME":
            text = text[len(b"NAME ") :]
            text = text.lstrip()
            if text[:1] == b"'":
                text = text[1:]
                end = text.index(b"'")
                self.name = (text[:end],)
                text = text[end + 1 :]
            elif text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.name = self._strings_to_list(text[:end])
                text = text[end + 1 :]
            else:
                raise AssertionError()

        text = text.lstrip()

        if peekWord(text) == b"DESC":
            text = text[len(b"DESC ") :]
            text = text.lstrip()
            assert text[:1] == b"'"
            text = text[1:]
            end = text.index(b"'")
            self.desc = text[:end]
            text = text[end + 1 :]

        text = text.lstrip()

        if peekWord(text) == b"OBSOLETE":
            self.obsolete = 1
            text = text[len(b"OBSOLETE ") :]

        text = text.lstrip()

        if peekWord(text) == b"SYNTAX":
            text = text[len(b"SYNTAX ") :]
            text = text.lstrip()
            self.syntax, text = extractWord(text)

        text = text.lstrip()

        self.x_attrs, text = self._parse_extensions(text)

        assert text == b"", "Text was not empty: %s" % repr(text)

        if self.obsolete is None:
            self.obsolete = 0
        self._check_oid(self.oid)
        assert self.syntax

    def toWire(self) -> bytes:
        assert self.oid is not None
        r = [self.oid]

        if self.name is not None:
            r.append(b"NAME %s" % self._str_list(self.name))
        if self.desc is not None:
            r.append(b"DESC %s" % self._str(self.desc))
        if self.obsolete:
            r.append(b"OBSOLETE")
        r.append(b"SYNTAX %s" % self.syntax)
        r.extend(self._extensions_to_wire(self.x_attrs))

        return b"( " + b" ".join(r) + b" )"

    def __repr__(self) -> str:
        nice = {}
        for k, v in self.__dict__.items():
            nice[k] = repr(v)
        return (
            f"<{self.__class__.__name__} instance at 0x{id(self):x}"
            + (" oid=%(oid)s desc=%(desc)s>") % nice
        )
