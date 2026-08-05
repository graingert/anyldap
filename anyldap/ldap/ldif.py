"""python-ldap's ``ldif`` module: reading and writing LDIF (RFC 2849).

anyldap has an LDIF reader of its own in
:mod:`anyldap.protocols.ldap.ldifprotocol`, but it is a line-receiving
protocol that answers with the objects the rest of anyldap is built out of,
so it is not what code written against python-ldap asks for. This is that
module instead: the same classes, taking the same arguments and handing back
the same ``(dn, entry)`` pairs, so a script that reads or writes LDIF ports
without being rewritten.

Nothing here touches the network, so nothing here is awaited::

    from anyldap.ldap import ldif

    records = ldif.LDIFRecordList(open("people.ldif"))
    records.parse()
    for dn, entry in records.all_records:
        print(dn, entry)

An attribute value is ``bytes`` and a DN is ``str``, which is what
python-ldap makes of them too.
"""

import re
from base64 import b64decode, b64encode
from collections.abc import Iterable, Mapping, Sequence
from typing import Protocol, cast
from urllib.parse import urlparse

from anyldap.ldap import _fetch

__all__ = [
    "CHANGE_TYPES",
    "MOD_OP_INTEGER",
    "MOD_OP_STR",
    "SAFE_STRING_PATTERN",
    "LDIFCopy",
    "LDIFParser",
    "LDIFRecordList",
    "LDIFWriter",
    "is_dn",
    "ldif_pattern",
    "list_dict",
    "valid_changetype_dict",
]

attrtype_pattern = r"[\w;.-]+(;[\w_-]+)*"
attrvalue_pattern = r'(([^,]|\\,)+|".*?")'
attrtypeandvalue_pattern = attrtype_pattern + r"[ ]*=[ ]*" + attrvalue_pattern
rdn_pattern = attrtypeandvalue_pattern + r"([ ]*\+[ ]*" + attrtypeandvalue_pattern + r")*[ ]*"
dn_pattern = rdn_pattern + r"([ ]*,[ ]*" + rdn_pattern + r")*[ ]*"
dn_regex = re.compile("^%s$" % dn_pattern)

ldif_pattern = "^((dn(:|::) %(dn_pattern)s)|(%(attrtype_pattern)s(:|::) .*)$)+" % vars()

# What a change record's operation is called in LDIF, and the ldap.MOD_*
# constant that says the same thing.
MOD_OP_INTEGER = {
    "add": 0,  # ldap.MOD_ADD
    "delete": 1,  # ldap.MOD_DELETE
    "replace": 2,  # ldap.MOD_REPLACE
    "increment": 3,  # ldap.MOD_INCREMENT
}

MOD_OP_STR = {0: "add", 1: "delete", 2: "replace", 3: "increment"}

CHANGE_TYPES = ["add", "delete", "modify", "modrdn"]
valid_changetype_dict: dict[str, None] = {}
for c in CHANGE_TYPES:
    valid_changetype_dict[c] = None


def is_dn(s: str) -> int:
    """returns 1 if s is a LDAP DN"""
    if s == "":
        return 1
    rm = dn_regex.match(s)
    return rm is not None and rm.group(0) == s


# A value matching this cannot be written after a plain ``:``, so it is
# written base64-encoded instead: RFC 2849 lets only safe ASCII be written
# as it stands.
SAFE_STRING_PATTERN = b"(^(\000|\n|\r| |:|<)|[\000\n\r\200-\377]+|[ ]+$)"
safe_string_re = re.compile(SAFE_STRING_PATTERN)


def list_dict(l: Iterable[str]) -> dict[str, None]:
    """return a dictionary with all items of l being the keys of the dictionary"""
    return {i: None for i in l}


class _TextOutput(Protocol):
    """Somewhere LDIF is written: a file opened in *text* mode."""

    def write(self, s: str, /) -> object: ...


class _Input(Protocol):
    """Somewhere LDIF is read from, opened in text or in binary mode."""

    def read(self, size: int, /) -> str | bytes: ...

    def readline(self) -> str | bytes: ...


# A record, as python-ldap spells one: an entry is attributes to their
# values, a change is the modlist that LDAPObject.modify() takes.
Entry = Mapping[str, Sequence[bytes]]
AddModlist = Sequence[tuple[str, Sequence[bytes]]]
ModifyModlist = Sequence[tuple[int, str, Sequence[bytes] | None]]

# An entry as it was read. A value the LDIF gave as a URL is None when the
# URL was not one of the schemes to fetch, which is what python-ldap stores
# for it too -- so a parsed entry is not always one that can be written.
ParsedEntry = dict[str, list[bytes | None]]


class LDIFWriter:
    """
    Write LDIF entry or change records to file object
    Copy LDIF input to a file output object containing all data retrieved
    via URLs
    """

    def __init__(
        self,
        output_file: _TextOutput,
        base64_attrs: Iterable[str] | None = None,
        cols: int = 76,
        line_sep: str = "\n",
    ) -> None:
        """
        output_file
            file object for output; should be opened in *text* mode
        base64_attrs
            list of attribute types to be base64-encoded in any case
        cols
            Specifies how many columns a line may have before it's
            folded into many lines.
        line_sep
            String used as line separator
        """
        self._output_file = output_file
        self._base64_attrs = list_dict([a.lower() for a in (base64_attrs or [])])
        self._cols = cols
        self._last_line_sep = line_sep
        self.records_written = 0

    def _unfold_lines(self, line: str) -> None:
        """Write string line as one or more folded lines"""
        # Check maximum line length
        line_len = len(line)
        if line_len <= self._cols:
            self._output_file.write(line)
            self._output_file.write(self._last_line_sep)
        else:
            # Fold line
            pos = self._cols
            self._output_file.write(line[0 : min(line_len, self._cols)])
            self._output_file.write(self._last_line_sep)
            while pos < line_len:
                self._output_file.write(" ")
                self._output_file.write(line[pos : min(line_len, pos + self._cols - 1)])
                self._output_file.write(self._last_line_sep)
                pos = pos + self._cols - 1

    def _needs_base64_encoding(self, attr_type: str, attr_value: bytes) -> bool:
        """
        returns 1 if attr_value has to be base-64 encoded because
        of special chars or because attr_type is in self._base64_attrs
        """
        return (
            attr_type.lower() in self._base64_attrs
            or safe_string_re.search(attr_value) is not None
        )

    def _unparseAttrTypeandValue(self, attr_type: str, attr_value: bytes) -> None:
        """
        Write a single attribute type/value pair

        attr_type
              attribute type (text)
        attr_value
              attribute value (bytes)
        """
        if self._needs_base64_encoding(attr_type, attr_value):
            # Encode with base64
            encoded = b64encode(attr_value).decode("ascii")
            encoded = encoded.replace("\n", "")
            self._unfold_lines(":: ".join([attr_type, encoded]))
        else:
            self._unfold_lines(": ".join([attr_type, attr_value.decode("ascii")]))

    def _unparseEntryRecord(self, entry: Entry) -> None:
        """
        entry
            dictionary holding an entry
        """
        for attr_type, values in sorted(entry.items()):
            for attr_value in values:
                self._unparseAttrTypeandValue(attr_type, attr_value)

    def _unparseChangeRecord(self, modlist: AddModlist | ModifyModlist) -> None:
        """
        modlist
            list of additions (2-tuple) or modifications (3-tuple)
        """
        mod_len = len(modlist[0])
        if mod_len == 2:
            changetype = "add"
        elif mod_len == 3:
            changetype = "modify"
        else:
            raise ValueError("modlist item of wrong length: %d" % (mod_len))
        self._unparseAttrTypeandValue("changetype", changetype.encode("ascii"))
        for mod in modlist:
            mod_type: str
            mod_vals: Sequence[bytes] | None
            if mod_len == 2:
                mod_type, mod_vals = mod  # type: ignore[misc]
            else:
                mod_op, mod_type, mod_vals = mod  # type: ignore[misc]
                self._unparseAttrTypeandValue(
                    MOD_OP_STR[mod_op], mod_type.encode("ascii")
                )
            if mod_vals:
                for mod_val in mod_vals:
                    self._unparseAttrTypeandValue(mod_type, mod_val)
            if mod_len == 3:
                self._output_file.write("-" + self._last_line_sep)

    def unparse(self, dn: str, record: Entry | AddModlist | ModifyModlist) -> None:
        """
        dn
              string-representation of distinguished name
        record
              Either a dictionary holding the LDAP entry {attrtype:record}
              or a list with a modify list like for LDAPObject.modify().
        """
        # Start with line containing the distinguished name
        self._unparseAttrTypeandValue("dn", dn.encode("utf-8"))
        # Dispatch to record type specific writers
        if isinstance(record, dict):
            self._unparseEntryRecord(record)
        elif isinstance(record, list):
            self._unparseChangeRecord(record)
        else:
            raise ValueError(
                "Argument record must be dictionary or list instead of %s"
                % (repr(record))
            )
        # Write empty line separating the records
        self._output_file.write(self._last_line_sep)
        # Count records written
        self.records_written = self.records_written + 1


class LDIFParser:
    """
    Base class for a LDIF parser. Applications should sub-class this
    class and override method handle() to implement something meaningful.

    Public class attributes:

    records_read
          Counter for records processed so far
    """

    def __init__(
        self,
        input_file: _Input,
        ignored_attr_types: Iterable[str] | None = None,
        max_entries: int = 0,
        process_url_schemes: Iterable[str] | None = None,
        line_sep: str = "\n",
    ) -> None:
        """
        Parameters:
        input_file
            File-object to read the LDIF input from
        ignored_attr_types
            Attributes with these attribute type names will be ignored.
        max_entries
            If non-zero specifies the maximum number of entries to be
            read from f.
        process_url_schemes
            List containing strings with URLs schemes to process.
            An empty list turns off all URL processing and the attribute
            is ignored completely. Only ``file``, ``http`` and ``https``
            can be fetched; python-ldap hands the URL to urllib, which
            fetches whatever it happens to support.
        line_sep
            String used as line separator
        """
        self._input_file = input_file
        # Detect whether the file is open in text or bytes mode.
        self._file_sends_bytes = isinstance(self._input_file.read(0), bytes)
        self._max_entries = max_entries
        self._process_url_schemes = list_dict(
            [s.lower() for s in (process_url_schemes or [])]
        )
        self._ignored_attr_types = list_dict(
            [a.lower() for a in (ignored_attr_types or [])]
        )
        self._last_line_sep = line_sep
        self.version: int | None = None
        # Initialize counters
        self.line_counter = 0
        self.byte_counter = 0
        self.records_read = 0
        self.changetype_counter: dict[str | None, int] = dict.fromkeys(CHANGE_TYPES, 0)
        # Store some symbols for better performance
        self._b64decode = b64decode
        # Read very first line
        self._last_line = self._readline()

    def handle(self, dn: str, entry: ParsedEntry) -> None:
        """
        Process a single content LDIF record. This method should be
        implemented by applications using LDIFParser.
        """

    def _readline(self) -> str | None:
        line = self._input_file.readline()
        if isinstance(line, bytes):
            # The RFC does not allow UTF-8 values; we support it as a
            # non-official, backwards compatibility layer
            s = line.decode("utf-8")
        else:
            s = line
        self.line_counter = self.line_counter + 1
        self.byte_counter = self.byte_counter + len(s)
        if not s:
            return None
        elif s[-2:] == "\r\n":
            return s[:-2]
        elif s[-1:] == "\n":
            return s[:-1]
        else:
            return s

    def _unfold_lines(self) -> str:
        """Unfold several folded lines with trailing space into one line"""
        if self._last_line is None:
            raise EOFError(
                "EOF reached after %d lines (%d bytes)"
                % (self.line_counter, self.byte_counter)
            )
        unfolded_lines = [self._last_line]
        next_line = self._readline()
        while next_line and next_line[0] == " ":
            unfolded_lines.append(next_line[1:])
            next_line = self._readline()
        self._last_line = next_line
        return "".join(unfolded_lines)

    def _next_key_and_value(self) -> tuple[str | None, bytes | None]:
        """
        Parse a single attribute type and value pair from one or
        more lines of LDIF data

        Returns attr_type (text) and attr_value (bytes)
        """
        # Reading new attribute line
        unfolded_line = self._unfold_lines()
        # Ignore comments which can also be folded
        while unfolded_line and unfolded_line[0] == "#":
            unfolded_line = self._unfold_lines()
        if not unfolded_line:
            return None, None
        if unfolded_line == "-":
            return "-", None
        try:
            colon_pos = unfolded_line.index(":")
        except ValueError:
            raise ValueError("no value-spec in %s" % (repr(unfolded_line))) from None
        attr_type = unfolded_line[0:colon_pos]
        # if needed attribute value is BASE64 decoded
        value_spec = unfolded_line[colon_pos : colon_pos + 2]
        attr_value: bytes | None
        if value_spec == ": ":
            # All values should be valid ascii; we support UTF-8 as a
            # non-official, backwards compatibility layer.
            attr_value = unfolded_line[colon_pos + 2 :].lstrip().encode("utf-8")
        elif value_spec == "::":
            # attribute value needs base64-decoding
            # base64 makes sens only for ascii
            attr_value = self._b64decode(
                unfolded_line[colon_pos + 2 :].encode("ascii")
            )
        elif value_spec == ":<":
            # fetch attribute value from URL
            url = unfolded_line[colon_pos + 2 :].strip()
            attr_value = None
            if self._process_url_schemes:
                u = urlparse(url)
                if u[0] in self._process_url_schemes:
                    attr_value = _fetch.read(url)
        else:
            # All values should be valid ascii; we support UTF-8 as a
            # non-official, backwards compatibility layer.
            attr_value = unfolded_line[colon_pos + 1 :].encode("utf-8")
        return attr_type, attr_value

    def _consume_empty_lines(self) -> tuple[str | None, bytes | None]:
        """
        Consume empty lines until first non-empty line.
        Must only be used between full records!

        Returns non-empty key-value-tuple.
        """
        # Local symbol for better performance
        next_key_and_value = self._next_key_and_value
        # Consume empty lines
        try:
            k, v = next_key_and_value()
            while k is None and v is None:
                k, v = next_key_and_value()
        except EOFError:
            k, v = None, None
        return k, v

    def parse_entry_records(self) -> None:
        """Continuously read and parse LDIF entry records"""
        # Local symbol for better performance
        next_key_and_value = self._next_key_and_value

        # Consume empty lines
        k, v = self._consume_empty_lines()
        # Consume 'version' line
        if k == "version":
            assert v is not None
            self.version = int(v.decode("ascii"))
            k, v = self._consume_empty_lines()

        # Loop for processing whole records
        while k is not None and (
            not self._max_entries or self.records_read < self._max_entries
        ):
            # Consume first line which must start with "dn: "
            if k != "dn":
                raise ValueError(
                    'Line %d: First line of record does not start with "dn:": %s'
                    % (self.line_counter, repr(k))
                )
            # Value of a 'dn' field *has* to be valid UTF-8
            # k is text, v is bytes.
            assert v is not None
            dn = v.decode("utf-8")
            if not is_dn(dn):
                raise ValueError(
                    "Line %d: Not a valid string-representation for dn: %s."
                    % (self.line_counter, repr(dn))
                )
            entry: ParsedEntry = {}
            # Consume second line of record
            k, v = next_key_and_value()

            # Loop for reading the attributes
            while k is not None:
                # Add the attribute to the entry if not ignored attribute
                if k.lower() not in self._ignored_attr_types:
                    entry.setdefault(k, []).append(v)
                # Read the next line within the record
                try:
                    k, v = next_key_and_value()
                except EOFError:
                    k, v = None, None

            # handle record
            self.handle(dn, entry)
            self.records_read = self.records_read + 1
            # Consume empty separator line(s)
            k, v = self._consume_empty_lines()

    def parse(self) -> None:
        """Invokes LDIFParser.parse_entry_records() for backward compatibility"""
        return self.parse_entry_records()

    def handle_modify(
        self,
        dn: str,
        modops: list[tuple[int, str, list[bytes] | None]],
        controls: list[tuple[str, str, str | None]] | None = None,
    ) -> None:
        """
        Process a single LDIF record representing a single modify operation.
        This method should be implemented by applications using LDIFParser.
        """

    def parse_change_records(self) -> None:
        # Local symbol for better performance
        next_key_and_value = self._next_key_and_value
        # Consume empty lines
        k, v = self._consume_empty_lines()
        # Consume 'version' line
        if k == "version":
            assert v is not None
            self.version = int(v)
            k, v = self._consume_empty_lines()

        # Loop for processing whole records
        while k is not None and (
            not self._max_entries or self.records_read < self._max_entries
        ):
            # Consume first line which must start with "dn: "
            if k != "dn":
                raise ValueError(
                    'Line %d: First line of record does not start with "dn:": %s'
                    % (self.line_counter, repr(k))
                )
            # Value of a 'dn' field *has* to be valid UTF-8
            # k is text, v is bytes.
            assert v is not None
            dn = v.decode("utf-8")
            if not is_dn(dn):
                raise ValueError(
                    "Line %d: Not a valid string-representation for dn: %s."
                    % (self.line_counter, repr(dn))
                )
            # Consume second line of record
            k, v = next_key_and_value()
            # Read "control:" lines
            controls = []
            while k is not None and k == "control":
                # v is still bytes, spec says it should be valid utf-8; decode it.
                assert v is not None
                control = v.decode("utf-8")
                control_value: str | None
                try:
                    control_type, criticality, control_value = control.split(" ", 2)
                except ValueError:
                    control_value = None
                    control_type, criticality = control.split(" ", 1)
                controls.append((control_type, criticality, control_value))
                k, v = next_key_and_value()

            # Determine changetype first
            changetype = None
            # Consume changetype line of record
            if k == "changetype":
                # v is still bytes, spec says it should be valid utf-8; decode it.
                assert v is not None
                changetype = v.decode("utf-8")
                if changetype not in valid_changetype_dict:
                    raise ValueError("Invalid changetype: %s" % repr(changetype))
                k, v = next_key_and_value()

            if changetype == "modify":
                # From here we assume a change record is read with changetype: modify
                modops: list[tuple[int, str, list[bytes] | None]] = []

                try:
                    # Loop for reading the list of modifications
                    while k is not None:
                        # Extract attribute mod-operation (add, delete, replace)
                        try:
                            modop = MOD_OP_INTEGER[k]
                        except KeyError:
                            raise ValueError(
                                "Line %d: Invalid mod-op string: %s"
                                % (self.line_counter, repr(k))
                            ) from None
                        # we now have the attribute name to be modified
                        # v is still bytes, spec says it should be valid utf-8.
                        assert v is not None
                        modattr = v.decode("utf-8")
                        modvalues = []
                        try:
                            k, v = next_key_and_value()
                        except EOFError:
                            k, v = None, None
                        while k == modattr:
                            assert v is not None
                            modvalues.append(v)
                            try:
                                k, v = next_key_and_value()
                            except EOFError:
                                k, v = None, None
                        modops.append((modop, modattr, modvalues or None))
                        k, v = next_key_and_value()
                        if k == "-":
                            # Consume next line
                            k, v = next_key_and_value()
                except EOFError:
                    k, v = None, None

                if modops:
                    # append entry to result list
                    self.handle_modify(dn, modops, controls)

            else:
                # Consume the unhandled change record
                while k is not None:
                    k, v = next_key_and_value()

            # Consume empty separator line(s)
            k, v = self._consume_empty_lines()

            # Increment record counters
            self.changetype_counter[changetype] = (
                self.changetype_counter.get(changetype, 0) + 1
            )
            self.records_read = self.records_read + 1


class LDIFRecordList(LDIFParser):
    """
    Collect all records of a LDIF file. It can be a memory hog!

    Records are stored in :attr:`.all_records` as a single list
    of 2-tuples (dn, entry), after calling
    :meth:`~anyldap.ldap.ldif.LDIFParser.parse`.
    """

    def __init__(
        self,
        input_file: _Input,
        ignored_attr_types: Iterable[str] | None = None,
        max_entries: int = 0,
        process_url_schemes: Iterable[str] | None = None,
    ) -> None:
        LDIFParser.__init__(
            self, input_file, ignored_attr_types, max_entries, process_url_schemes
        )

        #: List storing parsed records.
        self.all_records: list[tuple[str, ParsedEntry]] = []
        self.all_modify_changes: list[
            tuple[
                str,
                list[tuple[int, str, list[bytes] | None]],
                list[tuple[str, str, str | None]] | None,
            ]
        ] = []

    def handle(self, dn: str, entry: ParsedEntry) -> None:
        """
        Append a single record to the list of all records (:attr:`.all_records`).
        """
        self.all_records.append((dn, entry))

    def handle_modify(
        self,
        dn: str,
        modops: list[tuple[int, str, list[bytes] | None]],
        controls: list[tuple[str, str, str | None]] | None = None,
    ) -> None:
        """
        Process a single LDIF record representing a single modify operation.
        This method should be implemented by applications using LDIFParser.
        """
        # python-ldap hands back None rather than the controls it read, and
        # code written against it reads a None here.
        self.all_modify_changes.append((dn, modops, None))


class LDIFCopy(LDIFParser):
    """
    Copy LDIF input to LDIF output containing all data retrieved
    via URLs
    """

    def __init__(
        self,
        input_file: _Input,
        output_file: _TextOutput,
        ignored_attr_types: Iterable[str] | None = None,
        max_entries: int = 0,
        process_url_schemes: Iterable[str] | None = None,
        base64_attrs: Iterable[str] | None = None,
        cols: int = 76,
        line_sep: str = "\n",
    ) -> None:
        """See LDIFParser.__init__() and LDIFWriter.__init__()"""
        LDIFParser.__init__(
            self, input_file, ignored_attr_types, max_entries, process_url_schemes
        )
        self._output_ldif = LDIFWriter(output_file, base64_attrs, cols, line_sep)

    def handle(self, dn: str, entry: ParsedEntry) -> None:
        """Write single LDIF record to output file."""
        # A value that was named by a URL and not fetched cannot be written
        # back out; python-ldap does not check for one either.
        self._output_ldif.unparse(dn, cast(Entry, entry))
