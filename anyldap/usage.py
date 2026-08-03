"""
Command line argument/options available to various anyldap tools.
"""
import sys
from collections.abc import Iterator, Sequence
from typing import Any, ClassVar, Protocol

from anyldap.protocols import pureldap
from anyldap.protocols.ldap import distinguishedname

# An option's value is whatever its own handler makes of it: a string from
# the command line, a flag, a parsed scope, a mapping of service locations.
# Reading one back is untyped by nature, which is what Any is for.
OptionValue = Any

__all__ = [
    "Options",
    "Options_base",
    "Options_base_optional",
    "Options_bind",
    "Options_bind_mandatory",
    "Options_scope",
    "Options_service_location",
    "UsageError",
]


class UsageError(Exception):
    pass


class HasOptions(Protocol):
    """What the option mixins need of the Options they are mixed into."""

    opts: dict[str, OptionValue]


class Options:
    optParameters: ClassVar[Sequence[tuple[str, str | None, object, str]]] = ()
    optFlags: ClassVar[Sequence[tuple[str, str | None, str]]] = ()

    def __init__(self) -> None:
        self.opts: dict[str, OptionValue] = {}
        for name, _, default, _ in self._iter_opt_parameters():
            self.opts[name] = default
        for name, _, _ in self._iter_opt_flags():
            self.opts[name] = False

    def __getitem__(self, key: str) -> OptionValue:
        return self.opts[key]

    def __setitem__(self, key: str, value: OptionValue) -> None:
        self.opts[key] = value

    @classmethod
    def _iter_opt_parameters(
        cls,
    ) -> Iterator[tuple[str, str | None, object, str]]:
        seen = set()
        for base in reversed(cls.__mro__):
            for item in getattr(base, "optParameters", ()):
                name = item[0]
                if name not in seen:
                    seen.add(name)
                    yield item

    @classmethod
    def _iter_opt_flags(cls) -> Iterator[tuple[str, str | None, str]]:
        seen = set()
        for base in reversed(cls.__mro__):
            for item in getattr(base, "optFlags", ()):
                name = item[0]
                if name not in seen:
                    seen.add(name)
                    yield item

    def parseOptions(
        self, options: Sequence[str] | None = None
    ) -> dict[str, OptionValue]:
        if options is None:
            options = sys.argv[1:]

        parameters = {name: (short, default, doc) for name, short, default, doc in self._iter_opt_parameters()}
        flags = {name: (short, doc) for name, short, doc in self._iter_opt_flags()}

        index = 0
        option = ""
        positional: Sequence[str] = []
        while index < len(options):
            option = options[index]
            if not option.startswith("-"):
                positional = options[index:]
                break
            if option == "--":
                positional = options[index + 1 :]
                break

            value: str | None = None
            key: str | None
            if option.startswith("--"):
                key = option[2:]
                if "=" in key:
                    key, value = key.split("=", 1)
            else:
                short = option[1:]
                key = None
                for name, (candidate, _, _) in parameters.items():
                    if candidate == short:
                        key = name
                        break
                if key is None:
                    for name, (candidate, _) in flags.items():
                        if candidate == short:
                            key = name
                            break
                if key is None:
                    raise UsageError(f"Unknown option: {option}")

            assert key is not None
            attr_name = key.replace("-", "_")
            handler = getattr(self, f"opt_{attr_name}", None)
            if key in flags:
                if value is not None:
                    raise UsageError(f"Option --{key} does not take a value")
                if handler is not None:
                    handler()
                else:
                    self.opts[key] = True
            elif key in parameters:
                if value is None:
                    index += 1
                    if index >= len(options):
                        raise UsageError(f"Option --{key} requires an argument")
                    value = options[index]
                if handler is not None:
                    handler(value)
                else:
                    self.opts[key] = value
            elif handler is not None:
                if value is None:
                    index += 1
                    if index >= len(options):
                        raise UsageError(f"Option --{key} requires an argument")
                    value = options[index]
                handler(value)
            else:
                raise UsageError(f"Unknown option: {option}")

            index += 1

        parse_args = getattr(self, "parseArgs", None)
        if parse_args is not None:
            try:
                parse_args(*positional)
            except TypeError as exc:
                raise UsageError(f"Invalid arguments: {exc}") from exc
        elif positional and option != "--":
            raise UsageError(f"Unknown argument: {positional[0]}")

        self.postOptions()
        return self.opts

    def postOptions(self) -> None:
        for name in dir(self):
            if name.startswith("postOptions_"):
                getattr(self, name)()


class Options_service_location:
    """
    Mixing for providing the --service-location option.
    """

    def opt_service_location(self: HasOptions, value: str) -> None:
        """Service location, in the form BASEDN:HOST[:PORT]"""

        if "service-location" not in self.opts:
            self.opts["service-location"] = {}

        if ":" not in value:
            raise UsageError("service-location must specify host")

        base, location = value.split(":", 1)
        try:
            dn = distinguishedname.DistinguishedName(base)
        except distinguishedname.InvalidRelativeDistinguishedName as e:
            raise UsageError(str(e))

        host: str
        port: str | None
        if ":" in location:
            host, port = location.split(":", 1)
        else:
            host, port = location, None

        self.opts["service-location"][dn] = (host, port)

    def postOptions_service_location(self: HasOptions) -> None:
        if "service-location" not in self.opts:
            self.opts["service-location"] = {}


class Options_base_optional:
    optParameters: ClassVar[Sequence[tuple[str, str | None, object, str]]] = (
        ("base", None, None, "LDAP base dn"),
    )


class Options_base(Options_base_optional):
    def postOptions_base(self: HasOptions) -> None:
        # check that some things are given
        if self.opts["base"] is None:
            raise UsageError("base must be given")


class Options_scope:
    optParameters: ClassVar[Sequence[tuple[str, str | None, object, str]]] = (
        ("scope", None, "sub", "LDAP search scope (one of base, one, sub)"),
    )

    def postOptions_scope(self: HasOptions) -> None:
        synonyms = {
            "base": "baseObject",
            "single": "singleLevel",
            "subtree": "wholeSubtree",
            "sub": "wholeSubtree",
        }
        scope: str = self.opts["scope"]
        name = synonyms.get(scope, scope)
        try:
            resolved = getattr(pureldap, "LDAP_SCOPE_" + name)
        except AttributeError:
            raise UsageError(f"bad scope: {name}")
        self.opts["scope"] = resolved


class Options_bind:
    optParameters: ClassVar[Sequence[tuple[str, str | None, object, str]]] = (
        ("binddn", None, None, "use Distinguished Name to bind to the directory"),
        ("bind-auth-fd", None, None, "read bind password from filedescriptor"),
    )

    def postOptions_bind_auth_fd_numeric(self: HasOptions) -> None:
        val = self.opts["bind-auth-fd"]
        if val is not None:
            try:
                val = int(val)
            except ValueError:
                raise UsageError("bind-auth-fd value must be numeric")
            self.opts["bind-auth-fd"] = val


class Options_bind_mandatory(Options_bind):
    def postOptions_bind_mandatory(self: HasOptions) -> None:
        if not self.opts["binddn"]:
            raise UsageError("binddn must be given")
