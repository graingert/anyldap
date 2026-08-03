"""
Test cases for anyldap.usage
"""
import re
import sys

import pytest

from anyldap.protocols.ldap.distinguishedname import DistinguishedName
from anyldap.usage import (
    Options,
    Options_base,
    Options_bind_mandatory,
    Options_scope,
    Options_service_location,
    UsageError,
)


def test_duplicate_flag_declarations_are_yielded_once() -> None:
    class DuplicateFlags(Options):
        optFlags = (("verbose", "v", "first"), ("verbose", "v", "second"))

    assert list(DuplicateFlags._iter_opt_flags()) == [("verbose", "v", "first")]


class ScopeOptionsImplementation(Options, Options_scope):
    """


class FirstFlagOptions(Options):
    optFlags = (("shared", "s", "first"),)


class DuplicateFlagOptions(FirstFlagOptions):
    optFlags = (("shared", "s", "second"),)


def test_duplicate_inherited_flags_are_yielded_once() -> None:
    assert list(DuplicateFlagOptions._iter_opt_flags()) == [
        ("shared", "s", "first")
    ]
    Minimal implementation for a command line using `Options_scope`.
    """


class TestOptions_scope:
    def test_parseOptions_bad_scope(self) -> None:
        """
        It fails to parse the option when the scope is bad
        """
        with pytest.raises(
            UsageError, match=re.escape("bad scope: this is a bad scope")
        ):
            ScopeOptionsImplementation().parseOptions(
                options=["--scope", "this is a bad scope"]
            )

    def test_parseOptions_default(self) -> None:
        """
        When no explicit options is provided it will set an empty dict.
        """
        sut = ServiceLocationOptionsImplementation()
        assert "service-location" not in sut.opts

        sut.parseOptions(options=[])

        assert {} == sut.opts["service-location"]


class ServiceLocationOptionsImplementation(Options, Options_service_location):
    """Minimal implementation for a command line using service locations."""


class CompleteOptions(
    Options,
    Options_service_location,
    Options_scope,
    Options_base,
    Options_bind_mandatory,
):
    optFlags = (("verbose", "v", "verbose output"),)
    optParameters = (("custom", "c", "default", "custom value"),)

    def opt_custom_handler(self, value: str) -> None:
        self.opts["handled"] = value

    def opt_toggle(self, value: str) -> None:
        self.opts["toggled"] = value


class HandlerOptions(Options):
    optFlags = (("verbose", "v", "verbose output"),)
    optParameters = (("custom", "c", None, "custom value"),)

    def opt_verbose(self) -> None:
        self.opts["handled-flag"] = True

    def opt_custom(self, value: str) -> None:
        self.opts["handled-parameter"] = value


class TestCompleteOptions:
    def test_uses_process_arguments_and_option_handlers(self) -> None:
        previous = sys.argv
        try:
            sys.argv = ["command", "--verbose", "--custom=value"]
            result = HandlerOptions().parseOptions()
        finally:
            sys.argv = previous
        assert result["handled-flag"]
        assert result["handled-parameter"] == "value"

    def test_mapping_protocol(self) -> None:
        options = Options()
        options["key"] = "value"
        assert options["key"] == "value"

    def test_long_short_flags_and_parameters(self) -> None:
        options = CompleteOptions()
        result = options.parseOptions(
            [
                "--base=dc=example,dc=com",
                "--binddn",
                "cn=admin",
                "--bind-auth-fd=7",
                "--scope=single",
                "--service-location=dc=example,dc=com:ldap.example.com:1389",
                "-v",
                "-c",
                "chosen",
                "--custom-handler",
                "handled",
                "--toggle=enabled",
            ]
        )
        assert result["verbose"]
        assert result["custom"] == "chosen"
        assert result["handled"] == "handled"
        assert result["toggled"] == "enabled"
        assert result["bind-auth-fd"] == 7

    def test_double_dash_stops_option_parsing(self) -> None:
        options = Options()
        assert options.parseOptions(["--", "ignored"]) == {}

    def test_positional_arguments_are_dispatched(self) -> None:
        options = HandlerOptions()
        received: list[str] = []
        # parseOptions looks for this by name; the Options it is mixed into
        # does not declare one.
        options.parseArgs = lambda *args: received.extend(args)  # type: ignore[attr-defined]
        options.parseOptions(["first", "second"])
        assert received == ["first", "second"]

    def test_option_errors(self) -> None:
        cases = [
            (["argument"], "Unknown argument"),
            (["--unknown"], "Unknown option"),
            (["-z"], "Unknown option"),
            (["--verbose=yes"], "does not take a value"),
            (["--custom"], "requires an argument"),
            (["--toggle"], "requires an argument"),
        ]
        for arguments, message in cases:
            with pytest.raises(UsageError, match=message):
                CompleteOptions().parseOptions(arguments)

    def test_required_values(self) -> None:
        with pytest.raises(UsageError, match="base must be given"):
            CompleteOptions().parseOptions(["--binddn=cn=admin"])
        with pytest.raises(UsageError, match="binddn must be given"):
            CompleteOptions().parseOptions(["--base=dc=example,dc=com"])
        with pytest.raises(UsageError, match="must be numeric"):
            CompleteOptions().parseOptions(
                [
                    "--base=dc=example,dc=com",
                    "--binddn=cn=admin",
                    "--bind-auth-fd=invalid",
                ]
            )
class TestOptions_service_location:
    """
    Unit tests for Options_service_location.
    """

    def test_parseOptions_default(self) -> None:
        """
        When no explicit options is provided it will set an empty dict.
        """
        sut = ServiceLocationOptionsImplementation()
        assert "service-location" not in sut.opts

        sut.parseOptions(options=[])

        assert {} == sut.opts["service-location"]

    def test_parseOptions_single(self) -> None:
        """
        It can have a single --service-location option.
        """
        sut = ServiceLocationOptionsImplementation()

        sut.parseOptions(
            options=["--service-location", "dc=example,dc=com:127.0.0.1:1234"]
        )

        base = DistinguishedName("dc=example,dc=com")
        value = sut.opts["service-location"][base]
        assert ("127.0.0.1", "1234") == value

    def test_parseOptions_invalid_DN(self) -> None:
        """
        It fails to parse the option when the base DN is not valid.
        """
        sut = ServiceLocationOptionsImplementation()

        with pytest.raises(UsageError) as excinfo:
            sut.parseOptions(options=["--service-location", "example.com:1.2.3.4"])

        assert "Invalid relative distinguished name 'example.com'." == excinfo.value.args[0]

    def test_parseOptions_no_server(self) -> None:
        """
        It fails to parse the option when no host is defined, but only
        a base DN.
        """
        sut = ServiceLocationOptionsImplementation()

        with pytest.raises(UsageError) as excinfo:
            sut.parseOptions(options=["--service-location", "dc=example,dc=com"])

        assert "service-location must specify host" == excinfo.value.args[0]

    def test_parseOptions_multiple(self) -> None:
        """
        It can have have multiple --service-location options and they are
        indexed using the base DN.
        """
        sut = ServiceLocationOptionsImplementation()

        sut.parseOptions(
            options=[
                "--service-location",
                "dc=example,dc=com:127.0.0.1",
                "--service-location",
                "dc=example,dc=org:172.0.0.1",
            ]
        )

        base_com = DistinguishedName("dc=example,dc=com")
        base_org = DistinguishedName("dc=example,dc=org")
        value_com = sut.opts["service-location"][base_com]
        value_org = sut.opts["service-location"][base_org]
        assert ("127.0.0.1", None) == value_com
        assert ("172.0.0.1", None) == value_org
