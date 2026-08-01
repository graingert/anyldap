"""
Test cases for anyldap.usage
"""
import re
import sys

from anyldap.protocols.ldap.distinguishedname import DistinguishedName
from anyldap.test.unittest import TestCase
from anyldap.usage import (
    Options,
    Options_base,
    Options_bind_mandatory,
    Options_scope,
    Options_service_location,
    UsageError,
)


class ScopeOptionsImplementation(Options, Options_scope):
    """
    Minimal implementation for a command line using `Options_scope`.
    """


class TestOptions_scope(TestCase):
    def test_parseOptions_bad_scope(self):
        """
        It fails to parse the option when the scope is bad
        """
        self.assertRaisesRegex(
            UsageError,
            re.escape("bad scope: this is a bad scope"),
            ScopeOptionsImplementation().parseOptions,
            options=["--scope", "this is a bad scope"],
        )

    def test_parseOptions_default(self):
        """
        When no explicit options is provided it will set an empty dict.
        """
        sut = ServiceLocationOptionsImplementation()
        self.assertNotIn("service-location", sut.opts)

        sut.parseOptions(options=[])

        self.assertEqual({}, sut.opts["service-location"])


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

    def opt_custom_handler(self, value):
        self.opts["handled"] = value

    def opt_toggle(self, value):
        self.opts["toggled"] = value


class HandlerOptions(Options):
    optFlags = (("verbose", "v", "verbose output"),)
    optParameters = (("custom", "c", None, "custom value"),)

    def opt_verbose(self):
        self.opts["handled-flag"] = True

    def opt_custom(self, value):
        self.opts["handled-parameter"] = value


class TestCompleteOptions(TestCase):
    def test_uses_process_arguments_and_option_handlers(self):
        previous = sys.argv
        try:
            sys.argv = ["command", "--verbose", "--custom=value"]
            result = HandlerOptions().parseOptions()
        finally:
            sys.argv = previous
        self.assertTrue(result["handled-flag"])
        self.assertEqual(result["handled-parameter"], "value")

    def test_mapping_protocol(self):
        options = Options()
        options["key"] = "value"
        self.assertEqual(options["key"], "value")

    def test_long_short_flags_and_parameters(self):
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
        self.assertTrue(result["verbose"])
        self.assertEqual(result["custom"], "chosen")
        self.assertEqual(result["handled"], "handled")
        self.assertEqual(result["toggled"], "enabled")
        self.assertEqual(result["bind-auth-fd"], 7)

    def test_double_dash_stops_option_parsing(self):
        options = Options()
        self.assertEqual(options.parseOptions(["--", "ignored"]), {})

    def test_option_errors(self):
        cases = [
            (["argument"], "Unknown argument"),
            (["--unknown"], "Unknown option"),
            (["-z"], "Unknown option"),
            (["--verbose=yes"], "does not take a value"),
            (["--custom"], "requires an argument"),
            (["--toggle"], "requires an argument"),
        ]
        for arguments, message in cases:
            with self.assertRaisesRegex(UsageError, message):
                CompleteOptions().parseOptions(arguments)

    def test_required_values(self):
        with self.assertRaisesRegex(UsageError, "base must be given"):
            CompleteOptions().parseOptions(["--binddn=cn=admin"])
        with self.assertRaisesRegex(UsageError, "binddn must be given"):
            CompleteOptions().parseOptions(["--base=dc=example,dc=com"])
        with self.assertRaisesRegex(UsageError, "must be numeric"):
            CompleteOptions().parseOptions(
                [
                    "--base=dc=example,dc=com",
                    "--binddn=cn=admin",
                    "--bind-auth-fd=invalid",
                ]
            )
class TestOptions_service_location(TestCase):
    """
    Unit tests for Options_service_location.
    """

    def test_parseOptions_default(self):
        """
        When no explicit options is provided it will set an empty dict.
        """
        sut = ServiceLocationOptionsImplementation()
        self.assertNotIn("service-location", sut.opts)

        sut.parseOptions(options=[])

        self.assertEqual({}, sut.opts["service-location"])

    def test_parseOptions_single(self):
        """
        It can have a single --service-location option.
        """
        sut = ServiceLocationOptionsImplementation()

        sut.parseOptions(
            options=["--service-location", "dc=example,dc=com:127.0.0.1:1234"]
        )

        base = DistinguishedName("dc=example,dc=com")
        value = sut.opts["service-location"][base]
        self.assertEqual(("127.0.0.1", "1234"), value)

    def test_parseOptions_invalid_DN(self):
        """
        It fails to parse the option when the base DN is not valid.
        """
        sut = ServiceLocationOptionsImplementation()

        exception = self.assertRaises(
            UsageError,
            sut.parseOptions,
            options=["--service-location", "example.com:1.2.3.4"],
        )

        self.assertEqual(
            "Invalid relative distinguished name 'example.com'.", exception.args[0]
        )

    def test_parseOptions_no_server(self):
        """
        It fails to parse the option when no host is defined, but only
        a base DN.
        """
        sut = ServiceLocationOptionsImplementation()

        exception = self.assertRaises(
            UsageError,
            sut.parseOptions,
            options=["--service-location", "dc=example,dc=com"],
        )

        self.assertEqual("service-location must specify host", exception.args[0])

    def test_parseOptions_multiple(self):
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
        self.assertEqual(("127.0.0.1", None), value_com)
        self.assertEqual(("172.0.0.1", None), value_org)
