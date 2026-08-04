"""``ldap.controls``: the controls a request carries and a response answers with.

A control is an OID, whether the server must understand it, and a value
whose encoding the control itself knows. python-ldap encodes those values
with pyasn1; here they are encoded with the BER library anyldap already has,
so nothing else is needed to send or read one.

A request control is turned into the ``(type, criticality, value)`` triple
that goes on the wire by :func:`encode_controls`, and the triples a server
answers with are turned back into control objects by
:func:`decode_controls`, which knows the controls registered in
``KNOWN_RESPONSE_CONTROLS``.
"""

from collections.abc import Iterable, Mapping, Sequence

from anyldap._encoder import to_bytes, to_unicode
from anyldap.ldap import errors
from anyldap.protocols import pureldap


class RequestControl:
    """A control sent with a request, as python-ldap's base class is."""

    controlType: str | None
    criticality: bool
    encodedControlValue: bytes | None

    def __init__(
        self,
        controlType: str | None = None,
        criticality: bool = False,
        encodedControlValue: bytes | None = None,
    ) -> None:
        self.controlType = controlType
        self.criticality = criticality
        self.encodedControlValue = encodedControlValue

    def encodeControlValue(self) -> bytes | None:
        """The value as it goes on the wire, or None when it has none."""
        return self.encodedControlValue


class ResponseControl:
    """A control a response carried, as python-ldap's base class is."""

    controlType: str | None
    criticality: bool
    encodedControlValue: bytes | None

    def __init__(
        self, controlType: str | None = None, criticality: bool = False
    ) -> None:
        self.controlType = controlType
        self.criticality = criticality

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        """Read the value the server sent into this control's own fields."""
        self.encodedControlValue = encodedControlValue


class LDAPControl(RequestControl, ResponseControl):
    """A control that is only its three parts, whatever they mean."""

    controlValue: bytes | None

    def __init__(
        self,
        controlType: str | None = None,
        criticality: bool = False,
        controlValue: bytes | None = None,
        encodedControlValue: bytes | None = None,
    ) -> None:
        self.controlType = controlType
        self.criticality = criticality
        self.controlValue = controlValue
        self.encodedControlValue = encodedControlValue

    def encodeControlValue(self) -> bytes | None:
        if self.encodedControlValue is not None:
            return self.encodedControlValue
        return None if self.controlValue is None else to_bytes(self.controlValue)

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        self.controlValue = encodedControlValue
        self.encodedControlValue = encodedControlValue


# Which class reads which control out of a response, keyed by its OID, as
# python-ldap keys its own registry.
KNOWN_RESPONSE_CONTROLS: dict[str, type[ResponseControl]] = {}


def encode_controls(
    ldapControls: Iterable[RequestControl] | None,
) -> list[pureldap.Control] | None:
    """The triples that go on the wire for these controls."""
    if ldapControls is None:
        return None
    return [
        (
            to_bytes(control.controlType or ""),
            1 if control.criticality else 0,
            control.encodeControlValue(),
        )
        for control in ldapControls
    ]


def decode_controls(
    ldapControlTuples: Iterable[pureldap.Control] | None,
    knownLDAPControls: Mapping[str, type[ResponseControl]] | None = None,
) -> list[ResponseControl]:
    """The controls a response carried, read into the classes that know them.

    A control whose OID is not registered comes back as an
    :class:`LDAPControl` holding the bytes the server sent, so nothing is
    lost by not knowing it.
    """
    known = KNOWN_RESPONSE_CONTROLS if knownLDAPControls is None else knownLDAPControls
    controls: list[ResponseControl] = []
    for controlType, criticality, controlValue in ldapControlTuples or ():
        oid = to_unicode(controlType)
        control: ResponseControl
        cls = known.get(oid)
        if cls is None:
            control = LDAPControl(oid, bool(criticality))
        else:
            # A registered control is asked for without arguments and then
            # told what it is, which is what python-ldap does: not every
            # response control takes its own OID.
            control = cls()
            control.controlType = oid
            control.criticality = bool(criticality)
        if controlValue is not None:
            try:
                control.decodeControlValue(to_bytes(controlValue))
            except Exception as exc:
                raise errors.DECODING_ERROR(
                    {
                        "desc": errors.DECODING_ERROR.desc,
                        "info": f"control {oid}: {exc}",
                    }
                ) from exc
        controls.append(control)
    return controls


# python-ldap's own spellings of the two above.
encodeControlTuples = encode_controls
decodeControlTuples = decode_controls


def RequestControlTuples(
    ldapControls: Iterable[RequestControl] | None,
) -> list[pureldap.Control] | None:
    """python-ldap's name for what goes on the wire."""
    return encode_controls(ldapControls)


def ResponseControlTuples(
    ldapControls: Iterable[ResponseControl] | None,
) -> Sequence[ResponseControl]:
    return list(ldapControls or ())


from anyldap.ldap.controls.libldap import (  # noqa: E402
    AssertionControl as AssertionControl,
)
from anyldap.ldap.controls.libldap import (  # noqa: E402
    MatchedValuesControl as MatchedValuesControl,
)
from anyldap.ldap.controls.openldap import (  # noqa: E402
    SearchNoOpControl as SearchNoOpControl,
)
from anyldap.ldap.controls.pagedresults import (  # noqa: E402
    SimplePagedResultsControl as SimplePagedResultsControl,
)
from anyldap.ldap.controls.ppolicy import (  # noqa: E402
    PasswordPolicyControl as PasswordPolicyControl,
)
from anyldap.ldap.controls.readentry import (  # noqa: E402
    PostReadControl as PostReadControl,
)
from anyldap.ldap.controls.readentry import (  # noqa: E402
    PreReadControl as PreReadControl,
)
from anyldap.ldap.controls.simple import (  # noqa: E402
    AuthorizationIdentityRequestControl as AuthorizationIdentityRequestControl,
)
from anyldap.ldap.controls.simple import (  # noqa: E402
    AuthorizationIdentityResponseControl as AuthorizationIdentityResponseControl,
)
from anyldap.ldap.controls.simple import (  # noqa: E402
    BooleanControl as BooleanControl,
)
from anyldap.ldap.controls.simple import (  # noqa: E402
    ManageDSAITControl as ManageDSAITControl,
)
from anyldap.ldap.controls.simple import (  # noqa: E402
    OctetStringInteger as OctetStringInteger,
)
from anyldap.ldap.controls.simple import (  # noqa: E402
    ProxyAuthzControl as ProxyAuthzControl,
)
from anyldap.ldap.controls.simple import (  # noqa: E402
    RelaxRulesControl as RelaxRulesControl,
)
from anyldap.ldap.controls.simple import (  # noqa: E402
    ValueLessRequestControl as ValueLessRequestControl,
)
from anyldap.ldap.controls.sss import (  # noqa: E402
    SSSRequestControl as SSSRequestControl,
)
from anyldap.ldap.controls.sss import (  # noqa: E402
    SSSResponseControl as SSSResponseControl,
)
