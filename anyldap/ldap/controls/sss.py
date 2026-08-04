"""``ldap.controls.sss``: asking the server to sort what it sends back.

RFC 2891. The request names the attributes to sort by, each optionally with
the matching rule to sort with and whether to reverse it; the response says
whether the sort could be done.
"""

from collections.abc import Sequence

from anyldap._encoder import to_unicode
from anyldap.ldap.constants import CONTROL_SORTREQUEST, CONTROL_SORTRESPONSE
from anyldap.ldap.controls import (
    KNOWN_RESPONSE_CONTROLS,
    RequestControl,
    ResponseControl,
)
from anyldap.protocols import pureber

# The parts of a sort key and a sort result that are written with a tag of
# their own rather than by position.
_ORDERING_RULE = pureber.CLASS_CONTEXT | 0x00
_REVERSE_ORDER = pureber.CLASS_CONTEXT | 0x01
_ATTRIBUTE_TYPE = pureber.CLASS_CONTEXT | 0x00


class _SortResultDecoder(pureber.BERDecoderContext):
    """Reads the attribute the server names when a sort could not be done."""

    Identities = {
        **pureber.BERDecoderContext.Identities,
        _ATTRIBUTE_TYPE: pureber.BEROctetString,
    }


class SSSRequestControl(RequestControl):
    """Sort by these attributes, in this order.

    An ordering rule is written after the attribute and a colon, and a
    leading minus sign sorts that attribute the other way round::

        SSSRequestControl(ordering_rules=['-uidNumber', 'cn:caseIgnoreMatch'])
    """

    controlType = CONTROL_SORTREQUEST

    def __init__(
        self,
        criticality: bool = False,
        ordering_rules: Sequence[str] | str | None = None,
    ) -> None:
        self.controlType = CONTROL_SORTREQUEST
        self.criticality = criticality
        if isinstance(ordering_rules, str):
            ordering_rules = [ordering_rules]
        self.ordering_rules = list(ordering_rules or [])
        for rule in self.ordering_rules:
            if len(rule.split(":")) > 2:
                raise ValueError(
                    "syntax for ordering rule: [-]<attribute-type>[:ordering-rule]"
                )
            if not rule.partition(":")[0].lstrip("-"):
                raise ValueError(f"empty attribute in ordering rule {rule!r}")

    def encodeControlValue(self) -> bytes:
        keys = []
        for rule in self.ordering_rules:
            attribute, _, matching_rule = rule.partition(":")
            reverse = attribute.startswith("-")
            attribute = attribute.lstrip("-")
            key: list[pureber.BERBase] = [pureber.BEROctetString(attribute)]
            if matching_rule:
                key.append(
                    pureber.BEROctetString(matching_rule, tag=_ORDERING_RULE)
                )
            if reverse:
                key.append(pureber.BERBoolean(1, tag=_REVERSE_ORDER))
            keys.append(pureber.BERSequence(key))
        return pureber.BERSequence(keys).toWire()


class SSSResponseControl(ResponseControl):
    """Whether the sort was done, and what stopped it if it was not."""

    controlType = CONTROL_SORTRESPONSE

    # What the result code the server sends means, as python-ldap names them.
    sortResultCodes = {
        0: "success",
        1: "operationsError",
        3: "timeLimitExceeded",
        8: "strongAuthRequired",
        11: "adminLimitExceeded",
        16: "noSuchAttribute",
        18: "inappropriateMatching",
        50: "insufficientAccessRights",
        51: "busy",
        53: "unwillingToPerform",
        80: "other",
    }

    def __init__(self, criticality: bool = False) -> None:
        ResponseControl.__init__(self, CONTROL_SORTRESPONSE, criticality)
        self.sortResult = 0
        self.result = 0
        self.result_code: str | None = None
        self.attributeType: str | None = None
        self.attribute_type_error: str | None = None

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        value, _ = pureber.berDecodeObject(_SortResultDecoder(), encodedControlValue)
        assert isinstance(value, pureber.BERSequence)
        result = value[0]
        assert isinstance(result, pureber.BERInteger)
        self.sortResult = result.value
        self.result_code = self.sortResultCodes.get(self.sortResult)
        if len(value.data) > 1:
            attribute = value[1]
            assert isinstance(attribute, pureber.BEROctetString)
            self.attributeType = to_unicode(attribute.value)
        else:
            self.attributeType = None
        # The names python-ldap kept for what it used to call these.
        self.result = self.sortResult
        self.attribute_type_error = self.attributeType


KNOWN_RESPONSE_CONTROLS[CONTROL_SORTRESPONSE] = SSSResponseControl
