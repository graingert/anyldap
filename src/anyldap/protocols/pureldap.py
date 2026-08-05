"""LDAP protocol message conversion; no application logic here."""

import string
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import ClassVar, Protocol, runtime_checkable

from typing_extensions import Self

from anyldap._encoder import to_bytes, to_unicode
from anyldap.protocols.pureber import (
    CLASS_APPLICATION,
    CLASS_CONTEXT,
    BERBase,
    BERBoolean,
    BERDecoderContext,
    BEREnumerated,
    BERInteger,
    BERNull,
    BEROctetString,
    BERSequence,
    BERSequenceOf,
    BERSet,
    BERStructured,
    berDecodeMultiple,
    berDecodeObject,
    int2berlen,
)

next_ldap_message_id = 1

# A control as callers spell it: type, criticality, value.
Control = tuple[str | bytes, int | None, str | bytes | None]


@runtime_checkable
class SupportsAsText(Protocol):
    """A filter that can render itself in RFC 4515 text form.

    asText is spread across classes with no common base -- a filter set holds
    LDAPFilter subclasses and LDAPAttributeValueAssertion subclasses alike --
    so what its members have in common is only this.
    """

    def asText(self) -> str: ...


def _octetString(obj: BERBase) -> BEROctetString:
    """Narrow a decoded sequence member to the string the schema requires.

    berDecodeMultiple can only promise BER objects; which of them a given
    position holds is the LDAP message format's business, not BER's.
    """
    assert isinstance(obj, BEROctetString)
    return obj


def _sequence(obj: BERBase) -> BERSequence:
    """Narrow a decoded member to the nested sequence the schema requires."""
    assert isinstance(obj, BERSequence)
    return obj


def alloc_ldap_message_id() -> int:
    global next_ldap_message_id
    r = next_ldap_message_id
    next_ldap_message_id = next_ldap_message_id + 1
    return r


def escape(s: str) -> str:
    s = s.replace("\\", r"\5c")
    s = s.replace("*", r"\2a")
    s = s.replace("(", r"\28")
    s = s.replace(")", r"\29")
    s = s.replace("\0", r"\00")
    return s


def binary_escape(s: str) -> str:
    return "".join(f"\\{ord(c):02x}" for c in s)


def smart_escape(s: str, threshold: float = 0.30) -> str:
    binary_count = sum(c not in string.printable for c in s)
    if float(binary_count) / float(len(s)) > threshold:
        return binary_escape(s)

    return escape(s)


class LDAPInteger(BERInteger):
    pass


class LDAPString(BEROctetString):
    def __init__(
        self,
        value: str | bytes | None = None,
        tag: int | None = None,
        escaper: Callable[[str], str] = escape,
    ) -> None:
        self.escaper = escaper
        super().__init__(value, tag)


class LDAPAttributeValue(BEROctetString):
    pass


class LDAPMessage(BERSequence):
    """
    To encode this object in order to be sent over the network use the toWire()
    method.
    """

    id: int
    value: BERBase

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        assert berdecoder is not None
        l = berDecodeMultiple(content, berdecoder)

        id_ = l[0]
        assert isinstance(id_, BERInteger)
        value = l[1]
        controls: list[Control] | None
        if l[2:]:
            controls = []
            wrapper = l[2]
            assert isinstance(wrapper, LDAPControls)
            for c in wrapper:
                assert isinstance(c, LDAPControl)
                controls.append(
                    (
                        c.controlType,
                        c.criticality,
                        c.controlValue,
                    )
                )
        else:
            controls = None
        assert not l[3:]

        r = klass(id=id_.value, value=value, controls=controls, tag=tag)
        return r

    def __init__(
        self,
        value: BERBase | None = None,
        controls: Iterable[Control] | None = None,
        id: int | None = None,
        tag: int | None = None,
    ) -> None:
        BERSequence.__init__(self, value=[], tag=tag)
        assert value is not None
        self.id = alloc_ldap_message_id() if id is None else id
        self.value = value
        self.controls = controls

    def toWire(self) -> bytes:
        """
        This is the wire/encoded representation.
        """
        l = [BERInteger(self.id), self.value]
        if self.controls is not None:
            l.append(LDAPControls([LDAPControl(*a) for a in self.controls]))
        return BERSequence(l).toWire()

    def __repr__(self) -> str:
        l = []
        l.append("id=%r" % self.id)
        l.append("value=%r" % self.value)
        l.append("controls=%r" % self.controls)
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPProtocolOp(BERBase):
    """An operation that goes on the wire.

    Which makes it a BER object; every concrete one already inherits the BER
    class matching its encoding alongside this.
    """

    def __init__(self) -> None:
        pass

    def toWire(self) -> bytes:
        raise NotImplementedError()


class LDAPProtocolRequest(LDAPProtocolOp):
    needs_answer = 1


class LDAPProtocolResponse(LDAPProtocolOp):
    pass


class LDAPBERDecoderContext_LDAPBindRequest(BERDecoderContext):
    Identities = {
        CLASS_CONTEXT | 0x00: BEROctetString,
        CLASS_CONTEXT | 0x03: BERSequence,
    }


class LDAPBindRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x00

    # Simple binds carry a password, SASL binds a (mechanism, credentials)
    # pair whose credentials are optional.
    auth: str | bytes | tuple[str | bytes, str | bytes | None]

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPBindRequest(fallback=berdecoder)
        )

        version, dn, credentials = l[0], l[1], l[2]
        assert isinstance(version, BERInteger)
        assert isinstance(dn, BEROctetString)

        sasl = False
        auth: str | bytes | tuple[str | bytes, str | bytes | None] | None = None
        if isinstance(credentials, BEROctetString):
            auth = credentials.value
        elif isinstance(credentials, BERSequence):
            # per https://ldap.com/ldapv3-wire-protocol-reference-bind/
            # Credentials are optional and not always provided
            mechanism = credentials[0]
            assert isinstance(mechanism, BEROctetString)
            if len(credentials.data) == 2:
                secret = credentials[1]
                assert isinstance(secret, BEROctetString)
                auth = (mechanism.value, secret.value)
            else:
                auth = (mechanism.value, None)
            sasl = True

        r = klass(version=version.value, dn=dn.value, auth=auth, tag=tag, sasl=sasl)
        return r

    def __init__(
        self,
        version: int | None = None,
        dn: str | bytes | None = None,
        auth: str | bytes | tuple[str | bytes, str | bytes | None] | None = None,
        tag: int | None = None,
        sasl: bool = False,
    ) -> None:
        """Constructor for LDAP Bind Request

        For sasl=False, pass a string password for 'auth'
        For sasl=True, pass a tuple of (mechanism, credentials) for 'auth'"""

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        self.version = 3 if version is None else version
        self.dn = "" if dn is None else dn
        if auth is None:
            auth = ""
            assert not sasl
        self.auth = auth
        self.sasl = sasl

    def toWire(self) -> bytes:
        auth_ber: BERBase
        if not self.sasl:
            assert not isinstance(self.auth, tuple)
            auth_ber = BEROctetString(self.auth, tag=CLASS_CONTEXT | 0)
        else:
            assert isinstance(self.auth, tuple)
            # The credentials are optional, and an empty one is not the
            # same as none at all: SASL EXTERNAL sends an empty response to
            # say it has nothing more to prove.
            if self.auth[1] is not None:
                auth_ber = BERSequence(
                    [BEROctetString(self.auth[0]), BEROctetString(self.auth[1])],
                    tag=CLASS_CONTEXT | 3,
                )
            else:
                auth_ber = BERSequence(
                    [BEROctetString(self.auth[0])], tag=CLASS_CONTEXT | 3
                )
        return BERSequence(
            [
                BERInteger(self.version),
                BEROctetString(self.dn),
                auth_ber,
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self) -> str:
        auth = "*" * len(self.auth)
        l = []
        l.append("version=%d" % self.version)
        l.append("dn=%s" % repr(self.dn))
        l.append("auth=%s" % repr(auth))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        l.append("sasl=%s" % repr(self.sasl))
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPReferral(BERSequence):
    tag = CLASS_CONTEXT | 0x03


def _referral(uris: Sequence[str | bytes] | None) -> LDAPReferral | None:
    """The referral field of a result, out of the URLs it names."""
    if not uris:
        return None
    return LDAPReferral([LDAPString(uri) for uri in uris])


def _referral_uris(referral: BERBase) -> list[bytes]:
    """The URLs a decoded referral field names."""
    assert isinstance(referral, LDAPReferral)
    uris = []
    for uri in referral:
        assert isinstance(uri, BEROctetString)
        uris.append(to_bytes(uri.value))
    return uris


# A result's referral is [3], the same tag a bind request's SASL credentials
# have; which one a message carries depends on what kind of message it is, so
# results are decoded with a context that says a referral is what [3] means.
class LDAPBERDecoderContext_LDAPResult(BERDecoderContext):
    Identities = {
        LDAPReferral.tag: LDAPReferral,
    }


class LDAPBERDecoderContext_LDAPSearchResultReference(BERDecoderContext):
    Identities = {
        BEROctetString.tag: LDAPString,
    }


class LDAPSearchResultReference(LDAPProtocolResponse, BERSequence):
    tag = CLASS_APPLICATION | 0x13

    def __init__(
        self, uris: Sequence[BERBase] | None = None, tag: int | None = None
    ) -> None:
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, value=[], tag=tag)
        assert uris is not None
        self.uris = uris

    @classmethod
    def fromBER(
        cls,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_LDAPSearchResultReference(fallback=berdecoder),
        )
        r = cls(uris=l)
        return r

    def toWire(self) -> bytes:
        return BERSequence(BERSequence(self.uris), tag=self.tag).toWire()

    def __repr__(self) -> str:
        return "{}(uris={}{})".format(
            self.__class__.__name__,
            repr([uri for uri in self.uris]),
            f", tag={self.tag}" if self.tag != self.__class__.tag else "",
        )


class LDAPResult(LDAPProtocolResponse, BERSequence):
    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPResult(fallback=berdecoder)
        )

        assert 3 <= len(l) <= 4

        resultCode, matchedDN, errorMessage = l[0], l[1], l[2]
        assert isinstance(resultCode, BERInteger)
        assert isinstance(matchedDN, BEROctetString)
        assert isinstance(errorMessage, BEROctetString)

        referral = _referral_uris(l[3]) if l[3:] else None

        r = klass(
            resultCode=resultCode.value,
            matchedDN=matchedDN.value,
            errorMessage=errorMessage.value,
            referral=referral,
            tag=tag,
        )
        return r

    def __init__(
        self,
        resultCode: int | None = None,
        matchedDN: str | bytes | None = None,
        errorMessage: str | bytes | None = None,
        referral: Sequence[str | bytes] | None = None,
        serverSaslCreds: str | bytes | None = None,
        tag: int | None = None,
    ) -> None:
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, value=[], tag=tag)
        assert resultCode is not None
        self.resultCode = resultCode
        if matchedDN is None:
            matchedDN = ""
        self.matchedDN = matchedDN
        if errorMessage is None:
            errorMessage = ""
        self.errorMessage = errorMessage
        self.referral = referral
        self.serverSaslCreds = serverSaslCreds

    def toWire(self) -> bytes:
        l: list[BERBase] = [
            BEREnumerated(self.resultCode),
            BEROctetString(self.matchedDN),
            BEROctetString(self.errorMessage),
        ]
        referral = _referral(self.referral)
        if referral is not None:
            l.append(referral)
        if self.serverSaslCreds:
            l.append(LDAPBindResponse_serverSaslCreds(self.serverSaslCreds))
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self) -> str:
        l = []
        l.append("resultCode=%r" % self.resultCode)
        if self.matchedDN:
            l.append("matchedDN=%r" % self.matchedDN)
        if self.errorMessage:
            l.append("errorMessage=%r" % self.errorMessage)
        if self.referral:
            l.append("referral=%r" % self.referral)
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPBindResponse_serverSaslCreds(BEROctetString):
    tag = CLASS_CONTEXT | 0x07

    def __repr__(self) -> str:
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%r)" % self.value
        else:
            return self.__class__.__name__ + "(value=%r, tag=%d)" % (
                self.value,
                self.tag,
            )


class LDAPBERDecoderContext_BindResponse(BERDecoderContext):
    Identities = {
        LDAPBindResponse_serverSaslCreds.tag: LDAPBindResponse_serverSaslCreds,
        LDAPReferral.tag: LDAPReferral,
    }


class LDAPBindResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x01

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_BindResponse(fallback=berdecoder)
        )

        assert 3 <= len(l) <= 5

        serverSaslCreds: str | bytes | None = None
        referral: list[bytes] | None = None
        for obj in l[3:]:
            if isinstance(obj, LDAPBindResponse_serverSaslCreds):
                serverSaslCreds = obj.value
            else:
                referral = _referral_uris(obj)

        resultCode, matchedDN, errorMessage = l[0], l[1], l[2]
        assert isinstance(resultCode, BERInteger)
        assert isinstance(matchedDN, BEROctetString)
        assert isinstance(errorMessage, BEROctetString)

        r = klass(
            resultCode=resultCode.value,
            matchedDN=matchedDN.value,
            errorMessage=errorMessage.value,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            tag=tag,
        )
        return r

    def __init__(
        self,
        resultCode: int | None = None,
        matchedDN: str | bytes | None = None,
        errorMessage: str | bytes | None = None,
        referral: Sequence[str | bytes] | None = None,
        serverSaslCreds: str | bytes | None = None,
        tag: int | None = None,
    ) -> None:
        LDAPResult.__init__(
            self,
            resultCode=resultCode,
            matchedDN=matchedDN,
            errorMessage=errorMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            tag=None,
        )

    def __repr__(self) -> str:
        return LDAPResult.__repr__(self)


class LDAPUnbindRequest(LDAPProtocolRequest, BERNull):
    tag = CLASS_APPLICATION | 0x02
    needs_answer = 0

    def __init__(self, tag: int | None = None) -> None:
        LDAPProtocolRequest.__init__(self)
        BERNull.__init__(self, tag)

    def toWire(self) -> bytes:
        return BERNull.toWire(self)


class LDAPAttributeDescription(BEROctetString):
    pass


class LDAPAttributeValueAssertion(BERSequence):
    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        assert berdecoder is not None
        l = berDecodeMultiple(content, berdecoder)
        assert len(l) == 2

        attributeDesc, assertionValue = l[0], l[1]
        assert isinstance(attributeDesc, BEROctetString)
        assert isinstance(assertionValue, BEROctetString)

        r = klass(
            attributeDesc=attributeDesc, assertionValue=assertionValue, tag=tag
        )
        return r

    def __init__(
        self,
        attributeDesc: BEROctetString | None = None,
        assertionValue: BEROctetString | None = None,
        tag: int | None = None,
        escaper: Callable[[str], str] = escape,
    ) -> None:
        BERSequence.__init__(self, value=[], tag=tag)
        assert attributeDesc is not None
        self.attributeDesc = attributeDesc
        self.assertionValue = assertionValue
        self.escaper = escaper

    def toWire(self) -> bytes:
        assert self.assertionValue is not None
        return BERSequence(
            [self.attributeDesc, self.assertionValue], tag=self.tag
        ).toWire()

    def __repr__(self) -> str:
        if self.tag == self.__class__.tag:
            return (
                self.__class__.__name__
                + f"(attributeDesc={self.attributeDesc!r}, assertionValue={self.assertionValue!r})"
            )
        else:
            return (
                self.__class__.__name__
                + "(attributeDesc=%s, assertionValue=%s, tag=%d)"
                % (repr(self.attributeDesc), repr(self.assertionValue), self.tag)
            )


class LDAPFilter(BERStructured):
    def __init__(self, tag: int | None = None) -> None:
        BERStructured.__init__(self, tag=tag)


class LDAPFilterSet(BERSet):
    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_Filter(fallback=berdecoder)
        )
        r = klass(l, tag=tag)
        return r

    def __eq__(self, rhs: object) -> bool:
        # Fast paths
        if self is rhs:
            return True
        if not isinstance(rhs, LDAPFilterSet):
            return NotImplemented
        elif len(self) != len(rhs):
            return False

        return sorted(self, key=lambda x: x.toWire()) == sorted(
            rhs, key=lambda x: x.toWire()
        )

    def _memberText(self) -> Iterator[str]:
        """The members' text forms."""
        for f in self:
            assert isinstance(f, SupportsAsText)
            yield f.asText()


class LDAPFilter_and(LDAPFilterSet):
    tag = CLASS_CONTEXT | 0x00

    def asText(self) -> str:
        return "(&" + "".join(self._memberText()) + ")"


class LDAPFilter_or(LDAPFilterSet):
    tag = CLASS_CONTEXT | 0x01

    def asText(self) -> str:
        return "(|" + "".join(self._memberText()) + ")"


class LDAPFilter_not(LDAPFilter):
    tag = CLASS_CONTEXT | 0x02

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        value, bytes = berDecodeObject(
            LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder),
            content,
        )
        assert bytes == len(content)

        r = klass(value=value, tag=tag)
        return r

    def __init__(self, value: BERBase | None, tag: int | None = tag) -> None:
        LDAPFilter.__init__(self, tag=tag)
        assert value is not None
        self.value = value

    def __repr__(self) -> str:
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(self.value)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                repr(self.value),
                self.tag,
            )

    def toWire(self) -> bytes:
        value = to_bytes(self.value)
        return bytes((self.identification(),)) + int2berlen(len(value)) + value

    def asText(self) -> str:
        assert isinstance(self.value, SupportsAsText)
        return "(!" + self.value.asText() + ")"


class LDAPFilter_equalityMatch(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x03

    def asText(self) -> str:
        assert self.assertionValue is not None
        return (
            "("
            + to_unicode(self.attributeDesc.value)
            + "="
            + self.escaper(to_unicode(self.assertionValue.value))
            + ")"
        )


class LDAPFilter_substrings_initial(LDAPString):
    tag = CLASS_CONTEXT | 0x00

    def asText(self) -> str:
        return self.escaper(to_unicode(self.value))


class LDAPFilter_substrings_any(LDAPString):
    tag = CLASS_CONTEXT | 0x01

    def asText(self) -> str:
        return self.escaper(to_unicode(self.value))


class LDAPFilter_substrings_final(LDAPString):
    tag = CLASS_CONTEXT | 0x02

    def asText(self) -> str:
        return self.escaper(to_unicode(self.value))


class LDAPBERDecoderContext_Filter_substrings(BERDecoderContext):
    Identities = {
        LDAPFilter_substrings_initial.tag: LDAPFilter_substrings_initial,
        LDAPFilter_substrings_any.tag: LDAPFilter_substrings_any,
        LDAPFilter_substrings_final.tag: LDAPFilter_substrings_final,
    }


class LDAPFilter_substrings(BERSequence):
    tag = CLASS_CONTEXT | 0x04

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_Filter_substrings(fallback=berdecoder)
        )
        assert len(l) == 2

        type_, substrings = l[0], l[1]
        assert isinstance(type_, BEROctetString)
        assert isinstance(substrings, BERSequence)
        assert len(substrings) >= 1

        r = klass(type=type_.value, substrings=list(substrings), tag=tag)
        return r

    def __init__(
        self,
        type: str | bytes | None = None,
        substrings: Sequence[BERBase] | None = None,
        tag: int | None = None,
    ) -> None:
        BERSequence.__init__(self, value=[], tag=tag)
        assert type is not None
        assert substrings is not None
        self.type = type
        self.substrings = substrings

    def toWire(self) -> bytes:
        return BERSequence(
            [LDAPString(self.type), BERSequence(self.substrings)], tag=self.tag
        ).toWire()

    def __repr__(self) -> str:
        tp = self.type
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + f"(type={tp!r}, substrings={self.substrings!r})"
        else:
            return self.__class__.__name__ + "(type=%s, substrings=%s, tag=%d)" % (
                repr(tp),
                repr(self.substrings),
                self.tag,
            )

    def asText(self) -> str:
        initial = None
        final = None
        any: list[str] = []

        for s in self.substrings:
            assert s is not None
            if isinstance(s, LDAPFilter_substrings_initial):
                assert initial is None
                assert not any
                assert final is None
                initial = s.asText()
            elif isinstance(s, LDAPFilter_substrings_final):
                assert final is None
                final = s.asText()
            elif isinstance(s, LDAPFilter_substrings_any):
                assert final is None
                any.append(s.asText())
            else:
                raise NotImplementedError("TODO: Filter type not supported %r" % s)

        if initial is None:
            initial = ""
        if final is None:
            final = ""

        return (
            "("
            + to_unicode(self.type)
            + "="
            + "*".join([initial] + any + [final])
            + ")"
        )


class LDAPFilter_greaterOrEqual(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x05

    def asText(self) -> str:
        assert self.assertionValue is not None
        return (
            "("
            + to_unicode(self.attributeDesc.value)
            + ">="
            + self.escaper(to_unicode(self.assertionValue.value))
            + ")"
        )


class LDAPFilter_lessOrEqual(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x06

    def asText(self) -> str:
        assert self.assertionValue is not None
        return (
            "("
            + to_unicode(self.attributeDesc.value)
            + "<="
            + self.escaper(to_unicode(self.assertionValue.value))
            + ")"
        )


class LDAPFilter_present(LDAPAttributeDescription):
    tag = CLASS_CONTEXT | 0x07

    def asText(self) -> str:
        return "(%s=*)" % to_unicode(self.value)


class LDAPFilter_approxMatch(LDAPAttributeValueAssertion):
    tag = CLASS_CONTEXT | 0x08

    def asText(self) -> str:
        assert self.assertionValue is not None
        return (
            "("
            + to_unicode(self.attributeDesc.value)
            + "~="
            + self.escaper(to_unicode(self.assertionValue.value))
            + ")"
        )


class LDAPMatchingRuleId(LDAPString):
    pass


class LDAPAssertionValue(BEROctetString):
    pass


class LDAPMatchingRuleAssertion_matchingRule(LDAPMatchingRuleId):
    tag = CLASS_CONTEXT | 0x01


class LDAPMatchingRuleAssertion_type(LDAPAttributeDescription):
    tag = CLASS_CONTEXT | 0x02


class LDAPMatchingRuleAssertion_matchValue(LDAPAssertionValue):
    tag = CLASS_CONTEXT | 0x03


class LDAPMatchingRuleAssertion_dnAttributes(BERBoolean):
    tag = CLASS_CONTEXT | 0x04


class LDAPBERDecoderContext_MatchingRuleAssertion(BERDecoderContext):
    Identities = {
        LDAPMatchingRuleAssertion_matchingRule.tag: LDAPMatchingRuleAssertion_matchingRule,
        LDAPMatchingRuleAssertion_type.tag: LDAPMatchingRuleAssertion_type,
        LDAPMatchingRuleAssertion_matchValue.tag: LDAPMatchingRuleAssertion_matchValue,
        LDAPMatchingRuleAssertion_dnAttributes.tag: LDAPMatchingRuleAssertion_dnAttributes,
    }


class LDAPMatchingRuleAssertion(BERSequence):
    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        matchingRule = None
        atype = None
        matchValue = None
        dnAttributes = None
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_MatchingRuleAssertion(
                fallback=berdecoder, inherit=berdecoder
            ),
        )
        assert 1 <= len(l) <= 4
        if isinstance(l[0], LDAPMatchingRuleAssertion_matchingRule):
            matchingRule = l[0]
            del l[0]
        if len(l) >= 1 and isinstance(l[0], LDAPMatchingRuleAssertion_type):
            atype = l[0]
            del l[0]
        if len(l) >= 1 and isinstance(l[0], LDAPMatchingRuleAssertion_matchValue):
            matchValue = l[0]
            del l[0]
        if len(l) >= 1 and isinstance(l[0], LDAPMatchingRuleAssertion_dnAttributes):
            dnAttributes = l[0]
            del l[0]
        assert matchValue
        if not dnAttributes:
            dnAttributes = None
        r = klass(
            matchingRule=matchingRule,
            type=atype,
            matchValue=matchValue,
            dnAttributes=dnAttributes,
            tag=tag,
        )

        return r

    def __init__(
        self,
        matchingRule: str | bytes | LDAPMatchingRuleAssertion_matchingRule | None = None,
        type: str | bytes | LDAPMatchingRuleAssertion_type | None = None,
        matchValue: str | bytes | LDAPMatchingRuleAssertion_matchValue | None = None,
        dnAttributes: bool | LDAPMatchingRuleAssertion_dnAttributes | None = None,
        tag: int | None = None,
        escaper: Callable[[str], str] = escape,
    ) -> None:
        BERSequence.__init__(self, value=[], tag=tag)
        assert matchValue is not None
        if isinstance(matchingRule, (bytes, str)):
            matchingRule = LDAPMatchingRuleAssertion_matchingRule(matchingRule)

        if isinstance(type, (bytes, str)):
            type = LDAPMatchingRuleAssertion_type(type)

        if isinstance(matchValue, (bytes, str)):
            matchValue = LDAPMatchingRuleAssertion_matchValue(matchValue)

        if isinstance(dnAttributes, bool):
            dnAttributes = LDAPMatchingRuleAssertion_dnAttributes(dnAttributes)

        self.matchingRule = matchingRule
        self.type = type
        self.matchValue = matchValue
        self.dnAttributes = dnAttributes if dnAttributes else None
        self.escaper = escaper

    def toWire(self) -> bytes:
        members: list[BERBase | None] = [
            self.matchingRule,
            self.type,
            self.matchValue,
            self.dnAttributes,
        ]
        return BERSequence(
            [m for m in members if m is not None],
            tag=self.tag,
        ).toWire()

    def __repr__(self) -> str:
        l = []
        l.append("matchingRule=%s" % repr(self.matchingRule))
        l.append("type=%s" % repr(self.type))
        l.append("matchValue=%s" % repr(self.matchValue))
        l.append("dnAttributes=%s" % repr(self.dnAttributes))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPFilter_extensibleMatch(LDAPMatchingRuleAssertion):
    tag = CLASS_CONTEXT | 0x09

    def asText(self) -> str:
        return (
            "("
            + (to_unicode(self.type.value) if self.type else "")
            + (":dn" if self.dnAttributes and self.dnAttributes.value else "")
            + ((":" + to_unicode(self.matchingRule.value)) if self.matchingRule else "")
            + ":="
            + self.escaper(to_unicode(self.matchValue.value))
            + ")"
        )


class LDAPBERDecoderContext_Filter(BERDecoderContext):
    Identities = {
        LDAPFilter_and.tag: LDAPFilter_and,
        LDAPFilter_or.tag: LDAPFilter_or,
        LDAPFilter_not.tag: LDAPFilter_not,
        LDAPFilter_equalityMatch.tag: LDAPFilter_equalityMatch,
        LDAPFilter_substrings.tag: LDAPFilter_substrings,
        LDAPFilter_greaterOrEqual.tag: LDAPFilter_greaterOrEqual,
        LDAPFilter_lessOrEqual.tag: LDAPFilter_lessOrEqual,
        LDAPFilter_present.tag: LDAPFilter_present,
        LDAPFilter_approxMatch.tag: LDAPFilter_approxMatch,
        LDAPFilter_extensibleMatch.tag: LDAPFilter_extensibleMatch,
    }


LDAP_SCOPE_baseObject = 0
LDAP_SCOPE_singleLevel = 1
LDAP_SCOPE_wholeSubtree = 2

LDAP_DEREF_neverDerefAliases = 0
LDAP_DEREF_derefInSearching = 1
LDAP_DEREF_derefFindingBaseObj = 2
LDAP_DEREF_derefAlways = 3

LDAPFilterMatchAll = LDAPFilter_present("objectClass")


class LDAPSearchRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x03

    baseObject: str | bytes = ""
    scope: int = LDAP_SCOPE_wholeSubtree
    derefAliases: int = LDAP_DEREF_neverDerefAliases
    sizeLimit: int = 0
    timeLimit: int = 0
    typesOnly: int = 0
    filter: BERBase = LDAPFilterMatchAll
    attributes: Sequence[str | bytes] = []  # TODO AttributeDescriptionList

    # TODO decode

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder),
        )

        assert 8 <= len(l) <= 8

        baseObject, scope, derefAliases = l[0], l[1], l[2]
        sizeLimit, timeLimit, typesOnly = l[3], l[4], l[5]
        attributes = l[7]
        assert isinstance(baseObject, BEROctetString)
        assert isinstance(scope, BERInteger)
        assert isinstance(derefAliases, BERInteger)
        assert isinstance(sizeLimit, BERInteger)
        assert isinstance(timeLimit, BERInteger)
        assert isinstance(typesOnly, BERBoolean)
        assert isinstance(attributes, BERSequence)

        r = klass(
            baseObject=baseObject.value,
            scope=scope.value,
            derefAliases=derefAliases.value,
            sizeLimit=sizeLimit.value,
            timeLimit=timeLimit.value,
            typesOnly=typesOnly.value,
            filter=l[6],
            attributes=[_octetString(x).value for x in attributes],
            tag=tag,
        )
        return r

    def __init__(
        self,
        baseObject: str | bytes | None = None,
        scope: int | None = None,
        derefAliases: int | None = None,
        sizeLimit: int | None = None,
        timeLimit: int | None = None,
        typesOnly: int | None = None,
        filter: BERBase | None = None,
        attributes: Sequence[str | bytes] | None = None,
        tag: int | None = None,
    ) -> None:
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)

        if baseObject is not None:
            self.baseObject = baseObject
        if scope is not None:
            self.scope = scope
        if derefAliases is not None:
            self.derefAliases = derefAliases
        if sizeLimit is not None:
            self.sizeLimit = sizeLimit
        if timeLimit is not None:
            self.timeLimit = timeLimit
        if typesOnly is not None:
            self.typesOnly = typesOnly
        if filter is not None:
            self.filter = filter
        if attributes is not None:
            self.attributes = attributes

    def toWire(self) -> bytes:
        return BERSequence(
            [
                BEROctetString(self.baseObject),
                BEREnumerated(self.scope),
                BEREnumerated(self.derefAliases),
                BERInteger(self.sizeLimit),
                BERInteger(self.timeLimit),
                BERBoolean(self.typesOnly),
                self.filter,
                BERSequenceOf(map(BEROctetString, self.attributes)),
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self) -> str:
        base = self.baseObject
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + (
                "(baseObject=%s, scope=%s, derefAliases=%s, "
                + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, "
                "filter=%s, attributes=%s)"
            ) % (
                repr(base),
                self.scope,
                self.derefAliases,
                self.sizeLimit,
                self.timeLimit,
                self.typesOnly,
                repr(self.filter),
                self.attributes,
            )

        else:
            return self.__class__.__name__ + (
                "(baseObject=%s, scope=%s, derefAliases=%s, "
                + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, "
                "filter=%s, attributes=%s, tag=%d)"
            ) % (
                repr(base),
                self.scope,
                self.derefAliases,
                self.sizeLimit,
                self.timeLimit,
                self.typesOnly,
                repr(self.filter),
                self.attributes,
                self.tag,
            )


class LDAPSearchResultEntry(LDAPProtocolResponse, BERSequence):
    tag = CLASS_APPLICATION | 0x04

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder),
        )

        objectName, entries = l[0], l[1]
        assert isinstance(objectName, BEROctetString)
        assert isinstance(entries, BERSequence)

        attributes = []
        for pair in entries.data:
            attr, li = _sequence(pair)
            attributes.append(
                (_octetString(attr).value, [_octetString(x).value for x in _sequence(li)])
            )
        r = klass(objectName=objectName.value, attributes=attributes, tag=tag)
        return r

    def __init__(
        self,
        objectName: str | bytes,
        attributes: Sequence[tuple[str | bytes, Sequence[str | bytes]]],
        tag: int | None = None,
    ) -> None:
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert objectName is not None
        assert attributes is not None
        self.objectName = objectName
        self.attributes = attributes

    def toWire(self) -> bytes:
        return BERSequence(
            [
                BEROctetString(self.objectName),
                BERSequence(
                    [
                        BERSequence(
                            [
                                BEROctetString(attr_li[0]),
                                BERSet([BEROctetString(x) for x in attr_li[1]]),
                            ]
                        )
                        for attr_li in self.attributes
                    ]
                ),
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self) -> str:
        name = self.objectName
        attributes = [(key, [v for v in value]) for (key, value) in self.attributes]
        return "{}(objectName={}, attributes={}{})".format(
            self.__class__.__name__,
            repr(name),
            repr(attributes),
            f", tag={self.tag}" if self.tag != self.__class__.tag else "",
        )


class LDAPSearchResultDone(LDAPResult):
    tag = CLASS_APPLICATION | 0x05


class LDAPControls(BERSequence):
    tag = CLASS_CONTEXT | 0x00

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPControls(inherit=berdecoder)
        )

        r = klass(l, tag=tag)
        return r


class LDAPControl(BERSequence):
    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        assert berdecoder is not None
        l = berDecodeMultiple(content, berdecoder)

        assert 1 <= len(l) <= 3

        criticality: int | None = None
        controlValue: str | bytes | None = None
        if len(l) == 2:
            if isinstance(l[1], BERBoolean):
                criticality = l[1].value
            elif isinstance(l[1], BEROctetString):
                controlValue = l[1].value
        elif len(l) == 3:
            assert isinstance(l[1], BERBoolean)
            criticality = l[1].value
            controlValue = _octetString(l[2]).value

        r = klass(
            controlType=_octetString(l[0]).value,
            criticality=criticality,
            controlValue=controlValue,
            tag=tag,
        )
        return r

    def __init__(
        self,
        controlType: str | bytes,
        criticality: int | None = None,
        controlValue: str | bytes | None = None,
        id: int | None = None,
        tag: int | None = None,
    ) -> None:
        BERSequence.__init__(self, value=[], tag=tag)
        assert controlType is not None
        self.controlType = controlType
        self.criticality = criticality
        self.controlValue = controlValue

    def toWire(self) -> bytes:
        self.data = [LDAPOID(self.controlType)]
        if self.criticality is not None:
            self.data.append(BERBoolean(self.criticality))
        if self.controlValue is not None:
            self.data.append(BEROctetString(self.controlValue))
        return BERSequence.toWire(self)


class LDAPBERDecoderContext_LDAPControls(BERDecoderContext):
    Identities = {
        LDAPControl.tag: LDAPControl,
    }


class LDAPBERDecoderContext_LDAPMessage(BERDecoderContext):
    Identities = {
        LDAPControls.tag: LDAPControls,
        LDAPSearchResultReference.tag: LDAPSearchResultReference,
        # LDAPIntermediateResponse is defined further down, and is put here
        # once it is: a message can carry one while an operation runs.
    }


class LDAPBERDecoderContext_TopLevel(BERDecoderContext):
    Identities = {
        BERSequence.tag: LDAPMessage,
    }


class LDAPModifyRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x06

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        assert berdecoder is not None
        l = berDecodeMultiple(content, berdecoder)

        assert len(l) == 2

        modification = l[1]
        assert isinstance(modification, BERSequence)

        r = klass(
            object=_octetString(l[0]).value, modification=modification.data, tag=tag
        )
        return r

    def __init__(
        self,
        object: str | bytes | None = None,
        modification: Sequence[BERBase] | None = None,
        tag: int | None = None,
    ) -> None:
        """
        Initialize the object

        Example usage::

                l = LDAPModifyRequest(
                    object='cn=foo,dc=example,dc=com',
                    modification=[

                      BERSequence([
                        BEREnumerated(0),
                        BERSequence([
                          LDAPAttributeDescription('attr1'),
                          BERSet([
                            LDAPString('value1'),
                            LDAPString('value2'),
                            ]),
                          ]),
                        ]),

                      BERSequence([
                        BEREnumerated(1),
                        BERSequence([
                          LDAPAttributeDescription('attr2'),
                          ]),
                        ]),

                    ])

        But more likely you just want to say::

                mod = delta.ModifyOp('cn=foo,dc=example,dc=com',
                    [delta.Add('attr1', ['value1', 'value2']),
                     delta.Delete('attr1', ['value1', 'value2'])])
                l = mod.asLDAP()
        """

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        self.object = object
        self.modification = modification

    def toWire(self) -> bytes:
        l: list[BERBase] = [LDAPString(self.object)]
        if self.modification is not None:
            l.append(BERSequence(self.modification))
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self) -> str:
        name = self.object
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + f"(object={name!r}, modification={self.modification!r})"
        else:
            return self.__class__.__name__ + "(object=%s, modification=%s, tag=%d)" % (
                repr(name),
                repr(self.modification),
                self.tag,
            )


class LDAPModifyResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x07


class LDAPAddRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x08

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        assert berdecoder is not None
        l = berDecodeMultiple(content, berdecoder)

        attributes = l[1]
        assert isinstance(attributes, BERSequence)

        r = klass(
            entry=_octetString(l[0]).value,
            attributes=[_sequence(pair) for pair in attributes],
            tag=tag,
        )
        return r

    def __init__(
        self,
        entry: str | bytes | None = None,
        attributes: Sequence[Sequence[BERBase]] | None = None,
        tag: int | None = None,
    ) -> None:
        """
        Initialize the object

        Example usage::

                l=LDAPAddRequest(entry='cn=foo,dc=example,dc=com',
                        attributes=[(LDAPAttributeDescription("attrFoo"),
                             BERSet(value=(
                                 LDAPAttributeValue("value1"),
                                 LDAPAttributeValue("value2"),
                             ))),
                             (LDAPAttributeDescription("attrBar"),
                             BERSet(value=(
                                 LDAPAttributeValue("value1"),
                                 LDAPAttributeValue("value2"),
                             ))),
                             ])"""

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        self.entry = entry
        self.attributes = attributes

    def toWire(self) -> bytes:
        assert self.attributes is not None
        return BERSequence(
            [
                LDAPString(self.entry),
                BERSequence(BERSequence(pair) for pair in self.attributes),
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self) -> str:
        entry = self.entry
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + f"(entry={entry!r}, attributes={self.attributes!r})"
        else:
            return self.__class__.__name__ + "(entry=%s, attributes=%s, tag=%d)" % (
                repr(entry),
                repr(self.attributes),
                self.tag,
            )


class LDAPAddResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x09


class LDAPDelRequest(LDAPProtocolRequest, LDAPString):
    tag = CLASS_APPLICATION | 0x0A

    def __init__(
        self,
        value: str | bytes | None = None,
        entry: str | bytes | None = None,
        tag: int | None = None,
    ) -> None:
        """
        Initialize the object

        l=LDAPDelRequest(entry='cn=foo,dc=example,dc=com')
        """
        if entry is None and value is not None:
            entry = value
        LDAPProtocolRequest.__init__(self)
        LDAPString.__init__(self, value=entry, tag=tag)

    def toWire(self) -> bytes:
        return LDAPString.toWire(self)

    def __repr__(self) -> str:
        entry = self.value
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(entry=%s)" % repr(entry)
        else:
            return self.__class__.__name__ + "(entry=%s, tag=%d)" % (
                repr(entry),
                self.tag,
            )


class LDAPDelResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x0B


class LDAPModifyDNResponse_newSuperior(LDAPString):
    tag = CLASS_CONTEXT | 0x00


class LDAPBERDecoderContext_ModifyDNRequest(BERDecoderContext):
    Identities = {
        LDAPModifyDNResponse_newSuperior.tag: LDAPModifyDNResponse_newSuperior,
    }


class LDAPModifyDNRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 12

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_ModifyDNRequest(fallback=berdecoder)
        )

        newSuperior: bytes | None
        try:
            newSuperior = to_bytes(_octetString(l[3]).value)
        except IndexError:
            newSuperior = None

        deleteoldrdn = l[2]
        assert isinstance(deleteoldrdn, BERBoolean)

        r = klass(
            entry=to_bytes(_octetString(l[0]).value),
            newrdn=to_bytes(_octetString(l[1]).value),
            deleteoldrdn=deleteoldrdn.value,
            newSuperior=newSuperior,
            tag=tag,
        )
        return r

    def __init__(
        self,
        entry: str | bytes,
        newrdn: str | bytes,
        deleteoldrdn: int,
        newSuperior: str | bytes | None = None,
        tag: int | None = None,
    ) -> None:
        """
        Initialize the object

        Example usage::

                l=LDAPModifyDNRequest(entry='cn=foo,dc=example,dc=com',
                                      newrdn='someAttr=value',
                                      deleteoldrdn=0)
        """

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert entry is not None
        assert newrdn is not None
        assert deleteoldrdn is not None
        self.entry = entry
        self.newrdn = newrdn
        self.deleteoldrdn = deleteoldrdn
        self.newSuperior = newSuperior

    def toWire(self) -> bytes:
        l: list[BERBase] = [
            LDAPString(self.entry),
            LDAPString(self.newrdn),
            BERBoolean(self.deleteoldrdn),
        ]
        if self.newSuperior is not None:
            l.append(LDAPString(self.newSuperior, tag=CLASS_CONTEXT | 0))
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self) -> str:
        l = [
            "entry=%s" % repr(self.entry),
            "newrdn=%s" % repr(self.newrdn),
            "deleteoldrdn=%s" % repr(self.deleteoldrdn),
        ]
        if self.newSuperior is not None:
            l.append("newSuperior=%s" % repr(self.newSuperior))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPModifyDNResponse(LDAPResult):
    tag = CLASS_APPLICATION | 13


class LDAPBERDecoderContext_Compare(BERDecoderContext):
    Identities = {BERSequence.tag: LDAPAttributeValueAssertion}


class LDAPCompareRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 14

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_Compare(fallback=berdecoder, inherit=berdecoder),
        )

        ava = l[1]
        assert isinstance(ava, LDAPAttributeValueAssertion)

        r = klass(entry=_octetString(l[0]).value, ava=ava, tag=tag)

        return r

    def __init__(
        self,
        entry: str | bytes,
        ava: LDAPAttributeValueAssertion,
        tag: int | None = None,
    ) -> None:
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert entry is not None
        assert ava is not None
        self.entry = entry
        self.ava = ava

    def toWire(self) -> bytes:
        l: list[BERBase] = [LDAPString(self.entry), self.ava]
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self) -> str:
        l = [
            f"entry={self.entry!r}",
            f"ava={self.ava!r}",
        ]
        return "{}({})".format(self.__class__.__name__, ", ".join(l))


class LDAPCompareResponse(LDAPResult):
    tag = CLASS_APPLICATION | 15


class LDAPAbandonRequest(LDAPProtocolRequest, LDAPInteger):
    tag = CLASS_APPLICATION | 0x10
    needs_answer = 0

    def __init__(
        self,
        value: int | None = None,
        id: int | None = None,
        tag: int | None = None,
    ) -> None:
        """
        Initialize the object

        l=LDAPAbandonRequest(id=1)
        """
        if id is None and value is not None:
            id = value
        LDAPProtocolRequest.__init__(self)
        LDAPInteger.__init__(self, value=id, tag=tag)

    def toWire(self) -> bytes:
        return LDAPInteger.toWire(self)

    def __repr__(self) -> str:
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(id=%s)" % repr(self.value)
        else:
            return self.__class__.__name__ + "(id=%s, tag=%d)" % (
                repr(self.value),
                self.tag,
            )


class LDAPOID(BEROctetString):
    pass


class LDAPResponseName(LDAPOID):
    tag = CLASS_CONTEXT | 10


class LDAPResponse(BEROctetString):
    tag = CLASS_CONTEXT | 11


class LDAPBERDecoderContext_LDAPExtendedRequest(BERDecoderContext):
    Identities = {
        CLASS_CONTEXT | 0x00: BEROctetString,
        CLASS_CONTEXT | 0x01: BEROctetString,
    }


class LDAPExtendedRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 23

    oid: ClassVar[bytes]

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPExtendedRequest(fallback=berdecoder)
        )

        requestValue: str | bytes | None
        try:
            requestValue = _octetString(l[1]).value
        except IndexError:
            requestValue = None

        r = klass(
            requestName=_octetString(l[0]).value, requestValue=requestValue, tag=tag
        )
        return r

    def __init__(
        self,
        requestName: str | bytes | None = None,
        requestValue: str | bytes | None = None,
        tag: int | None = None,
    ) -> None:
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert requestName is not None
        assert isinstance(requestName, (bytes, str))
        assert requestValue is None or isinstance(requestValue, (bytes, str))
        self.requestName = requestName
        self.requestValue = requestValue

    def toWire(self) -> bytes:
        l: list[BERBase] = [LDAPOID(self.requestName, tag=CLASS_CONTEXT | 0)]
        if self.requestValue is not None:
            value = to_bytes(self.requestValue)
            l.append(BEROctetString(value, tag=CLASS_CONTEXT | 1))
        return BERSequence(l, tag=self.tag).toWire()


class LDAPPasswordModifyRequest_userIdentity(BEROctetString):
    tag = CLASS_CONTEXT | 0


class LDAPPasswordModifyRequest_passwd(BEROctetString):
    def __repr__(self) -> str:
        value = "*" * len(self.value)
        return "{}(value={}{})".format(
            self.__class__.__name__,
            repr(value),
            f", tag={self.tag}" if self.tag != self.__class__.tag else "",
        )


class LDAPPasswordModifyRequest_oldPasswd(LDAPPasswordModifyRequest_passwd):
    tag = CLASS_CONTEXT | 1


class LDAPPasswordModifyRequest_newPasswd(LDAPPasswordModifyRequest_passwd):
    tag = CLASS_CONTEXT | 2


class LDAPBERDecoderContext_LDAPPasswordModifyRequest(BERDecoderContext):
    Identities = {
        LDAPPasswordModifyRequest_userIdentity.tag: LDAPPasswordModifyRequest_userIdentity,
        LDAPPasswordModifyRequest_oldPasswd.tag: LDAPPasswordModifyRequest_oldPasswd,
        LDAPPasswordModifyRequest_newPasswd.tag: LDAPPasswordModifyRequest_newPasswd,
    }


class LDAPPasswordModifyRequest(LDAPExtendedRequest):
    oid = b"1.3.6.1.4.1.4203.1.11.1"

    def __init__(
        self,
        requestName: str | bytes | None = None,
        userIdentity: str | bytes | None = None,
        oldPasswd: str | bytes | None = None,
        newPasswd: str | bytes | None = None,
        tag: int | None = None,
    ) -> None:
        assert (
            requestName is None or requestName == self.oid
        ), f"{self.__class__.__name__} requestName was {requestName!r} instead of {self.oid!r}"
        # TODO genPasswd

        l: list[BERBase] = []
        self.userIdentity = None
        if userIdentity is not None:
            self.userIdentity = LDAPPasswordModifyRequest_userIdentity(userIdentity)
            l.append(self.userIdentity)

        self.oldPasswd = None
        if oldPasswd is not None:
            self.oldPasswd = LDAPPasswordModifyRequest_oldPasswd(oldPasswd)
            l.append(self.oldPasswd)

        self.newPasswd = None
        if newPasswd is not None:
            self.newPasswd = LDAPPasswordModifyRequest_newPasswd(newPasswd)
            l.append(self.newPasswd)

        LDAPExtendedRequest.__init__(
            self, requestName=self.oid, requestValue=BERSequence(l).toWire(), tag=tag
        )

    def __repr__(self) -> str:
        l = []
        if self.userIdentity is not None:
            l.append(f"userIdentity={self.userIdentity!r}")
        if self.oldPasswd is not None:
            l.append(f"oldPasswd={self.oldPasswd!r}")
        if self.newPasswd is not None:
            l.append(f"newPasswd={self.newPasswd!r}")
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPCancelRequest(LDAPExtendedRequest):
    """
    Ask the server to stop working on an operation, and say that it has.
    See RFC 3909 for details: unlike an abandon, this is answered.
    """

    oid = b"1.3.6.1.1.8"

    def __init__(
        self,
        requestName: str | bytes | None = None,
        cancelID: int | None = None,
        tag: int | None = None,
    ) -> None:
        assert (
            requestName is None or requestName == self.oid
        ), f"{self.__class__.__name__} requestName was {requestName!r} instead of {self.oid!r}"
        assert cancelID is not None
        self.cancelID = cancelID
        LDAPExtendedRequest.__init__(
            self,
            requestName=self.oid,
            requestValue=BERSequence([BERInteger(cancelID)]).toWire(),
            tag=tag,
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(cancelID={self.cancelID})"


class LDAPBERDecoderContext_LDAPExtendedResponse(BERDecoderContext):
    Identities = {
        LDAPResponseName.tag: LDAPResponseName,
        LDAPResponse.tag: LDAPResponse,
        LDAPReferral.tag: LDAPReferral,
    }


class LDAPExtendedResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x18

    oid: ClassVar[bytes]

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPExtendedResponse(fallback=berdecoder)
        )

        assert 3 <= len(l) <= 6

        referral: list[bytes] | None = None
        responseName: str | bytes | None = None
        response: str | bytes | None = None
        for obj in l[3:]:
            if isinstance(obj, LDAPResponseName):
                responseName = obj.value
            elif isinstance(obj, LDAPResponse):
                response = obj.value
            elif isinstance(obj, LDAPReferral):
                referral = _referral_uris(obj)
            else:
                assert False

        resultCode = l[0]
        assert isinstance(resultCode, BERInteger)

        r = klass(
            resultCode=resultCode.value,
            matchedDN=_octetString(l[1]).value,
            errorMessage=_octetString(l[2]).value,
            referral=referral,
            responseName=responseName,
            response=response,
            tag=tag,
        )
        return r

    def __init__(
        self,
        resultCode: int | None = None,
        matchedDN: str | bytes | None = None,
        errorMessage: str | bytes | None = None,
        referral: Sequence[str | bytes] | None = None,
        serverSaslCreds: str | bytes | None = None,
        responseName: str | bytes | None = None,
        response: str | bytes | None = None,
        tag: int | None = None,
    ) -> None:
        LDAPResult.__init__(
            self,
            resultCode=resultCode,
            matchedDN=matchedDN,
            errorMessage=errorMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            tag=tag,
        )
        self.responseName = responseName
        self.response = response

    def toWire(self) -> bytes:
        l: list[BERBase] = [
            BEREnumerated(self.resultCode),
            BEROctetString(self.matchedDN),
            BEROctetString(self.errorMessage),
        ]
        referral = _referral(self.referral)
        if referral is not None:
            l.append(referral)
        if self.responseName is not None:
            l.append(LDAPOID(self.responseName, tag=CLASS_CONTEXT | 0x0A))
        if self.response is not None:
            l.append(BEROctetString(self.response, tag=CLASS_CONTEXT | 0x0B))
        return BERSequence(l, tag=self.tag).toWire()


class LDAPBERDecoderContext_LDAPIntermediateResponse(BERDecoderContext):
    Identities = {
        CLASS_CONTEXT | 0x00: LDAPOID,
        CLASS_CONTEXT | 0x01: BEROctetString,
    }


class LDAPIntermediateResponse(LDAPProtocolResponse, BERSequence):
    """
    Something the server says while an operation is still running.

    RFC 4511 section 4.13: a name saying what kind of message it is, and a
    value whose shape that name decides. Syncrepl's Sync Info message is
    one of these.
    """

    tag = CLASS_APPLICATION | 0x19

    responseName: bytes | None
    responseValue: bytes | None

    @classmethod
    def fromBER(
        klass,
        tag: int,
        content: bytes,
        berdecoder: BERDecoderContext | None = None,
    ) -> Self:
        l = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPIntermediateResponse(fallback=berdecoder)
        )
        responseName: bytes | None = None
        responseValue: bytes | None = None
        for obj in l:
            assert isinstance(obj, BEROctetString)
            if obj.tag == CLASS_CONTEXT | 0x00:
                responseName = to_bytes(obj.value)
            else:
                responseValue = to_bytes(obj.value)
        return klass(
            responseName=responseName, responseValue=responseValue, tag=tag
        )

    def __init__(
        self,
        responseName: str | bytes | None = None,
        responseValue: str | bytes | None = None,
        tag: int | None = None,
    ) -> None:
        BERSequence.__init__(self, value=[], tag=tag)
        self.responseName = None if responseName is None else to_bytes(responseName)
        self.responseValue = None if responseValue is None else to_bytes(responseValue)

    def toWire(self) -> bytes:
        l: list[BERBase] = []
        if self.responseName is not None:
            l.append(LDAPOID(self.responseName, tag=CLASS_CONTEXT | 0x00))
        if self.responseValue is not None:
            l.append(BEROctetString(self.responseValue, tag=CLASS_CONTEXT | 0x01))
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self) -> str:
        return "{}(responseName={!r}, responseValue={!r})".format(
            self.__class__.__name__, self.responseName, self.responseValue
        )


LDAPBERDecoderContext_LDAPMessage.Identities[LDAPIntermediateResponse.tag] = (
    LDAPIntermediateResponse
)


class LDAPStartTLSRequest(LDAPExtendedRequest):
    """
    Request to start Transport Layer Security.
    See RFC 2830 for details.
    """

    oid = b"1.3.6.1.4.1.1466.20037"

    def __init__(
        self, requestName: str | bytes | None = None, tag: int | None = None
    ) -> None:
        assert (
            requestName is None or requestName == self.oid
        ), f"{self.__class__.__name__} requestName was {requestName!r} instead of {self.oid!r}"

        LDAPExtendedRequest.__init__(self, requestName=self.oid, tag=tag)

    def __repr__(self) -> str:
        l = []
        if self.tag != self.__class__.tag:
            l.append(f"tag={self.tag}")
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPStartTLSResponse(LDAPExtendedResponse):
    """
    Response to start Transport Layer Security.
    See RFC 4511 section 4.14.2 for details.
    """

    oid = b"1.3.6.1.4.1.1466.20037"

    def __init__(
        self,
        resultCode: int | None = None,
        matchedDN: str | bytes | None = None,
        errorMessage: str | bytes | None = None,
        referral: Sequence[str | bytes] | None = None,
        serverSaslCreds: str | bytes | None = None,
        responseName: str | bytes | None = None,
        response: str | bytes | None = None,
        tag: int | None = None,
    ) -> None:
        LDAPExtendedResponse.__init__(
            self,
            resultCode=resultCode,
            matchedDN=matchedDN,
            errorMessage=errorMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            responseName=responseName,
            response=response,
            tag=tag,
        )

    def __repr__(self) -> str:
        l = []
        if self.tag != self.__class__.tag:
            l.append(f"tag={self.tag}")
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPBERDecoderContext(BERDecoderContext):
    Identities = {
        LDAPBindResponse.tag: LDAPBindResponse,
        LDAPBindRequest.tag: LDAPBindRequest,
        LDAPUnbindRequest.tag: LDAPUnbindRequest,
        LDAPSearchRequest.tag: LDAPSearchRequest,
        LDAPSearchResultEntry.tag: LDAPSearchResultEntry,
        LDAPSearchResultDone.tag: LDAPSearchResultDone,
        LDAPSearchResultReference.tag: LDAPSearchResultReference,
        LDAPReferral.tag: LDAPReferral,
        LDAPModifyRequest.tag: LDAPModifyRequest,
        LDAPModifyResponse.tag: LDAPModifyResponse,
        LDAPAddRequest.tag: LDAPAddRequest,
        LDAPAddResponse.tag: LDAPAddResponse,
        LDAPDelRequest.tag: LDAPDelRequest,
        LDAPDelResponse.tag: LDAPDelResponse,
        LDAPExtendedRequest.tag: LDAPExtendedRequest,
        LDAPExtendedResponse.tag: LDAPExtendedResponse,
        LDAPModifyDNRequest.tag: LDAPModifyDNRequest,
        LDAPModifyDNResponse.tag: LDAPModifyDNResponse,
        LDAPAbandonRequest.tag: LDAPAbandonRequest,
        LDAPCompareRequest.tag: LDAPCompareRequest,
        LDAPCompareResponse.tag: LDAPCompareResponse,
    }
