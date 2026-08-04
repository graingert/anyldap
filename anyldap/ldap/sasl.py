"""``ldap.sasl``: the mechanisms a SASL bind can be made with.

A mechanism is an object that knows its name and answers the challenges the
server sends, which is the same shape python-ldap's ``ldap.sasl`` classes
have. python-ldap hands the exchange to Cyrus SASL; the mechanisms here
answer for themselves, so what is available is what is written below.
"""

import hashlib
import hmac
import secrets
from collections.abc import Mapping
from typing import Any

from anyldap._encoder import to_bytes

# What python-ldap's callback dictionaries are keyed by, so that a mechanism
# written for it can be built the same way here.
CB_USER = 0x4001
CB_AUTHNAME = 0x4002
CB_LANGUAGE = 0x4003
CB_PASS = 0x4004
CB_ECHOPROMPT = 0x4005
CB_NOECHOPROMPT = 0x4006
CB_GETREALM = 0x4008


class sasl:
    """A SASL mechanism, as python-ldap's base class names one.

    ``process()`` is given what the server sent, or nothing on the first
    step, and answers with what to send back; the bind is finished when the
    server says it is.
    """

    def __init__(
        self, cb_value_dict: Mapping[int, str] | None, mech: str | bytes
    ) -> None:
        self.cb_value_dict = dict(cb_value_dict or {})
        # The name goes on the wire as it is written, which is why
        # python-ldap keeps it in bytes and so does this.
        self.mech = to_bytes(mech)

    def callback(self, cb_id: int, challenge: str, prompt: str, defresult: str) -> str:
        """What python-ldap's interactive bind asks its caller for."""
        return self.cb_value_dict.get(cb_id, defresult)

    def process(self, challenge: bytes | None = None) -> bytes | None:
        """The credentials to send, given what the server sent."""
        return None


class external(sasl):
    """EXTERNAL: the identity is the one the connection already proved.

    Which is TLS with a client certificate, or the credentials of whoever
    opened a socket in the filesystem.
    """

    def __init__(self, authz_id: str | None = None) -> None:
        sasl.__init__(self, {CB_USER: authz_id} if authz_id else {}, "EXTERNAL")
        self.authz_id = authz_id

    def process(self, challenge: bytes | None = None) -> bytes:
        # The response is always sent, even when it is empty: that is what
        # says the identity is the connection's own.
        return to_bytes(self.authz_id or self.cb_value_dict.get(CB_USER, ""))


class plain(sasl):
    """PLAIN: the name and password, sent as they are (RFC 4616)."""

    def __init__(
        self, authc_id: str, password: str, authz_id: str = ""
    ) -> None:
        sasl.__init__(
            self, {CB_AUTHNAME: authc_id, CB_PASS: password}, "PLAIN"
        )
        self.authz_id = authz_id

    def process(self, challenge: bytes | None = None) -> bytes:
        return b"\0".join(
            (
                to_bytes(self.authz_id),
                to_bytes(self.cb_value_dict[CB_AUTHNAME]),
                to_bytes(self.cb_value_dict[CB_PASS]),
            )
        )


class cram_md5(sasl):
    """CRAM-MD5: the server's challenge, answered with a keyed digest.

    RFC 2195. The password is not sent, and the challenge is used once.
    """

    def __init__(self, authc_id: str, password: str) -> None:
        sasl.__init__(
            self, {CB_AUTHNAME: authc_id, CB_PASS: password}, "CRAM-MD5"
        )

    def process(self, challenge: bytes | None = None) -> bytes | None:
        if challenge is None:
            # The server speaks first; there is nothing to answer yet.
            return None
        digest = hmac.new(
            to_bytes(self.cb_value_dict[CB_PASS]), challenge, hashlib.md5
        ).hexdigest()
        return to_bytes(self.cb_value_dict[CB_AUTHNAME]) + b" " + to_bytes(digest)


class digest_md5(sasl):
    """DIGEST-MD5: a challenge answered without sending the password.

    RFC 2831, which is historic; a server that offers it usually offers
    something better as well.
    """

    def __init__(self, authc_id: str, password: str, authz_id: str = "") -> None:
        sasl.__init__(
            self, {CB_AUTHNAME: authc_id, CB_PASS: password}, "DIGEST-MD5"
        )
        self.authz_id = authz_id

    def process(self, challenge: bytes | None = None) -> bytes | None:
        if challenge is None:
            return None
        fields = _parse_challenge(challenge)
        if b"rspauth" in fields:
            # The server proving itself in turn, which needs no answer.
            return b""
        realm = fields.get(b"realm", b"")
        nonce = fields[b"nonce"]
        cnonce = to_bytes(secrets.token_hex(16))
        digest_uri = b"ldap/" + fields.get(b"host", realm or b"localhost")
        username = to_bytes(self.cb_value_dict[CB_AUTHNAME])
        password = to_bytes(self.cb_value_dict[CB_PASS])

        a1 = (
            hashlib.md5(b":".join((username, realm, password))).digest()
            + b":"
            + nonce
            + b":"
            + cnonce
        )
        if self.authz_id:
            a1 += b":" + to_bytes(self.authz_id)
        a2 = b"AUTHENTICATE:" + digest_uri
        response = hashlib.md5(
            b":".join(
                (
                    to_bytes(hashlib.md5(a1).hexdigest()),
                    nonce,
                    b"00000001",
                    cnonce,
                    b"auth",
                    to_bytes(hashlib.md5(a2).hexdigest()),
                )
            )
        ).hexdigest()

        answer = [
            b'username="' + username + b'"',
            b'realm="' + realm + b'"',
            b'nonce="' + nonce + b'"',
            b'cnonce="' + cnonce + b'"',
            b"nc=00000001",
            b"qop=auth",
            b'digest-uri="' + digest_uri + b'"',
            b"response=" + to_bytes(response),
        ]
        if self.authz_id:
            answer.append(b'authzid="' + to_bytes(self.authz_id) + b'"')
        return b",".join(answer)


class gssapi(sasl):
    """GSSAPI: Kerberos, as RFC 4752 exchanges it.

    The exchange needs a Kerberos library, which the ``gssapi`` package is:
    it is not a dependency, and this mechanism says so if it is asked for
    without it. The ticket comes from the caller's credential cache, so
    there is nothing to pass but the identity to act as, if any.

    ``service`` names what the ticket is for. Left unset, the bind fills it
    in with ``ldap@`` and the host it is connecting to, which is what a
    server registers itself as.
    """

    def __init__(self, authz_id: str = "", service: str | None = None) -> None:
        sasl.__init__(self, {CB_USER: authz_id}, "GSSAPI")
        self.authz_id = authz_id
        self.service = service
        self._context: Any = None

    def process(self, challenge: bytes | None = None) -> bytes:
        gssapi = _gssapi()
        if self._context is None:
            if self.service is None:
                raise ValueError("gssapi() was not told which service to ask for")
            name = gssapi.Name(self.service, gssapi.NameType.hostbased_service)
            self._context = gssapi.SecurityContext(name=name, usage="initiate")
        context = self._context
        if not context.complete:
            # Still proving who each side is: whatever the library says to
            # send next goes as it stands.
            return context.step(challenge) or b""
        # The context is up, and what is left is to say which security layer
        # to use. The server offers them in a wrapped token; this answers
        # with none, since TLS is what protects the connection.
        assert challenge is not None
        context.unwrap(challenge)
        answer = bytes([_NO_SECURITY_LAYER, 0, 0, 0]) + to_bytes(self.authz_id)
        wrapped = context.wrap(answer, False)
        return bytes(wrapped.message)


# What RFC 4752 calls the bit for "no security layer": the connection is
# protected by TLS, or by nothing, but not by SASL.
_NO_SECURITY_LAYER = 0x01


def _gssapi() -> Any:  # pragma: no cover - depends on what is installed
    """The ``gssapi`` package, or a plain word about it not being there."""
    try:
        import gssapi
    except ImportError as exc:
        raise ImportError(
            "the GSSAPI mechanism needs the gssapi package, which is not"
            " installed: pip install gssapi"
        ) from exc
    return gssapi


def _parse_challenge(challenge: bytes) -> dict[bytes, bytes]:
    """A DIGEST-MD5 challenge, taken apart into the fields it is written in."""
    fields: dict[bytes, bytes] = {}
    for part in challenge.split(b","):
        key, sep, value = part.strip().partition(b"=")
        if sep:
            fields[key] = value.strip(b'"')
    return fields
