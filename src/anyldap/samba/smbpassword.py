from anyldap import config
from anyldap.samba._passlib._md4 import md4
from anyldap.samba._passlib.des import des_encrypt_block

# The fixed plaintext the LM hash encrypts under each half of the password.
_LM_CONSTANT = b"KGS!@#$%"


def nthash(password: str | bytes = b"") -> bytes:
    """Generates nt md4 password hash for a given password."""
    text = password.decode("utf-8") if isinstance(password, bytes) else password
    return md4(text[:128].encode("utf-16-le")).hexdigest().upper().encode("ascii")


def lmhash_locked(password: str | bytes = b"") -> bytes:
    """
    Generates a lanman password hash that matches no password.

    Note that the author thinks LanMan hashes should be banished from
    the face of the earth.
    """
    return 32 * b"X"


def lmhash(password: str | bytes = b"") -> bytes:
    """
    Generates lanman password hash for a given password.

    Note that the author thinks LanMan hashes should be banished from
    the face of the earth.
    """

    if not config.useLMhash():
        return lmhash_locked()

    raw = password.encode("utf-8") if isinstance(password, str) else password
    secret = raw.upper()[:14].ljust(14, b"\0")
    digest = b"".join(
        des_encrypt_block(secret[offset : offset + 7], _LM_CONSTANT)
        for offset in (0, 7)
    )
    return digest.hex().upper().encode("ascii")
