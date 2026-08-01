"""Serve a minimal in-memory LDAP directory with AnyIO."""

import anyio

from anyldap.inmemory import ReadOnlyInMemoryLDAPEntry
from anyldap.protocols.ldap import ldapserver


def build_server():
    root = ReadOnlyInMemoryLDAPEntry(
        dn="dc=example,dc=com",
        attributes={"dc": "example", "objectClass": ["domain"]},
    )
    root.addChild(
        "ou=people",
        {"ou": "people", "objectClass": ["organizationalUnit"]},
    )
    server = ldapserver.LDAPServer()
    server.factory = root
    return server


async def main():
    await ldapserver.listen("127.0.0.1", 1389, build_server)


if __name__ == "__main__":
    anyio.run(main)
