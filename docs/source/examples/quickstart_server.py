"""Serve a minimal in-memory LDAP directory with AnyIO."""

import anyio

from anyldap.inmemory import ReadOnlyInMemoryLDAPEntry
from anyldap.protocols.ldap import ldapserver


class DirectoryServer(ldapserver.LDAPServer):
    def __init__(self) -> None:
        super().__init__()
        root = ReadOnlyInMemoryLDAPEntry(
            dn="dc=example,dc=com",
            attributes={"dc": "example", "objectClass": ["domain"]},
        )
        root.addChild(
            "ou=people",
            {"ou": "people", "objectClass": ["organizationalUnit"]},
        )
        self.factory = root


async def main() -> None:
    async with anyio.create_task_group() as task_group:
        host, port = await task_group.start(
            DirectoryServer.listen,
            "127.0.0.1",
            1389,
        )
        print(f"LDAP server listening on {host}:{port}")
        await anyio.sleep_forever()


if __name__ == "__main__":
    anyio.run(main)
