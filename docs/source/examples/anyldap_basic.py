"""Run a minimal LDAP directory with the AnyIO listener API."""

import anyio

from anyldap.inmemory import ReadOnlyInMemoryLDAPEntry
from anyldap.protocols.ldap import ldapserver


class DirectoryServer(ldapserver.LDAPServer):
    def __init__(self):
        super().__init__()
        self.factory = ReadOnlyInMemoryLDAPEntry(
            dn="dc=example,dc=com",
            attributes={"dc": "example", "objectClass": ["domain"]},
        )


async def main():
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
