import sys
from collections.abc import Sequence

import anyio

from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapconnector, ldapsyntax


async def lookup(server: str) -> None:
    connection = await ldapconnector.connectToLDAPEndpointAsync(
        f"tcp:host={server}:port=389",
        lambda: __import__("anyldap.protocols.ldap.ldapclient", fromlist=["LDAPClient"]).LDAPClient(),
    )
    client = connection.protocol
    await client.bind_async()
    entry = ldapsyntax.LDAPEntry(client=client, dn="")
    result = await entry.search_async(
        filterText="(objectClass=*)",
        scope=pureldap.LDAP_SCOPE_baseObject,
        attributes=["namingContexts"],
    )
    assert isinstance(result, Sequence)
    for context in result[0]["namingContexts"]:
        print(f"{server}\t{context}")


async def main(servers: Sequence[str]) -> None:
    for server in servers:
        await lookup(server)


def console_script() -> None:
    if not sys.argv[1:]:
        print(f"{sys.argv[0]}: usage:", file=sys.stderr)
        print(f"  {sys.argv[0]} HOST..", file=sys.stderr)
        raise SystemExit(1)
    anyio.run(main, sys.argv[1:])


if __name__ == "__main__":
    console_script()
