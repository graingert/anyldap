"""Connect, bind, and search an LDAP directory with AnyIO."""

from collections.abc import Sequence
from typing import cast

import anyio

from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapsyntax


async def main() -> None:
    base_dn = b"dc=example,dc=com"
    overrides = {base_dn: ("ldap.example.com", 389)}

    connection = await ldapconnector.connectToLDAPDNAsync(
        base_dn,
        ldapclient.LDAPClient,
        overrides=overrides,
    )
    async with connection as client:
        await client.bind_async(b"uid=alice,ou=people,dc=example,dc=com", b"secret")
        directory = ldapsyntax.LDAPEntry(client, base_dn)
        # What a search hands back depends on how it was called, so the
        # interface says only that it hands something back.
        results = cast(
            Sequence[ldapsyntax.LDAPEntry],
            await directory.search_async(filterText="(cn=Alice*)"),
        )
        for result in results:
            print(result.getLDIF())


if __name__ == "__main__":
    anyio.run(main)
