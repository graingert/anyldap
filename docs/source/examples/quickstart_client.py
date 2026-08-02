"""Connect, bind, and search an LDAP directory with AnyIO."""

import anyio

from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapsyntax


async def main():
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
        results = await directory.search_async(filterText=b"(cn=Alice*)")
        for result in results:
            print(result.getLDIF())


if __name__ == "__main__":
    anyio.run(main)
