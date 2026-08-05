import getpass
import os
import sys
from collections.abc import Sequence

import anyio

from anyldap import generate_password, interfaces, usage
from anyldap.protocols.ldap import (
    distinguishedname,
    ldapclient,
    ldapconnector,
    ldapsyntax,
)


async def _get_password(dn: str, generatePasswords: bool) -> str:
    if not generatePasswords:
        return getpass.getpass(f"NEW Password for {dn}: ")
    return (await generate_password.generate_async())[0]


async def main(
    binddn: str,
    bindPassword: str | None,
    dnlist: Sequence[str],
    generatePasswords: bool,
    overrides: interfaces.ServiceLocationOverrides | None,
) -> None:
    creator = ldapconnector.LDAPClientCreator(None, ldapclient.LDAPClient)
    dn = distinguishedname.DistinguishedName(stringValue=binddn)
    client = await creator.connectAsync(dn=dn, overrides=overrides)
    await client.bind_async(binddn, bindPassword or getpass.getpass(f"Password for {binddn}: "))
    for target_dn in dnlist:
        password = await _get_password(target_dn, generatePasswords)
        entry = ldapsyntax.LDAPEntry(client=client, dn=target_dn)
        await entry.setPassword_async(newPasswd=password.encode("utf-8"))
        if generatePasswords:
            print(target_dn, password)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_bind_mandatory
):
    """Password change utility."""

    synopsis = f"Usage: {sys.argv[0]} --binddn=DN [OPTION..] [DN..]"
    optFlags = [("generate", None, "Generate random passwords")]

    def parseArgs(self, *dnlist: str) -> None:
        self.opts["dnlist"] = dnlist or (self.opts["binddn"],)


def console_script() -> None:
    try:
        options = MyOptions()
        options.parseOptions()
    except usage.UsageError as exc:
        print(f"{sys.argv[0]}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    bindPassword = None
    if options.opts["bind-auth-fd"]:
        with os.fdopen(options.opts["bind-auth-fd"]) as fd:
            bindPassword = fd.readline().rstrip("\n")

    anyio.run(
        main,
        options.opts["binddn"],
        bindPassword,
        options.opts["dnlist"],
        options.opts["generate"],
        options.opts["service-location"],
    )


if __name__ == "__main__":
    console_script()
