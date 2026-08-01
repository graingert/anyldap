import getpass
import os
import sys

import anyio

from anyldap import config, usage
from anyldap.protocols.ldap import (
    distinguishedname,
    ldapclient,
    ldapconnector,
    ldapsyntax,
)


async def main(cfg, fromDN, toDN, binddn, bindPassword):
    from_dn = distinguishedname.DistinguishedName(stringValue=fromDN)
    to_dn = distinguishedname.DistinguishedName(stringValue=toDN)
    creator = ldapconnector.LDAPClientCreator(None, ldapclient.LDAPClient)
    client = await creator.connectAsync(
        dn=from_dn,
        overrides=cfg.getServiceLocationOverrides(),
    )
    if binddn:
        password = bindPassword
        if password is None:
            password = getpass.getpass(f"Password for {binddn}: ")
        await client.bind_async(binddn, password)
    else:
        await client.bind_async()
    entry = ldapsyntax.LDAPEntry(client=client, dn=from_dn)
    await entry.move_async(to_dn)


class MyOptions(usage.Options, usage.Options_service_location, usage.Options_bind):
    """Object rename utility."""

    def parseArgs(self, fromDN, toDN):
        self.opts["from"] = fromDN
        self.opts["to"] = toDN


def console_script():
    try:
        opts = MyOptions()
        opts.parseOptions()
    except usage.UsageError as exc:
        sys.stderr.write(f"{sys.argv[0]}: {exc}\n")
        raise SystemExit(1) from exc

    cfg = config.LDAPConfig(serviceLocationOverrides=opts["service-location"])
    bindPassword = None
    if opts["bind-auth-fd"]:
        with os.fdopen(opts["bind-auth-fd"]) as fd:
            bindPassword = fd.readline().rstrip("\n")
    anyio.run(main, cfg, opts["from"], opts["to"], opts["binddn"], bindPassword)


if __name__ == "__main__":
    console_script()
