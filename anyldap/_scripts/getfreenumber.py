import sys

import anyio

from anyldap import config, interfaces, numberalloc, usage
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapsyntax


async def main(cfg: interfaces.ILDAPConfig) -> None:
    try:
        base_dn = cfg.getBaseDN()
    except config.MissingBaseDNError as exc:
        print(f"{sys.argv[0]}: {exc}.", file=sys.stderr)
        raise SystemExit(1) from exc

    creator = ldapconnector.LDAPClientCreator(None, ldapclient.LDAPClient)
    client = await creator.connectAnonymouslyAsync(
        dn=base_dn,
        overrides=cfg.getServiceLocationOverrides(),
    )
    entry = ldapsyntax.LDAPEntry(client=client, dn=base_dn)
    number = await numberalloc.getFreeNumber(entry, "uidNumber", min=1000)
    sys.stdout.write(f"{number!r}\n")


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """Command line free-number utility."""


def console_script() -> None:
    try:
        opts = MyOptions()
        opts.parseOptions()
    except usage.UsageError as exc:
        sys.stderr.write(f"{sys.argv[0]}: {exc}\n")
        raise SystemExit(1) from exc

    cfg = config.LDAPConfig(
        baseDN=opts["base"],
        serviceLocationOverrides=opts["service-location"],
    )
    anyio.run(main, cfg)


if __name__ == "__main__":
    console_script()
