import sys

import anyio

from anyldap import config, usage
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapsyntax


def printResults(entry):
    sys.stdout.write(str(entry))


async def main(cfg, filter_text, attributes):
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
    await entry.search_async(
        filterText=filter_text,
        attributes=attributes,
        callback=printResults,
    )


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """Command line search utility."""

    def parseArgs(self, filter, *attributes):
        self.opts["filter"] = filter
        self.opts["attributes"] = attributes


def console_script():
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
    anyio.run(main, cfg, opts["filter"], opts["attributes"])


if __name__ == "__main__":
    console_script()
