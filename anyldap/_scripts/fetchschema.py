import sys

import anyio

from anyldap import config, usage
from anyldap.protocols.ldap import fetchschema, ldapclient, ldapconnector


def _printResults(result):
    attributeTypes, objectClasses = result
    something = False
    for attribute_type in attributeTypes:
        print("attributetype", attribute_type)
        something = True
    if something:
        print()
    for object_class in objectClasses:
        print("objectclass", object_class)


async def main(cfg):
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
    result = await fetchschema.fetch(client, base_dn)
    _printResults(result)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """Command line schema fetching utility."""


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
    anyio.run(main, cfg)


if __name__ == "__main__":
    console_script()
