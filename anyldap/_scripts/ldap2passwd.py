import sys

import anyio

from anyldap import config, interfaces, ldapfilter, usage
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapsyntax


def _cbSearch(entry: interfaces.Attributes) -> None:
    attributes: dict[str, list[str]] = {}
    for attr, vals in entry.items():
        attributes[str(attr)] = [str(val) for val in vals]
    print(
        ":".join(
            (
                attributes["uid"][0],
                "x",
                attributes["uidNumber"][0],
                attributes["gidNumber"][0],
                attributes.get("gecos", attributes.get("cn", [""]))[0],
                attributes["homeDirectory"][0],
                attributes.get("loginShell", [""])[0],
            )
        )
    )


async def main(cfg: interfaces.LDAPBaseConfigLike, filter_text: str | None) -> None:
    try:
        base_dn = cfg.getBaseDN()
    except config.MissingBaseDNError as exc:
        print(f"{sys.argv[0]}: {exc}.", file=sys.stderr)
        raise SystemExit(1) from exc

    filt = ldapfilter.parseFilter("(objectClass=posixAccount)")
    if filter_text is not None:
        filt = pureldap.LDAPFilter_and([filt, ldapfilter.parseFilter(filter_text)])

    creator = ldapconnector.LDAPClientCreator(None, ldapclient.LDAPClient)
    client = await creator.connectAnonymouslyAsync(
        dn=base_dn,
        overrides=cfg.getServiceLocationOverrides(),
    )
    entry = ldapsyntax.LDAPEntry(client=client, dn=base_dn)
    await entry.search_async(
        filterObject=filt,
        attributes=[
            "uid",
            "uidNumber",
            "gidNumber",
            "gecos",
            "cn",
            "homeDirectory",
            "loginShell",
        ],
        callback=_cbSearch,
    )


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """Command line passwd-file export utility."""

    def parseArgs(self, filter: str | None = None) -> None:
        self.opts["filter"] = filter


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
    anyio.run(main, cfg, opts["filter"])


if __name__ == "__main__":
    console_script()
