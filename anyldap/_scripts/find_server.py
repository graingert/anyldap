import sys
from collections.abc import Sequence

import anyio
import dns.asyncresolver
import dns.rdatatype

from anyldap.protocols.ldap.distinguishedname import DistinguishedName


async def lookup(dn_string: str) -> None:
    dn = DistinguishedName(stringValue=dn_string)
    domain = dn.getDomainName()
    answers = await dns.asyncresolver.resolve(f"_ldap._tcp.{domain}", "SRV")
    for record in answers:
        if record.rdtype == dns.rdatatype.SRV:
            print(
                f"{dn_string}\tpri={record.priority} weight={record.weight} {record.target}:{record.port}"
            )


async def main(dns_names: Sequence[str]) -> None:
    for dn_string in dns_names:
        await lookup(dn_string)


def console_script() -> None:
    if not sys.argv[1:]:
        print(f"{sys.argv[0]}: usage:", file=sys.stderr)
        print(f"  {sys.argv[0]} DN..", file=sys.stderr)
        raise SystemExit(1)
    anyio.run(main, sys.argv[1:])


if __name__ == "__main__":
    console_script()
