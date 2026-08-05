import sys
from typing import IO

import anyio

from anyldap import delta, inmemory, interfaces, usage
from anyldap.protocols.ldap import ldif, ldifdelta


async def output(
    tree: inmemory.ReadOnlyInMemoryLDAPEntry, outputFile: IO[bytes]
) -> None:
    outputFile.write(ldif._header())

    async def _write(node: interfaces.IConnectedLDAPEntry) -> None:
        outputFile.write(node.toWire())

    await tree.subtree(callback=_write)


async def main(dataPath: str, patchFile: IO[bytes], outputFile: IO[bytes]) -> None:
    async with await anyio.Path(dataPath).open("rb") as dataFile:
        db = await inmemory.fromLDIFFile(dataFile)
    patches = ldifdelta.fromLDIFFile(patchFile)
    for patch in patches:
        assert isinstance(patch, delta.Operation)
        await patch.patch(db)
    await output(db, outputFile)


class MyOptions(usage.Options):
    """LDIF patching utility."""

    def parseArgs(self, data: str) -> None:
        self["data"] = data


def console_script() -> None:
    try:
        options = MyOptions()
        options.parseOptions()
    except usage.UsageError as exc:
        sys.stderr.write(f"{sys.argv[0]}: {exc}\n")
        raise SystemExit(1) from exc

    anyio.run(main, options["data"], sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    console_script()
