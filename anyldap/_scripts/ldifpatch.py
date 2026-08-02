import sys

import anyio

from anyldap import inmemory, usage
from anyldap.protocols.ldap import ldif, ldifdelta


async def output(tree, outputFile):
    outputFile.write(ldif._header())

    def _write(node):
        outputFile.write(node.toWire())

    await tree.subtree(callback=_write)


async def main(dataPath, patchFile, outputFile):
    async with await anyio.Path(dataPath).open("rb") as dataFile:
        db = await inmemory.fromLDIFFile(dataFile)
    patches = ldifdelta.fromLDIFFile(patchFile)
    for patch in patches:
        await patch.patch(db)
    await output(db, outputFile)


class MyOptions(usage.Options):
    """LDIF patching utility."""

    def parseArgs(self, data):
        self["data"] = data


def console_script():
    try:
        options = MyOptions()
        options.parseOptions()
    except usage.UsageError as exc:
        sys.stderr.write(f"{sys.argv[0]}: {exc}\n")
        raise SystemExit(1) from exc

    anyio.run(main, options["data"], sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    console_script()
