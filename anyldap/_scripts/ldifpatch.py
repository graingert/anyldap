import sys

import anyio

from anyldap import inmemory, usage
from anyldap._async import await_result
from anyldap.protocols.ldap import ldif, ldifdelta


def output(tree, outputFile):
    outputFile.write(ldif._header().decode("ascii"))

    def _write(node):
        outputFile.write(str(node))

    tree.subtree(callback=_write)


async def main(dataFile, patchFile, outputFile):
    db = await await_result(inmemory.fromLDIFFile(dataFile))
    patches = ldifdelta.fromLDIFFile(patchFile)
    for patch in patches:
        patch.patch(db)
    output(db, outputFile)


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

    with open(options["data"]) as data:
        anyio.run(main, data, sys.stdin, sys.stdout)


if __name__ == "__main__":
    console_script()
