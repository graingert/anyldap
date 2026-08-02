import sys

import anyio

from anyldap import inmemory, usage
from anyldap.protocols.ldap import ldif


def output(result, outputFile):
    outputFile.write(ldif._header())
    for operation in result:
        outputFile.write(operation.asLDIF())


async def main(filename1, filename2, outputFile):
    with open(filename1, "rb") as file1:
        db1 = await inmemory.fromLDIFFile(file1)
    with open(filename2, "rb") as file2:
        db2 = await inmemory.fromLDIFFile(file2)
    output(await db1.diffTree(db2), outputFile)


class MyOptions(usage.Options):
    """LDIF diff utility."""

    def parseArgs(self, file1, file2):
        self.opts["file1"] = file1
        self.opts["file2"] = file2


def console_script():
    try:
        options = MyOptions()
        options.parseOptions()
    except usage.UsageError as exc:
        sys.stderr.write(f"{sys.argv[0]}: {exc}\n")
        raise SystemExit(1) from exc
    anyio.run(main, options["file1"], options["file2"], sys.stdout.buffer)


if __name__ == "__main__":
    console_script()
