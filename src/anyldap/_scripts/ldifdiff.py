import sys
from collections.abc import Iterable
from typing import IO

import anyio

from anyldap import delta, inmemory, usage
from anyldap.protocols.ldap import ldif


def output(result: Iterable[delta.Operation], outputFile: IO[bytes]) -> None:
    outputFile.write(ldif._header())
    for operation in result:
        outputFile.write(operation.asLDIF())


async def main(
    filename1: str, filename2: str, outputFile: IO[bytes]
) -> None:
    async with await anyio.Path(filename1).open("rb") as file1:
        db1 = await inmemory.fromLDIFFile(file1)
    async with await anyio.Path(filename2).open("rb") as file2:
        db2 = await inmemory.fromLDIFFile(file2)
    output(await db1.diffTree(db2), outputFile)


class MyOptions(usage.Options):
    """LDIF diff utility."""

    def parseArgs(self, file1: str, file2: str) -> None:
        self.opts["file1"] = file1
        self.opts["file2"] = file2


def console_script() -> None:
    try:
        options = MyOptions()
        options.parseOptions()
    except usage.UsageError as exc:
        sys.stderr.write(f"{sys.argv[0]}: {exc}\n")
        raise SystemExit(1) from exc
    anyio.run(main, options["file1"], options["file2"], sys.stdout.buffer)


if __name__ == "__main__":
    console_script()
