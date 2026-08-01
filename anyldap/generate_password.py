import subprocess

import anyio

from anyldap.deferred import ensureDeferred


class PwgenException(Exception):
    pass


async def generate_async(n=1):
    assert n > 0
    result = await anyio.run_process(
        ["pwgen", "-cn1", "-N", str(n)],
        check=False,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    stdout = result.stdout.decode()
    stderr = result.stderr.decode()
    if result.returncode != 0:
        raise PwgenException(result.returncode, stderr)
    if stderr:
        raise PwgenException(result.returncode, stderr)
    lines = [line for line in stdout.splitlines() if line]
    if len(lines) != n:
        raise PwgenException(result.returncode, "Wrong number of lines received.")
    return lines


def generate(_unused_runtime=None, n=1):
    return ensureDeferred(generate_async(n))


if __name__ == "__main__":
    import sys

    async def _main():
        for password in await generate_async(5):
            sys.stdout.write(f"{password}\n")

    anyio.run(_main)
