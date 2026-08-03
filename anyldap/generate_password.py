import subprocess

import anyio


class PwgenException(Exception):
    pass


async def generate_async(n: int = 1) -> list[str]:
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


async def generate(_unused_runtime: object = None, n: int = 1) -> list[str]:
    return await generate_async(n)


if __name__ == "__main__":
    import sys

    async def _main() -> None:
        for password in await generate_async(5):
            sys.stdout.write(f"{password}\n")

    anyio.run(_main)
