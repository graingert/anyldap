import os
import pathlib
import sys
from types import SimpleNamespace

import anyio
import pytest

from anyldap import generate_password

pytestmark = pytest.mark.anyio


async def test_generate_async_success(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_process(*args: object, **kwargs: object) -> object:
        assert args[0] == ["pwgen", "-cn1", "-N", "2"]
        return SimpleNamespace(returncode=0, stdout=b"first\nsecond\n", stderr=b"")

    monkeypatch.setattr(anyio, "run_process", run_process)
    assert await generate_password.generate_async(2) == ["first", "second"]


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (SimpleNamespace(returncode=2, stdout=b"", stderr=b"failed"), "failed"),
        (SimpleNamespace(returncode=0, stdout=b"value\n", stderr=b"warning"), "warning"),
        (SimpleNamespace(returncode=0, stdout=b"one\n", stderr=b""), "Wrong number"),
    ],
)
async def test_generate_async_errors(
    monkeypatch: pytest.MonkeyPatch, result: object, message: str
) -> None:
    async def run_process(*args: object, **kwargs: object) -> object:
        return result

    monkeypatch.setattr(anyio, "run_process", run_process)
    with pytest.raises(generate_password.PwgenException, match=message):
        await generate_password.generate_async(2)


async def test_generate_async_rejects_nonpositive_count() -> None:
    with pytest.raises(AssertionError):
        await generate_password.generate_async(0)


async def test_generate_delegates_to_generate_async(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_generate(n: int) -> list[str]:
        return [str(n)]

    monkeypatch.setattr(generate_password, "generate_async", fake_generate)
    assert await generate_password.generate(n=3) == ["3"]


async def test_generate_password_module_entrypoint(tmp_path: pathlib.Path) -> None:
    executable = anyio.Path(tmp_path) / "pwgen"
    await executable.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' password0 password1 password2 password3 password4\n"
    )
    await executable.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = str(tmp_path) + os.pathsep + environment["PATH"]

    result = await anyio.run_process(
        [sys.executable, "-m", generate_password.__name__],
        check=True,
        env=environment,
    )

    assert result.stdout.decode().splitlines() == [
        f"password{i}" for i in range(5)
    ]
