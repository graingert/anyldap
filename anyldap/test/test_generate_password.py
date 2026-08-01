from types import SimpleNamespace

import pytest

from anyldap import generate_password
from anyldap._async import await_result
from anyldap.deferred import Deferred

pytestmark = pytest.mark.anyio


async def test_generate_async_success(monkeypatch):
    async def run_process(*args, **kwargs):
        assert args[0] == ["pwgen", "-cn1", "-N", "2"]
        return SimpleNamespace(returncode=0, stdout=b"first\nsecond\n", stderr=b"")

    monkeypatch.setattr(generate_password.anyio, "run_process", run_process)
    assert await generate_password.generate_async(2) == ["first", "second"]


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (SimpleNamespace(returncode=2, stdout=b"", stderr=b"failed"), "failed"),
        (SimpleNamespace(returncode=0, stdout=b"value\n", stderr=b"warning"), "warning"),
        (SimpleNamespace(returncode=0, stdout=b"one\n", stderr=b""), "Wrong number"),
    ],
)
async def test_generate_async_errors(monkeypatch, result, message):
    async def run_process(*args, **kwargs):
        return result

    monkeypatch.setattr(generate_password.anyio, "run_process", run_process)
    with pytest.raises(generate_password.PwgenException, match=message):
        await generate_password.generate_async(2)


async def test_generate_async_rejects_nonpositive_count():
    with pytest.raises(AssertionError):
        await generate_password.generate_async(0)


async def test_generate_returns_deferred(monkeypatch):
    async def fake_generate(n):
        return [str(n)]

    monkeypatch.setattr(generate_password, "generate_async", fake_generate)
    deferred = generate_password.generate(n=3)
    assert isinstance(deferred, Deferred)
    assert await await_result(deferred) == ["3"]
