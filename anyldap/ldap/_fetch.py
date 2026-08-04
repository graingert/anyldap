"""Reading what a URL points at, for the two places that are given one.

python-ldap hands every URL to ``urllib.request.urlopen``, which will fetch
whatever scheme it happens to support -- so a name that was meant to be a
file can turn out to be an HTTP request, and one that was meant to be a
request can turn out to read a file. Only two schemes are wanted here, so
only two are done: ``file:``, which is read straight off the disk, and
``http:``/``https:``, which are fetched with httpx2.

httpx2 is not a dependency. It is asked for only when a URL says to fetch
one, and says plainly if it is not installed, the same as the ``gssapi``
package the GSSAPI mechanism needs.
"""

from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

import anyio.to_thread

# What may be read, and nothing else: a scheme not named here is refused
# rather than handed to something that might know how to fetch it.
FETCHABLE = ("file", "http", "https")


def _httpx2() -> Any:  # pragma: no cover - depends on what is installed
    """The ``httpx2`` package, or a plain word about it not being there."""
    try:
        import httpx2
    except ImportError as exc:
        raise ImportError(
            "fetching over HTTP needs the httpx2 package, which is not"
            " installed: pip install 'anyldap[http]'"
        ) from exc
    return httpx2


def _path(uri: str) -> str:
    """The file a ``file:`` URL names."""
    return url2pathname(urlparse(uri).path)


def _refuse(uri: str) -> ValueError:
    scheme = urlparse(uri).scheme
    return ValueError(
        f"{scheme or uri!r} is not a scheme that is read here:"
        f" {', '.join(FETCHABLE)}"
    )


def _read_file(path: str) -> bytes:
    with open(path, "rb") as source:
        return source.read()


def read(uri: str) -> bytes:
    """What the URL points at, read here and now."""
    scheme = urlparse(uri).scheme
    if scheme == "file":
        return _read_file(_path(uri))
    if scheme in ("http", "https"):
        httpx2 = _httpx2()
        with httpx2.Client() as client:
            response = client.get(uri, follow_redirects=True)
            response.raise_for_status()
            content = response.content
            assert isinstance(content, bytes)
            return content
    raise _refuse(uri)


async def read_async(uri: str) -> bytes:
    """The same, without stopping whichever task asked for it.

    Reading a file blocks, so that is what a worker thread is handed; an
    HTTP request does not have to block anything, so it does not.
    """
    scheme = urlparse(uri).scheme
    if scheme == "file":
        return await anyio.to_thread.run_sync(_read_file, _path(uri))
    if scheme in ("http", "https"):
        httpx2 = _httpx2()
        async with httpx2.AsyncClient() as client:
            response = await client.get(uri, follow_redirects=True)
            response.raise_for_status()
            content = response.content
            assert isinstance(content, bytes)
            return content
    raise _refuse(uri)
