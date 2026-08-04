"""Reading what a URL points at, for the two places that are given one.

python-ldap hands every URL to ``urllib.request.urlopen``, which will fetch
whatever scheme it happens to support -- so a name that was meant to be a
file can turn out to be an HTTP request, and one that was meant to be a
request can turn out to read a file. Only two schemes are wanted here, so
only two are done: ``file:``, which is read straight off the disk, and
``http:``/``https:``, which are fetched with httpx2.
"""

from urllib.parse import urlparse
from urllib.request import url2pathname

import anyio
import httpx2

# What may be read, and nothing else: a scheme not named here is refused
# rather than handed to something that might know how to fetch it.
FETCHABLE = ("file", "http", "https")


def _path(uri: str) -> str:
    """The file a ``file:`` URL names."""
    return url2pathname(urlparse(uri).path)


def _refuse(uri: str) -> ValueError:
    scheme = urlparse(uri).scheme
    return ValueError(
        f"{scheme or uri!r} is not a scheme that is read here:"
        f" {', '.join(FETCHABLE)}"
    )


def read(uri: str) -> bytes:
    """What the URL points at, read here and now."""
    scheme = urlparse(uri).scheme
    if scheme == "file":
        # The parser this is for is not a coroutine, so this cannot be
        # anyio.Path: whoever calls it blocks for as long as the read takes.
        with open(_path(uri), "rb") as source:
            return source.read()
    if scheme in ("http", "https"):
        with httpx2.Client() as client:
            response = client.get(uri, follow_redirects=True)
            response.raise_for_status()
            return response.content
    raise _refuse(uri)


async def read_async(uri: str) -> bytes:
    """The same, without stopping whichever task asked for it.

    A file is read through :class:`anyio.Path`, which does the blocking
    part somewhere it does not matter; an HTTP request does not have to
    block anything, so it is simply awaited.
    """
    scheme = urlparse(uri).scheme
    if scheme == "file":
        return await anyio.Path(_path(uri)).read_bytes()
    if scheme in ("http", "https"):
        async with httpx2.AsyncClient() as client:
            response = await client.get(uri, follow_redirects=True)
            response.raise_for_status()
            return response.content
    raise _refuse(uri)
