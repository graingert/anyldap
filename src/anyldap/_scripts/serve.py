"""Run an LDAP application from the command line."""

import sys
from importlib import import_module
from typing import cast

import anyio

from anyldap import app, usage


def load(spec: str, factory: bool = False) -> app.LDAPApp:
    """The application a ``module:name`` says to run.

    It is spelled the way an ASGI server spells one, so that what runs an
    application is the same thing that names it. With ``factory``, what
    the name points at is called and the application is what it answers
    with, which is how an application that has to be built rather than
    imported is named.
    """
    module, _, name = spec.partition(":")
    if not module or not name:
        raise usage.UsageError(f"{spec!r} is not module:name")
    try:
        loaded = import_module(module)
    except ImportError as exc:
        raise usage.UsageError(f"cannot import {module!r}: {exc}") from exc
    try:
        application = getattr(loaded, name)
    except AttributeError as exc:
        raise usage.UsageError(f"{module!r} has no {name!r}") from exc
    if not callable(application):
        raise usage.UsageError(f"{spec!r} is not callable")
    if factory:
        application = application()
        if not callable(application):
            raise usage.UsageError(f"{spec!r} did not make an application")
    # What was imported is whatever the name was bound to; taking it as an
    # application is what running it means.
    return cast(app.LDAPApp, application)


class MyOptions(usage.Options):
    """Serve an LDAP application.

    The application is named as ``module:name``, and each ``--bind`` says
    where to listen: ``ldap://host:port`` for a TCP socket, or
    ``ldapi://path`` for one in the filesystem.
    """

    optParameters = (  # noqa: RUF012
        ("backend", None, "asyncio", "Which async library to run on."),
    )
    optFlags = (  # noqa: RUF012
        ("factory", None, "Call what is named, and serve what it answers with."),
    )

    def __init__(self) -> None:
        super().__init__()
        self.opts["bind"] = []

    def opt_bind(self, value: str) -> None:
        """Where to listen, as an LDAP URL. May be given more than once."""
        self.opts["bind"].append(value)

    def parseArgs(self, application: str) -> None:
        self["application"] = application


async def main(application: app.LDAPApp, binds: list[str]) -> None:
    async with anyio.create_task_group() as task_group:
        bound = await task_group.start(app.listen, application, *binds)
        for url in bound:
            print(f"Listening on {url}", file=sys.stderr, flush=True)


def console_script() -> None:
    try:
        options = MyOptions()
        options.parseOptions()
        application = load(options["application"], options["factory"])
    except usage.UsageError as exc:
        sys.stderr.write(f"{sys.argv[0]}: {exc}\n")
        raise SystemExit(1) from exc

    backend = options["backend"]
    if backend not in ("asyncio", "trio"):
        sys.stderr.write(f"{sys.argv[0]}: unknown backend {backend!r}\n")
        raise SystemExit(1)

    binds = options["bind"] or ["ldap://localhost:389"]
    anyio.run(main, application, binds, backend=backend)


if __name__ == "__main__":
    console_script()
