"""Run an LDAP application from the command line."""

import pkgutil
import sys
from typing import cast

import anyio

from anyldap import app, usage


def load(spec: str) -> app.LDAPApp:
    """The application a ``module:name`` says to run.

    It is spelled the way an ASGI server spells one, so that what runs an
    application is the same thing that names it. A trailing ``()`` says
    the name points at something to call and that its answer is the
    application, for one that has to be built rather than imported.
    """
    called = spec.endswith("()")
    name = spec[:-2] if called else spec
    try:
        loaded = pkgutil.resolve_name(name)
    except (ValueError, ImportError, AttributeError) as exc:
        raise usage.UsageError(f"cannot load {name!r}: {exc}") from exc
    if called:
        loaded = loaded()
    if not callable(loaded):
        raise usage.UsageError(f"{spec!r} is not an application")
    # What was named is whatever it was bound to; taking it as an
    # application is what running it means.
    return cast(app.LDAPApp, loaded)


class MyOptions(usage.Options):
    """Serve an LDAP application.

    The application is named as ``module:name``, or as ``module:name()``
    for one that has to be called to be made, and each ``--bind`` says
    where to listen: ``ldap://host:port`` for a TCP socket, or
    ``ldapi://path`` for one in the filesystem.
    """

    optParameters = (  # noqa: RUF012
        ("backend", None, "asyncio", "Which async library to run on."),
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
        application = load(options["application"])
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
