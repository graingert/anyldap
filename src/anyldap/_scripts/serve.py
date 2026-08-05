"""Run an LDAP application from the command line."""

import functools
import pkgutil
import signal
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


async def main(
    application: app.LDAPApp,
    binds: list[str],
    *,
    shutdown_trigger: app.ShutdownTrigger | None = None,
    task_status: anyio.abc.TaskStatus[list[str]] = anyio.TASK_STATUS_IGNORED,
) -> None:
    """Serve until told to stop, saying where it is listening as it starts.

    Being told is a signal by default -- an interrupt, or a termination,
    which is what a service manager sends -- so that the application gets
    to shut down rather than being cancelled out from under itself. The
    signals are taken over before anything is bound, since a server that
    says it is listening before it can be stopped can be missed.
    """
    with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:

        async def interrupted() -> None:
            async for _ in signals:
                return

        async with anyio.create_task_group() as task_group:
            bound = await task_group.start(
                functools.partial(
                    app.listen,
                    application,
                    *binds,
                    shutdown_trigger=shutdown_trigger or interrupted,
                )
            )
            for url in bound:
                print(f"Listening on {url}", file=sys.stderr, flush=True)
            task_status.started(bound)


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

    binds = options["bind"]
    if not binds:
        sys.stderr.write(f"{sys.argv[0]}: nothing to listen on; give --bind\n")
        raise SystemExit(1)

    # Nothing to catch: the signals are the server's own, so being stopped
    # is a return rather than an interrupt to report.
    anyio.run(main, application, binds, backend=backend)


if __name__ == "__main__":
    console_script()
