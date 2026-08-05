"""Serve a directory by writing an application rather than a subclass.

Each LDAP operation is handed to ``directory`` with a scope saying what
was asked, and answered by sending responses back one at a time. The
lifespan scope comes first and last, which is where the task group that
outlives any one connection is opened.
"""

import anyio

from anyldap import app
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors

ENTRIES = {
    "cn=jack,dc=example,dc=com": [("cn", ["jack"]), ("objectClass", ["person"])],
    "cn=jill,dc=example,dc=com": [("cn", ["jill"]), ("objectClass", ["person"])],
}


async def directory(
    scope: app.Scope, receive: app.Receive, send: app.Send
) -> None:
    if scope["type"] == "lifespan":
        assert (await receive())["type"] == "lifespan.startup"
        async with anyio.create_task_group() as background:
            # Open for as long as the server runs, so an operation can
            # start work that outlives the connection it came in on.
            scope["state"]["background"] = background
            await send({"type": "lifespan.startup.complete"})
            assert (await receive())["type"] == "lifespan.shutdown"
            await send({"type": "lifespan.shutdown.complete"})
        return
    if scope["type"] == "ldap.bind":
        # Whatever a bind decides belongs to the connection, not to the
        # operation that decided it.
        scope["connection"]["state"]["bound"] = scope["request"]
        await send(
            {
                "type": "ldap.response",
                "response": pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.Success.resultCode
                ),
            }
        )
    elif scope["type"] == "ldap.search":
        for dn, attributes in ENTRIES.items():
            # Written as it is found, rather than gathered up first.
            await send(
                {
                    "type": "ldap.response",
                    "response": pureldap.LDAPSearchResultEntry(
                        objectName=dn, attributes=attributes
                    ),
                }
            )
        await send(
            {
                "type": "ldap.response",
                "response": pureldap.LDAPSearchResultDone(
                    resultCode=ldaperrors.Success.resultCode
                ),
            }
        )
    elif scope["type"] == "ldap.unbind":
        await send({"type": "ldap.close"})
    else:
        await send(
            {
                "type": "ldap.response",
                "response": app.result_response(
                    scope["type"], ldaperrors.LDAPProtocolError.resultCode
                ),
            }
        )


async def main() -> None:
    async with anyio.create_task_group() as task_group:
        [url] = await task_group.start(app.listen, directory, "ldap://127.0.0.1:1389")
        print(f"LDAP server listening on {url}")
        await anyio.sleep_forever()


if __name__ == "__main__":
    anyio.run(main)
