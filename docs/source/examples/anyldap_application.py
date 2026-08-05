"""Serve a directory by writing an application rather than a subclass.

Each LDAP operation is handed to ``directory`` with a scope saying what
was asked, and answered by sending responses back one at a time.
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
    scope: app.OperationScope, receive: app.Receive, send: app.Send
) -> None:
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
                "response": app.failure_response(scope["type"], "not implemented"),
            }
        )


async def main() -> None:
    async with anyio.create_task_group() as task_group:
        host, port = await task_group.start(app.listen, directory, "127.0.0.1", 1389)
        print(f"LDAP server listening on {host}:{port}")
        await anyio.sleep_forever()


if __name__ == "__main__":
    anyio.run(main)
