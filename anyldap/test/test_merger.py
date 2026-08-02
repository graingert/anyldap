import anyio
import pytest

from anyldap import config, testutil
from anyldap.deferred import succeed
from anyldap.protocols.ldap import ldapclient, ldaperrors
from anyldap.protocols.ldap.merger import MergedLDAPServer
from anyldap.protocols.pureldap import (
    LDAPAddRequest,
    LDAPAddResponse,
    LDAPBindRequest,
    LDAPBindResponse,
    LDAPDelRequest,
    LDAPDelResponse,
    LDAPExtendedRequest,
    LDAPExtendedResponse,
    LDAPMessage,
    LDAPModifyDNRequest,
    LDAPModifyDNResponse,
    LDAPModifyRequest,
    LDAPModifyResponse,
    LDAPSearchRequest,
    LDAPSearchResultDone,
    LDAPSearchResultEntry,
    LDAPUnbindRequest,
)
from anyldap.runtime import ConnectionDone
from anyldap.test import unittest
from anyldap.test._anyio_helpers import AsyncLDAPClientDriver


@pytest.mark.anyio
async def test_waiting_request_runs_when_real_client_connects():
    server = MergedLDAPServer([config.LDAPConfig()], [False])
    waiting = server._whenConnected(lambda value: value, "connected")
    client = AsyncLDAPClientDriver([])
    server._cbConnectionMade(client)
    assert await waiting == "connected"


@pytest.mark.anyio
async def test_async_client_queue_uses_async_client_interface():
    client = testutil.LDAPClientTestDriver([LDAPBindResponse(resultCode=0)], [])
    client.connectionMade()
    server = MergedLDAPServer([], [])
    server.clients = [client]
    replies = []
    await server._clientQueue_async(LDAPBindRequest(), None, replies.append)
    await server._clientQueue_async(LDAPUnbindRequest(), None, replies.append)
    assert replies == [LDAPBindResponse(resultCode=0)]
    client.assertSent(LDAPBindRequest(), LDAPUnbindRequest())


def test_connection_lost_skips_an_already_disconnected_client():
    client = ldapclient.LDAPClient()
    server = MergedLDAPServer([], [])
    server.clients = [client]
    server.connectionMade()

    server.connectionLost(ConnectionDone())

    assert server.clients == []


def test_connection_lost_without_task_group_clears_connected_client():
    client = testutil.LDAPClientTestDriver()
    client.connectionMade()
    server = MergedLDAPServer([], [])
    server.clients = [client]
    server.connectionLost(ConnectionDone())
    assert server.clients == []


@pytest.mark.anyio
async def test_connection_lost_closes_connected_client():
    client = AsyncLDAPClientDriver([])
    server = MergedLDAPServer([], [])
    server.clients = [client]
    async with anyio.create_task_group() as task_group:
        server._anyio_task_group = task_group
        server.connectionLost(ConnectionDone())
        await client.closed_event.wait()
        assert not client.connected


class MergedLDAPServerTest(unittest.TestCase):
    def createMergedServer(self, *responses):
        """
        Create an MergedLDAP server for testing. Initialize with
        len(responses) clients.
        :param responses: The responses to initialize the `LDAPClientTestDrives`.
        :type responses: args of lists of lists
        :return a deferred, fires when server finished connecting
        """

        def createClient(factory):
            proto = factory()
            proto.connectionMade()
            return proto

        clients = []
        for r in responses:
            clients.append(testutil.LDAPClientTestDriver(*r))

        conf = config.LDAPConfig(serviceLocationOverrides={"": createClient})
        server = MergedLDAPServer([conf for _ in clients], [False for _ in clients])
        self.clients = clients * 1
        server.protocol = lambda: clients.pop()
        return succeed(server)

    async def test_bind_both_success(self):
        d = self.createMergedServer(
            [[LDAPBindResponse(resultCode=0)]], [[LDAPBindResponse(resultCode=0)]]
        )

        async def test_f(server):
            response = await testutil.exchange_async(
                server, LDAPMessage(LDAPBindRequest(), id=4).toWire()
            )

            self.assertEqual(
                response,
                LDAPMessage(LDAPBindResponse(resultCode=0), id=4).toWire(),
            )

        await test_f(await d)

    async def test_bind_one_invalid(self):
        d = self.createMergedServer(
            [
                [
                    LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
                ]
            ],
            [[LDAPBindResponse(resultCode=0)]],
        )

        async def test_f(server):
            response = await testutil.exchange_async(
                server, LDAPMessage(LDAPBindRequest(), id=4).toWire()
            )
            self.assertEqual(
                response,
                LDAPMessage(LDAPBindResponse(resultCode=0), id=4).toWire(),
            )

        await test_f(await d)

    async def test_bind_both_invalid(self):
        d = self.createMergedServer(
            [
                [
                    LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
                ]
            ],
            [
                [
                    LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
                ]
            ],
        )

        async def test_f(server):
            response = await testutil.exchange_async(
                server, LDAPMessage(LDAPBindRequest(), id=4).toWire()
            )
            self.assertEqual(
                response,
                LDAPMessage(
                    LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    ),
                    id=4,
                ).toWire(),
            )

        await test_f(await d)

    async def test_search_merged(self):
        d = self.createMergedServer(
            [
                [
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    LDAPSearchResultEntry("cn=bar,dc=example,dc=com", [("b", ["c"])]),
                    LDAPSearchResultDone(ldaperrors.Success.resultCode),
                ]
            ],
            [
                [
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    LDAPSearchResultEntry("cn=bar2,dc=example,dc=com", [("b", ["c"])]),
                    LDAPSearchResultDone(ldaperrors.Success.resultCode),
                ]
            ],
        )

        async def test_f(server):
            response = await testutil.exchange_async(
                server, LDAPMessage(LDAPSearchRequest(), id=3).toWire()
            )
            self.assertEqual(
                response,
                LDAPMessage(
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultEntry("cn=bar2,dc=example,dc=com", [("b", ["c"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultEntry("cn=bar,dc=example,dc=com", [("b", ["c"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3
                ).toWire(),
            )

        await test_f(await d)

    async def test_search_one_invalid(self):
        d = self.createMergedServer(
            [
                [
                    LDAPSearchResultDone(
                        ldaperrors.LDAPInappropriateAuthentication.resultCode
                    )
                ]
            ],
            [
                [
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    LDAPSearchResultEntry("cn=bar,dc=example,dc=com", [("b", ["c"])]),
                    LDAPSearchResultDone(ldaperrors.Success.resultCode),
                ]
            ],
        )

        async def test_f(server):
            response = await testutil.exchange_async(
                server, LDAPMessage(LDAPSearchRequest(), id=3).toWire()
            )
            self.assertEqual(
                response,
                LDAPMessage(
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultEntry("cn=bar,dc=example,dc=com", [("b", ["c"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3
                ).toWire(),
            )

        await test_f(await d)

    async def test_unbind_clientUnbinds(self):
        d = self.createMergedServer([[]], [[]])

        async def test_f(server):
            response = await testutil.exchange_async(
                server, LDAPMessage(LDAPUnbindRequest(), id=3).toWire()
            )
            self.assertEqual(
                [c.sent[0] for c in self.clients],
                [LDAPUnbindRequest() for c in self.clients],
            )
            self.assertEqual(response, b"")

        await test_f(await d)

    async def test_unbind_clientEOF(self):
        """
        No connection is done when client has nothing to say.
        """
        d = self.createMergedServer([[]], [[]])

        async def test_f(server):
            server.connectionLost(ConnectionDone())

            self.assertEqual([], server.clients, "A connection should not be done.")

        await test_f(await d)

    async def test_unwilling_to_perform(self):
        d = self.createMergedServer([[]], [[]])

        async def test_f(server):
            requests = (
                LDAPMessage(LDAPAddRequest(entry="", attributes=[]), id=3).toWire()
                + LDAPMessage(LDAPDelRequest(entry=""), id=4).toWire()
                +
                LDAPMessage(
                    LDAPModifyRequest(object="", modification=[]), id=5
                ).toWire()
                +
                LDAPMessage(
                    LDAPModifyDNRequest(entry="", newrdn="", deleteoldrdn=0), id=6
                ).toWire()
                +
                LDAPMessage(LDAPExtendedRequest(requestName=""), id=7).toWire()
            )
            response = await testutil.exchange_async(server, requests)

            self.assertEqual(
                response,
                LDAPMessage(
                    LDAPAddResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPDelResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=4,
                ).toWire()
                + LDAPMessage(
                    LDAPModifyResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=5,
                ).toWire()
                + LDAPMessage(
                    LDAPModifyDNResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=6,
                ).toWire()
                + LDAPMessage(
                    LDAPExtendedResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=7,
                ).toWire(),
            )

        await test_f(await d)
