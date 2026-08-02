LDAP Clients
============

Clients use AnyIO byte streams. The high-level connection helpers open the
socket, attach it to a fresh ``LDAPClient``, and return an async context manager
which closes both the protocol and its reader task group.

.. code-block:: python

   from anyldap.protocols.ldap import ldapclient, ldapconnector

   connection = await ldapconnector.connectToLDAPDNAsync(
       b"dc=example,dc=com",
       ldapclient.LDAPClient,
       overrides={b"dc=example,dc=com": ("127.0.0.1", 389)},
   )
   async with connection as client:
       await client.bind_async(b"uid=alice,dc=example,dc=com", b"secret")

Use ``connectToLDAPEndpointAsync()`` when an endpoint string such as
``tcp:host=127.0.0.1:port=389`` is already available. Pass ``tls=True`` for
LDAP-over-TLS at connection time, or call ``await client.startTLS_async(...)``
to upgrade an established plain-text connection.

The request methods are asynchronous:

* ``await client.send_async(request)`` for one response;
* ``await client.send_multiResponse_async(request, handler)`` for searches and
  other multi-response operations;
* ``await client.send_multiResponse_ex_async(...)`` when response controls are
  needed;
* ``await client.send_noResponse_async(request)`` for operations such as
  abandon and unbind;
* ``await client.aclose()`` to close a manually attached client.

``LDAPClient.attach_stream(stream, task_group)`` is the low-level API for an
already-connected AnyIO ``ByteStream``. Applications normally use the
connection helpers so stream and task-group cleanup cannot be forgotten.
