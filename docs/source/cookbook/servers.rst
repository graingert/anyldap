============
LDAP Servers
============

An LDAP directory information tree (DIT) is a highly specialized
database with entries arranged in a tree-like structure.

AnyIO server API
----------------

``BaseLDAPServer.listen()`` creates and owns a TCP ``SocketListener``. Start it
with ``TaskGroup.start()`` to receive the bound ``(host, port)`` after the
listener is ready:

.. code-block:: python

   async with anyio.create_task_group() as task_group:
       host, port = await task_group.start(
           MyLDAPServer.listen,
           "127.0.0.1",
           0,
       )
       print(f"listening on {host}:{port}")

The listener creates a fresh server protocol instance for every accepted
socket. Connection-specific state—including the receive buffer, bound user,
TLS state, and write lock—is therefore never shared between clients.

Use ``ldapserver.listen(host, port, protocol_factory)`` when constructing a
server requires a factory function rather than a no-argument protocol class.
``ldapserver.serve_stream(stream, protocol_factory)`` is the lower-level entry
point for one already-accepted AnyIO byte stream.

.. contents:: :local:


""""""""""""""""""""
File-System LDAP DIT
""""""""""""""""""""
A minimal LDAP DIT that stores entries in the local file system

''''
Code
''''

First, a module that defines our DIT entries-- :file:`schema.py`

.. literalinclude:: /examples/schema.py
   :language: python
   :linenos:


Next, the server code-- :file:`anyldap_basic.py`

.. literalinclude:: /examples/anyldap_basic.py
   :language: python
   :linenos:


""""""""""""""""""""""""""""""""""""""
LDAP Server which allows BIND with UPN
""""""""""""""""""""""""""""""""""""""

The LDAP server implemented by Microsoft Active Directory allows using the
UPN as the BIND DN.

It is possible to implement something similar using anyldap.

Below is a proof-of-concept implementation, which should not be used for
production as it has an heuristic method for detecting which BIND DN is an
UPN.

`handle_LDAPBindRequest` is the method called when a BIND request is
received.


.. literalinclude:: /examples/anyldap_with_upn_bind.py
    :language: python
    :emphasize-lines: 34
    :linenos:
