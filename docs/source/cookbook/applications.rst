=================
LDAP Applications
=================

A server can be written as a subclass of
:class:`~anyldap.protocols.ldap.ldapserver.LDAPServer`, with a
``handle_LDAPSearchRequest`` method for each kind of request. It can also
be written as an *application*: a coroutine function that is handed one
operation at a time.

.. code-block:: python

   from anyldap import app

   async def directory(scope, receive, send):
       if scope["type"] == "ldap.search":
           await send({"type": "ldap.response", "response": entry})
       await send({"type": "ldap.response", "response": done})

The three arguments are the ones an ASGI web application takes, so that
anyone who has written one will recognise the shape, but a scope here
describes an LDAP *operation* rather than an HTTP request.

.. contents:: :local:


"""""""""""""""""""""""
One scope per operation
"""""""""""""""""""""""

LDAP multiplexes. A client numbers each request and may have several
outstanding at once -- that is what abandon exists for -- so a connection
is the wrong unit for an application to answer. Each operation gets its
own scope, its own task and its own cancel scope, and they run
concurrently: reading the next request does not wait for the last one to
be answered.

What the operations of one connection share is
:class:`~anyldap.app.ConnectionScope`, reached through
``scope["connection"]``. Its ``state`` is a plain dict, and is where
per-connection things belong -- the bound user most of all, since a bind
on one operation is meant to be seen by the next.

``scope["type"]`` names the operation: ``"ldap.bind"``, ``"ldap.search"``,
``"ldap.modify"`` and so on. An extended request is named by its OID, so
StartTLS arrives as ``"ldap.starttls"`` and a cancel as ``"ldap.cancel"``,
rather than as one undifferentiated ``"ldap.extended"``.


"""""""""""""""""""""
Sending and receiving
"""""""""""""""""""""

``send`` takes one event at a time and writes it out before it returns, so
a search over a large tree sends each entry as it finds it instead of
holding them all. Besides ``ldap.response`` there are two events that act
on the connection rather than answering the operation: ``ldap.starttls``,
which asks for the stream to be raised once the next response is out, and
``ldap.close``, which is what an unbind asks for.

A request arrives whole, so it is in the scope rather than being received.
``receive`` hands over what happens *after* it: ``ldap.abandon`` when the
client abandons this operation, and ``ldap.disconnect`` when the
connection goes away. Neither is queued -- an event reaches an application
that is waiting for one, and delivery waits rather than throwing the event
away.


""""""""""""""""""
Abandon and cancel
""""""""""""""""""

An abandon cancels the operation it names. RFC 4511 section 4.11 says an
abandoned operation is never answered, so anything the application had
left to send is dropped rather than written.

A cancel (RFC 3909) is an operation of its own and *is* answered, so an
application handles it by stopping the operation it names and then saying
so::

   if scope["type"] == "ldap.cancel":
       scope["connection"]["abandon"](app.cancel_id(scope["request"]))
       await send({"type": "ldap.response", "response": canceled})


''''
Code
''''

:file:`anyldap_application.py`

.. literalinclude:: /examples/anyldap_application.py
   :language: python
   :linenos:
