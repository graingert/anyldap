=================
LDAP Applications
=================

A server can be written as a subclass of
:class:`~anyldap.protocols.ldap.ldapserver.LDAPServer`, with a
``handle_LDAPSearchRequest`` method for each kind of request. It can also
be written as an *application*: a coroutine function that is handed one
operation at a time.

.. code-block:: python

   import anyio

   from anyldap import app

   async def directory(scope, receive, send):
       if scope["type"] == "ldap.search":
           await send({"type": "ldap.response", "response": entry})
       await send({"type": "ldap.response", "response": done})

   anyio.run(app.listen, directory, "ldap://127.0.0.1:1389")

The three arguments are the ones an ASGI web application takes, so that
anyone who has written one will recognise the shape, but a scope here
describes an LDAP *operation* rather than an HTTP request.

:func:`~anyldap.app.listen` takes the URLs to listen on, the way
OpenLDAP's ``slapd -h`` does: ``ldap://host:port`` for a TCP socket,
``ldapi://path`` for one in the filesystem, and ``ldaps://host:port``
for a TCP socket with TLS already up, which needs an ``ssl_context``.

What it reports through :meth:`~anyio.abc.TaskGroup.start` is the URLs it
actually bound, so a port of 0 comes back as the port that was chosen and
what comes back can be opened::

   async with anyio.create_task_group() as task_group:
       [url] = await task_group.start(app.listen, directory, "ldap://127.0.0.1:0")
       async with ldap.initialize(url) as connection:
           ...

:func:`~anyldap.app.serve` is the same for a listener that has already
been made, and :func:`~anyldap.app.app_factory` turns an application into
a protocol factory, for the places that take one.

There is also a command for it, which runs an application on asyncio or
on trio::

   anyldap-serve --bind ldap://127.0.0.1:1389 mymodule:directory
   anyldap-serve --backend trio --bind ldapi:///run/ldapi mymodule:directory

The application is named the way an ASGI server names one. A trailing
``()`` -- ``mymodule:make_directory()`` -- says the name points at
something to call, and that its answer is the application, for one that
has to be built rather than imported. At least one ``--bind`` is needed,
since where to listen is not something to guess at, and interrupting it
is how it is stopped.

.. contents:: :local:


"""""""""""""""""""""""
One scope per operation
"""""""""""""""""""""""

LDAP multiplexes. A client numbers each request and may have several
outstanding at once -- that is what abandon exists for -- so a connection
is the wrong unit for an application to answer. Each operation gets its
own scope and its own task, and they run concurrently: reading the next
request does not wait for the last one to be answered.

What the operations of one connection share is
:class:`~anyldap.app.ConnectionScope`, reached through
``scope["connection"]``. Its ``state`` is a plain dict, and is where
per-connection things belong -- the bound user most of all, since a bind
on one operation is meant to be seen by the next.

``scope["type"]`` names the operation: ``"ldap.bind"``, ``"ldap.search"``,
``"ldap.modify"`` and so on. An extended request is named by its OID, so
StartTLS arrives as ``"ldap.starttls"`` rather than as one
undifferentiated ``"ldap.extended"``.


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

Stopping an operation is the connection's business rather than an
application's, so neither an abandon nor a cancel arrives as a scope.
Both cancel the operation they name, and ``send`` then refuses rather than
writing: it raises :exc:`~anyldap.app.ClientDisconnected`, an
:exc:`OSError`, the way a reset HTTP/2 stream refuses what is written to
it. A closed connection refuses the same way. An application that lets the
error escape ends that operation and nothing else.

Nothing is cancelled. As with a reset HTTP/2 stream, what ends is the
message id rather than the work: an application finds out by being
refused when it next sends, or by an ``ldap.abandon`` event if it is
waiting on ``receive``, and when it stops is its own business. A
connection is not finished until every operation on it has returned.

The difference between the two is what the client is told. RFC 4511
section 4.11 says an abandoned operation is never answered, and it is not.
RFC 3909 says a cancel *is* answered, so the connection answers both the
Cancel itself, with ``canceled``, and the operation it stopped, in
whatever shape that operation was going to be answered in -- a search with
a search-done, a modify with a modify response -- so that a client waiting
on it stops waiting. A Cancel naming an operation that is not running is
answered with ``noSuchOperation``.


""""""""""""""""""""""""
Starting up and stopping
""""""""""""""""""""""""

:func:`~anyldap.app.listen` and :func:`~anyldap.app.serve` call the
application once more before the first connection is accepted, with a
:class:`~anyldap.app.LifespanScope`, and once again when they are done.
That is where an application opens whatever it needs for as long as it is
serving, and the usual shape holds the scope open across the whole of it::

   async def app(scope, receive, send):
       if scope["type"] == "lifespan":
           assert (await receive())["type"] == "lifespan.startup"
           async with anyio.create_task_group() as background:
               scope["state"]["background"] = background
               await send({"type": "lifespan.startup.complete"})
               assert (await receive())["type"] == "lifespan.shutdown"
               await send({"type": "lifespan.shutdown.complete"})
           return

Every connection scope's ``state`` starts as a copy of the lifespan
scope's, so ``scope["connection"]["state"]["background"]`` is that task
group, and work an operation starts in it is owned by the application
rather than by the connection that started it. Leaving the block is what
shuts the application down; the task group it opened is waited for as it
goes. An application that will not take a lifespan scope -- one that
raises when it is given one -- is served without it.

Startup finishing before the socket is bound means the address
:func:`~anyldap.app.listen` reports says the application is ready too, not
only the listener.


''''
Code
''''

:file:`anyldap_application.py`

.. literalinclude:: /examples/anyldap_application.py
   :language: python
   :linenos:
