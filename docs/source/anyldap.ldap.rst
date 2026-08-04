anyldap.ldap package
====================

``anyldap.ldap`` is python-ldap's ``ldap`` module with every operation
awaited. The names, the arguments they take and the values they hand back
are the ones python-ldap documents, so code ported from it reads the same
with ``await`` in front:

.. code-block:: python

    from anyldap import ldap


    async def example() -> None:
        async with ldap.initialize("ldap://ldap.example.com") as connection:
            await connection.simple_bind_s("cn=admin,dc=example,dc=com", "secret")
            results = await connection.search_s(
                "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(cn=Babs*)"
            )
            for dn, attributes in results:
                print(dn, attributes)

``initialize()`` opens nothing: the first operation that is awaited connects,
which is what lets it stay the plain call it is in python-ldap. The
connection is closed by ``unbind_s()``, and ``async with`` closes it however
the block ends.

Nothing runs in the background. As in python-ldap, an operation is sent when
it is started and the connection is read while a result is being waited for,
so a connection needs no task group and belongs to whichever task holds it.
Operations can be started with ``search_ext()``, ``add()`` and the rest, and
collected later by message id with ``result3()``; ``result(msgid,
all=ldap.MSG_ONE)`` walks a large search one entry at a time.

Binding with SASL
-----------------

``sasl_interactive_bind_s()`` drives the exchange, asking the mechanism what
to send for as long as the server says the bind is still in progress:

.. code-block:: python

    from anyldap import ldap

    async with ldap.initialize("ldapi:///run/slapd/ldapi") as connection:
        await connection.sasl_external_bind_s()
        print(await connection.whoami_s())

The mechanisms in :mod:`anyldap.ldap.sasl` answer for themselves rather than
through Cyrus SASL: ``external``, ``plain``, ``cram_md5``, ``digest_md5``,
and ``gssapi`` if the ``gssapi`` package is installed, which is not a
dependency. A mechanism of your own works anywhere these do, as long as it
has a ``mech`` and a ``process()`` that answers a challenge.

Controls
--------

Controls are the objects :mod:`anyldap.ldap.controls` builds, encoded with
the BER library anyldap already has rather than with pyasn1, and a response
hands back the ones it carried, read into the classes that know them:

.. code-block:: python

    from anyldap.ldap.controls import SimplePagedResultsControl

    paged = SimplePagedResultsControl(True, size=100, cookie=b"")
    while True:
        msgid = await connection.search_ext(base, scope, serverctrls=[paged])
        rtype, data, rmsgid, answered = await connection.result3(msgid)
        ...
        cookies = [
            control.cookie
            for control in answered
            if control.controlType == ldap.CONTROL_PAGEDRESULTS
        ]
        if not cookies or not cookies[0]:
            break
        paged.cookie = cookies[0]

The controls with a class of their own are paged results, pre-read and
post-read, server-side sorting, the password policy response, OpenLDAP's
no-op search, assertion and matched-values, ManageDSAIT, relax rules,
proxied authorization and the authorization identity pair; each lives in
the module python-ldap keeps it in, and the names are re-exported from
:mod:`anyldap.ldap.controls` as python-ldap re-exports them. Anything else
is an ``LDAPControl`` carrying
the bytes as they came, and a control of your own only has to encode and
decode its own value. A ``(type, criticality, value)`` triple is still
accepted wherever controls are.

Schema
------

:mod:`anyldap.ldap.schema` reads what a server publishes about itself into
the model classes python-ldap names, on top of the schema parsing in
:mod:`anyldap.schema`::

    subschema = await connection.read_schema_s()
    person = subschema.get_obj(ldap.schema.ObjectClass, "person")
    must, may = subschema.attribute_types(["inetOrgPerson"])

Every kind of definition is read: object classes, attribute types, matching
rules and their uses, syntaxes, content rules, structure rules and name
forms. A definition writes itself back out again -- ``str(person)`` is the
``objectClasses`` value the server published -- and ``x_origin`` and the
rest of the ``X-`` fields a definition carries are read into ``extensions``.

:class:`~anyldap.ldap.schema.models.Entry` is an entry that knows the schema
its attributes are described by, so ``entry["cn"]``, ``entry["commonName"]``
and ``entry["2.5.4.3"]`` are the same attribute.

``urlfetch()`` is python-ldap's, taking an LDAP URL and opening a connection
of its own to ask; ``read_schema_s()`` is not a method python-ldap has, and
uses the connection that is already open::

    dn, subschema = await ldap.schema.urlfetch("ldap://localhost")

It takes the address of an LDIF file as well, and reads the schema out of
its first record -- which is how a schema someone else published is read
without a server to ask::

    dn, subschema = await ldap.schema.urlfetch("file:///tmp/subschema.ldif")

A definition may name itself rather than be numbered
(``( nsEncryptionConfig-oid NAME 'nsEncryptionConfig' ... )``), which RFC
4512 section 1.4 allows and 389-ds publishes a great many of.

TLS
---

The ``OPT_X_TLS_*`` options build the :class:`ssl.SSLContext` a connection
is raised with -- the certificates to trust, the certificate to send, what
to check, which protocol versions and ciphers -- and ``OPT_X_TLS_NEWCTX``
starts a new one. A context can be passed to ``initialize()`` instead, and
then it is used as it stands. ``ldaps://`` raises TLS before anything is
sent; ``start_tls_s()`` raises it on a connection that is already open.

URLs
----

:mod:`anyldap.ldap.ldapurl` is python-ldap's top-level ``ldapurl`` module:
an LDAP URL taken apart into what it says, and written back out again::

    from anyldap.ldap.ldapurl import LDAPUrl

    url = LDAPUrl("ldap://localhost/dc=example,dc=com?cn?sub?(cn=jack)")
    async with ldap.initialize(url.initializeUrl()) as connection:
        found = await connection.search_s(url.dn, url.scope, url.filterstr)

``who`` and ``cred`` are the bind DN and its password, which a URL carries
as the ``bindname`` and ``X-BINDPW`` extensions.

LDIF
----

:mod:`anyldap.ldap.ldif` is python-ldap's top-level ``ldif`` module. anyldap
has an LDIF reader of its own in :mod:`anyldap.protocols.ldap.ldifprotocol`,
but it is a line-receiving protocol answering with the objects the rest of
anyldap is built out of, which is not what code written against python-ldap
asks for. Nothing in it touches the network, so nothing in it is awaited::

    from anyldap.ldap import ldif

    records = ldif.LDIFRecordList(open("people.ldif"))
    records.parse()
    for dn, entry in records.all_records:
        await connection.add_s(dn, ldap.modlist.addModlist(entry))

``LDIFWriter`` writes entry records and change records, folding long lines
and base64-encoding whatever RFC 2849 does not allow to be written as it
stands; ``LDIFParser`` reads them, and a class of your own overrides
``handle()`` or ``handle_modify()``. ``LDIFRecordList`` collects them all,
and ``LDIFCopy`` reads and writes at once. ``CreateLDIF()`` and
``ParseLDIF()``, which python-ldap has deprecated, are not here.

Following referrals
-------------------

A server that does not hold what was asked for can say where to look
instead, and unless ``OPT_REFERRALS`` is turned off the operation is made
again there, which is what libldap does and so what python-ldap inherits::

    # On by default, and read back as -1 however it was set, as libldap
    # keeps it.
    connection.set_option(ldap.OPT_REFERRALS, 0)

A referral is followed anonymously: it says where to look and nothing about
whose credentials may be sent there. For the same reason a bind is never
followed -- the referral it is answered with is raised instead. A search
continuation is followed too, and what the other server holds is added to
what the search found; the continuation itself stays among the results as
``(None, [uri, ...])``, which is what python-ldap hands back whether or not
it followed one.

When no server a referral names can be reached, the referral is raised as
:exc:`~anyldap.ldap.errors.REFERRAL`, carrying the URLs as its ``info`` and
how far the name was recognised as its ``matched``. Referrals are followed
five deep, after which one is called a loop and
:exc:`~anyldap.ldap.errors.REFERRAL_LIMIT_EXCEEDED` is raised. That is
libldap's own limit; like libldap, this does not let it be set, so asking
for ``OPT_REFHOPLIMIT`` is an error.

Reading a long search
---------------------

:mod:`anyldap.ldap.asyncsearch` reads a search result by result rather than
asking for all of it at once, which is what python-ldap's ``asyncsearch``
does::

    from anyldap.ldap import asyncsearch

    found = asyncsearch.Dict(connection)
    await found.startSearch("dc=example,dc=com", ldap.SCOPE_SUBTREE, "(cn=*)")
    await found.processResults()
    print(found.allEntries)

``List``, ``Dict``, ``IndexedDict``, ``FileWriter`` and ``LDIFWriter`` are
python-ldap's, and a handler of your own overrides
``_processSingleResult()``. Only ``startSearch()`` and ``processResults()``
touch the connection and are awaited; the hooks are plain methods, because
they are called while a result is being dispatched.

Reconnecting
------------

:class:`~anyldap.ldap.ldapobject.ReconnectLDAPObject` tries an operation
again on a connection that went away, opening it and putting it back as it
was: the options that were set, StartTLS if it had been raised, and the last
bind that was made::

    connection = ldap.ReconnectLDAPObject(uri, retry_max=3, retry_delay=5.0)
    await connection.simple_bind_s(who, cred)
    # Whatever happens to the server in between, this is answered.
    entries = await connection.search_ext_s(base, ldap.SCOPE_SUBTREE)

Unlike python-ldap's, it does not open the connection before the first
operation: nothing is sent until something is awaited, so there is nothing
to reconnect until an operation has failed.

Keeping a copy
--------------

:mod:`anyldap.ldap.syncrepl` is RFC 4533, which is how a copy of what a
server holds is kept up to date. A connection mixes in
:class:`~anyldap.ldap.syncrepl.SyncreplConsumer`, overrides the
``syncrepl_*`` methods to keep whatever it is keeping, and polls::

    class Consumer(ldap.syncrepl.SyncreplConsumer, ldap.SimpleLDAPObject):
        def syncrepl_entry(self, dn, attrs, uuid):
            self.entries[uuid] = (dn, attrs)

    msgid = await connection.syncrepl_search(base, ldap.SCOPE_SUBTREE)
    while await connection.syncrepl_poll(msgid=msgid):
        pass

``refreshOnly`` stops once the copy has caught up and ``refreshAndPersist``
stays open and keeps being told. ``cancel_s()`` stops a search that is
staying open, and unlike ``abandon()`` the server answers to say it has.

Extended operations
-------------------

:mod:`anyldap.ldap.extop` is what an extended operation of your own is
built out of: a request that knows its OID and writes its value, and a
response that reads one::

    from anyldap.ldap.extop.dds import RefreshRequest, RefreshResponse

    request = RefreshRequest(entryName=dn, requestTtl=3600)
    name, value = await connection.extop_s(
        pureldap.LDAPExtendedRequest(
            requestName=request.requestName,
            requestValue=request.encodedRequestValue(),
        )
    )
    left = RefreshResponse(name, value).responseTtl

``extop.dds`` is RFC 2589, entries that go away by themselves, and
``extop.passwd`` reads the password a server made up when it was asked to
change one without being given a new one.

What is not here
----------------

- **GSSAPI without the ``gssapi`` package**: the mechanism is
  :class:`anyldap.ldap.sasl.gssapi`, and it says so if it is asked for
  without Kerberos to hand. The SASL security layer it negotiates is always
  none: what protects a connection here is TLS.
- **The ``OPT_X_SASL_*`` options beyond what they say**: they supply the
  defaults a mechanism reads and report what the bind ended up with, rather
  than configuring Cyrus SASL, which is not what does the exchange here.
- **A referral that points at itself** stops rather than being followed
  until something else gives up. libldap keeps going, and what ends it
  there is the timeout rather than the hop limit.

``abandon()`` sends a real abandon request and forgets the operation, but
the server may already have answered.

anyldap.ldap module
-------------------

.. automodule:: anyldap.ldap
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.ldapobject module
------------------------------

.. automodule:: anyldap.ldap.ldapobject
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.errors module
--------------------------

.. automodule:: anyldap.ldap.errors
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.constants module
-----------------------------

.. automodule:: anyldap.ldap.constants
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.dn module
----------------------

.. automodule:: anyldap.ldap.dn
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.filter module
--------------------------

.. automodule:: anyldap.ldap.filter
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.modlist module
---------------------------

.. automodule:: anyldap.ldap.modlist
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.cidict module
--------------------------

.. automodule:: anyldap.ldap.cidict
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.functions module
-----------------------------

.. automodule:: anyldap.ldap.functions
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.sasl module
------------------------

.. automodule:: anyldap.ldap.sasl
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.controls package
-----------------------------

.. automodule:: anyldap.ldap.controls
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.controls.simple
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.controls.pagedresults
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.controls.readentry
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.controls.sss
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.controls.ppolicy
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.controls.libldap
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.controls.openldap
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.ldapurl module
---------------------------

.. automodule:: anyldap.ldap.ldapurl
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.ldif module
------------------------

.. automodule:: anyldap.ldap.ldif
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.asyncsearch module
-------------------------------

.. automodule:: anyldap.ldap.asyncsearch
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.syncrepl module
----------------------------

.. automodule:: anyldap.ldap.syncrepl
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.extop package
--------------------------

.. automodule:: anyldap.ldap.extop
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.extop.dds
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.extop.passwd
    :members:
    :undoc-members:
    :show-inheritance:

anyldap.ldap.schema package
---------------------------

.. automodule:: anyldap.ldap.schema
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.schema.models
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.schema.subentry
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: anyldap.ldap.schema.tokenizer
    :members:
    :undoc-members:
    :show-inheritance:
