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
through Cyrus SASL: ``external``, ``plain``, ``cram_md5`` and
``digest_md5``. GSSAPI needs Kerberos and is not among them. A mechanism of
your own works anywhere these do, as long as it has a ``mech`` and a
``process()`` that answers a challenge.

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
post-read, ManageDSAIT, relax rules, proxied authorization and the
authorization identity pair; anything else is an ``LDAPControl`` carrying
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

``read_schema_s()`` is not a method python-ldap has: it fetches schema with
``ldap.schema.urlfetch()``, which opens a connection of its own, and this
uses the one already open.

TLS
---

The ``OPT_X_TLS_*`` options build the :class:`ssl.SSLContext` a connection
is raised with -- the certificates to trust, the certificate to send, what
to check, which protocol versions and ciphers -- and ``OPT_X_TLS_NEWCTX``
starts a new one. A context can be passed to ``initialize()`` instead, and
then it is used as it stands. ``ldaps://`` raises TLS before anything is
sent; ``start_tls_s()`` raises it on a connection that is already open.

What is not here
----------------

- **GSSAPI**, which needs Kerberos, and the ``OPT_X_SASL_*`` options that
  configure Cyrus SASL. The SASL option numbers are defined, since a
  mechanism may want to name them, but setting them does nothing.
- **``ldap.async``/``ldap.asyncsearch`` and ``ldap.syncrepl``**, and
  ``LDAPUrl``.
- **``ReconnectLDAPObject``'s reconnection**: the name is here and is the
  plain object, which does not reconnect behind the caller's back.
- **Referrals are never chased**: a search hands back the referral URLs as
  ``(None, [uri, ...])``, which is what python-ldap does with
  ``OPT_REFERRALS`` off.

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
