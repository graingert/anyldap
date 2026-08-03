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

What is not here
----------------

Everything python-ldap needs the C library for:

- SASL binds. Simple binds and StartTLS are supported.
- The ``ldap.controls`` and ``ldap.schema`` packages. Controls are sent and
  received as the ``(type, criticality, value)`` triples
  :mod:`anyldap.protocols.pureldap` uses.
- The ``OPT_X_TLS_*`` options. TLS is asked for with an
  :class:`ssl.SSLContext` passed to ``initialize()``, and ``ldaps://`` URLs
  raise TLS before anything is sent.
- Referrals are never chased: a search hands back the referral URLs as
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
