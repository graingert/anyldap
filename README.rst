anyldap
=======

.. image:: https://img.shields.io/codecov/c/github/graingert/anyldap?label=codecov&logo=codecov
    :alt: Codecov
    :target: https://codecov.io/gh/graingert/anyldap
.. image:: https://img.shields.io/readthedocs/anyldap?logo=read-the-docs
    :alt: Read the Docs
    :target: https://anyldap.readthedocs.io/en/latest/
.. image:: https://img.shields.io/github/actions/workflow/status/graingert/anyldap/main.yml?label=GitHub%20Actions&logo=github
    :alt: GitHub Actions
    :target: https://github.com/graingert/anyldap
.. image:: https://img.shields.io/pypi/v/anyldap?logo=pypi
    :alt: PyPI
    :target: https://pypi.org/project/anyldap/
.. image:: https://img.shields.io/badge/code%20style-black-black
    :alt: Black
    :target: https://github.com/psf/black

anyldap is a pure-Python, AnyIO-based library for Python 3.10 and newer that
implements:

- LDAP client and server logic
- a client with python-ldap's API, awaited rather than blocking
- separately-accessible LDAP and BER protocol message generation/parsing
- ASCII-format LDAP filter generation and parsing
- LDIF format data generation
- Samba password changing logic

Also included is a set of LDAP utilities for use from the command line.

The full documentation is available on `Read the Docs
<https://anyldap.readthedocs.io/en/latest/>`_.


Quick Usage Example
-------------------

.. code-block:: python

    import anyio

    from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapsyntax


    async def example():
        serverip = "192.168.128.21"
        basedn = b"dc=example,dc=com"
        binddn = b"bjensen@example.com"
        bindpw = b"secret"
        query = b"(cn=Babs*)"
        overrides = {basedn: (serverip, 389)}
        connection = await ldapconnector.connectToLDAPDNAsync(
            basedn,
            ldapclient.LDAPClient,
            overrides=overrides,
        )
        async with connection as client:
            await client.bind_async(binddn, bindpw)
            entry = ldapsyntax.LDAPEntry(client, basedn)
            results = await entry.search_async(filterText=query)
            for result in results:
                print(result.getLDIF())


    if __name__ == "__main__":
        anyio.run(example)


python-ldap's API but async
---------------------------

``anyldap.ldap`` is python-ldap's ``ldap`` module made async: the names, the
arguments they take and the values they hand back are python-ldap's, with
every operation a coroutine, so code written against it ports by adding
``await``. It runs on asyncio and on trio, since it is written against AnyIO,
and none of it is a binding to OpenLDAP's C library -- the protocol, the SASL
mechanisms and the TLS handshake are anyldap's own, which is also why the
handful of things only libldap can answer are not here:

.. code-block:: python

    import anyio

    from anyldap import ldap


    async def example():
        async with ldap.initialize("ldap://ldap.example.com") as connection:
            await connection.simple_bind_s("bjensen@example.com", b"secret")
            results = await connection.search_s(
                "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(cn=Babs*)"
            )
            for dn, attributes in results:
                print(dn, attributes)


    if __name__ == "__main__":
        anyio.run(example)

``ldap.controls``, ``ldap.schema``, ``ldap.sasl``, ``ldap.dn``, ``ldap.filter``,
``ldap.modlist``, ``ldap.cidict``, ``ldap.ldapurl``, ``ldap.ldif``,
``ldap.asyncsearch``, ``ldap.syncrepl`` and ``ReconnectLDAPObject`` are here
too. What it does and does not cover is in the `documentation
<https://anyldap.readthedocs.io/en/latest/anyldap.ldap.html>`_. Most of
python-ldap's own test suite is ported under ``interop/``, next to tests that
run the same operations through both libraries against one OpenLDAP server and
compare the answers; ``tox -e interop`` runs them.


Installation
------------

Install anyldap from PyPI::

    python -m pip install anyldap

To install a repository checkout in editable mode::

    python -m pip install -e .

For a server example from a repo checkout, see
``docs/source/examples/quickstart_server.py``.

Dependencies:

- `AnyIO <https://pypi.org/project/anyio/>`_ for asynchronous networking
- `dnspython <https://pypi.org/project/dnspython/>`_ for LDAP service discovery
- `pyparsing <https://pypi.org/project/pyparsing/>`_ for LDAP filters
- `zope.interface <https://pypi.org/project/zope.interface/>`_
