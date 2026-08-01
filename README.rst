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

anyldap is a pure-Python library that implements:

- LDAP client logic
- separately-accessible LDAP and BER protocol message generation/parsing
- ASCII-format LDAP filter generation and parsing
- LDIF format data generation
- Samba password changing logic

Also included is a set of LDAP utilities for use from the command line.

Verbose documentation can be found on `ReadTheDocs <https://anyldap.readthedocs.org>`_.


Quick Usage Example
-------------------

.. code-block:: python

    import anyio

    from anyldap.protocols.ldap import ldapclient, ldapconnector, ldapsyntax


    async def example():
        serverip = b"192.168.128.21"
        basedn = b"dc=example,dc=com"
        binddn = b"bjensen@example.com"
        bindpw = b"secret"
        query = b"(cn=Babs*)"
        creator = ldapconnector.LDAPClientCreator(None, ldapclient.LDAPClient)
        overrides = {basedn: (serverip, 389)}
        client = await creator.connectAsync(basedn, overrides=overrides)
        await client.bind_async(binddn, bindpw)
        entry = ldapsyntax.LDAPEntry(client, basedn)
        results = await entry.search_async(filterText=query)
        for result in results:
            print(result.getLDIF())


    if __name__ == "__main__":
        anyio.run(example)


Installation
------------

anyldap can be installed using the standard command line method::

    python setup.py install

or using pip from PyPI::

    pip install anyldap

Linux distributions may also have ready packaged versions of anyldap. Debian and Ubuntu may provide packages that can be installed e.g., by::

    apt-get install python-anyldap

For a server example from a repo checkout, see
``docs/source/examples/quickstart_server.py``.

Dependencies:

- `anyio <https://pypi.org/project/anyio/>`_
- `pyparsing <https://pypi.python.org/pypi/pyparsing/>`_
- `passlib <https://pypi.python.org/pypi/passlib/>`_ for Samba passwords
- `six <https://pypi.python.org/pypi/six/>`_ for simultaneous Python 2 and 3 compatability
- `zope.interface <https://pypi.python.org/pypi/zope.interface/>`_
