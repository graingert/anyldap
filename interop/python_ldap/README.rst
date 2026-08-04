python-ldap's own tests, ported
===============================

The tests in this directory are ported from python-ldap's test suite. They
are what python-ldap checks its own behaviour with, so running them against
``anyldap.ldap`` is the closest thing there is to a definition of "the same
as python-ldap".

Provenance
----------

Ported from python-ldap 3.4.7 (the ``Tests/`` directory of the source
distribution), taken from https://pypi.org/project/python-ldap/.

==============================  ===============================
This directory                  python-ldap
==============================  ===============================
``test_dn.py``                  ``Tests/t_ldap_dn.py``
``test_filter.py``              ``Tests/t_ldap_filter.py``
``test_functions.py``           ``Tests/t_ldap_functions.py``
``test_modlist.py``             ``Tests/t_ldap_modlist.py``
``test_cidict.py``              ``Tests/t_cidict.py``
``test_ldapobject.py``          ``Tests/t_ldapobject.py``,
                                ``Tests/t_bind.py``,
                                ``Tests/t_edit.py``
==============================  ===============================

Licence
-------

python-ldap is distributed under a Python-style licence, with contributions
after 1 July 2021 under the MIT licence. Both are here verbatim, as
``LICENCE.python-ldap`` and ``LICENCE.python-ldap.MIT``, and both permit
these modified copies. Copyright remains with the python-ldap authors;
anyldap itself is MIT-licensed, which the terms of neither licence conflict
with.

What was changed
----------------

- Every operation is awaited, and the tests are ``pytest`` functions rather
  than ``unittest`` methods. python-ldap's ``SlapdTestCase`` is a fixture
  here, starting one slapd for the module.
- ``self.assertEqual(a, b)`` becomes ``assert a == b``, and
  ``assertRaises`` becomes ``pytest.raises``. The values asserted on are
  python-ldap's own, unchanged.
- Where python-ldap reaches into an object's internals (``cidict._keys``),
  the port asks the same question through the public API.

What was not ported, and why
----------------------------

- **The bytes/text checks.** python-ldap rejects a ``bytes`` DN or filter
  with ``TypeError``, and warns with ``LDAPBytesWarning``; this client takes
  either on purpose, so ``test_reject_bytes_base`` and the ``bytes_mode``
  parts of ``t_bind.py`` do not apply.
- **The ``DN_FORMAT_*`` cases** of ``t_ldap_dn.py``. Those flags are the C
  library's DN parser options, which this has no equivalent for.
- **``ldap.cidict.strlist_*`` and ``cidict.data``**, which python-ldap has
  deprecated, and ``t_cidict.test_strlist_deprecated`` with them.
- **Anything needing a module this does not have**: ``ldap.asyncsearch``,
  ``ldap.syncrepl``, ``LDAPUrl``, and the LDIF module python-ldap ships
  (anyldap has its own, tested in ``anyldap/test``). ``ldap.schema``,
  ``ldap.controls`` and ``ldap.sasl`` are here; the interop tests next door
  check them against python-ldap's own.
- **``ReconnectLDAPObject``'s reconnection tests** and the ``fileno``
  variant: this client's ``ReconnectLDAPObject`` is the plain object, which
  does not reconnect behind the caller's back.
- **The TLS ones** that read the peer certificate through the C library
  (``test_get_tls_peercert``, ``test_multiple_starttls``). StartTLS itself
  is tested in ``anyldap/test/test_ldap.py``.
- **``passwd_s(..., extract_newpw=True)``**, which decodes a
  server-generated password out of the extended response. The rest of
  ``test_passwd_s`` is ported.

Running them
------------

They need slapd installed, the same as the rest of ``interop``::

    tox -e interop
