python-ldap's own tests, ported
===============================

The tests in this directory are ported from python-ldap's test suite. They
are what python-ldap checks its own behaviour with, so running them against
``anyldap.ldap`` is the closest thing there is to a definition of "the same
as python-ldap".

Not all of it is here. Of python-ldap's 23 test files, 19 are ported into the
14 in this directory -- some of upstream's are merged, as the table below
shows. Individual tests are left out of those 19 as well. What is missing and
why is at the end of this file.

Provenance
----------

Ported from python-ldap 3.4.7 (the ``Tests/`` directory of the source
distribution), taken from https://pypi.org/project/python-ldap/.

==============================  =========================================
This directory                  python-ldap
==============================  =========================================
``test_dn.py``                  ``Tests/t_ldap_dn.py``
``test_filter.py``              ``Tests/t_ldap_filter.py``
``test_functions.py``           ``Tests/t_ldap_functions.py``
``test_modlist.py``             ``Tests/t_ldap_modlist.py``
``test_cidict.py``              ``Tests/t_cidict.py``
``test_ldapurl.py``             ``Tests/t_ldapurl.py``
``test_ldif.py``                ``Tests/t_ldif.py``
``test_options.py``             ``Tests/t_ldap_options.py``
``test_sasl.py``                ``Tests/t_ldap_sasl.py``
``test_schema_subentry.py``     ``Tests/t_ldap_schema_subentry.py``
``test_schema_tokenizer.py``    ``Tests/t_ldap_schema_tokenizer.py``
``test_syncrepl.py``            ``Tests/t_ldap_syncrepl.py``
``test_controls.py``            ``Tests/t_ldap_controls_libldap.py``,
                                ``Tests/t_ldap_controls_readentry.py``,
                                ``Tests/t_ldap_controls_ppolicy.py``,
                                ``Tests/t_ldap_controls_sss.py``
``test_ldapobject.py``          ``Tests/t_ldapobject.py``,
                                ``Tests/t_bind.py``,
                                ``Tests/t_edit.py``
==============================  =========================================

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
- Each test runs twice, once on asyncio and once on trio, which is what the
  rest of the test suite does. One slapd is shared by a module and so by
  both runs, so a test that writes to the directory writes under a name of
  its own.

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
- **``CreateLDIF()`` and ``ParseLDIF()``** of ``t_ldif.py``, which python-ldap
  deprecated and does not test either. ``anyldap.ldap.ldif`` does not have
  them, so the rest of that file is ported and this is what is left out.
- **``t_cext.py``**, which tests python-ldap's C extension directly. There
  is no C extension here, and everything it covers through ``_ldap`` is
  covered through the connection instead. It is 40 of upstream's 197 tests,
  and the largest single thing left out.
- **``t_slapdobject.py``**, which tests python-ldap's ``slapdtest`` helper
  rather than python-ldap, and **``t_untested_mods.py``**, which is a list of
  the modules upstream has no tests for and contains no tests itself.
- **``t_ldap_asyncsearch.py``**, whose only test is that ``ldap.async`` is
  the deprecated spelling of ``ldap.asyncsearch``. There is no deprecated
  spelling here. What ``ldap.asyncsearch`` does is tested in
  ``anyldap/test``.
- **The options that are the C library's** (from ``t_ldap_options.py``):
  ``OPT_API_INFO`` describes libldap, and ``OPT_CLIENT_CONTROLS`` and
  ``OPT_SERVER_CONTROLS`` are its default controls -- which upstream's own
  connection-level tests are marked as expected failures.
- **``t_ldapurl.test_bad_urls``** is marked as failing upstream too: the URLs
  it lists ought to be rejected and are not. It is ported with the same
  expectation, so the ones python-ldap does reject stay rejected here.
- **The GSSAPI parts of ``t_ldap_sasl.py``**, which need a Kerberos realm to
  bind against.
- **``ldap.cidict.strlist_*``**, ``bytes_mode``/``bytes_strictness``, the
  ``DN_FORMAT_*`` flags, the threading locks, the C entry points and the
  constants that describe libldap itself (``API_VERSION``,
  ``LIBLDAP_API_INFO``, ``OPT_API_INFO``, ``OPT_DESC``, ``OPT_ERROR_*``,
  ``TLS_AVAIL``): there is no C library here for them to be about. The
  pyasn1 classes that describe what a control's value looks like are not
  here either, because the values are encoded with anyldap's own BER.
- **The two LDIF files ``t_ldap_schema_subentry.py`` reads**, which are
  about half a megabyte each. The definitions each of its tests needs are
  inline in ``test_schema_subentry.py`` instead, taken from those files, and
  the tests that read a whole schema read slapd's.
- **The ``fileno`` variants**, which hand libldap a socket that was opened
  elsewhere. ``ReconnectLDAPObject``'s own tests are ported, except that
  ``__getstate__()`` is checked field by field: what it stores beside
  python-ldap's fields is this client's own.
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
