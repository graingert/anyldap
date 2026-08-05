Changelog
=========

0.2.0 (2026-08-05)
------------------

Backwards incompatible changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- A server handler's ``reply`` writes each response as it is given, rather
  than collecting them all and writing them once the handler has returned.
  A search over a large tree now sends each entry as it is found, so the
  server no longer holds the whole result in memory, and a client reading
  the results sees them arrive rather than waiting for the last one. The
  callback is awaited, so ``reply(response)`` becomes ``await
  reply(response)`` -- ``Reply`` is now
  ``Callable[[BERBase], Awaitable[None]]``.
- The callbacks that walk a tree are awaited too: the ``callback`` argument
  to ``children()``, ``subtree()`` and ``search()`` must be a coroutine
  function, which is what lets an entry be written out as it is reached
  instead of gathered first. ``ProxyBase.handleProxiedResponse()`` may now
  return an awaitable, as ``handleBeforeForwardRequest()`` already could.
- ``LDAPClient.dataReceived()`` is ``dataReceived_async()``, a coroutine,
  because dispatching a response may now await. The old name raises
  ``TypeError`` naming the new one rather than quietly dropping the bytes.
- ``MergedLDAPServer`` interleaves the entries it merges. Each upstream
  server's entries used to be held until that server had finished; now each
  is forwarded as it arrives, so entries from the servers may alternate.
  The result-done still comes last, once every upstream has answered.
- ``pureber.BERSequence`` is a read-only ``Sequence``, not a ``UserList``.
  Reading one is unchanged -- indexing, slicing, iterating and ``len()`` all
  work -- but ``append()``, ``extend()``, ``insert()``, ``pop()`` and item
  assignment are gone. A sequence is built from the items it is to hold.
- ``passlib`` is no longer a dependency. The DES and MD4 that the Samba
  password code needed are vendored under ``anyldap.samba._passlib``, with
  passlib's own licence beside them, so nothing has to be installed for
  ``setPassword_Samba()`` to work.

Features
^^^^^^^^

- ``anyldap.app`` serves a directory written as an application rather than
  as a subclass: a coroutine function of ``(scope, receive, send)``, the
  three arguments an ASGI web application takes. What a scope describes is
  an LDAP *operation*, since LDAP multiplexes and a client may have several
  outstanding at once, and the operations of one connection share
  ``scope["connection"]``, whose ``state`` is where the bound user and
  anything else per-connection belongs. Each operation runs in its own task
  so reading the next request does not wait for the last one to be
  answered. Stopping an operation is the connection's business rather than
  an application's, so neither an abandon nor a cancel arrives as a scope.
  Neither cancels anything either: what ends is the message id, the way
  resetting an HTTP/2 stream does, and ``send`` raises
  ``ClientDisconnected``, an ``OSError``, from then on. A closed connection refuses the same way. What the client is told is
  what differs -- RFC 4511 section 4.11 leaves an abandoned operation
  unanswered, while RFC 3909 has a cancel answer both itself and the
  operation it stopped, in whatever shape that one was going to be
  answered in. A response may carry controls of its own, which is what a
  paged search needs and what a ``handle_*`` method has no way to say.
- ``anyldap.app.lifespan()`` calls an application once with a lifespan
  scope before the first connection is accepted, and once more when
  serving is over, which is where it opens what it needs for as long as it
  is running -- a task group, a connection pool -- by leaving it in
  ``scope["state"]``. Every connection scope's ``state`` starts as a copy
  of that, so work an operation starts in the application's task group
  outlives the connection it came in on. ``app.listen()`` and
  ``app.serve()`` run one the way ``ldapserver.listen()`` and
  ``ldapserver.serve()`` run a protocol, with startup finishing before the
  sockets are bound, so what ``listen()`` reports says the application is
  ready as well as the listener. An application that will not take a
  lifespan scope is served without one, as the ASGI specification says to
  do.
- ``app.listen()`` takes the URLs to listen on, the way OpenLDAP's
  ``slapd -h`` does: ``ldap://host:port`` is a TCP socket,
  ``ldapi://path`` one in the filesystem, and ``ldaps://host:port`` a TCP
  socket with TLS already up. Several may be given. What it reports
  through ``task_status`` is the URLs it actually bound, so a port of 0
  comes back as the port that was chosen and what comes back can be handed
  to ``ldap.initialize()``.
- ``anyldap-serve`` runs an application from the command line, on asyncio
  or on trio: ``anyldap-serve --bind ldap://127.0.0.1:1389
  mymodule:directory``. The application is named the way an ASGI server
  names one, resolved with ``pkgutil.resolve_name()``; a trailing ``()``
  says the name points at something to call, whose answer is the
  application. At least one ``--bind`` is needed, and interrupting or
  terminating it is how it is stopped, on either backend: it takes those
  signals over before it binds anything, so the application shuts down
  rather than being cancelled.
- ``app.listen()`` and ``app.serve()`` take a ``shutdown_trigger``, as
  anycorn's ``serve()`` does. It is awaited alongside the serving, and
  returning from it stops the server, which is how to stop one without
  cancelling it -- and so how the lifespan still gets to shut the
  application down.
- ``ldapconnector`` can connect with TLS already up, which is what an
  ``ldaps://`` server expects, rather than only raising it afterwards with
  StartTLS. ``connectToLDAPEndpointAsync()`` and ``connectToLDAPDNAsync()``
  take ``tls=True``, or an ``ssl_context``, which asks for TLS by itself.
  They are told in their arguments; neither reads a URL scheme.
- ``ldiftree`` lists a directory through ``anyio.Path`` rather than
  ``os.listdir()``, so reading a tree no longer blocks the event loop while
  it waits for the filesystem.
- ``anyldap.ldap`` is python-ldap's API, awaited. Every method python-ldap
  spells synchronously is a coroutine here, taking the same arguments and
  handing back the same values, so code ports by adding ``await``::

      import anyldap.ldap as ldap

      async with ldap.initialize("ldap://localhost") as connection:
          await connection.simple_bind_s("cn=admin,dc=example,dc=com", "secret")
          for dn, entry in await connection.search_s(
              "dc=example,dc=com", ldap.SCOPE_SUBTREE, "(cn=jack)"
          ):
              print(dn, entry)

  Like python-ldap, a connection reads its socket only while an operation is
  being waited for, so it needs no task group and no background task: it can
  be used from whichever task holds it.
- The parts of python-ldap that live beside the connection are here under the
  same names: ``ldap.dn``, ``ldap.filter``, ``ldap.modlist``, ``ldap.cidict``,
  ``ldap.functions``, ``ldap.sasl``, ``ldap.controls``, ``ldap.schema``,
  ``ldap.ldapurl`` and ``ldap.ldif``, along with the error classes, the
  constants and the ``*_s``, ``*_ext`` and ``result3()``/``result4()``
  spellings of each operation.
- SASL binds are driven by the client: EXTERNAL, PLAIN, CRAM-MD5 and
  DIGEST-MD5 answer for themselves, and ``ldapi://`` connects to a socket in
  the filesystem, which is what EXTERNAL is usually asked over. GSSAPI is
  there too, exchanged as RFC 4752 says, if the ``gssapi`` package is
  installed; it is not a dependency, and the mechanism says so if it is
  asked for without it. The ``OPT_X_SASL_*`` options supply the defaults a
  mechanism reads and report what the bind ended up with.
- ``ldap.asyncsearch`` reads a long search result by result rather than
  asking for all of it at once, with python-ldap's ``List``, ``Dict``,
  ``IndexedDict``, ``FileWriter`` and ``LDIFWriter`` handlers.
- ``ReconnectLDAPObject`` opens the connection again when the server goes
  away and tries the operation once more, putting back the options that were
  set, StartTLS if it had been raised, and the last bind that was made. It
  can be pickled, and reads back as a connection that opens and binds itself
  when it is next used.
- ``ldap.syncrepl`` keeps a copy of what a server holds, as RFC 4533 says:
  the Sync Request, Sync State and Sync Done controls, the Sync Info message
  the server sends while the search runs, and the ``SyncreplConsumer`` mixin
  that drives them.
- ``cancel()`` and ``cancel_s()`` stop an operation and are answered, which
  is what RFC 3909 adds over ``abandon()``. Intermediate responses (RFC 4511
  section 4.13) are read, and ``result4(add_intermediates=1)`` hands them
  back; ``add_ctrls=1`` hands back each message with the controls it
  carried.
- ``OPT_TIMEOUT`` and ``OPT_NETWORK_TIMEOUT`` say how long an operation may
  take the way libldap says it: ``None`` and ``-1`` both mean no limit, and
  anything else negative is refused. ``OPT_URI`` can be set as well as read,
  which names another server to open.
- The controls python-ldap encodes with pyasn1 are encoded with the BER
  library anyldap already has: paged results, pre-read and post-read,
  server-side sorting, the password policy response, OpenLDAP's no-op search,
  assertion and matched-values, and the valueless ones.
- The ``OPT_X_TLS_*`` options build the ``ssl.SSLContext`` a connection is
  raised with; a context can still be passed to ``initialize()`` instead.
- ``ldap.extop`` is what an extended operation of your own is built out of,
  with ``extop.dds`` for the dynamic entries of RFC 2589 and
  ``extop.passwd`` for the password a server made up. ``extop_result()``
  collects an operation started with ``extop()``.
- Every kind of schema definition is read, not four of the eight: matching
  rule uses, content rules, structure rules and name forms are there too,
  which is why a server's own ``matchingRuleUse`` is no longer dropped.
  ``ldap.schema.Entry`` is an entry that knows its schema, and
  ``split_tokens()``/``extract_tokens()`` are what read a definition.
- Every error class carries ``errnum``, the result code it stands for,
  under the name python-ldap gives it, and ``NO_UNIQUE_ENTRY`` is a kind of
  ``NO_SUCH_OBJECT`` as it is there.
- ``SubSchema`` checks that a schema does not describe one thing twice, the
  way python-ldap does: ``check_uniqueness`` decides whether the second
  definition is kept under a name of its own, replaces the first, or is
  refused with ``OIDNotUnique``, and a name claimed twice raises
  ``NameNotUnique``.
- ``extop_s()`` takes the class to read the answer into, ``result3()`` and
  ``result4()`` take the classes that read particular controls, ``whoami_s()``
  takes controls, and the SASL binds take ``sasl_flags`` where python-ldap
  takes it -- before the identity, so one passed positionally lands where it
  is meant to.
- The names python-ldap has that were missing: ``ldap.error``, the ``REQ_*``
  and ``TAG_*`` constants, ``OPT_NAMES_DICT`` and every ``OPT_*`` number,
  ``abandon_ext()``, ``fileno()``, ``sasl_gssapi_bind_s()``,
  ``ldap.filter.time_span_filter()``,
  ``ldap.controls.GetEffectiveRightsControl`` and the re-exports
  ``ldap.functions`` carries. Module-level ``ldap.set_option()`` says what
  every connection opened after it starts with.
- Setting an attribute that is an option underneath goes through
  ``set_option()``, as ``CLASSATTR_OPTION_MAPPING`` says it should:
  ``connection.network_timeout = -1`` says the same thing as setting
  ``OPT_NETWORK_TIMEOUT`` to -1, and means no limit either way.
- A schema definition writes itself back out the way python-ldap writes it,
  and ``x_origin`` and the other ``X-`` fields a definition carries are read
  rather than refused. ``ldap.schema.urlfetch()`` takes an LDAP URL and
  opens a connection of its own to ask, and ``SubSchema.ldap_entry()``
  writes a whole schema back out as the entry it was read from.
- ``ldap.ldif`` is python-ldap's top-level ``ldif`` module: ``LDIFWriter``,
  ``LDIFParser``, ``LDIFRecordList`` and ``LDIFCopy``, reading and writing
  entry records and change records as RFC 2849 spells them. anyldap's own
  LDIF reader is a line-receiving protocol answering with anyldap's objects,
  which is not what code written against python-ldap asks for. The
  deprecated ``CreateLDIF()`` and ``ParseLDIF()`` are not here.
- Referrals are followed, unless ``OPT_REFERRALS`` is turned off -- which is
  what libldap does, and so what python-ldap inherits. A result that is
  nothing but a referral is made again where it points, and a search
  continuation is read from the server it names and added to what the search
  found. Following one is anonymous, and a bind is never followed: a
  referral says where to look and nothing about whose credentials may be
  sent there. A referral nobody answers is raised as ``REFERRAL``, carrying
  the URLs as its ``info``, and one that points at itself stops after five
  hops with ``REFERRAL_LIMIT_EXCEEDED``.
- A result carries its referral over the wire, which ``pureldap`` used to
  leave undecoded, and an error says how far the server did recognise the
  name as python-ldap's ``matched``. A search continuation is handed back as
  ``RES_SEARCH_REFERENCE`` rather than as an entry.
- ``ldap.schema.urlfetch()`` takes the address of an LDIF file as well as an
  LDAP URL, and reads the schema out of its first record, which is what
  python-ldap's does.
- A URL is read only if it is one of ``file:``, ``http:`` or ``https:``, and
  refused otherwise. A file is read with ``anyio.Path``, and an ``http:``
  address is fetched with httpx2. python-ldap hands the address to
  ``urlopen`` instead, which fetches whatever scheme it happens to support,
  so an address meant to name a file can turn out to be a request and the
  other way about -- which matters most for the URLs ``ldap.ldif`` fetches
  when ``process_url_schemes`` tells it to fetch any, since those are named
  by the data being parsed rather than by the caller.
- A schema definition may name itself rather than be numbered:
  ``( nsEncryptionConfig-oid NAME ... )`` is what a 389-ds server publishes,
  and RFC 4512 section 1.4 allows it. It used to be refused, which meant a
  real FreeIPA schema could not be read at all.

Other changes
^^^^^^^^^^^^^

- The package lives under ``src/`` and the tests beside it rather than
  inside it, so what is imported in a test run is what was installed. The
  distribution is unchanged: it is still ``anyldap``, with the same modules
  in it.
- Everything is checked under mypy's ``strict``, and not only the package:
  the tests, the documentation's example scripts and the interop suite are
  checked too. ``typing_extensions`` is a dependency, for the pieces of the
  typing API that the oldest Python supported here does not have.
- anyldap ships a ``py.typed`` marker, so the annotations it is written with
  are ones a type checker will read. Everything in it is annotated and checked
  under mypy's ``strict``; until now that was of no use to anybody importing
  it, since without the marker a checker treats an installed package as
  having no types at all (PEP 561).
- `httpx2 <https://pypi.org/project/httpx2/>`_ is a new dependency. It is what
  a schema or an LDIF value named by an ``http:`` URL is fetched with.
- python-ldap's own test suite is ported under ``interop/python_ldap/``, with
  its licences and a note of what each file came from, and ``tox -e interop``
  runs this client and python-ldap through the same script against one real
  OpenLDAP server.


0.1.0 (2026-08-02)
------------------

First release of anyldap, a fork of ldaptor 21.2.0 ported from Twisted to
AnyIO. It runs unmodified on both asyncio and trio.

Backwards incompatible changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- The project, the importable package and the console scripts are renamed
  from ``ldaptor`` to ``anyldap``. Replace ``import ldaptor`` with
  ``import anyldap``, ``ldaptor-search`` with ``anyldap-search``, and so on
  for the rest of the utilities. The bundled schema file is now
  ``anyldap.schema``.
- Twisted is no longer a dependency. Protocols are driven by AnyIO byte
  streams rather than a reactor and transports, so there is no global reactor
  to install, start or stop.
- ``Deferred`` is gone. Every operation that used to return one is now a
  coroutine, and the callback-style API that came with it — ``addCallback``,
  ``addErrback``, ``addCallbacks``, ``addBoth`` — has no replacement, because
  the results are awaited instead::

      # before
      d = entry.search(filterText="(cn=bob)")
      d.addCallback(handle)

      # now
      results = await entry.search(filterText="(cn=bob)")

  Failures surface as ordinary raised exceptions rather than ``Failure``
  objects passed to an errback.
- ``ProxyBase.handleProxiedResponse()`` must now be a plain method. It is
  called while dispatching a response and cannot await; returning an
  awaitable from it will not work.
- Python 3.10 or newer is required. Support for Python 3.5 through 3.9 is
  dropped, along with the last of the Python 2 compatibility code.
- ``anyldap-ldap2pdns``, ``anyldap-ldap2dhcpconf``, ``anyldap-ldap2dnszones``
  and ``anyldap-ldap2maradns`` are not yet ported and exit with a message
  saying so. The remaining utilities work.

Features
^^^^^^^^

- Servers are started with ``BaseLDAPServer.listen()``, which can be handed to
  ``TaskGroup.start()`` to get the bound ``(host, port)`` once the listener is
  ready. ``ldapserver.listen()`` takes a protocol factory, and
  ``ldapserver.serve_stream()`` serves a single already-accepted stream.
- Clients connect with ``ldapconnector.connectToLDAPDNAsync()`` or
  ``connectToLDAPEndpointAsync()``, both of which return an async context
  manager that closes the connection on exit.
- Every LDAP operation is also available under an explicit ``*_async`` name —
  ``bind_async()``, ``search_async()``, ``commit_async()`` and friends — for
  code that prefers to spell out which calls await.
- ``startTLS`` is supported on both the client and the server, wrapping the
  live stream in an AnyIO ``TLSStream``.

Other changes
^^^^^^^^^^^^^

- The version is derived from the git tag by setuptools-scm; there is no
  hardcoded version in the source.
- The test suite runs against both asyncio and trio, and statement and branch
  coverage are both enforced at 100%.
- Packaging metadata moved to PEP 621, and the documentation was rewritten
  around the AnyIO API.


.. note::

   anyldap was forked from ldaptor 21.2.0. Everything below is ldaptor's own
   changelog, kept for reference. The project and script names in it were
   rewritten by the fork, so it reads ``anyldap`` where it originally said
   ``ldaptor``.


21.2.0 (2021-02-28)
-------------------

- fix ``ModuleNotFoundError: No module named 'cStringIO'`` in anyldap-ldap2pdns.
- move scripts to console_scripts entry_points
- replace deprecated calls to ``base64.decodestring`` and ``base64.encodestring``.
- *This will be the last anyldap release to support Python 3.5*.


20.1.1 (2020-10-02)
-------------------

- Updated the object representations of pureber and pureldap containers to
  directly pass on their contained item object representations. Previously
  they always passed on the repr after decoding to str with utf-8.


20.1.0 (2020-09-30)
-------------------

- Dropped support for Python 2
- removed Travis CI


20.0.0 (2020-09-30)
-------------------

Changes
^^^^^^^

- The next release v20.1.0 will drop support for Python 2, and require Python~=3.5
- PyPI release is now done via GitHub Action
- the anyldap whl is now built with pep517.
- the anyldap whl is tested with tox. The sdist is now untested,
  deprecated and should only be used for compatability with very old
  packaging tools.
- the setup.py file is deprecated and will be removed in a future release.

Bugfixes
^^^^^^^^

- SASL Bind without credentials caused list index out of range. Issue #157.
- anyldap.protocols.ldap.ldapserver.LDAPServer.handle_LDAPSearchRequest
  now returns an LDAPSearchResultEntry without any attributes when there is no match
  between the requested attributes and the entrie's attributes. Issue #166.


Release 19.1 (2019-09-09)
-------------------------

Features
^^^^^^^^

- Basic implementation of ``anyldap.protocols.pureldap.LDAPSearchResultReference``.
- Explicit ``anyldap.protocols.ldap.ldaperrors`` classes declaration was made
  to allow syntax highlighting for this module.
- Example of using LDAP server with the database. Employees are store in the database table and retrieved
  on server initialization.

Changes
^^^^^^^

- ``anyldap.protocols.pureldap.LDAPPasswordModifyRequest`` string representation now contains
  ``userIdentity``, ``oldPasswd`` and ``newPasswd`` attributes. Password attributes are represented as asterisks.
- ``anyldap.protocols.pureldap.LDAPBindRequest`` string representation is now using asterisks to represent
  ``auth`` attribute.

Bugfixes
^^^^^^^^

- ``DeprecationWarning`` stacklevel was set to mark the caller of the deprecated
  methods of the ``anyldap._encoder`` classes.
- ``NotImplementedError`` for ``anyldap.protocols.pureldap.LDAPSearchResultReference`` was fixed.
- Regression bug with ``LDAPException`` instances was fixed (``anyldap.protocols.ldap.ldapclient``
  exceptions failed to get their string representations).
- StartTLS regression bug was fixed: ``anyldap.protocols.pureldap.LDAPStartTLSRequest.oid`` and
  ``anyldap.protocols.pureldap.LDAPStartTLSResponse.oid`` must be of bytes type.
- ``anyldap.protocols.pureldap`` and ``anyldap.protocols.pureber`` string representations were fixed:
  `LDAPResult(resultCode=0, matchedDN='uid=user')` instead of `LDAPResult(resultCode=0, matchedDN="b'uid=user'")`.
- ``anyldap.protocols.pureldap.LDAPMatchingRuleAssertion`` initialization for Python 3 was failed for bytes arguments.
- ``anyldap.protocols.pureldap.LDAPExtendedResponse`` custom tag parameter was not used.
- ``anyldap._encoder.to_bytes()`` was fixed under Python 3 to return integers as their numeric
  representation rather than a sequence of null bytes.

Release 19.0 (2019-03-05)
-------------------------

Features
^^^^^^^^

- Ability to logically compare anyldap.protocols.pureldap.LDAPFilter_and and anyldap.protocols.pureldap.LDAPFilter_or objects with ==.
- Ability to customize anyldap.protocols.pureldap.LDAPFilter_* object's encoding of values when using asText.
- New client recipe- adding an entry to the DIT.
- Ability to use paged search control for LDAP clients.
- New client recipie- using the paged search control.

Changes
^^^^^^^

- Using modern classmethod decorator instead of old-style method call.
- Usage of zope.interfaces was updated in preparation for python3 port.
- ``toWire`` method is used to get bytes representation of `anyldap` classes
  instead of ``__str__`` which is deprecated now.
- Code was updated to pass `python3 -m compileall` in preparation for py3 port.
- Code is linted under python 3  in preparation for py3 port.
- Continuous test are executed only against the latest supported runtime stack.
- The local development environment was updated to produce overall and diff
  coverage reports in HTML format.
- `six` package is now a direct dependency in preparation for the Python 3
  port, and has replaced the anyldap.compat module.
- Remove Python 3.3 from tox as it is EOL.
- Add API documentation for ``LDAPAttributeSet`` and ``startTLS``.
- Quick start and cookbook examples were moved to separate files and
  made agnostic to the Python version.
- dependency on pyCrypto replaced with pure python passlib.
- replace the old TLS dependency stack with the current runtime dependency set

Bugfixes
^^^^^^^^

- DN matching is now case insensitive.
- Proxies now terminate the connection to the proxied server in case a client immediately closes the connection.
- asText() implemented for LDAPFilter_extensibleMatch
- Children of ``anyldap.inmemory.ReadOnlyInMemoryLDAPEntry`` subclass instances are added as the same class instances.
- Redundant attributes keys sorting was removed from ``anyldap.entry.BaseLDAPEntry`` methods.

Release 16.0 (2016-06-07)
-------------------------

Features
^^^^^^^^

- Make meta data introspectable
- Added `proxybase.py`, an LDAP proxy that is easier to hook into.
- When parsing LDAPControls, criticality may not exist while controlValue still does
- Requested attributes can also be passed as '*' symbol
- Numerous small bug fixes.
- Additional documentation
- Updated Travis-CI, Tox and other bits for better coverage.

Release 14.0 (2014-10-31)
-------------------------

anyldap has a new version schema aligned with the project's release process.

License
^^^^^^^

- anyldap's original author `Tommi Virtanen <https://github.com/tv42>`_ changed the license to the MIT (Expat) license.
- anyldap.md4 has been replaced by a 3-clause BSD version.

API Changes
^^^^^^^^^^^

- anyldap client and server: None
- Everything having to do with webui and Nevow have been *removed*.

Features
^^^^^^^^

- `Travis CI <https://travis-ci.org/graingert/anyldap/>`_ is now used for continuous integration.
- Test coverage is now measured. We're currently at around 75%.
- tox is used now to test anyldap across the supported Python versions.
- A few ordering bugs that were exposed by that and are fixed now.
- anyldap.protocols.pureldap.LDAPExtendedRequest now has additional tests.
- The new anyldap.protocols.pureldap.LDAPAbandonRequest adds support for abandoning requests.
- anyldap.protocols.pureldap.LDAPBindRequest has basic SASL support now.
  Higher-level APIs like ldapclient don't expose it yet though.

Bugfixes
^^^^^^^^

- anyldap.protocols.ldap.ldapclient now uses the project logger for debug output.
- String literal exceptions have been replaced by real Exceptions.
- "bin/anyldap-ldap2passwd --help" now does not throws an exception anymore (`debian bug #526522 <https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=526522>`_).
- anyldap.delta.Modification and anyldap.protocols.ldap.ldapsyntax.PasswordSetAggregateError that are used for adding contacts now handle unicode arguments properly.
- anyldap.protocols.pureldap.LDAPExtendedRequest's constructor now handles STARTTLS in accordance to `RFC2251 <http://tools.ietf.org/html/rfc2251>`_ so the constructor of anyldap.protocols.pureldap.LDAPStartTLSRequest doesn't fail anymore.
- anyldap.protocols.ldap.ldapserver.BaseLDAPServer now uses the correct exception module in dataReceived.
- anyldap.protocols.ldap.ldaperrors.LDAPException: "Fix deprecated exception error"
- anyldap-find-server now imports DNS helpers from the supported modules.
- bin/anyldap-find-server now only prints SRV records.
- anyldap.protocols.ldap.ldapsyntax.LDAPEntryWithClient now correctly propagates errors on search().
  The test suite has been adapted appropriately.
- anyldap.protocols.ldap.ldapconnector.LDAPConnector now supports specifying a local address when connecting to a server.
- The new anyldap.protocols.pureldap.LDAPSearchResultReference now prevents anyldap from choking on results containing SearchResultReference (usually from Active Directory servers).
  It is currently only a stub and silently ignored.
- hashlib and built-in set() are now used instead of deprecated modules.

Improved Documentation
^^^^^^^^^^^^^^^^^^^^^^

- Added, updated and reworked documentation using Sphinx.
  `Dia <https://wiki.gnome.org/Apps/Dia/>`_ is required for converting diagrams to svg/png, this might change in the future.
- Dia is now invoked correctly for diagram generation in a headless environment.
- The documentation is now hosted on https://anyldap.readthedocs.org/.

Prehistory
----------

All versions up to and including 0.0.43 didn't have a changelog.
