LDAP Clients
============

The legacy client cookbook examples were written for an older event-loop API.

Use the examples under ``docs/source/examples`` that target the current AnyIO
runtime instead, or build clients with:

* ``anyldap.protocols.ldap.ldapconnector.LDAPClientCreator.connectAsync()``
* ``anyldap.protocols.ldap.ldapclient.LDAPClient.bind_async()``
* ``anyldap.protocols.ldap.ldapsyntax.LDAPEntry.search_async()``
