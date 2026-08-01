from anyldap import schema
from anyldap._encoder import to_bytes
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors, ldapsyntax


def _fetchCb(subschemaSubentry, client):
    o = ldapsyntax.LDAPEntry(client=client, dn=subschemaSubentry)
    d = o.search(
        scope=pureldap.LDAP_SCOPE_baseObject,
        sizeLimit=1,
        attributes=["attributeTypes", "objectClasses"],
    )

    def handleSearchResults(l):
        if len(l) == 0:
            raise ldaperrors.LDAPOther("No such DN")
        elif len(l) == 1:
            o = l[0]

            attributeTypes = []
            objectClasses = []
            for text in o.get("attributeTypes", []):
                attributeTypes.append(schema.AttributeTypeDescription(to_bytes(text)))
            for text in o.get("objectClasses", []):
                objectClasses.append(schema.ObjectClassDescription(to_bytes(text)))
            assert attributeTypes, (
                "LDAP server doesn't give attributeTypes for subschemaSubentry dn=%s"
                % o.dn
            )
            return (attributeTypes, objectClasses)
        else:
            raise ldaperrors.LDAPOther("DN matched multiple entries")

    d.addCallback(handleSearchResults)
    return d


def fetch(client, baseObject):
    o = ldapsyntax.LDAPEntry(client=client, dn=baseObject)
    d = o.search(
        scope=pureldap.LDAP_SCOPE_baseObject,
        sizeLimit=1,
        attributes=["subschemaSubentry"],
    )

    def handleSearchResults(l):
        if len(l) == 0:
            raise ldaperrors.LDAPOther("No such DN")
        elif len(l) == 1:
            o = l[0]
            assert "subschemaSubentry" in o, "No subschemaSubentry. TODO"
            subSchemas = o["subschemaSubentry"]
            assert (
                len(subSchemas) == 1
            ), "More than one subschemaSubentry is not support yet. TODO"
            return next(iter(subSchemas))
        else:
            raise ldaperrors.LDAPOther("DN matched multiple entries")

    d.addCallback(handleSearchResults)
    d.addCallback(_fetchCb, client)
    return d
