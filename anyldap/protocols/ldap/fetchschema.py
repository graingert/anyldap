from anyldap import schema
from anyldap._encoder import to_bytes
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldaperrors, ldapsyntax


def _onlyResult(results):
    if len(results) == 0:
        raise ldaperrors.LDAPOther("No such DN")
    if len(results) > 1:
        raise ldaperrors.LDAPOther("DN matched multiple entries")
    return results[0]


async def _fetchCb(subschemaSubentry, client):
    o = ldapsyntax.LDAPEntry(client=client, dn=subschemaSubentry)
    results = await o.search(
        scope=pureldap.LDAP_SCOPE_baseObject,
        sizeLimit=1,
        attributes=["attributeTypes", "objectClasses"],
    )
    o = _onlyResult(results)

    attributeTypes = []
    objectClasses = []
    for text in o.get("attributeTypes", []):
        attributeTypes.append(schema.AttributeTypeDescription(to_bytes(text)))
    for text in o.get("objectClasses", []):
        objectClasses.append(schema.ObjectClassDescription(to_bytes(text)))
    assert attributeTypes, (
        "LDAP server doesn't give attributeTypes for subschemaSubentry dn=%s" % o.dn
    )
    return (attributeTypes, objectClasses)


async def fetch(client, baseObject):
    o = ldapsyntax.LDAPEntry(client=client, dn=baseObject)
    results = await o.search(
        scope=pureldap.LDAP_SCOPE_baseObject,
        sizeLimit=1,
        attributes=["subschemaSubentry"],
    )
    o = _onlyResult(results)
    assert "subschemaSubentry" in o, "No subschemaSubentry. TODO"
    subSchemas = o["subschemaSubentry"]
    assert (
        len(subSchemas) == 1
    ), "More than one subschemaSubentry is not support yet. TODO"
    return await _fetchCb(next(iter(subSchemas)), client)
