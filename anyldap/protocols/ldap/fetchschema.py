from collections.abc import Sequence

from anyldap import interfaces, schema
from anyldap._encoder import to_bytes
from anyldap.protocols import pureldap
from anyldap.protocols.ldap import ldapclient, ldaperrors, ldapsyntax


def _onlyResult(
    results: Sequence[ldapsyntax.LDAPEntryWithClient],
) -> ldapsyntax.LDAPEntryWithClient:
    if len(results) == 0:
        raise ldaperrors.LDAPOther("No such DN")
    if len(results) > 1:
        raise ldaperrors.LDAPOther("DN matched multiple entries")
    return results[0]


async def _fetchCb(
    subschemaSubentry: interfaces.AnyDN, client: ldapclient.LDAPClient
) -> tuple[
    list[schema.AttributeTypeDescription], list[schema.ObjectClassDescription]
]:
    o = ldapsyntax.LDAPEntry(client=client, dn=subschemaSubentry)
    results = await o.search(
        scope=pureldap.LDAP_SCOPE_baseObject,
        sizeLimit=1,
        attributes=["attributeTypes", "objectClasses"],
    )
    assert isinstance(results, Sequence)
    o = _onlyResult(results)

    attributeTypes = []
    objectClasses = []
    for text in o.get("attributeTypes", []) or ():
        attributeTypes.append(schema.AttributeTypeDescription(to_bytes(text)))
    for text in o.get("objectClasses", []) or ():
        objectClasses.append(schema.ObjectClassDescription(to_bytes(text)))
    assert attributeTypes, (
        "LDAP server doesn't give attributeTypes for subschemaSubentry dn=%s" % o.dn
    )
    return (attributeTypes, objectClasses)


async def fetch(
    client: ldapclient.LDAPClient, baseObject: interfaces.AnyDN
) -> tuple[
    list[schema.AttributeTypeDescription], list[schema.ObjectClassDescription]
]:
    o = ldapsyntax.LDAPEntry(client=client, dn=baseObject)
    results = await o.search(
        scope=pureldap.LDAP_SCOPE_baseObject,
        sizeLimit=1,
        attributes=["subschemaSubentry"],
    )
    assert isinstance(results, Sequence)
    o = _onlyResult(results)
    assert "subschemaSubentry" in o, "No subschemaSubentry. TODO"
    subSchemas = o["subschemaSubentry"]
    assert (
        len(subSchemas) == 1
    ), "More than one subschemaSubentry is not support yet. TODO"
    return await _fetchCb(next(iter(subSchemas)), client)
