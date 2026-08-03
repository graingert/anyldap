#!/usr/bin/env python3


from typing import Any, NoReturn

from anyldap._encoder import to_unicode
from anyldap.protocols import pureber, pureldap

"""

RFC2254:

        filter     = "(" filtercomp ")"
        filtercomp = and / or / not / item
        and        = "&" filterlist
        or         = "|" filterlist
        not        = "!" filter
        filterlist = 1*filter
        item       = simple / present / substring / extensible
        simple     = attr filtertype value
        filtertype = equal / approx / greater / less
        equal      = "="
        approx     = "~="
        greater    = ">="
        less       = "<="
        extensible = attr [":dn"] [":" matchingrule] ":=" value
                     / [":dn"] ":" matchingrule ":=" value
        present    = attr "=*"
        substring  = attr "=" [initial] any [final]
        initial    = value
        any        = "*" *(value "*")
        final      = value
        attr       = AttributeDescription from Section 4.1.5 of [1]
        matchingrule = MatchingRuleId from Section 4.1.9 of [1]
        value      = AttributeValue from Section 4.1.6 of [1]
"""


class InvalidLDAPFilter(Exception):
    def __init__(self, msg: str, loc: int, text: str) -> None:
        Exception.__init__(self)
        self.msg = msg
        self.loc = loc
        self.text = text

    def __str__(self) -> str:
        return "Invalid LDAP filter: %s at point %d in %r" % (
            self.msg,
            self.loc,
            self.text,
        )


def parseExtensible(attr: str, s: str) -> NoReturn:
    raise NotImplementedError()


import string

from pyparsing import (
    CharsNotIn,
    Combine,
    DelimitedList,
    Forward,
    Group,
    Literal,
    OneOrMore,
    Optional,
    ParseException,
    StringEnd,
    StringStart,
    Suppress,
    Word,
    ZeroOrMore,
)

filter_ = Forward()
attr = Word(
    string.ascii_letters,
    string.ascii_letters + string.digits + ";-",
)
attr.leave_whitespace()
attr.set_name("attr")
hexdigits = Word(string.hexdigits, exact=2)
hexdigits.set_name("hexdigits")
escaped = Suppress(Literal("\\")) + hexdigits
escaped.set_name("escaped")


def _p_escaped(s: str, l: int, t: Any) -> Any:
    text = t[0]
    return chr(int(text, 16))


escaped.set_parse_action(_p_escaped)
value = Combine(OneOrMore(CharsNotIn("*()\\\0") | escaped))
value.set_name("value")
equal = Literal("=")
equal.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_equalityMatch)
approx = Literal("~=")
approx.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_approxMatch)
greater = Literal(">=")
greater.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_greaterOrEqual)
less = Literal("<=")
less.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_lessOrEqual)
filtertype = equal | approx | greater | less
filtertype.set_name("filtertype")
simple = attr + filtertype + value
simple.leave_whitespace()
simple.set_name("simple")


def _p_simple(s: str, l: int, t: Any) -> Any:
    attr, filtertype, value = t
    return filtertype(
        attributeDesc=pureldap.LDAPAttributeDescription(attr),
        assertionValue=pureldap.LDAPAssertionValue(value),
    )


simple.set_parse_action(_p_simple)
present = attr + "=*"
present.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_present(t[0]))
initial = value.copy()
initial.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_substrings_initial(t[0]))
initial.set_name("initial")
any_value = value + Suppress(Literal("*"))
any_value.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_substrings_any(t[0]))
any = Suppress(Literal("*")) + ZeroOrMore(any_value)
any.set_name("any")
final = value.copy()
final.set_name("final")
final.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_substrings_final(t[0]))
substring = (
    attr + Suppress(Literal("=")) + Group(Optional(initial) + any + Optional(final))
)
substring.set_name("substring")


def _p_substring(s: str, l: int, t: Any) -> Any:
    attrtype, substrings = t
    return pureldap.LDAPFilter_substrings(type=attrtype, substrings=substrings)


substring.set_parse_action(_p_substring)

keystring = Word(string.ascii_letters, string.ascii_letters + string.digits + ";-")
keystring.set_name("keystring")
numericoid = DelimitedList(Word(string.digits), delim=".", combine=True)
numericoid.set_name("numericoid")
oid = numericoid | keystring
oid.set_name("oid")
matchingrule = oid.copy()
matchingrule.set_name("matchingrule")

extensible_dn = Optional(":dn")


def _p_extensible_dn(s: str, l: int, t: Any) -> Any:
    return bool(t)


extensible_dn.set_parse_action(_p_extensible_dn)

matchingrule_or_none = Optional(Suppress(":") + matchingrule)


def _p_matchingrule_or_none(s: str, l: int, t: Any) -> Any:
    if not t:
        return [None]
    else:
        return t[0]


matchingrule_or_none.set_parse_action(_p_matchingrule_or_none)

extensible_attr = attr + extensible_dn + matchingrule_or_none + Suppress(":=") + value
extensible_attr.set_name("extensible_attr")


def _p_extensible_attr(s: str, l: int, t: Any) -> Any:
    return list(t)


extensible_attr.set_parse_action(_p_extensible_attr)

extensible_noattr = (
    extensible_dn + Suppress(":") + matchingrule + Suppress(":=") + value
)
extensible_noattr.set_name("extensible_noattr")


def _p_extensible_noattr(s: str, l: int, t: Any) -> Any:
    return [None] + list(t)


extensible_noattr.set_parse_action(_p_extensible_noattr)

extensible = extensible_attr | extensible_noattr
extensible.set_name("extensible")


def _p_extensible(s: str, l: int, t: Any) -> Any:
    attr, dn, matchingRule, value = t
    return pureldap.LDAPFilter_extensibleMatch(
        matchingRule=matchingRule, type=attr, matchValue=value, dnAttributes=dn
    )


extensible.set_parse_action(_p_extensible)
item = simple ^ present ^ substring ^ extensible
item.set_name("item")
item.leave_whitespace()
not_ = Suppress(Literal("!")) + filter_
not_.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_not(t[0]))
not_.set_name("not")
filterlist = OneOrMore(filter_)
or_ = Suppress(Literal("|")) + filterlist
or_.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_or(t))
or_.set_name("or")
and_ = Suppress(Literal("&")) + filterlist
and_.set_parse_action(lambda s, l, t: pureldap.LDAPFilter_and(t))
and_.set_name("and")
filtercomp = and_ | or_ | not_ | item
filtercomp.set_name("filtercomp")
filter_ << (
    Suppress(Literal("(").leave_whitespace())
    + filtercomp
    + Suppress(Literal(")").leave_whitespace())
)
filter_.set_name("filter")
filtercomp.leave_whitespace()
filter_.leave_whitespace()

toplevel = StringStart().leave_whitespace() + filter_ + StringEnd().leave_whitespace()
toplevel.leave_whitespace()
toplevel.set_name("toplevel")


def parseFilter(s: str | bytes) -> pureber.BERBase:
    """
    Converting source string to pureldap.LDAPFilter

    Source string is converted to unicode as pyparsing cannot parse bytes
    objects with the rules declared in this module.
    """
    text = to_unicode(s)
    try:
        x = toplevel.parse_string(text)
    except ParseException as e:
        raise InvalidLDAPFilter(e.msg, e.loc, e.line)
    assert len(x) == 1
    parsed = x[0]
    assert isinstance(parsed, pureber.BERBase)
    return parsed


maybeSubString_value = Combine(OneOrMore(CharsNotIn("*\\\0") | escaped))

maybeSubString_simple = maybeSubString_value.copy()


def _p_maybeSubString_simple(s: str, l: int, t: Any) -> Any:
    return lambda attr: pureldap.LDAPFilter_equalityMatch(
        attributeDesc=pureldap.LDAPAttributeDescription(attr),
        assertionValue=pureldap.LDAPAssertionValue(t[0]),
    )


maybeSubString_simple.set_parse_action(_p_maybeSubString_simple)

maybeSubString_present = Literal("*")


def _p_maybeSubString_present(s: str, l: int, t: Any) -> Any:
    return lambda attr: pureldap.LDAPFilter_present(attr)


maybeSubString_present.set_parse_action(_p_maybeSubString_present)

maybeSubString_substring = Optional(initial) + any + Optional(final)


def _p_maybeSubString_substring(s: str, l: int, t: Any) -> Any:
    return lambda attr: pureldap.LDAPFilter_substrings(type=attr, substrings=t)


maybeSubString_substring.set_parse_action(_p_maybeSubString_substring)

maybeSubString = (
    maybeSubString_simple ^ maybeSubString_present ^ maybeSubString_substring
)


def parseMaybeSubstring(attrType: str, s: str) -> pureber.BERBase:
    try:
        x = maybeSubString.parse_string(s)
    except ParseException as e:
        raise InvalidLDAPFilter(e.msg, e.loc, e.line)
    assert len(x) == 1
    fn = x[0]
    built = fn(attrType)
    assert isinstance(built, pureber.BERBase)
    return built


if __name__ == "__main__":
    import sys

    for filt in sys.argv[1:]:
        print(repr(parseFilter(filt)))
        print()
