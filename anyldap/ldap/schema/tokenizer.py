"""``ldap.schema.tokenizer``: a schema definition, taken apart word by word.

A schema definition is parentheses, bare words and quoted strings, and what
each word means depends only on the keyword before it. That is enough to
read the kinds of definition that have no parser of their own in
:mod:`anyldap.schema` -- content rules, structure rules, name forms and
matching rule uses -- and it is how python-ldap reads every kind.
"""

import re

__all__ = ["Tokens", "split_tokens", "extract_tokens"]

# What each keyword of a definition was given: the values it was given, or
# None where the keyword stands for nothing on its own.
Tokens = dict[str, "tuple[str | None, ...] | None"]

TOKENS_FINDALL = re.compile(
    r"(\()"  # opening parenthesis
    r"|"  # or
    r"(\))"  # closing parenthesis
    r"|"  # or
    r"([^'$()\s]+)"  # string of length >= 1 without '$() or whitespace
    r"|"  # or
    r"('(?:[^'\\]|\\.)*'(?!\w))"
    # any string or empty string surrounded by unescaped
    # single quotes except if right quote is succeeded by
    # alphanumeric char
    r"|"  # or
    r"([^\s]+?)",  # residue, all non-whitespace strings
).findall

UNESCAPE_PATTERN = re.compile(r"\\(.)")


def split_tokens(s: str) -> list[str]:
    """The elements of a definition, with quotes and spaces stripped."""
    parts = []
    parens = 0
    for opar, cpar, unquoted, quoted, residue in TOKENS_FINDALL(s):
        if unquoted:
            parts.append(unquoted)
        elif quoted:
            parts.append(UNESCAPE_PATTERN.sub(r"\1", quoted[1:-1]))
        elif opar:
            parens += 1
            parts.append(opar)
        elif cpar:
            parens -= 1
            parts.append(cpar)
        elif residue == "$":
            if not parens:
                raise ValueError("'$' outside parenthesis in %r" % (s))
        else:
            raise ValueError(residue, s)
    if parens:
        raise ValueError("Unbalanced parenthesis in %r" % (s))
    return parts


def extract_tokens(
    l: list[str],  # noqa: E741
    known_tokens: Tokens,
) -> Tokens:
    """What each keyword was given, for the keywords asked about.

    ``known_tokens`` says which keywords to look for and what each one is
    worth when the definition does not mention it.
    """
    assert l[0].strip() == "(" and l[-1].strip() == ")", ValueError(l)
    result: Tokens = {}
    result.update(known_tokens)
    i = 0
    l_len = len(l)
    while i < l_len:
        if l[i] not in result:
            i += 1  # Consume unrecognized item
            continue
        token = l[i]
        i += 1  # Consume token
        # A definition ends with a closing parenthesis, which is never a
        # keyword, so there is always something after the one just consumed.
        if l[i] in result:
            # non-valued
            result[token] = ()
        elif l[i] == "(":
            # multi-valued
            i += 1  # Consume left parentheses
            start = i
            while i < l_len and l[i] != ")":
                i += 1
            result[token] = tuple(v for v in l[start:i] if v != "$")
            i += 1  # Consume right parentheses
        else:
            # single-valued
            result[token] = (l[i],)
            i += 1  # Consume single value
    return result
