"""Vendored pure-Python MD4 and DES, taken from passlib 1.7.4.

anyldap needs these two primitives for the NT and LM password hashes, and
neither is reliably available from the standard library: OpenSSL 3 moved MD4
and DES into its legacy provider, which is disabled by default, so
``hashlib.new("md4")`` raises on most current systems.

Rather than depend on passlib as a whole -- unreleased since 2020, and it
imports the ``crypt`` module that Python 3.13 removed -- the two modules are
vendored here. Their Python 2 compatibility shims are dropped, and they are
otherwise formatted by this project's linters rather than kept byte-identical
to upstream. passlib's own tests for them are vendored alongside, as
test/test_vendored_des.py and test_vendored_md4.py.

See LICENSE in this directory for the passlib copyright notice, and for the
separate notice covering the DES routines that passlib itself derived from
Aki Yoshida's UnixCrypt.java.
"""
