"""Vendored from passlib 1.7.4's passlib/tests/test_crypto_builtin_md4.py.

Adapted to pytest and Python 3; the test vectors and the checks they make
are passlib's.

Copyright (c) 2008-2020 Assurance Technologies, LLC.
Released under the BSD 3-Clause License. The full text, including the
conditions and the disclaimer that must be retained, is in
anyldap/samba/_passlib/LICENSE.

The backend-selection machinery is dropped: anyldap always uses the vendored
pure-Python implementation, because OpenSSL 3 keeps MD4 in its legacy
provider and ``hashlib.new("md4")`` therefore fails on most systems.
"""

from binascii import hexlify

import pytest

from anyldap.samba._passlib._md4 import md4


class TestMD4:
    vectors = [
        # input -> hex digest
        # test vectors from http://www.faqs.org/rfcs/rfc1320.html - A.5
        (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            b"1234567890123456789012345678901234567890"
            b"1234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ]

    def test_attrs(self):
        """informational attributes"""
        h = md4()
        assert h.name == "md4"
        assert h.digest_size == 16
        assert h.block_size == 64

    def test_md4_update(self):
        """update() method"""
        h = md4(b"")
        assert h.hexdigest() == "31d6cfe0d16ae931b73c59d7e0c089c0"

        h.update(b"a")
        assert h.hexdigest() == "bde52cb31de33e46245e05fbdbd6fb24"

        h.update(b"bcdefghijklmnopqrstuvwxyz")
        assert h.hexdigest() == "d79e1c308aa5bbcdeea8ed63df412da9"

        # reject unicode, hash should return digest of b''
        h = md4()
        with pytest.raises(TypeError):
            h.update("a")
        assert h.hexdigest() == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_md4_hexdigest(self):
        """hexdigest() method"""
        for input, hex in self.vectors:
            assert md4(input).hexdigest() == hex

    def test_md4_digest(self):
        """digest() method"""
        for input, hex in self.vectors:
            assert hexlify(md4(input).digest()).decode("ascii") == hex

    def test_md4_copy(self):
        """copy() method"""
        h = md4(b"abc")

        h2 = h.copy()
        h2.update(b"def")
        assert h2.hexdigest() == "804e7f1c2586e50b49ac65db5b645131"

        h.update(b"ghi")
        assert h.hexdigest() == "c5225580bfe176f6deeee33dee98732c"
