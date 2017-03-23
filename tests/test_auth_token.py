#!/usr/bin/python3

# pecryptfs - Portable Userspace eCryptfs
# Copyright (C) 2015 Ingo Ruhnke <grumbel@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import unittest
from pecryptfs import AuthToken


class TestAuthToken(unittest.TestCase):

    def setUp(self):
        self.auth_token = AuthToken(b"Password")

    def tearDown(self):
        pass

    def test_signature(self):
        self.assertEqual(self.auth_token.signature_text, "326bd307c877876f")

    def test_session_key(self):
        self.assertEqual(self.auth_token.session_key,
                         (b"m\x161\x12\xbb_\xa3\xa4\x99\x02T\x8e\xd6\xdcS*{:]k7\x1e+7+\xa4\xa8\x98\xf9)\x10\xd6!\xab"
                          b"\xe1G[\x1d\xf1Uq\xd24V\xf3c\xed\xaf\xc6\xaf\x96N\x9e\x96y\xe3\x92\xe9\xcc>\x9aD\x9fq"))


if __name__ == "__main__":
    unittest.main()


# EOF #
