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
from pecryptfs import AuthToken, decrypt_filename


class TestFilename(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_decrypt_filename(self):
        # decrypt the filename
        enc_filename = b"ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoDzbVOSbBh3ttRUURq5F-zE--"
        right_auth_token = AuthToken(b"Test")
        self.assertEqual(decrypt_filename(right_auth_token, enc_filename), b"TestFile")

        # passthrough of unencrypted filename
        self.assertEqual(decrypt_filename(right_auth_token, b"TestFile"), b"TestFile")

    def test_incorrect_key(self):
        enc_filename = b"ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoDzbVOSbBh3ttRUURq5F-zE--"

        right_auth_token = AuthToken(b"Test")
        self.assertEqual(decrypt_filename(right_auth_token, enc_filename), b"TestFile")

        wrong_auth_token = AuthToken(b"Password")
        with self.assertRaises(Exception):
            decrypt_filename(wrong_auth_token, enc_filename)


if __name__ == "__main__":
    unittest.main()


# EOF #
