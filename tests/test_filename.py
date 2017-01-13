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
from pecryptfs import AuthToken, decrypt_filename, encrypt_filename
from pecryptfs.filename import convert_6bit_to_8bit, convert_8bit_to_6bit


class TestFilename(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_roundtrip_filename(self):
        auth_token = AuthToken(b"Test")
        filenames = [b"HelloWorld",
                     b"a",
                     b"\x01",
                     b"ReallyLongFilename" * 12]

        for filename in filenames:
            self.assertEqual(filename,
                             decrypt_filename(
                                 auth_token,
                                 encrypt_filename(auth_token, filename)))

    def test_encrypt_filename(self):
        enc_filename = b"ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoDzbVOSbBh3ttRUURq5F-zE--"
        filename = b"TestFile"
        auth_token = AuthToken(b"Test")

        self.assertEqual(encrypt_filename(auth_token, filename,
                                          junk=b'2s)\x84O&+iZ\x83\xa5\xd0A\t\xe3\x81Q\xfb\x13fB\x96\xb4'),
                         enc_filename)

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

    def test_convert_8bit_to_6bit(self):
        text = b"FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoDzbVOSbBh3ttRUURq5F-zE--"
        result = (b"F)5\x15\xcc\xa9\xba\xae\xa1\xf4\x07je\x82\xc5\xa1\x15m\x97'\x16\x9c\xb7\x81'\xdf"
                  b"\xb4?\xf9\xe1i\xe9\xcd\xb4^yv\x08\x1d\xd8t@\xfd\x00\x00")
        self.assertEqual(convert_6bit_to_8bit(text), result)
        self.assertEqual(text, convert_8bit_to_6bit(convert_6bit_to_8bit(text)))

    def test_convert_6bit_to_8bit(self):
        text = (b"F)5\x15\xcc\xa9\xba\xae\xa1\xf4\x07je\x82\xc5\xa1\x15m\x97'\x16\x9c\xb7\x81'\xdf"
                b"\xb4?\xf9\xe1i\xe9\xcd\xb4^yv\x08\x1d\xd8t@\xfd\x00\x00")
        result = b"FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoDzbVOSbBh3ttRUURq5F-zE--"
        self.assertEqual(result, convert_8bit_to_6bit(text))
        self.assertEqual(text, convert_6bit_to_8bit(convert_8bit_to_6bit(text)))


if __name__ == "__main__":
    unittest.main()


# EOF #
