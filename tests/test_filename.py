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
        auth_token = AuthToken("Test")
        filenames = ["HelloWorld",
                     "a",
                     "\x01",
                     "1" * 143]

        for filename in filenames:
            encrypted_filename = encrypt_filename(filename, auth_token)
            decrypted_filename = decrypt_filename(encrypted_filename, auth_token)
            self.assertEqual(filename, decrypted_filename)

    def test_encrypt_filename(self):
        enc_filename = "ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-UP0Bp5ZhSV8z0l0qmRIVPgjmpEsGWRgxIcl0sTzLZcs---"
        filename = "TestFile"
        auth_token = AuthToken("Test")

        self.assertEqual(encrypt_filename(filename, auth_token),
                         enc_filename)

    def test_decrypt_filename(self):
        # decrypt the filename
        auth_token = AuthToken("Test")

        # Password: Test
        # Salt:     0011223344556677
        # Filename: TestFile
        # -------------------------------------------------------------------------------------------------
        data = [
            ('aes', 16, "ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoDzbVOSbBh3ttRUURq5F-zE--"),
            ('aes', 32, "ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-aK6fArd1FkXCt3ijqL6Arsiu3IFxKKhksWZXxt2HR.i---"),
            ('aes', 24, "ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-UP0Bp5ZhSV8z0l0qmRIVPgjmpEsGWRgxIcl0sTzLZcs---"),
            ('blowfish', 16, "ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-Fi4vCFunEkpmguVPgTV8O7OCI7gcIM0RzNtZOMT.ad8k--"),
            ('blowfish', 32, "ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-Gcj-1XYP8.88HiL.Iqo1dD0FdJ43mOKINZrz4jr23Alk--"),
            ('blowfish', 56, "ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-ENJPazcrf3HQ7pWVxijnxeY.TJuf5cmIawdVooB35qhU--"),
            ('des3_ede', 24, "ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-7SUzZ0hbmbz5nk3WMwv4ZjYta1MzcS0Zfdls0zMhkKmk--"),
        ]
        # twofish  16  ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-dxaIZlhnn0IL1A0yGabE.2NzWC-quHTGlvm8pmEKMfbk--
        # twofish  32  ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-fYL1xMpMmdFjqaJi9sIgj8dZ-JCGwSNy1z0jeaA3Xa0U--
        # cast6    16  ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-iVruuRcV5MVN0bTnYT8x7OmVQPutg9Nd8wzTUkDI3Y4E--
        # cast6    32  ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-hXoa6jmmm7G6ncyvOwfrhKvnaTxcFRZZA2T8r6pirQ.---
        # cast5    16  ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-CmuNOpVG2GsCd8MdmEh7ndp5ixhBAtzsKYxq46G0BYH---

        for cipher, key_bytes, enc_filename in data:
            self.assertEqual(decrypt_filename(enc_filename, auth_token, key_bytes=key_bytes), "TestFile")

        # passthrough of unencrypted filename
        self.assertEqual(decrypt_filename("TestFile", auth_token), "TestFile")

    def test_incorrect_key(self):
        enc_filename = "ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoDzbVOSbBh3ttRUURq5F-zE--"

        right_auth_token = AuthToken("Test")
        self.assertEqual(decrypt_filename(enc_filename, right_auth_token), "TestFile")

        wrong_auth_token = AuthToken("Password")
        with self.assertRaises(Exception):
            decrypt_filename(enc_filename, wrong_auth_token)

    def test_convert_8bit_to_6bit(self):
        text = "FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoDzbVOSbBh3ttRUURq5F-zE--"
        result = (b"F)5\x15\xcc\xa9\xba\xae\xa1\xf4\x07je\x82\xc5\xa1\x15m\x97'\x16\x9c\xb7\x81'\xdf"
                  b"\xb4?\xf9\xe1i\xe9\xcd\xb4^yv\x08\x1d\xd8t@\xfd\x00\x00")
        self.assertEqual(convert_6bit_to_8bit(text), result)
        self.assertEqual(text, convert_8bit_to_6bit(convert_6bit_to_8bit(text)))

    def test_convert_6bit_to_8bit(self):
        text = (b"F)5\x15\xcc\xa9\xba\xae\xa1\xf4\x07je\x82\xc5\xa1\x15m\x97'\x16\x9c\xb7\x81'\xdf"
                b"\xb4?\xf9\xe1i\xe9\xcd\xb4^yv\x08\x1d\xd8t@\xfd\x00\x00")
        result = "FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoDzbVOSbBh3ttRUURq5F-zE--"
        self.assertEqual(result, convert_8bit_to_6bit(text))
        self.assertEqual(text, convert_6bit_to_8bit(convert_8bit_to_6bit(text)))


if __name__ == "__main__":
    unittest.main()


# EOF #
