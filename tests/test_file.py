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


import os
import unittest

import pecryptfs.file
from pecryptfs.auth_token import AuthToken


DATADIR = os.path.join(os.path.dirname(__file__), 'data')


class TestFilename(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_file_read(self):
        auth_token = AuthToken('Test')

        ciphers = [
            ('aes', 16),
            # ('aes', 24),
            ('aes', 32),
            ('blowfish', 32)
        ]

        for cipher, key_bytes in ciphers:
            try:
                with pecryptfs.file.File.from_file(os.path.join(DATADIR, '{}-{}.raw'.format(cipher, key_bytes)),
                                                   auth_token, cipher, key_bytes) as fin:
                    content = fin.read()
                self.assertEqual(content, b'Hello World\n')
            except:
                print("failure in {} {}".format(cipher, key_bytes))
                raise


if __name__ == "__main__":
    unittest.main()


# EOF #
