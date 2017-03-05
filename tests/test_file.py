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


AES16_DATA_FILENAME = os.path.join(os.path.dirname(__file__), 'data/aes-16.raw')


class TestFilename(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_file_read(self):
        auth_token = AuthToken('Test')
        with pecryptfs.file.File.from_file(AES16_DATA_FILENAME, auth_token, 'aes', 16) as fin:
            content = fin.read()
        self.assertEqual(content, b'Hello World\n')


if __name__ == "__main__":
    unittest.main()


# EOF #
