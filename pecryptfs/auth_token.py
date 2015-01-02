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


import hashlib

from pecryptfs import b2h_short


class AuthToken:

    def __init__(self, password, salt=b"\x00\x11\x22\x33\x44\x55\x66\x77", hash_iterations=65536):
        self.password = password
        self.salt = salt

        self.session_key = self.salt + self.password
        for _ in range(hash_iterations):
            self.session_key = hashlib.sha512(self.session_key).digest()

        self.signature = b2h_short(hashlib.sha512(self.session_key).digest()[0:8])


# EOF #
