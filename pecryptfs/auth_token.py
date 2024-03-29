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


from typing import Optional

import hashlib
import os


class AuthToken:

    def __init__(self, password: str, salt: str = "0011223344556677") -> None:
        self.password_text: str = password
        self.password_bin: bytes = os.fsencode(password)

        self.salt_text: str = salt
        self.salt_bin: bytes = bytes.fromhex(salt)

        self._session_key: Optional[bytes] = None
        self._signature: Optional[str] = None

    @property
    def session_key(self) -> bytes:
        if self._session_key is None:
            hash_iterations = 65536

            tmp_key: bytes = self.salt_bin + self.password_bin
            for _ in range(hash_iterations):
                tmp_key = hashlib.sha512(tmp_key).digest()
            self._session_key = tmp_key

        return self._session_key

    @property
    def signature_text(self) -> str:
        if self._signature is None:
            self._signature = hashlib.sha512(self.session_key).digest()[0:8].hex()
        return self._signature


# EOF #
