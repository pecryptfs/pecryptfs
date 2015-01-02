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
import struct
from Crypto.Cipher import AES
from pecryptfs import b2h_short


class File:

    MAGIC_ECRYPTFS_MARKER = 0x3c81b7f5

    @staticmethod
    def from_file(filename, auth_token):
        fin = open(filename, "rb")
        efs = File(fin, auth_token)
        return efs

    def __init__(self, fin, auth_token):
        self.fin = fin
        self.auth_token = auth_token

        header = fin.read(8192)
        self.file_size = struct.unpack(">q", header[0:8])[0]
        self.marker1, self.marker2 = struct.unpack(">II", header[8:16])
        self.version = header[16]
        self.reserved = header[17:19]
        self.flags = header[19]
        self.header_extent_size = struct.unpack(">i", header[20:24])[0]
        self.header_extent_count = struct.unpack(">h", header[24:26])[0]
        self.rfc2440 = header[24:8192]

        # rfc2440 Tag3/Tag11
        self.salt = header[32:32+8]
        self.hash_iterations = header[32+8]
        self.encrypted_key = header[41:41+16]

        # check that the file is a proper eCryptfs file
        if self.marker1 != self.marker2 ^ File.MAGIC_ECRYPTFS_MARKER:
            raise Exception("marker missmatch, not a eCryptfs encrypted file")

        if self.salt != self.auth_token.salt:
            raise Exception("salt of file and auth_token missmatch")

        # calculate keys
        cipher = AES.new(self.auth_token.session_key[0:16], AES.MODE_CBC, IV=b"\x00" * 16)
        self.key = cipher.decrypt(self.encrypted_key)

        self.root_iv = hashlib.md5(self.key).digest()

    def close(self):
        self.fin.close()

    def read(self):
        page = 0
        byte_count = 0
        result = b""

        while True:
            data = self.fin.read(4096)
            if data == b"":
                break
            byte_count += len(data)

            if byte_count > self.file_size:
                actual_block_size = 4096 - (byte_count - self.file_size)
            else:
                actual_block_size = 4096

            derived_iv = hashlib.md5(self.root_iv + struct.pack("<Q", 0x30 + page) + b"\x00" * 8).digest()

            decryptor = AES.new(self.key, AES.MODE_CBC, IV=derived_iv)
            output = decryptor.decrypt(data)

            result += output[0:actual_block_size]
            page += 1

        return result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


# EOF #
