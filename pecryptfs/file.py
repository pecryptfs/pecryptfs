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


from typing import Any, IO, Optional, Type
from types import TracebackType

import hashlib
import struct
from Crypto.Cipher import AES, Blowfish, DES3

from pecryptfs.auth_token import AuthToken
from pecryptfs.define import MAGIC_ECRYPTFS_MARKER
from pecryptfs.filename import make_cipher_from_desc


Cipher = Any


def make_cipher_from_desc2(key: bytes, cipher: str, key_bytes: int, iv: bytes) -> Cipher:
    if cipher == "aes" and key_bytes == 16:
        return AES.new(key[0:16], AES.MODE_CBC, iv)
    elif cipher == "aes" and key_bytes == 24:
        return AES.new(key[0:24], AES.MODE_CBC, iv)
    elif cipher == "aes" and key_bytes == 32:
        return AES.new(key[0:32], AES.MODE_CBC, iv)
    elif cipher == "blowfish":
        return Blowfish.new(key[0:key_bytes], Blowfish.MODE_CBC, iv[:8])
    elif cipher == "des3":
        return DES3.new(key[0:24], DES3.MODE_CBC, iv)
    else:
        # RFC2440_CIPHER_CAST_5 = 0x03
        # RFC2440_CIPHER_TWOFISH = 0x0a
        # RFC2440_CIPHER_CAST_6 = 0x0b
        # RFC2440_CIPHER_RSA = 0x01
        raise Exception("unknown cipher: {}:{}".format(cipher, key_bytes))


class File:

    @staticmethod
    def from_file(filename: str, auth_token: AuthToken, cipher: str, key_bytes: int) -> 'File':
        fin = open(filename, "rb")  # pylint: disable=consider-using-with
        efs = File(fin, auth_token, cipher, key_bytes)
        return efs

    def __init__(self, fin: IO[bytes], auth_token: AuthToken, cipher: str, key_bytes: int) -> None:
        self.fin = fin
        self.auth_token = auth_token
        self.cipher = cipher
        self.key_bytes = key_bytes

        # see ecryptfs_write_headers_virt

        header = fin.read(8192)
        self.file_size = struct.unpack(">q", header[0:8])[0]
        self.marker1, self.marker2 = struct.unpack(">II", header[8:16])
        self.version = header[16]
        self.reserved = header[17:19]
        self.flags = header[19]

        self.header_extent_size = struct.unpack(">i", header[20:24])[0]
        self.header_extent_count = struct.unpack(">h", header[24:26])[0]
        assert self.header_extent_size == 4096
        assert self.header_extent_count == 2

        self.rfc2440 = header[24:8192]

        # rfc2440 Tag3/Tag11
        self.salt = header[32:32 + 8]
        self.hash_iterations = header[32 + 8]
        self.encrypted_key = header[41:41 + self.key_bytes]
        # b'\xed\x16b\x08_CONSOLE\x00' follows

        # print("16:", header[41+16:41+16+13])
        # print("32:", header[41+32:41+32+13])
        # print("56:", header[41+56:41+56+13])

        # check that the file is a proper eCryptfs file
        if self.marker1 != self.marker2 ^ MAGIC_ECRYPTFS_MARKER:
            raise Exception("marker missmatch, not a eCryptfs encrypted file")

        if self.salt != self.auth_token.salt_bin:
            raise Exception("salt of file and auth_token missmatch")

        # calculate keys
        # cipher = AES.new(self.auth_token.session_key[0:key_bytes], AES.MODE_ECB)
        cipher_proc: Cipher = make_cipher_from_desc(self.auth_token, cipher, key_bytes)

        self.key = cipher_proc.decrypt(self.encrypted_key)
        # print("\nLEN:", len(self.key))
        self.root_iv = hashlib.md5(self.key).digest()

    def close(self) -> None:
        self.fin.close()

    def read(self) -> bytes:
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

            # decryptor = AES.new(self.key, AES.MODE_CBC, IV=derived_iv)
            decryptor = make_cipher_from_desc2(self.key, self.cipher, self.key_bytes, derived_iv)
            output = decryptor.decrypt(data)

            result += output[0:actual_block_size]
            page += 1

        return result

    def __enter__(self) -> 'File':
        return self

    def __exit__(self,  # pylint: disable=useless-return
                 exc_type: Optional[Type[BaseException]],
                 exc_value: Optional[BaseException],
                 traceback: Optional[TracebackType]) -> Optional[bool]:
        self.close()
        return None


# EOF #
