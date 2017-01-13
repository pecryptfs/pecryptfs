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


import random
import binascii
from Crypto.Cipher import AES

from pecryptfs.define import (
    ECRYPTFS_TAG_70_PACKET_TYPE,
    ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX)


portable_filename_chars = b"-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

filename_rev_map = bytearray(b"\x00" * 256)
for i, c in enumerate(portable_filename_chars):
    filename_rev_map[c] = i
filename_rev_map = bytes(filename_rev_map)


def decrypt_filename(auth_token, enc_filename):
    if not enc_filename.startswith(ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX):
        # assume unencrypted filename
        return enc_filename
    else:
        data = convert_6bit_to_8bit(enc_filename[len(ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX):])

        assert data[0] == ECRYPTFS_TAG_70_PACKET_TYPE
        pkg_len = data[1]  # FIXME: this is really a variable length encoding
        block_aligned_filename_size = pkg_len - 8 - 1

        signature = data[2:10]
        if binascii.hexlify(signature) != auth_token.signature:
            raise Exception("signature mismatch, key not suited for filename")

        i = 11

        cipher = AES.new(auth_token.session_key[0:16], AES.MODE_ECB, IV=b"\x00" * 16)
        text = data[i:i + block_aligned_filename_size]
        res = cipher.decrypt(text)
        junk, filename = res.split(b'\0', 1)
        return filename.rstrip(b'\x00')


def encrypt_filename(auth_token, filename, junk=None):
    cipher = AES.new(auth_token.session_key[0:16], AES.MODE_ECB, IV=b"\x00" * 16)

    sys_rnd = random.SystemRandom()
    if junk is None:
        junk = bytes(list((sys_rnd.randint(1, 255) for _ in range(16))))

    # filenames are padded with random \0 terminated junk in the front
    junked_filename = junk + b"\x00" + filename

    padding_length = (((len(junked_filename) - 1) // 16) + 1) * 16 - len(junked_filename)
    padded_filename = junked_filename + b'\x00' * padding_length
    res = cipher.encrypt(padded_filename)

    return (b"ECRYPTFS_FNEK_ENCRYPTED." +
            convert_8bit_to_6bit(
                bytes([ECRYPTFS_TAG_70_PACKET_TYPE, len(padded_filename) + 9]) +
                binascii.unhexlify(auth_token.signature) +
                b"\x07" +
                res +
                b"\x00\x00"
                ))


def convert_6bit_to_8bit(data_6bit):
    result = []
    bit_offset = 0
    for c in data_6bit:
        src_byte = filename_rev_map[c]

        if bit_offset == 0:
            result.append((src_byte << 2) & 0xff)
            bit_offset = 6

        elif bit_offset == 6:
            result[-1] |= (src_byte >> 4)
            result.append(((src_byte & 0xF) << 4) & 0xff)
            bit_offset = 4

        elif bit_offset == 4:
            result[-1] |= (src_byte >> 2)
            result.append((src_byte << 6) & 0xff)
            bit_offset = 2

        elif bit_offset == 2:
            result[-1] |= src_byte
            bit_offset = 0

    return bytes(result)


def convert_8bit_to_6bit(data_8bit):
    result = []
    bit_offset = 0
    for c in data_8bit:
        if bit_offset == 0:
            result.append((c & 0b11111100) >> 2)
            result.append((c & 0b00000011) << 4)
            bit_offset = 2

        elif bit_offset == 2:
            result[-1] |= (c & 0b11110000) >> 4
            result.append((c & 0b00001111) << 2)
            bit_offset = 4

        elif bit_offset == 4:
            result[-1] |= (c & 0b11000000) >> 6
            result.append((c & 0b00111111))
            bit_offset = 0

    result = [portable_filename_chars[c] for c in result]

    return bytes(result)


# EOF #
