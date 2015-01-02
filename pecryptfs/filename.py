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


from Crypto.Cipher import AES

from pecryptfs import b2h_short


portable_filename_chars = b"-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

filename_rev_map = bytearray(b"\x00" * 256)
for i, c in enumerate(portable_filename_chars):
    filename_rev_map[c] = i
filename_rev_map = bytes(filename_rev_map)

fnek_marker = b"ECRYPTFS_FNEK_ENCRYPTED."


def decrypt_filename(auth_token, filename):
    if not filename.startswith(fnek_marker):
        # assume unencrypted filename
        return filename
    else:
        data = convert_6bit_to_8bit(filename[len(fnek_marker):])

        assert data[0] == 0x46  # TAG70
        pkg_len = data[1]  # FIXME: this is really a variable length encoding
        block_aligned_filename_size = pkg_len - 8 - 1

        signature = data[2:10]
        if b2h_short(signature) != auth_token.signature:
            raise Exception("signature mismatch, key not suited for filename")

        i = 11

        cipher = AES.new(auth_token.session_key[0:16], AES.MODE_ECB, IV=b"\x00" * 16)
        text = data[i:i + block_aligned_filename_size]
        res = cipher.decrypt(text)
        return res.split(b'\0', 1)[1]


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


# EOF #
