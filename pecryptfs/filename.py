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


filename_rev_map = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
    0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22,
    0x23, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
    0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    0x3D, 0x3E, 0x3F  # 123 - 255 initialized to 0x00
]


fnek_marker = b"ECRYPTFS_FNEK_ENCRYPTED."


def decrypt_filename(auth_token, filename):
    if not filename.startswith(fnek_marker):
        # assume unencrypted filename
        return filename
    else:
        data = convert_6bit_to_8bit(filename[len(fnek_marker):])

        assert data[0] == 0x46  # TAG70
        pkg_len = data[1]  # FIXME: this is really a variable length encoding
        blkfilename_len = pkg_len - 8 - 1

        signature = data[2:10]
        if b2h_short(signature) != auth_token.signature:
            raise Exception("signature mismatch, key not suited for filename")

        i = 11

        cipher = AES.new(auth_token.session_key[0:16], AES.MODE_ECB, IV=b"\x00" * 16)
        text = data[i:i+blkfilename_len]
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
