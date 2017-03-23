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
import hashlib
from Crypto.Cipher import AES, Blowfish, DES3

from pecryptfs.auth_token import AuthToken

from pecryptfs.define import (
    ECRYPTFS_TAG_70_PACKET_TYPE,
    ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX,
    ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE,
    RFC2440_CIPHER_AES_128,
    RFC2440_CIPHER_AES_192,
    RFC2440_CIPHER_AES_256,
    RFC2440_CIPHER_BLOWFISH,
    RFC2440_CIPHER_DES3_EDE)


PORTABLE_FILENAME_CHARS = b"-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def build_filename_rev_map():
    rev_map = bytearray(b"\x00" * 256)
    for i, c in enumerate(PORTABLE_FILENAME_CHARS):
        rev_map[c] = i
    return bytes(rev_map)


FILENAME_REV_MAP = build_filename_rev_map()


def make_cipher(auth_token, tag, key_bytes):
    if tag == RFC2440_CIPHER_AES_128:
        return AES.new(auth_token.session_key[0:16], AES.MODE_ECB)
    elif tag == RFC2440_CIPHER_AES_192:
        return AES.new(auth_token.session_key[0:24], AES.MODE_ECB)
    elif tag == RFC2440_CIPHER_AES_256:
        return AES.new(auth_token.session_key[0:32], AES.MODE_ECB)
    elif tag == RFC2440_CIPHER_BLOWFISH:
        return Blowfish.new(auth_token.session_key[0:key_bytes], Blowfish.MODE_ECB)
    elif tag == RFC2440_CIPHER_DES3_EDE:
        return DES3.new(auth_token.session_key[0:24], DES3.MODE_ECB)
    else:
        # RFC2440_CIPHER_CAST_5 = 0x03
        # RFC2440_CIPHER_TWOFISH = 0x0a
        # RFC2440_CIPHER_CAST_6 = 0x0b
        # RFC2440_CIPHER_RSA = 0x01
        raise Exception("unknown cipher tag: {}".format(tag))


def make_cipher_from_desc(auth_token, cipher, key_bytes):
    if cipher == "aes" and key_bytes == 16:
        return AES.new(auth_token.session_key[0:16], AES.MODE_ECB)
    elif cipher == "aes" and key_bytes == 24:
        return AES.new(auth_token.session_key[0:24], AES.MODE_ECB)
    elif cipher == "aes" and key_bytes == 32:
        return AES.new(auth_token.session_key[0:32], AES.MODE_ECB)
    elif cipher == "blowfish":
        return Blowfish.new(auth_token.session_key[0:key_bytes], Blowfish.MODE_ECB)
    elif cipher == "des3":
        return DES3.new(auth_token.session_key[0:24], DES3.MODE_ECB)
    else:
        # RFC2440_CIPHER_CAST_5 = 0x03
        # RFC2440_CIPHER_TWOFISH = 0x0a
        # RFC2440_CIPHER_CAST_6 = 0x0b
        # RFC2440_CIPHER_RSA = 0x01
        raise Exception("unknown cipher: {}:{}".format(cipher, key_bytes))


def get_cipher_tag(cipher: str, key_bytes: int):
    if cipher == "des3":
        return RFC2440_CIPHER_DES3_EDE
    # elif cipher == "cast5":
    #     return RFC2440_CIPHER_CAST_5
    elif cipher == "blowfish":
        return RFC2440_CIPHER_BLOWFISH
    elif cipher == "aes" and key_bytes == 16:
        return RFC2440_CIPHER_AES_128
    elif cipher == "aes" and key_bytes == 24:
        return RFC2440_CIPHER_AES_192
    elif cipher == "aes" and key_bytes == 32:
        return RFC2440_CIPHER_AES_256
    # elif cipher == "twofish":
    #     return RFC2440_CIPHER_TWOFISH
    # elif cipher == "cast6":
    #     RFC2440_CIPHER_CAST_6
    else:
        raise Exception("unknown cipher '{}:{}'".format(cipher, key_bytes))


def decrypt_filename(enc_filename: str, auth_token: AuthToken, key_bytes=None) -> str:
    enc_filename = os.fsdecode(enc_filename)  # type: str

    if not enc_filename.startswith(ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX):
        # assume unencrypted filename
        return enc_filename
    else:
        data = convert_6bit_to_8bit(enc_filename[ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE:])

        assert data[0] == ECRYPTFS_TAG_70_PACKET_TYPE
        pkg_len = data[1]  # FIXME: this is really a variable length encoding
        block_aligned_filename_size = pkg_len - 8 - 1

        signature = data[2:10]
        if signature.hex() != auth_token.signature_text:
            raise Exception("signature mismatch, key not suited for filename")

        cipher = make_cipher(auth_token, data[10], key_bytes)

        text = data[11:11 + block_aligned_filename_size]
        res = cipher.decrypt(text)

        try:
            _, filename = res.rsplit(b'\0', 1)
        except ValueError as err:
            print()
            print("error: failure to split: '{}'".format(res))
            print("  input:", enc_filename)
            raise

        result = filename.rstrip(b'\x00')

        return os.fsdecode(result)


def round_to_multiple_of(n, base):
    return (n + base - 1) // base * base


def generate_filename_prefix(auth_token: AuthToken, filename) -> bytes:
    """Used as prefix padding for blockaligned encrypted filename
    see ecryptfs/keystore.c:ecryptfs_write_tag_70_packet()"""

    block_aligned_filename_len = max(32,
                                     round_to_multiple_of(16 + 1 + len(filename), 16))
    prefix_len = block_aligned_filename_len - len(filename) - 1

    prefix = hashlib.md5(auth_token.session_key).digest()
    while len(prefix) < prefix_len:
        prefix += hashlib.md5(prefix).digest()

    return prefix[0:prefix_len]


def generate_filename_suffix(padded_filename) -> bytes:
    # No idea yet how this padding is calculated, but this ugly hack
    # will do for now.
    if len(padded_filename) == 32:
        return b"\x00\x00"
    elif len(padded_filename) == 48:
        return b"\x00"
    elif len(padded_filename) == 64:
        return b""
    elif len(padded_filename) == 80:
        return b"\x00\x00"
    elif len(padded_filename) == 96:
        return b"\x00"
    elif len(padded_filename) == 112:
        return b""
    elif len(padded_filename) == 128:
        return b"\x00\x00"
    elif len(padded_filename) == 144:
        return b"\x00"
    elif len(padded_filename) == 160:
        return b""
    else:
        raise Exception("filename to long")


def encrypt_filename(filename: str, auth_token: AuthToken, cipher_desc="aes", key_bytes=24) -> str:
    filename = os.fsencode(filename)  # type: bytes

    cipher = make_cipher_from_desc(auth_token, cipher_desc, key_bytes)

    prefix_padding = generate_filename_prefix(auth_token, filename)

    junked_filename = prefix_padding + b"\x00" + filename

    padding_length = (((len(junked_filename) - 1) // 16) + 1) * 16 - len(junked_filename)
    padded_filename = junked_filename + b'\x00' * padding_length
    res = cipher.encrypt(padded_filename)

    payload = (bytes([ECRYPTFS_TAG_70_PACKET_TYPE, len(padded_filename) + 9]) +
               bytes.fromhex(auth_token.signature_text) +
               bytes([get_cipher_tag(cipher_desc, key_bytes)]) +
               res +
               generate_filename_suffix(padded_filename))

    result = "ECRYPTFS_FNEK_ENCRYPTED." + convert_8bit_to_6bit(payload)

    return result


def convert_6bit_to_8bit(data_6bit: str) -> bytes:
    """Convert a 6bit encoded string into a byte sequence"""
    result = []
    bit_offset = 0
    for c in data_6bit:
        src_byte = FILENAME_REV_MAP[ord(c)]

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


def convert_8bit_to_6bit(data_8bit: bytes) -> str:
    """Convert a byte sequence into a 6bit encoded string"""
    result = bytearray()
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

    for i in range(len(result)):
        result[i] = PORTABLE_FILENAME_CHARS[result[i]]

    return result.decode("utf-8")


# EOF #
