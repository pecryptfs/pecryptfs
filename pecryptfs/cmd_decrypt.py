#!/usr/bin/env python3

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


import argparse
import getpass
import sys

import pecryptfs
from pecryptfs import b2h


def main() -> None:
    parser = argparse.ArgumentParser(description="eCryptfs file decrypter")
    parser.add_argument('files', metavar='FILE', type=str, nargs='+', help='Files to extract')
    auth_group = parser.add_argument_group("Authentication / Cipher")
    auth_group.add_argument('-p', '--password', type=str,
                            help=('Password to use for decryption, prompt when none given. '
                                  'This is the one used in ".ecryptfs/wrapped-passphrase", '
                                  'which can be recovered with "ecryptfs-unwrap-passphrase '
                                  '.ecryptfs/wrapped-passphrase"'))
    auth_group.add_argument('-s', '--salt', type=str, help='Salt to use for decryption', default="0011223344556677")
    auth_group.add_argument('-c', '--cipher', type=str, help='Cipher to use for encryption', default="aes")
    auth_group.add_argument('-k', '--key-bytes', metavar='BYTES', type=int, default=16,
                            help='Number of bytes in the encryption key')
    parser.add_argument('-i', '--info', action="store_true", help="Print info about the file")
    args = parser.parse_args()

    if args.password is None:
        password = getpass.getpass()
    else:
        password = args.password

    auth_token = pecryptfs.AuthToken(password, args.salt)

    for filename in args.files:
        if args.info:
            with pecryptfs.File.from_file(filename, auth_token, args.cipher, key_bytes=args.key_bytes) as efin:
                print("session key:", b2h(auth_token.session_key[0:16]))
                print("            ", b2h(auth_token.session_key[16:16+16]))
                print("            ", b2h(auth_token.session_key[32:32+16]))
                print("            ", b2h(auth_token.session_key[48:48+16]))
                print("signature:", auth_token.signature_text)
        else:
            with pecryptfs.File.from_file(filename, auth_token, args.cipher, args.key_bytes) as efin:
                sys.stdout.buffer.write(efin.read())  # pylint: disable=no-member


# EOF #
