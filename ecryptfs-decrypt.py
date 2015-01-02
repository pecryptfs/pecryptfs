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


import sys
import argparse
import getpass

import pecryptfs
from pecryptfs import b2h


def main():
    parser = argparse.ArgumentParser(description="eCryptfs file decrypter")
    parser.add_argument('files', metavar='FILE', type=str, nargs='+', help='Files to extract')
    parser.add_argument('-p', '--password', type=str, help='Password to use for decryption, prompt when none given')
    parser.add_argument('-s', '--salt', type=str, help='Salt to use for decryption', default="0011223344556677")
    parser.add_argument('-i', '--info', action="store_true", help="Print info about the file")
    args = parser.parse_args()

    if args.password is None:
        password = getpass.getpass().encode()
    else:
        password = args.password.encode()

    salt = bytearray.fromhex(args.salt)

    auth_token = pecryptfs.AuthToken(password, salt)

    for filename in args.files:
        if args.info:
            with pecryptfs.File.from_file(filename, password) as efin:
                print("session key:", b2h(efin.session_key[0:16]))
                print("            ", b2h(efin.session_key[16:16+16]))
                print("            ", b2h(efin.session_key[32:32+16]))
                print("            ", b2h(efin.session_key[48:48+16]))
                print("signature:", efin.signature)
        else:
            with pecryptfs.File.from_file(filename, auth_token) as efin:
                sys.stdout.buffer.write(efin.read())


if __name__ == "__main__":
    main()


# EOF #
