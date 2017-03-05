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
import os

from pecryptfs.ecryptfs import generate_encrypted_file
from pecryptfs.auth_token import AuthToken


def main():
    parser = argparse.ArgumentParser(description="eCryptfs Encrypted File Generator")
    parser.add_argument('files', metavar='FILE', type=str, nargs='+', help='Filenames to decrypt')
    parser.add_argument('-p', '--password', type=str, default="Test",
                        help='Password to use for decryption, prompt when none given')
    parser.add_argument('-s', '--salt', type=str, default="0011223344556677",
                        help='Salt to use for decryption')
    parser.add_argument('-o', '--output', type=str, help='Output directory')
    parser.add_argument('-c', '--cipher', type=str, help='Cipher to use', default="aes")
    parser.add_argument('-k', '--key-bytes', type=int, help='Key bytes to use', default=24)
    parser.add_argument('-v', '--verbose', action='store_true', help='Be verbose')

    args = parser.parse_args()

    output_directory = args.output

    if not os.path.isdir(output_directory):
        os.makedirs(output_directory)

    cipher = args.cipher
    key_bytes = args.key_bytes

    auth_token = AuthToken(args.password, args.salt)

    for input_filename in args.files:
        filenames = []

        data = generate_encrypted_file(auth_token, cipher, key_bytes)
        output_filename = "{}-{}.raw".format(cipher, key_bytes)
        with open(os.path.join(output_directory, output_filename), "wb") as fout:
            fout.write(data)

        if args.verbose:
            print("Password: {}".format(args.password))
            print("Salt:     {}".format(args.salt))
            print("Filename: {}".format(input_filename))
            print()
            for cipher, key_bytes, f in filenames:
                print("{:8}  {:2}  {}".format(cipher, key_bytes, f))
        else:
            for cipher, key_bytes, f in filenames:
                print(f)


# EOF #
