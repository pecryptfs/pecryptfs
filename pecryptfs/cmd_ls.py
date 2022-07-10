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
import os

import pecryptfs


def main() -> None:
    parser = argparse.ArgumentParser(description="eCryptfs ls")
    parser.add_argument('files', metavar='FILE', type=str, nargs='+', help='Filenames to decrypt')
    parser.add_argument('-p', '--password', type=str, help='Password to use for decryption, prompt when none given')
    parser.add_argument('-s', '--salt', type=str, help='Salt to use for decryption', default="0011223344556677")
    parser.add_argument('-d', '--directory', action='store_true', help='List content of directory')
    args = parser.parse_args()

    if args.password is None:
        password = getpass.getpass()
    else:
        password = args.password

    auth_token = pecryptfs.AuthToken(password, args.salt)

    if args.directory:
        for directory in args.files:
            for filename in os.listdir(directory):
                real_filename = pecryptfs.decrypt_filename(filename, auth_token)
                print("{} -> {}".format(real_filename, filename))
    else:
        for filename in args.files:
            real_filename = pecryptfs.decrypt_filename(filename, auth_token)
            print("{} -> {}".format(real_filename, filename))


# EOF #
