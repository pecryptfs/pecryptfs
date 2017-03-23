#!/usr/bin/env python3

# pecryptfs - Portable Userspace eCryptfs
# Copyright (C) 2017 Ingo Ruhnke <grumbel@gmail.com>
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
import io

import pecryptfs


def parse_args():
    parser = argparse.ArgumentParser(description="Generate hex signature from password")
    parser.add_argument('-v', '--verbose', action='store_true', help='Be more verbose')

    auth_group = parser.add_argument_group("Authentication / Cipher")
    auth_group.add_argument('-p', '--password', type=str, help='Password to use for decryption, prompt when none given')
    auth_group.add_argument('-s', '--salt', type=str, help='Salt to use for decryption', default="0011223344556677")

    return parser.parse_args()


def main():
    # Python 3.5.2 still doesn't have "surrogateescape" enabled by
    # default on stdout/stderr, so we have to do it manually. Test with:
    #   print(os.fsdecode(b"\xff"))
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, errors="surrogateescape", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, errors="surrogateescape", line_buffering=True)

    args = parse_args()

    if args.password is None:
        password = getpass.getpass()
    else:
        password = args.password

    salt = args.salt

    auth_token = pecryptfs.AuthToken(password, salt)

    print(auth_token.signature_text)


# EOF #
