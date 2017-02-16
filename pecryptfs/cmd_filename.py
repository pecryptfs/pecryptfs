#!/usr/bin/env python3

# pecryptfs - Portable Userspace eCryptfs
# Copyright (C) 2015,2016 Ingo Ruhnke <grumbel@gmail.com>
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
import os
import io

import pecryptfs
from pecryptfs.filename import encrypt_filename, decrypt_filename
from pecryptfs.define import ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX


def parse_args():
    parser = argparse.ArgumentParser(description="Decrypt and encrypt filenames from/for a eCryptfs volume")
    parser.add_argument('files', metavar='FILE', type=str, nargs='+', help='Filenames to process')
    parser.add_argument('-v', '--verbose', action='store_true', help='Be more verbose')

    auth_group = parser.add_argument_group("Authentication / Cipher")
    auth_group.add_argument('-p', '--password', type=str, help='Password to use for decryption, prompt when none given')
    auth_group.add_argument('-s', '--salt', type=str, help='Salt to use for decryption', default="0011223344556677")
    auth_group.add_argument('-k', '--key-bytes', metavar='BYTES', type=int, default=None,
                            help='Number of bytes in the encryption key')

    action_group = parser.add_argument_group("Action").add_mutually_exclusive_group()
    action_group.add_argument('-a', '--auto', action='store_true', help='Encrypt or decrypt filenames (default)')
    action_group.add_argument('-e', '--encrypt', action='store_true', help='Encrypt filenames')
    action_group.add_argument('-d', '--decrypt', action='store_true', help='Decrypt filenames')
    action_group.add_argument('-m', '--move', action='store_true',
                              help='Rename files to their encrypted/decrypted names')

    return parser.parse_args()


def main():
    # Python 3.5.2 still doesn't have "surrogateescape" enabled by
    # default on stdout/stderr, so we have to do it manually. Test with:
    #   print(os.fsdecode(b"\xff"))
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, errors="surrogateescape", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, errors="surrogateescape", line_buffering=True)

    args = parse_args()

    if args.move and not (args.encrypt or args.decrypt):
        raise Exception("--move requires explicit --encrypt or --decrypt")

    if args.password is None:
        password = os.fsencode(getpass.getpass())
    else:
        password = os.fsencode(args.password)

    salt = bytearray.fromhex(args.salt)

    auth_token = pecryptfs.AuthToken(password, salt)

    for filename in args.files:
        filename = os.fsencode(filename)

        base = os.path.dirname(filename)
        filename = os.path.basename(filename)

        if args.encrypt:
            if filename.startswith(ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX):
                if args.verbose:
                    print("already encrypted, ignoring {}".format(os.fsdecode(filename)))
                continue
            new_filename = encrypt_filename(auth_token, filename)
        elif args.decrypt:
            if not filename.startswith(ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX):
                if args.verbose:
                    print("missing FNEK marker, ignoring {}".format(os.fsdecode(filename)))
                continue
            new_filename = decrypt_filename(auth_token, filename, key_bytes=args.key_bytes)
        else:  # auto
            # FIXME: toggling per filename is a bad idea, should be
            # either all decrypt or all encrypt
            if filename.startswith(ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX):
                new_filename = decrypt_filename(auth_token, filename, key_bytes=args.key_bytes)
            else:
                new_filename = encrypt_filename(auth_token, filename)

        if args.move:
            if filename != new_filename:
                os.rename(os.path.join(base, filename),
                          os.path.join(new_filename))
        else:
            print("{} -> {}".format(os.fsdecode(os.path.join(base, filename)),
                                    os.fsdecode(os.path.join(base, new_filename))))


# EOF #
