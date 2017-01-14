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
import subprocess
import tempfile

from pecryptfs import AuthToken


def generate_encrypted_file(cipher, key_bytes, password, salt):
    back_directory = tempfile.mkdtemp("_pecryptfs_back")
    front_directory = tempfile.mkdtemp("_pecryptfs_front")

    # mount the encrypted directory
    cmd = ["sudo", "mount",
           "-t", "ecryptfs",
           "-o", ",".join(["key=passphrase:passwd={}".format(password),
                           "passphrase_salt={}".format(salt),
                           "ecryptfs_enable_filename_crypto=no",
                           "ecryptfs_passthrough=no",
                           "ecryptfs_unlink_sigs",
                           "no_sig_cache",
                           "ecryptfs_cipher={}".format(cipher),
                           "ecryptfs_key_bytes={}".format(key_bytes)]),
           back_directory,
           front_directory]
    subprocess.check_call(cmd)

    # write file and let it be encrypted
    with open(os.path.join(front_directory, "TestFile"), "w") as fout:
        fout.write("Hello World\n")

    # unmount the encrypted diretorys
    subprocess.check_call(["sudo", "umount", front_directory])

    # copy the encrypted file
    with open(os.path.join(back_directory, "TestFile"), "rb") as fin:
        data = fin.read()

    # FIXME: Why is the file not overwritten when it's not unlinked?!
    os.unlink(os.path.join(back_directory, "TestFile"))

    os.rmdir(back_directory)
    os.rmdir(front_directory)

    return data


def generate_encrypted_filename(cipher, key_bytes, password, salt, input_filename):
    auth_token = AuthToken(os.fsencode(password), bytes.fromhex(salt))

    back_directory = tempfile.mkdtemp("_pecryptfs_back")
    front_directory = tempfile.mkdtemp("_pecryptfs_front")

    # mount the encrypted directory
    cmd = ["sudo", "mount",
           "-t", "ecryptfs",
           "-o", ",".join(["key=passphrase:passwd={}".format(password),
                           "passphrase_salt={}".format(salt),
                           "ecryptfs_enable_filename_crypto=yes",
                           "ecryptfs_passthrough=no",
                           "ecryptfs_unlink_sigs",
                           "ecryptfs_fnek_sig={}".format(os.fsdecode(auth_token.signature)),
                           "no_sig_cache",
                           "ecryptfs_cipher={}".format(cipher),
                           "ecryptfs_key_bytes={}".format(key_bytes)]),
           back_directory,
           front_directory]
    subprocess.check_call(cmd)

    # write file and let it be encrypted
    with open(os.path.join(front_directory, input_filename), "w") as fout:
        fout.write("Hello World\n")

    # unmount the encrypted diretorys
    subprocess.check_call(["sudo", "umount", front_directory])

    files = os.listdir(back_directory)
    assert len(files) == 1
    filename = files[0]

    os.unlink(os.path.join(back_directory, filename))

    os.rmdir(back_directory)
    os.rmdir(front_directory)

    return filename


def main():
    parser = argparse.ArgumentParser(description="eCryptfs Encrypted File Generator")
    parser.add_argument('files', metavar='FILE', type=str, nargs='?', help='Filenames to decrypt')
    parser.add_argument('-p', '--password', type=str, default="Test",
                        help='Password to use for decryption, prompt when none given')
    parser.add_argument('-s', '--salt', type=str, default="0011223344556677",
                        help='Salt to use for decryption')
    parser.add_argument('-o', '--output', type=str, help='Output directory')
    parser.add_argument('-f', '--filename', action='store_true', help='Generate filenames')

    args = parser.parse_args()

    password = args.password
    salt = args.salt
    output_directory = args.output

    if not args.filename:
        if not os.path.isdir(output_directory):
            os.makedirs(output_directory)

    cipher_list = [("aes", [16, 32, 24]),
                   ("blowfish", [16, 32, 56]),
                   ("des3_ede", [24]),
                   ("twofish", [16, 32]),
                   ("cast6", [16, 32]),
                   ("cast5", [16])]

    input_filename = "TestFile"
    filenames = []
    for cipher, key_bytes_list in cipher_list:
        for key_bytes in key_bytes_list:
            if args.filename:
                filename = generate_encrypted_filename(cipher, key_bytes, password, salt, input_filename)
                filenames.append((cipher, key_bytes, filename))
            else:
                data = generate_encrypted_file(cipher, key_bytes, password, salt)
                output_filename = "{}-{}.raw".format(cipher, key_bytes)
                with open(os.path.join(output_directory, output_filename), "wb") as fout:
                    fout.write(data)

    print()
    print("Password: {}".format(args.password))
    print("Salt:     {}".format(args.salt))
    print("Filename: {}".format(input_filename))
    print()
    for cipher, key_bytes, f in filenames:
        print("{:8}  {:2}  {}".format(cipher, key_bytes, f))


# EOF #
