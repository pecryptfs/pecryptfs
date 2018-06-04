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


from typing import TYPE_CHECKING

import os
import subprocess
import tempfile

if TYPE_CHECKING:
    from pecryptfs.auth_token import AuthToken  # noqa: F401


def generate_encrypted_file(auth_token: 'AuthToken', cipher: str, key_bytes: str) -> bytes:
    back_directory = tempfile.mkdtemp("_pecryptfs_back")
    front_directory = tempfile.mkdtemp("_pecryptfs_front")

    # mount the encrypted directory
    cmd = ["sudo", "mount",
           "-t", "ecryptfs",
           "-o", ",".join(["key=passphrase:passwd={}".format(auth_token.password_text),
                           "passphrase_salt={}".format(auth_token.salt_text),
                           "ecryptfs_enable_filename_crypto=no",
                           "ecryptfs_passthrough=no",
                           "ecryptfs_unlink_sigs",
                           "no_sig_cache",
                           "ecryptfs_cipher={}".format(cipher),
                           "ecryptfs_key_bytes={}".format(key_bytes)]),
           back_directory,
           front_directory]

    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull)

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


def encrypt_filename_ecryptfs(filename: str, auth_token: 'AuthToken', cipher: str="aes", key_bytes: int=24) -> str:
    """Encrypt the given filename using native ecryptfs"""

    filename = os.fsdecode(filename)

    back_directory = tempfile.mkdtemp("_pecryptfs_back")
    front_directory = tempfile.mkdtemp("_pecryptfs_front")

    # mount the encrypted directory
    cmd = ["sudo", "mount",
           "-t", "ecryptfs",
           "-o", ",".join(["key=passphrase:passwd={}".format(auth_token.password_text),
                           "passphrase_salt={}".format(auth_token.salt_text),
                           "ecryptfs_enable_filename_crypto=yes",
                           "ecryptfs_passthrough=no",
                           "ecryptfs_unlink_sigs",
                           "ecryptfs_fnek_sig={}".format(auth_token.signature_text),
                           "no_sig_cache",
                           "ecryptfs_cipher={}".format(cipher),
                           "ecryptfs_key_bytes={}".format(key_bytes)]),
           back_directory,
           front_directory]

    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull)

    # write file and let it be encrypted
    with open(os.path.join(front_directory, filename), "w") as fout:
        fout.write("Hello World\n")

    # unmount the encrypted diretorys
    subprocess.check_call(["sudo", "umount", front_directory])

    files = os.listdir(back_directory)
    assert len(files) == 1
    encrypted_filename = files[0]

    os.unlink(os.path.join(back_directory, encrypted_filename))

    os.rmdir(back_directory)
    os.rmdir(front_directory)

    return encrypted_filename


def decrypt_filename_ecryptfs(enc_filename_bin: str, auth_token: 'AuthToken',
                              cipher: str="aes", key_bytes: int=24) -> str:
    """Decrypt the given filename using native ecryptfs"""

    enc_filename = os.fsdecode(enc_filename_bin)

    back_directory = tempfile.mkdtemp("_pecryptfs_back")
    front_directory = tempfile.mkdtemp("_pecryptfs_front")

    # write file and let it be encrypted
    with open(os.path.join(back_directory, enc_filename), "w") as fout:
        fout.write("Hello World\n")

    # mount the encrypted directory
    cmd = ["sudo", "mount",
           "-t", "ecryptfs",
           "-o", ",".join(["key=passphrase:passwd={}".format(auth_token.password_text),
                           "passphrase_salt={}".format(auth_token.salt_text),
                           "ecryptfs_enable_filename_crypto=yes",
                           "ecryptfs_passthrough=no",
                           "ecryptfs_unlink_sigs",
                           "ecryptfs_fnek_sig={}".format(auth_token.signature_text),
                           "no_sig_cache",
                           "ecryptfs_cipher={}".format(cipher),
                           "ecryptfs_key_bytes={}".format(key_bytes)]),
           back_directory,
           front_directory]

    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull)

    # retrieve the decrypted filename
    files = os.listdir(front_directory)
    assert len(files) == 1
    filename = files[0]

    # unmount the encrypted diretorys
    subprocess.check_call(["sudo", "umount", front_directory])

    os.unlink(os.path.join(back_directory, enc_filename))

    os.rmdir(back_directory)
    os.rmdir(front_directory)

    return filename


# EOF #
