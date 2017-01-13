# pecryptfs - Portable Userspace eCryptfs
# Copyright (C) 2016 Ingo Ruhnke <grumbel@gmail.com>
# Copyright (C) 1997-2003 Erez Zadok
# Copyright (C) 2001-2003 Stony Brook University
# Copyright (C) 2004-2008 International Business Machines Corp.
#    Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
#               Trevor S. Highland <trevor.highland@gmail.com>
#               Tyler Hicks <tyhicks@ou.edu>
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

# ecryptfs-util/include/linux/ecryptfs.h
ECRYPTFS_MAX_PASSWORD_LENGTH = 64
ECRYPTFS_MAX_PASSPHRASE_BYTES = ECRYPTFS_MAX_PASSWORD_LENGTH
ECRYPTFS_SALT_SIZE = 8
ECRYPTFS_SALT_SIZE_HEX = (ECRYPTFS_SALT_SIZE*2)

# The original signature size is only for what is stored on disk; all
# in-memory representations are expanded hex, so it better adapted to
# be passed around or referenced on the command line
ECRYPTFS_SIG_SIZE = 8
ECRYPTFS_SIG_SIZE_HEX = (ECRYPTFS_SIG_SIZE*2)
ECRYPTFS_PASSWORD_SIG_SIZE = ECRYPTFS_SIG_SIZE_HEX
ECRYPTFS_MAX_KEY_BYTES = 64
ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES = 512
ECRYPTFS_FILE_VERSION = 0x03
ECRYPTFS_MAX_PKI_NAME_BYTES = 16

RFC2440_CIPHER_DES3_EDE = 0x02
RFC2440_CIPHER_CAST_5 = 0x03
RFC2440_CIPHER_BLOWFISH = 0x04
RFC2440_CIPHER_AES_128 = 0x07
RFC2440_CIPHER_AES_192 = 0x08
RFC2440_CIPHER_AES_256 = 0x09
RFC2440_CIPHER_TWOFISH = 0x0a
RFC2440_CIPHER_CAST_6 = 0x0b

RFC2440_CIPHER_RSA = 0x01


# based on ecryptfs-util/fs/ecryptfs/ecryptfs_kernel.h
ECRYPTFS_MAX_KEYSET_SIZE = 1024
ECRYPTFS_MAX_CIPHER_NAME_SIZE = 32
ECRYPTFS_MAX_NUM_ENC_KEYS = 64
ECRYPTFS_MAX_IV_BYTES = 16  # 128 bits
ECRYPTFS_SALT_BYTES = 2
MAGIC_ECRYPTFS_MARKER = 0x3c81b7f5
MAGIC_ECRYPTFS_MARKER_SIZE_BYTES = 8  # 4*2
ECRYPTFS_FILE_SIZE_BYTES = 8
ECRYPTFS_SIZE_AND_MARKER_BYTES = (ECRYPTFS_FILE_SIZE_BYTES +
                                  MAGIC_ECRYPTFS_MARKER_SIZE_BYTES)
ECRYPTFS_DEFAULT_CIPHER = b"aes"
ECRYPTFS_DEFAULT_KEY_BYTES = 16
ECRYPTFS_DEFAULT_HASH = b"md5"
ECRYPTFS_TAG_70_DIGEST = ECRYPTFS_DEFAULT_HASH
ECRYPTFS_TAG_1_PACKET_TYPE = 0x01
ECRYPTFS_TAG_3_PACKET_TYPE = 0x8C
ECRYPTFS_TAG_11_PACKET_TYPE = 0xED
ECRYPTFS_TAG_64_PACKET_TYPE = 0x40
ECRYPTFS_TAG_65_PACKET_TYPE = 0x41
ECRYPTFS_TAG_66_PACKET_TYPE = 0x42
ECRYPTFS_TAG_67_PACKET_TYPE = 0x43
ECRYPTFS_TAG_70_PACKET_TYPE = 0x46  # FNEK-encrypted filename as dentry name
ECRYPTFS_TAG_71_PACKET_TYPE = 0x47  # FNEK-encrypted filename in metadata
ECRYPTFS_TAG_72_PACKET_TYPE = 0x48  # FEK-encrypted filename as dentry name
ECRYPTFS_TAG_73_PACKET_TYPE = 0x49  # FEK-encrypted filename as metadata
ECRYPTFS_MIN_PKT_LEN_SIZE = 1   # Min size to specify packet length
# Pass at least this many bytes to ecryptfs_parse_packet_length() and
# ecryptfs_write_packet_length()
ECRYPTFS_MAX_PKT_LEN_SIZE = 2

# Constraint: ECRYPTFS_FILENAME_MIN_RANDOM_PREPEND_BYTES >= ECRYPTFS_MAX_IV_BYTES
ECRYPTFS_FILENAME_MIN_RANDOM_PREPEND_BYTES = 16
ECRYPTFS_NON_NULL = 0x42  # A reasonable substitute for NULL
MD5_DIGEST_SIZE = 16
ECRYPTFS_TAG_70_DIGEST_SIZE = MD5_DIGEST_SIZE
ECRYPTFS_TAG_70_MIN_METADATA_SIZE = (1 + ECRYPTFS_MIN_PKT_LEN_SIZE
                                     + ECRYPTFS_SIG_SIZE + 1 + 1)
ECRYPTFS_TAG_70_MAX_METADATA_SIZE = (1 + ECRYPTFS_MAX_PKT_LEN_SIZE
                                     + ECRYPTFS_SIG_SIZE + 1 + 1)
ECRYPTFS_FEK_ENCRYPTED_FILENAME_PREFIX = b"ECRYPTFS_FEK_ENCRYPTED."
ECRYPTFS_FEK_ENCRYPTED_FILENAME_PREFIX_SIZE = 23
ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX = b"ECRYPTFS_FNEK_ENCRYPTED."
ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE = 24
ECRYPTFS_ENCRYPTED_DENTRY_NAME_LEN = (18 + 1 + 4 + 1 + 32)


# EOF #
