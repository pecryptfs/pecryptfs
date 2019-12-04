#!/usr/bin/env python3

# pecryptfs - Portable Userspace eCryptfs
# Copyright (C) 2016 Ingo Ruhnke <grumbel@gmail.com>
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


from setuptools import setup, find_packages


setup(name='pecryptfs',
      version='0.1.0',
      author = "Ingo Ruhnke",
      author_email = "grumbel@gmail.com",
      url='https://gitlab.com/pecryptfs/pecryptfs',
      description="Portable Userspace eCryptfs",
      long_description="pecryptfs is a simple and somewhat incomplete Python \
reimplementation of the eCryptfs filesystem encryption. Unlike \
eCryptfs, which is a Linux kernel module, pecryptfs runs completely in \
userspace and works on individual files via command line tools.",
      entry_points={
          'console_scripts': [
              'pecryptfs-decrypt = pecryptfs.cmd_decrypt:main',
              'pecryptfs-filename = pecryptfs.cmd_filename:main',
              'pecryptfs-genfile = pecryptfs.cmd_genfile:main',
              'pecryptfs-makesig = pecryptfs.cmd_makesig:pip_main',
              'pecryptfs-ls = pecryptfs.cmd_ls:main'
          ],
      },
      packages=find_packages())


# EOF #
