pecryptfs - Portable Userspace eCryptfs
=======================================

pecryptfs is a simple and somewhat incomplete Python reimplementation
of the eCryptfs filesystem encryption. Unlike eCryptfs, which is a
Linux kernel module, pecryptfs runs completely in userspace and works
on individual files via command line tools.

It is recommended to keep a backup around, as pecryptfs might not be
able to deal with more exotic features of eCryptfs correctly and do
bad things.


Features
--------

* encrypt filenames (AES, DES, Blowfish)
* decrypt filenames (AES, DES, Blowfish)
* decrypt file content (AES16 only)
* password based encryption/decryption


Missing Features
----------------

* no encryption of file content
* no recursive decryption of directory trees
* no in-place decryption of files, content goes to stdout
* no SSL support
* no xattr support


Installation
------------

pecryptfs comes with a `setup.py` and can be installed like most other
Python packages:

	sudo pip3 install .


Usage
-----

To encrypt a filename:

    $ pecryptfs-filename --encrypt HelloWorld
    Password:
    ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoNLh2yALCb17qYCkx232fM---

To decrypt a filename:

    $ pecryptfs-filename --decrypt ECRYPTFS_FNEK_ENCRYPTED.FWYp3QmdieuVx-ReNM93cFJhZmQKb9S.7xyoNLh2yALCb17qYCkx232fM---
    Password:
    HelloWorld

The `--move` option with rename the file, otherwise the name is just printed to stdout.

To decrypt the content of a file:

    $ pecryptfs-decrypt YourEncryptedFileHere
    Password:
    HelloWorld


Links
-----

* http://www.linuxjournal.com/article/9400
* https://www.kernel.org/doc/Documentation/filesystems/ecryptfs.txt
* https://defuse.ca/audits/ecryptfs.htm
* https://lkml.org/lkml/2006/3/24/318
* http://landley.net/kdocs/ols/2012/ols2012-wang.pdf
