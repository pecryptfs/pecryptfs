;; pecryptfs - Portable Userspace eCryptfs
;; Copyright (C) 2019 Ingo Ruhnke <grumbel@gmail.com>
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

(set! %load-path
  (cons* "/ipfs/QmceiEsAasqwujsdycdfwu56FKVDwfWwQreNkxtp94xrxZ/guix-cocfree_0.0.0-52-g9ca1320"
         %load-path))

(use-modules (guix packages)
             (guix build-system python)
             ((guix licenses) #:prefix license:)
             (gnu packages python-crypto)
             (guix-cocfree utils))

(define %source-dir (dirname (current-filename)))

(define-public pecryptfs
  (package
   (name "pecryptfs")
   (version (version-from-source %source-dir))
   (source (source-from-source %source-dir))
   (inputs
    `(("python-pycrypto" ,python-pycrypto)))
   (build-system python-build-system)
   (synopsis (synopsis-from-source %source-dir))
   (description (description-from-source %source-dir))
   (home-page (homepage-from-source %source-dir))
   (license license:gpl3+)))

pecryptfs

;; EOF ;;
