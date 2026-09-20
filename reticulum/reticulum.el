;;; reticulum.el --- Reticulum network stack in Emacs Lisp  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; Author: Paul Meier
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: comm, network, mesh
;; SPDX-License-Identifier: LicenseRef-Reticulum
;; URL: https://github.com/paulmeier/nomadnet.el

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; A client implementation of the Reticulum Network Stack
;; <https://reticulum.network> in Emacs Lisp: identities, destinations,
;; announces, a leaf transport over HDLC framed TCP interfaces, encrypted
;; links with requests and responses, and inbound resources.  The
;; cryptography (X25519, Ed25519, HKDF, AES-CBC tokens) runs on Emacs
;; bignums and GnuTLS; the wire format is compatible with RNS 1.5.
;;
;; This library has no user interface.  nomadnet.el is its first client.
;;
;; Modules:
;;   reticulum-bytes      byte strings, hex, integers, random, logging
;;   reticulum-msgpack    MessagePack, compatible with RNS's umsgpack
;;   reticulum-crypto     hashes, HMAC, HKDF, tokens, X25519, Ed25519
;;   reticulum-packet     packet codec
;;   reticulum-identity   identities, addressing, announces, ratchets
;;   reticulum-interface  TCP client and shared-instance interfaces
;;   reticulum-transport  path table, dispatch, receipts, path requests
;;   reticulum-link       links, requests, responses, keepalives
;;   reticulum-resource   inbound resources
;;   reticulum-bz2        bzip2 via the system utility
;;
;; Typical use:
;;   (require 'reticulum)
;;   (reticulum-transport-start)
;;   (reticulum-interface-add-tcp "hub" "example.org" 4242)
;;   (reticulum-transport-register-announce-handler "nomadnetwork.node" #'my-handler)

;;; Code:

(require 'reticulum-bytes)
(require 'reticulum-msgpack)
(require 'reticulum-crypto)
(require 'reticulum-packet)
(require 'reticulum-identity)
(require 'reticulum-interface)
(require 'reticulum-transport)
(require 'reticulum-bz2)
(require 'reticulum-link)
(require 'reticulum-resource)

(defconst reticulum-version "0.1.0" "Version of the reticulum.el library.")

(provide 'reticulum)

;;; reticulum.el ends here
