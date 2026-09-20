;;; reticulum-identity.el --- Identities, destinations and announces  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; Port of RNS.Identity and the addressing half of RNS.Destination:
;; key pairs, identity hashes, destination hashes, encryption to an
;; identity (with ratchets), signatures, the registry of known
;; destinations learned from announces, and announce validation and
;; construction.

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)
(require 'reticulum-crypto)
(require 'reticulum-msgpack)
(require 'reticulum-packet)

(defconst reticulum-identity-keysize 64 "Public key length: X25519 pub + Ed25519 pub.")
(defconst reticulum-identity-siglength 64)
(defconst reticulum-identity-hashlength 32)
(defconst reticulum-identity-name-hash-length 10)
(defconst reticulum-identity-ratchetsize 32)
(defconst reticulum-identity-derived-key-length 64)
(defconst reticulum-identity-ratchet-expiry (* 60 60 24 30))

;;;; Identity structure

(cl-defstruct (reticulum-identity (:constructor reticulum-identity--make)
                                  (:copier nil))
  prv sig-prv pub sig-pub hash hexhash app-data)

(defun reticulum-identity--finish (identity)
  "Compute hashes for IDENTITY after its keys are set."
  (setf (reticulum-identity-hash identity)
        (reticulum-truncated-hash (reticulum-identity-public-bytes identity)))
  (setf (reticulum-identity-hexhash identity) (reticulum-hex (reticulum-identity-hash identity)))
  identity)

(defun reticulum-identity-create ()
  "Generate a new identity with fresh keys."
  (let* ((prv (reticulum-x25519-generate-private))
         (sig-prv (reticulum-ed25519-generate-private)))
    (reticulum-identity--finish
     (reticulum-identity--make :prv prv :sig-prv sig-prv
                               :pub (reticulum-x25519-public prv)
                               :sig-pub (reticulum-ed25519-public sig-prv)))))

(defun reticulum-identity-from-private (prv-bytes)
  "Load an identity from 64 bytes of private key material."
  (unless (= (length prv-bytes) 64) (error "Private key must be 64 bytes"))
  (let ((prv (substring prv-bytes 0 32))
        (sig-prv (substring prv-bytes 32)))
    (reticulum-identity--finish
     (reticulum-identity--make :prv prv :sig-prv sig-prv
                               :pub (reticulum-x25519-public prv)
                               :sig-pub (reticulum-ed25519-public sig-prv)))))

(defun reticulum-identity-from-public (pub-bytes)
  "Load a public-only identity from 64 bytes of public key material."
  (unless (= (length pub-bytes) 64) (error "Public key must be 64 bytes"))
  (reticulum-identity--finish
   (reticulum-identity--make :pub (substring pub-bytes 0 32)
                             :sig-pub (substring pub-bytes 32))))

(defun reticulum-identity-public-bytes (identity)
  "Return the 64 byte public key of IDENTITY."
  (concat (reticulum-identity-pub identity) (reticulum-identity-sig-pub identity)))

(defun reticulum-identity-private-bytes (identity)
  "Return the 64 byte private key of IDENTITY, or nil for public identities."
  (when (reticulum-identity-prv identity)
    (concat (reticulum-identity-prv identity) (reticulum-identity-sig-prv identity))))

(defun reticulum-identity-to-file (identity path)
  "Write the private key of IDENTITY to PATH in RNS's file format."
  (let ((coding-system-for-write 'binary))
    (with-temp-file path
      (set-buffer-multibyte nil)
      (insert (reticulum-identity-private-bytes identity))))
  (set-file-modes path #o600)
  t)

(defun reticulum-identity-from-file (path)
  "Load an identity from the RNS identity file at PATH."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert-file-contents-literally path)
    (reticulum-identity-from-private (buffer-string))))

(defun reticulum-identity-sign (identity message)
  "Sign MESSAGE with IDENTITY."
  (unless (reticulum-identity-sig-prv identity)
    (error "Identity does not hold a private key"))
  (reticulum-ed25519-sign (reticulum-identity-sig-prv identity) message
                          (reticulum-identity-sig-pub identity)))

(defun reticulum-identity-validate (identity signature message)
  "Return non-nil if SIGNATURE over MESSAGE was made by IDENTITY."
  (reticulum-ed25519-verify (reticulum-identity-sig-pub identity) signature message))

(defun reticulum-identity-encrypt (identity plaintext &optional ratchet)
  "Encrypt PLAINTEXT for IDENTITY, using public RATCHET key if given.
Returns ephemeral public key || token."
  (let* ((ephemeral (reticulum-x25519-generate-private))
         (ephemeral-pub (reticulum-x25519-public ephemeral))
         (target (or ratchet (reticulum-identity-pub identity)))
         (shared (reticulum-x25519-shared ephemeral target))
         (derived (reticulum-hkdf reticulum-identity-derived-key-length shared
                                  (reticulum-identity-hash identity) nil)))
    (concat ephemeral-pub (reticulum-token-encrypt derived plaintext))))

(defun reticulum-identity--decrypt-with (identity private-key ciphertext peer-pub)
  "Decrypt CIPHERTEXT using PRIVATE-KEY against PEER-PUB for IDENTITY's salt."
  (let* ((shared (reticulum-x25519-shared private-key peer-pub))
         (derived (reticulum-hkdf reticulum-identity-derived-key-length shared
                                  (reticulum-identity-hash identity) nil)))
    (reticulum-token-decrypt derived ciphertext)))

(defun reticulum-identity-decrypt (identity token &optional ratchets enforce-ratchets)
  "Decrypt TOKEN addressed to IDENTITY.
RATCHETS is a list of private ratchet keys to try first.  Returns
\(PLAINTEXT . RATCHET-ID) where RATCHET-ID is nil when the identity key
was used, or nil if decryption fails.  With ENFORCE-RATCHETS, refuse to
fall back to the identity key."
  (unless (reticulum-identity-prv identity)
    (error "Identity does not hold a private key"))
  (when (> (length token) 32)
    (let ((peer-pub (substring token 0 32))
          (ciphertext (substring token 32))
          (result nil))
      (cl-loop for ratchet in ratchets
               until result
               do (condition-case nil
                      (setq result (cons (reticulum-identity--decrypt-with identity ratchet ciphertext peer-pub)
                                         (reticulum-identity-ratchet-id (reticulum-x25519-public ratchet))))
                    (error nil)))
      (when (and (null result) (not enforce-ratchets))
        (condition-case nil
            (setq result (cons (reticulum-identity--decrypt-with identity (reticulum-identity-prv identity)
                                                                 ciphertext peer-pub)
                               nil))
          (error nil)))
      result)))

;;;; Ratchets

(defun reticulum-identity-generate-ratchet ()
  "Return a new private ratchet key."
  (reticulum-x25519-generate-private))

(defun reticulum-identity-ratchet-public (ratchet)
  "Return the public key of private RATCHET."
  (reticulum-x25519-public ratchet))

(defun reticulum-identity-ratchet-id (ratchet-pub)
  "Return the ratchet id for public ratchet key RATCHET-PUB."
  (substring (reticulum-full-hash ratchet-pub) 0 reticulum-identity-name-hash-length))

;;;; Destination addressing

(defun reticulum-address-expand-name (identity app-name aspects)
  "Return the full name for APP-NAME, ASPECTS and optional IDENTITY."
  (when (string-search "." app-name) (error "Dots can't be used in app names"))
  (let ((name app-name))
    (dolist (aspect aspects)
      (when (string-search "." aspect) (error "Dots can't be used in aspects"))
      (setq name (concat name "." aspect)))
    (when identity
      (setq name (concat name "." (reticulum-identity-hexhash identity))))
    name))

(defun reticulum-address-name-hash (app-name aspects)
  "Return the 10 byte name hash for APP-NAME and ASPECTS."
  (substring (reticulum-full-hash (reticulum-utf8 (reticulum-address-expand-name nil app-name aspects)))
             0 reticulum-identity-name-hash-length))

(defun reticulum-address (identity app-name &rest aspects)
  "Return the destination hash for IDENTITY (struct, 16 byte hash or nil) and name."
  (let ((material (reticulum-address-name-hash app-name aspects)))
    (cond ((null identity))
          ((reticulum-identity-p identity)
           (setq material (concat material (reticulum-identity-hash identity))))
          ((and (stringp identity) (= (length identity) reticulum-truncated-hash-length))
           (setq material (concat material identity)))
          (t (error "Invalid identity for destination hash")))
    (substring (reticulum-full-hash material) 0 reticulum-truncated-hash-length)))

(defun reticulum-address-from-name (full-name identity)
  "Return the destination hash for FULL-NAME such as \"lxmf.delivery\" and IDENTITY."
  (let ((parts (split-string full-name "\\.")))
    (apply #'reticulum-address identity (car parts) (cdr parts))))

;;;; Known destinations

(defvar reticulum-known-destinations (make-hash-table :test #'equal)
  "Destination hash -> (TIMESTAMP PACKET-HASH PUBLIC-KEY APP-DATA).")

(defvar reticulum-known-ratchets (make-hash-table :test #'equal)
  "Destination hash -> (RATCHET-PUBLIC . RECEIVED-AT).")

(defun reticulum-identity-remember (packet-hash destination-hash public-key app-data)
  "Record PUBLIC-KEY and APP-DATA for DESTINATION-HASH learned from PACKET-HASH."
  (puthash destination-hash (list (float-time) packet-hash public-key app-data)
           reticulum-known-destinations))

(defun reticulum-identity-recall (destination-hash)
  "Return the identity announced for DESTINATION-HASH, or nil."
  (let ((entry (gethash destination-hash reticulum-known-destinations)))
    (when entry
      (let ((identity (reticulum-identity-from-public (nth 2 entry))))
        (setf (reticulum-identity-app-data identity) (nth 3 entry))
        identity))))

(defun reticulum-identity-recall-app-data (destination-hash)
  "Return the app data announced for DESTINATION-HASH, or nil."
  (nth 3 (gethash destination-hash reticulum-known-destinations)))

(defun reticulum-identity-remember-ratchet (destination-hash ratchet-pub)
  "Record public RATCHET-PUB for DESTINATION-HASH."
  (puthash destination-hash (cons ratchet-pub (float-time)) reticulum-known-ratchets))

(defun reticulum-identity-get-ratchet (destination-hash)
  "Return the current public ratchet for DESTINATION-HASH if not expired."
  (let ((entry (gethash destination-hash reticulum-known-ratchets)))
    (when (and entry (< (- (float-time) (cdr entry)) reticulum-identity-ratchet-expiry))
      (car entry))))

(defun reticulum-identity-save-known (path)
  "Persist known destinations and ratchets to PATH as msgpack."
  (let ((destinations (make-hash-table :test #'equal))
        (ratchets (make-hash-table :test #'equal)))
    (maphash (lambda (k v) (puthash k v destinations)) reticulum-known-destinations)
    (maphash (lambda (k v) (puthash k (list (car v) (cdr v)) ratchets)) reticulum-known-ratchets)
    (let ((coding-system-for-write 'binary))
      (with-temp-file path
        (set-buffer-multibyte nil)
        (insert (reticulum-msgpack-pack (list destinations ratchets)))))))

(defun reticulum-identity-load-known (path)
  "Load known destinations and ratchets from PATH if it exists."
  (when (file-exists-p path)
    (condition-case err
        (let ((data (with-temp-buffer
                      (set-buffer-multibyte nil)
                      (insert-file-contents-literally path)
                      (reticulum-msgpack-unpack (buffer-string)))))
          (maphash (lambda (k v) (puthash k v reticulum-known-destinations)) (nth 0 data))
          (maphash (lambda (k v) (puthash k (cons (nth 0 v) (nth 1 v)) reticulum-known-ratchets)) (nth 1 data))
          t)
      (error (reticulum-log 1 "could not load known destinations: %s" (error-message-string err))
             nil))))

;;;; Announces

(defun reticulum-announce-parse (packet)
  "Parse announce PACKET into a plist without validating it, or nil if malformed."
  (let* ((data (reticulum-packet-data packet))
         (keysize reticulum-identity-keysize)
         (nh reticulum-identity-name-hash-length)
         (sig reticulum-identity-siglength)
         (rs (if (= (reticulum-packet-context-flag packet) 1) reticulum-identity-ratchetsize 0))
         (minimum (+ keysize nh 10 rs sig)))
    (when (>= (length data) minimum)
      (let* ((pos 0)
             (public-key (substring data pos (cl-incf pos keysize)))
             (name-hash (substring data pos (cl-incf pos nh)))
             (random-hash (substring data pos (cl-incf pos 10)))
             (ratchet (if (> rs 0) (substring data pos (cl-incf pos rs)) ""))
             (signature (substring data pos (cl-incf pos sig)))
             (app-data (if (> (length data) minimum) (substring data pos) nil)))
        (list :destination-hash (reticulum-packet-destination-hash packet)
              :public-key public-key :name-hash name-hash :random-hash random-hash
              :ratchet (unless (string-empty-p ratchet) ratchet)
              :signature signature :app-data app-data
              :hops (reticulum-packet-hops packet)
              :transport-id (reticulum-packet-transport-id packet)
              :path-response (= (reticulum-packet-context packet) reticulum-context-path-response)
              :packet-hash (reticulum-packet-hash packet))))))

(defun reticulum-announce-validate (packet &optional remember)
  "Validate announce PACKET.  Return its plist with :identity, or nil.
With REMEMBER, record the announced destination and ratchet."
  (when (= (reticulum-packet-packet-type packet) reticulum-packet-announce)
    (let ((announce (reticulum-announce-parse packet)))
      (when announce
        (let* ((identity (reticulum-identity-from-public (plist-get announce :public-key)))
               (signed (concat (plist-get announce :destination-hash)
                               (plist-get announce :public-key)
                               (plist-get announce :name-hash)
                               (plist-get announce :random-hash)
                               (or (plist-get announce :ratchet) "")
                               (or (plist-get announce :app-data) ""))))
          (when (reticulum-identity-validate identity (plist-get announce :signature) signed)
            (let ((expected (substring (reticulum-full-hash (concat (plist-get announce :name-hash)
                                                                    (reticulum-identity-hash identity)))
                                       0 reticulum-truncated-hash-length)))
              (when (reticulum-bytes-equal expected (plist-get announce :destination-hash))
                (let ((known (gethash (plist-get announce :destination-hash) reticulum-known-destinations)))
                  (unless (and known (not (reticulum-bytes-equal (nth 2 known) (plist-get announce :public-key))))
                    (when remember
                      (reticulum-identity-remember (plist-get announce :packet-hash)
                                                   (plist-get announce :destination-hash)
                                                   (plist-get announce :public-key)
                                                   (plist-get announce :app-data))
                      (when (plist-get announce :ratchet)
                        (reticulum-identity-remember-ratchet (plist-get announce :destination-hash)
                                                             (plist-get announce :ratchet))))
                    (setf (reticulum-identity-app-data identity) (plist-get announce :app-data))
                    (plist-put announce :identity identity)))))))))))

(defun reticulum-announce-build (identity app-name aspects &optional app-data ratchet path-response)
  "Build an announce packet for IDENTITY's destination APP-NAME/ASPECTS.
APP-DATA and public RATCHET are optional.  Returns a packed packet."
  (let* ((destination-hash (apply #'reticulum-address identity app-name aspects))
         (name-hash (reticulum-address-name-hash app-name aspects))
         (random-hash (concat (substring (reticulum-random-bytes 16) 0 5)
                              (reticulum-int-to-bytes (floor (float-time)) 5)))
         (ratchet (or ratchet ""))
         (app-data (or app-data ""))
         (signed (concat destination-hash (reticulum-identity-public-bytes identity)
                         name-hash random-hash ratchet app-data))
         (signature (reticulum-identity-sign identity signed))
         (data (concat (reticulum-identity-public-bytes identity) name-hash random-hash
                       ratchet signature app-data)))
    (reticulum-packet-make :packet-type reticulum-packet-announce
                           :destination-type reticulum-destination-single
                           :context-flag (if (string-empty-p ratchet) 0 1)
                           :context (if path-response reticulum-context-path-response reticulum-context-none)
                           :destination-hash destination-hash
                           :data data)))

(provide 'reticulum-identity)

;;; reticulum-identity.el ends here
