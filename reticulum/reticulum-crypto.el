;;; reticulum-crypto.el --- Cryptographic primitives for Reticulum  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; The primitives Reticulum needs, implemented with what Emacs offers:
;;
;; - SHA-256 and SHA-512 via `secure-hash'.
;; - HMAC-SHA256, AES-128-CBC and AES-256-CBC via GnuTLS.
;; - HKDF in the exact form RNS.Cryptography.hkdf uses.
;; - Token: RNS's Fernet variant (iv || AES-CBC || HMAC).
;; - X25519 (RFC 7748) and Ed25519 (RFC 8032) in Emacs Lisp on bignums.
;;
;; The curve arithmetic is not constant time.  Emacs cannot provide that,
;; and for a messaging client it is an accepted limitation.

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)

;;;; Hashes and MACs

(defun reticulum-sha256 (bytes)
  "Return the SHA-256 digest of BYTES as a unibyte string."
  (secure-hash 'sha256 (string-to-unibyte bytes) nil nil t))

(defun reticulum-sha512 (bytes)
  "Return the SHA-512 digest of BYTES as a unibyte string."
  (secure-hash 'sha512 (string-to-unibyte bytes) nil nil t))

(defun reticulum-full-hash (bytes)
  "Reticulum's full hash: SHA-256 of BYTES."
  (reticulum-sha256 bytes))

(defun reticulum-truncated-hash (bytes)
  "Reticulum's truncated hash: the first 16 bytes of SHA-256 of BYTES."
  (substring (reticulum-sha256 bytes) 0 16))

(defun reticulum-hmac-sha256 (key data)
  "Return HMAC-SHA256 of DATA under KEY."
  (gnutls-hash-mac 'SHA256 (copy-sequence (string-to-unibyte key))
                   (string-to-unibyte data)))

(defun reticulum-hkdf (length ikm &optional salt context)
  "Derive LENGTH bytes from IKM with SALT and CONTEXT, as RNS.Cryptography.hkdf."
  (when (or (null length) (< length 1)) (error "Invalid HKDF output length"))
  (when (or (null ikm) (zerop (length ikm))) (error "Cannot derive key from empty input"))
  (let* ((salt (if (and salt (> (length salt) 0)) salt (make-string 32 0)))
         (context (or context ""))
         (prk (reticulum-hmac-sha256 salt ikm))
         (block "")
         (derived "")
         (i 0))
    (while (< (length derived) length)
      (setq block (reticulum-hmac-sha256 prk (reticulum-bytes block context (mod (1+ i) 256))))
      (setq derived (concat derived block))
      (cl-incf i))
    (substring derived 0 length)))

;;;; PKCS7 and Token

(defun reticulum-pkcs7-pad (data &optional block-size)
  "Pad DATA to a multiple of BLOCK-SIZE (default 16) with PKCS7."
  (let* ((bs (or block-size 16))
         (n (- bs (mod (length data) bs))))
    (concat data (make-string n n))))

(defun reticulum-pkcs7-unpad (data &optional block-size)
  "Remove PKCS7 padding from DATA."
  (let* ((bs (or block-size 16))
         (len (length data)))
    (when (or (zerop len) (not (zerop (mod len bs))))
      (error "Invalid padded data length"))
    (let ((n (aref data (1- len))))
      (when (or (zerop n) (> n bs) (> n len))
        (error "Invalid PKCS7 padding"))
      (dotimes (i n)
        (unless (= (aref data (- len 1 i)) n)
          (error "Invalid PKCS7 padding")))
      (substring data 0 (- len n)))))

(defun reticulum-aes-cbc-encrypt (key iv plaintext)
  "Encrypt PLAINTEXT (already padded) with AES-CBC under KEY and IV."
  (let ((cipher (pcase (length key)
                  (16 'AES-128-CBC)
                  (32 'AES-256-CBC)
                  (_ (error "Invalid AES key length %d" (length key))))))
    (car (gnutls-symmetric-encrypt cipher (copy-sequence key) (copy-sequence iv)
                                   (string-to-unibyte plaintext)))))

(defun reticulum-aes-cbc-decrypt (key iv ciphertext)
  "Decrypt CIPHERTEXT with AES-CBC under KEY and IV."
  (let ((cipher (pcase (length key)
                  (16 'AES-128-CBC)
                  (32 'AES-256-CBC)
                  (_ (error "Invalid AES key length %d" (length key))))))
    (car (gnutls-symmetric-decrypt cipher (copy-sequence key) (copy-sequence iv)
                                   (string-to-unibyte ciphertext)))))

(defconst reticulum-token-overhead 48
  "Bytes added by a token: 16 byte IV and 32 byte HMAC.")

(defun reticulum-token--keys (key)
  "Split token KEY into (SIGNING-KEY . ENCRYPTION-KEY)."
  (pcase (length key)
    (32 (cons (substring key 0 16) (substring key 16)))
    (64 (cons (substring key 0 32) (substring key 32)))
    (_ (error "Token key must be 32 or 64 bytes, not %d" (length key)))))

(defun reticulum-token-encrypt (key plaintext &optional iv)
  "Encrypt PLAINTEXT into a token under KEY.  IV is random unless given."
  (pcase-let ((`(,signing-key . ,encryption-key) (reticulum-token--keys key)))
    (let* ((iv (or iv (reticulum-random-bytes 16)))
           (ciphertext (reticulum-aes-cbc-encrypt encryption-key iv (reticulum-pkcs7-pad plaintext)))
           (signed (concat iv ciphertext)))
      (concat signed (reticulum-hmac-sha256 signing-key signed)))))

(defun reticulum-token-decrypt (key token)
  "Decrypt TOKEN under KEY, verifying its HMAC.  Signal an error if invalid."
  (pcase-let ((`(,signing-key . ,encryption-key) (reticulum-token--keys key)))
    (when (<= (length token) 32)
      (error "Token too short"))
    (let ((received (substring token -32))
          (expected (reticulum-hmac-sha256 signing-key (substring token 0 -32))))
      (unless (reticulum-bytes-equal received expected)
        (error "Token HMAC was invalid")))
    (let ((iv (substring token 0 16))
          (ciphertext (substring token 16 -32)))
      (reticulum-pkcs7-unpad (reticulum-aes-cbc-decrypt encryption-key iv ciphertext)))))

;;;; Field arithmetic modulo 2^255 - 19

(defconst reticulum--p (- (ash 1 255) 19))

(defun reticulum--fe-pow (base exponent)
  "Return BASE^EXPONENT modulo p by square and multiply."
  (let ((result 1) (b (mod base reticulum--p)) (e exponent))
    (while (> e 0)
      (when (= (logand e 1) 1)
        (setq result (mod (* result b) reticulum--p)))
      (setq b (mod (* b b) reticulum--p))
      (setq e (ash e -1)))
    result))

(defun reticulum--fe-inv (x)
  "Return the multiplicative inverse of X modulo p."
  (reticulum--fe-pow x (- reticulum--p 2)))

;;;; X25519

(defconst reticulum--x25519-a24 121665)

(defun reticulum-x25519-clamp (scalar-bytes)
  "Return the clamped scalar integer for 32 byte SCALAR-BYTES."
  (let ((k (copy-sequence scalar-bytes)))
    (aset k 0 (logand (aref k 0) 248))
    (aset k 31 (logior (logand (aref k 31) 127) 64))
    (reticulum-bytes-to-int k t)))

(defun reticulum-x25519-scalarmult (scalar-bytes u-bytes)
  "Multiply the Montgomery point with u coordinate U-BYTES by SCALAR-BYTES."
  (let* ((p reticulum--p)
         (k (reticulum-x25519-clamp scalar-bytes))
         (u (let ((b (copy-sequence u-bytes)))
              (aset b 31 (logand (aref b 31) 127))
              (mod (reticulum-bytes-to-int b t) p)))
         (x1 u) (x2 1) (z2 0) (x3 u) (z3 1) (swap 0))
    (cl-loop for i from 254 downto 0 do
             (let ((kt (logand (ash k (- i)) 1)))
               (setq swap (logxor swap kt))
               (when (= swap 1)
                 (cl-rotatef x2 x3)
                 (cl-rotatef z2 z3))
               (setq swap kt)
               (let* ((a (mod (+ x2 z2) p))
                      (aa (mod (* a a) p))
                      (b (mod (- x2 z2) p))
                      (bb (mod (* b b) p))
                      (e (mod (- aa bb) p))
                      (c (mod (+ x3 z3) p))
                      (d (mod (- x3 z3) p))
                      (da (mod (* d a) p))
                      (cb (mod (* c b) p)))
                 (setq x3 (mod (* (+ da cb) (+ da cb)) p))
                 (setq z3 (mod (* x1 (mod (* (- da cb) (- da cb)) p)) p))
                 (setq x2 (mod (* aa bb) p))
                 (setq z2 (mod (* e (+ aa (* reticulum--x25519-a24 e))) p)))))
    (when (= swap 1)
      (cl-rotatef x2 x3)
      (cl-rotatef z2 z3))
    (reticulum-int-to-bytes (mod (* x2 (reticulum--fe-inv z2)) p) 32 t)))

(defconst reticulum--x25519-basepoint (concat (unibyte-string 9) (make-string 31 0)))

(defun reticulum-x25519-generate-private ()
  "Return a fresh 32 byte X25519 private key."
  (reticulum-random-bytes 32))

(defun reticulum-x25519-public (private)
  "Return the 32 byte public key for X25519 PRIVATE key bytes."
  (reticulum-x25519-scalarmult private reticulum--x25519-basepoint))

(defun reticulum-x25519-shared (private peer-public)
  "Return the X25519 shared secret between PRIVATE and PEER-PUBLIC."
  (let ((shared (reticulum-x25519-scalarmult private peer-public)))
    (when (reticulum-bytes-equal shared (make-string 32 0))
      (error "X25519 produced an all-zero shared secret"))
    shared))

;;;; Ed25519

(defconst reticulum--ed-l (+ (ash 1 252) 27742317777372353535851937790883648493))
(defconst reticulum--ed-d
  (mod (* -121665 (reticulum--fe-inv 121666)) reticulum--p))
(defconst reticulum--ed-2d (mod (* 2 reticulum--ed-d) reticulum--p))
(defconst reticulum--ed-sqrt-m1
  (reticulum--fe-pow 2 (/ (- reticulum--p 1) 4)))

(defun reticulum--ed-recover-x (y sign)
  "Recover the x coordinate with parity SIGN for Y, or nil if invalid."
  (let* ((p reticulum--p)
         (y2 (mod (* y y) p))
         (u (mod (- y2 1) p))
         (v (mod (+ (* reticulum--ed-d y2) 1) p))
         (x2 (mod (* u (reticulum--fe-inv v)) p)))
    (if (zerop x2)
        (if (= sign 1) nil 0)
      (let ((x (reticulum--fe-pow x2 (/ (+ p 3) 8))))
        (unless (= (mod (* x x) p) x2)
          (setq x (mod (* x reticulum--ed-sqrt-m1) p)))
        (if (/= (mod (* x x) p) x2)
            nil
          (when (/= (logand x 1) sign)
            (setq x (- p x)))
          x)))))

(defconst reticulum--ed-base
  (let* ((y (mod (* 4 (reticulum--fe-inv 5)) reticulum--p))
         (x (reticulum--ed-recover-x y 0)))
    (list x y 1 (mod (* x y) reticulum--p)))
  "The Ed25519 base point in extended coordinates (X Y Z T).")

(defun reticulum--ed-add (p1 p2)
  "Add extended points P1 and P2."
  (pcase-let ((`(,x1 ,y1 ,z1 ,t1) p1)
              (`(,x2 ,y2 ,z2 ,t2) p2)
              (p reticulum--p))
    (let* ((a (mod (* (- y1 x1) (- y2 x2)) p))
           (b (mod (* (+ y1 x1) (+ y2 x2)) p))
           (c (mod (* t1 reticulum--ed-2d t2) p))
           (d (mod (* 2 z1 z2) p))
           (e (- b a)) (f (- d c)) (g (+ d c)) (h (+ b a)))
      (list (mod (* e f) p) (mod (* g h) p) (mod (* f g) p) (mod (* e h) p)))))

(defun reticulum--ed-double (p1)
  "Double extended point P1."
  (pcase-let ((`(,x1 ,y1 ,z1 ,_t1) p1)
              (p reticulum--p))
    (let* ((a (mod (* x1 x1) p))
           (b (mod (* y1 y1) p))
           (c (mod (* 2 z1 z1) p))
           (h (+ a b))
           (e (- h (mod (* (+ x1 y1) (+ x1 y1)) p)))
           (g (- a b))
           (f (+ c g)))
      (list (mod (* e f) p) (mod (* g h) p) (mod (* f g) p) (mod (* e h) p)))))

(defun reticulum--ed-scalarmult (scalar point)
  "Multiply extended POINT by integer SCALAR."
  (let ((result (list 0 1 1 0))
        (bits (if (zerop scalar) 0 (1+ (logb scalar)))))
    (cl-loop for i from (1- bits) downto 0 do
             (setq result (reticulum--ed-double result))
             (when (= (logand (ash scalar (- i)) 1) 1)
               (setq result (reticulum--ed-add result point))))
    result))

(defun reticulum--ed-encode (point)
  "Encode extended POINT as 32 bytes."
  (pcase-let ((`(,x ,y ,z ,_t) point)
              (p reticulum--p))
    (let* ((zi (reticulum--fe-inv z))
           (xa (mod (* x zi) p))
           (ya (mod (* y zi) p)))
      (reticulum-int-to-bytes (logior ya (ash (logand xa 1) 255)) 32 t))))

(defun reticulum--ed-decode (bytes)
  "Decode 32 byte BYTES into an extended point, or nil if invalid."
  (when (= (length bytes) 32)
    (let* ((n (reticulum-bytes-to-int bytes t))
           (sign (logand (ash n -255) 1))
           (y (logand n (1- (ash 1 255)))))
      (when (< y reticulum--p)
        (let ((x (reticulum--ed-recover-x y sign)))
          (when x
            (list x y 1 (mod (* x y) reticulum--p))))))))

(defun reticulum--ed-secret-scalar (seed)
  "Return (SCALAR . PREFIX) derived from the 32 byte SEED."
  (let* ((h (reticulum-sha512 seed))
         (a (copy-sequence (substring h 0 32))))
    (aset a 0 (logand (aref a 0) 248))
    (aset a 31 (logior (logand (aref a 31) 63) 64))
    (cons (reticulum-bytes-to-int a t) (substring h 32))))

(defun reticulum-ed25519-generate-private ()
  "Return a fresh 32 byte Ed25519 private key seed."
  (reticulum-random-bytes 32))

(defun reticulum-ed25519-public (seed)
  "Return the 32 byte public key for Ed25519 private SEED."
  (reticulum--ed-encode (reticulum--ed-scalarmult (car (reticulum--ed-secret-scalar seed))
                                                  reticulum--ed-base)))

(defun reticulum-ed25519-sign (seed message &optional public)
  "Sign MESSAGE with Ed25519 private SEED.  PUBLIC may be supplied to save work."
  (pcase-let* ((`(,a . ,prefix) (reticulum--ed-secret-scalar seed))
               (public (or public (reticulum--ed-encode (reticulum--ed-scalarmult a reticulum--ed-base))))
               (r (mod (reticulum-bytes-to-int (reticulum-sha512 (concat prefix message)) t) reticulum--ed-l))
               (r-enc (reticulum--ed-encode (reticulum--ed-scalarmult r reticulum--ed-base)))
               (k (mod (reticulum-bytes-to-int (reticulum-sha512 (concat r-enc public message)) t) reticulum--ed-l))
               (s (mod (+ r (* k a)) reticulum--ed-l)))
    (concat r-enc (reticulum-int-to-bytes s 32 t))))

(defun reticulum-ed25519-verify (public signature message)
  "Return non-nil if SIGNATURE over MESSAGE is valid for Ed25519 PUBLIC key."
  (condition-case nil
      (and (= (length signature) 64)
           (let* ((a (reticulum--ed-decode public))
                  (r-enc (substring signature 0 32))
                  (r (reticulum--ed-decode r-enc))
                  (s (reticulum-bytes-to-int (substring signature 32) t)))
             (and a r (< s reticulum--ed-l)
                  (let* ((k (mod (reticulum-bytes-to-int
                                  (reticulum-sha512 (concat r-enc public message)) t)
                                 reticulum--ed-l))
                         (lhs (reticulum--ed-scalarmult s reticulum--ed-base))
                         (rhs (reticulum--ed-add r (reticulum--ed-scalarmult k a))))
                    (reticulum-bytes-equal (reticulum--ed-encode lhs)
                                           (reticulum--ed-encode rhs))))))
    (error nil)))

(provide 'reticulum-crypto)

;;; reticulum-crypto.el ends here
