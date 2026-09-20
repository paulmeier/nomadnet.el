;;; reticulum-msgpack.el --- MessagePack codec  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; A MessagePack encoder and decoder compatible with the umsgpack library
;; vendored by Reticulum.  Value mapping:
;;
;;   nil              <-> nil
;;   true / false     <-> t / :false
;;   integers         <-> integers (bignums for 64 bit values)
;;   float            <-> float (always encoded as 64 bit)
;;   bin              <-> unibyte string
;;   str              <-> multibyte string (UTF-8 on the wire)
;;   array            <-> list (vectors are also encoded as arrays)
;;   map              <-> hash table with `equal' test
;;
;; Text intended as a msgpack str must be a multibyte string; use
;; `reticulum-msgpack-str' to force that for ASCII literals.

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)

(defun reticulum-msgpack-str (string)
  "Return STRING as a multibyte string so that it packs as msgpack str."
  (string-to-multibyte string))

(defun reticulum-msgpack-map (&rest pairs)
  "Return a hash table for msgpack map from KEY VALUE PAIRS."
  (let ((table (make-hash-table :test #'equal)))
    (while pairs
      (puthash (pop pairs) (pop pairs) table))
    table))

;;;; Floats

(defconst reticulum-msgpack--two52 4503599627370496.0)

(defun reticulum-msgpack--float-bits (x)
  "Return the IEEE 754 binary64 bit pattern of float X as an integer."
  (cond
   ((isnan x) #x7ff8000000000000)
   ((= x 1.0e+INF) #x7ff0000000000000)
   ((= x -1.0e+INF) #xfff0000000000000)
   ((= x 0.0) (if (< (copysign 1.0 x) 0) (ash 1 63) 0))
   (t
    (let* ((sign (if (< x 0) 1 0))
           (ax (abs x))
           (fe (frexp ax))
           (m (car fe)) (e (cdr fe))
           (exp (+ e 1022)))
      (if (<= exp 0)
          ;; Subnormal: value = f * 2^-1074.
          (logior (ash sign 63) (truncate (ldexp ax 1074)))
        (let ((frac (truncate (* (- (* 2 m) 1.0) reticulum-msgpack--two52))))
          (logior (ash sign 63) (ash exp 52) frac)))))))

(defun reticulum-msgpack--bits-float (bits)
  "Return the float whose IEEE 754 binary64 bit pattern is BITS."
  (let* ((sign (if (zerop (logand bits (ash 1 63))) 1.0 -1.0))
         (exp (logand (ash bits -52) #x7ff))
         (frac (logand bits (1- (ash 1 52)))))
    (cond
     ((= exp #x7ff) (if (zerop frac) (* sign 1.0e+INF) 0.0e+NaN))
     ((zerop exp) (* sign (ldexp (float frac) -1074)))
     (t (* sign (ldexp (+ 1.0 (/ (float frac) reticulum-msgpack--two52)) (- exp 1023)))))))

(defun reticulum-msgpack--bits-float32 (bits)
  "Return the float whose IEEE 754 binary32 bit pattern is BITS."
  (let* ((sign (if (zerop (logand bits (ash 1 31))) 1.0 -1.0))
         (exp (logand (ash bits -23) #xff))
         (frac (logand bits (1- (ash 1 23)))))
    (cond
     ((= exp #xff) (if (zerop frac) (* sign 1.0e+INF) 0.0e+NaN))
     ((zerop exp) (* sign (ldexp (float frac) -149)))
     (t (* sign (ldexp (+ 1.0 (/ (float frac) 8388608.0)) (- exp 127)))))))

;;;; Packing

(defun reticulum-msgpack--pack-into (obj parts)
  "Push the encoding of OBJ onto PARTS (a list, in reverse order) and return it."
  (cl-flet ((emit (&rest bytes) (push (apply #'reticulum-bytes bytes) parts)))
    (cond
     ((null obj) (emit #xc0))
     ((eq obj t) (emit #xc3))
     ((eq obj :false) (emit #xc2))
     ((integerp obj)
      (cond
       ((and (>= obj 0) (<= obj 127)) (emit obj))
       ((and (< obj 0) (>= obj -32)) (emit (logand obj #xff)))
       ((>= obj 0)
        (cond ((<= obj #xff) (emit #xcc obj))
              ((<= obj #xffff) (emit #xcd (reticulum-int-to-bytes obj 2)))
              ((<= obj #xffffffff) (emit #xce (reticulum-int-to-bytes obj 4)))
              ((<= obj #xffffffffffffffff) (emit #xcf (reticulum-int-to-bytes obj 8)))
              (t (error "Integer too large for msgpack: %s" obj))))
       (t
        (cond ((>= obj -128) (emit #xd0 (logand obj #xff)))
              ((>= obj -32768) (emit #xd1 (reticulum-int-to-bytes (logand obj #xffff) 2)))
              ((>= obj (- (ash 1 31))) (emit #xd2 (reticulum-int-to-bytes (logand obj #xffffffff) 4)))
              ((>= obj (- (ash 1 63))) (emit #xd3 (reticulum-int-to-bytes (logand obj #xffffffffffffffff) 8)))
              (t (error "Integer too small for msgpack: %s" obj))))))
     ((floatp obj)
      (emit #xcb (reticulum-int-to-bytes (reticulum-msgpack--float-bits obj) 8)))
     ((stringp obj)
      (if (multibyte-string-p obj)
          (let* ((bytes (reticulum-utf8 obj)) (n (length bytes)))
            (cond ((<= n 31) (emit (logior #xa0 n) bytes))
                  ((<= n #xff) (emit #xd9 n bytes))
                  ((<= n #xffff) (emit #xda (reticulum-int-to-bytes n 2) bytes))
                  (t (emit #xdb (reticulum-int-to-bytes n 4) bytes))))
        (let ((n (length obj)))
          (cond ((<= n #xff) (emit #xc4 n obj))
                ((<= n #xffff) (emit #xc5 (reticulum-int-to-bytes n 2) obj))
                (t (emit #xc6 (reticulum-int-to-bytes n 4) obj))))))
     ((hash-table-p obj)
      (let ((n (hash-table-count obj)))
        (cond ((<= n 15) (emit (logior #x80 n)))
              ((<= n #xffff) (emit #xde (reticulum-int-to-bytes n 2)))
              (t (emit #xdf (reticulum-int-to-bytes n 4))))
        (maphash (lambda (k v)
                   (setq parts (reticulum-msgpack--pack-into k parts))
                   (setq parts (reticulum-msgpack--pack-into v parts)))
                 obj)))
     ((or (listp obj) (vectorp obj))
      (let ((n (length obj)))
        (cond ((<= n 15) (emit (logior #x90 n)))
              ((<= n #xffff) (emit #xdc (reticulum-int-to-bytes n 2)))
              (t (emit #xdd (reticulum-int-to-bytes n 4))))
        (mapc (lambda (item) (setq parts (reticulum-msgpack--pack-into item parts))) obj)))
     (t (error "Cannot msgpack object: %S" obj))))
  parts)

(defun reticulum-msgpack-pack (obj)
  "Return the MessagePack encoding of OBJ as a unibyte string."
  (apply #'reticulum-bytes (nreverse (reticulum-msgpack--pack-into obj nil))))

;;;; Unpacking

(defun reticulum-msgpack--read (bytes pos)
  "Decode one object from BYTES at POS.  Return (VALUE . NEXT-POS)."
  (when (>= pos (length bytes))
    (error "Truncated msgpack data"))
  (let ((b (aref bytes pos)))
    (cl-flet ((uint (n) (reticulum-bytes-to-int (substring bytes (1+ pos) (+ 1 pos n))))
              (sint (n) (let ((v (reticulum-bytes-to-int (substring bytes (1+ pos) (+ 1 pos n)))))
                          (if (>= v (ash 1 (1- (* 8 n)))) (- v (ash 1 (* 8 n))) v)))
              (raw (start n) (substring bytes start (+ start n)))
              (items (start n)
                (let ((out nil) (p start))
                  (dotimes (_ n)
                    (let ((r (reticulum-msgpack--read bytes p)))
                      (push (car r) out)
                      (setq p (cdr r))))
                  (cons (nreverse out) p)))
              (pairs (start n)
                (let ((table (make-hash-table :test #'equal)) (p start))
                  (dotimes (_ n)
                    (let* ((k (reticulum-msgpack--read bytes p))
                           (v (reticulum-msgpack--read bytes (cdr k))))
                      (puthash (car k) (car v) table)
                      (setq p (cdr v))))
                  (cons table p))))
      (cond
       ((<= b #x7f) (cons b (1+ pos)))
       ((>= b #xe0) (cons (- b 256) (1+ pos)))
       ((<= #x80 b #x8f) (pairs (1+ pos) (logand b #x0f)))
       ((<= #x90 b #x9f) (items (1+ pos) (logand b #x0f)))
       ((<= #xa0 b #xbf)
        (let ((n (logand b #x1f)))
          (cons (reticulum-decode-utf8 (raw (1+ pos) n)) (+ 1 pos n))))
       (t
        (pcase b
          (#xc0 (cons nil (1+ pos)))
          (#xc2 (cons :false (1+ pos)))
          (#xc3 (cons t (1+ pos)))
          (#xc4 (let ((n (uint 1))) (cons (raw (+ pos 2) n) (+ pos 2 n))))
          (#xc5 (let ((n (uint 2))) (cons (raw (+ pos 3) n) (+ pos 3 n))))
          (#xc6 (let ((n (uint 4))) (cons (raw (+ pos 5) n) (+ pos 5 n))))
          (#xca (cons (reticulum-msgpack--bits-float32 (uint 4)) (+ pos 5)))
          (#xcb (cons (reticulum-msgpack--bits-float (uint 8)) (+ pos 9)))
          (#xcc (cons (uint 1) (+ pos 2)))
          (#xcd (cons (uint 2) (+ pos 3)))
          (#xce (cons (uint 4) (+ pos 5)))
          (#xcf (cons (uint 8) (+ pos 9)))
          (#xd0 (cons (sint 1) (+ pos 2)))
          (#xd1 (cons (sint 2) (+ pos 3)))
          (#xd2 (cons (sint 4) (+ pos 5)))
          (#xd3 (cons (sint 8) (+ pos 9)))
          (#xd9 (let ((n (uint 1))) (cons (reticulum-decode-utf8 (raw (+ pos 2) n)) (+ pos 2 n))))
          (#xda (let ((n (uint 2))) (cons (reticulum-decode-utf8 (raw (+ pos 3) n)) (+ pos 3 n))))
          (#xdb (let ((n (uint 4))) (cons (reticulum-decode-utf8 (raw (+ pos 5) n)) (+ pos 5 n))))
          (#xdc (items (+ pos 3) (uint 2)))
          (#xdd (items (+ pos 5) (uint 4)))
          (#xde (pairs (+ pos 3) (uint 2)))
          (#xdf (pairs (+ pos 5) (uint 4)))
          (_ (error "Unsupported msgpack type byte %02x" b))))))))

(defun reticulum-msgpack-unpack (bytes &optional allow-trailing)
  "Decode the MessagePack object in unibyte string BYTES.
Signal an error on trailing data unless ALLOW-TRAILING is non-nil."
  (let ((result (reticulum-msgpack--read bytes 0)))
    (when (and (not allow-trailing) (< (cdr result) (length bytes)))
      (error "Trailing data after msgpack object"))
    (car result)))

(provide 'reticulum-msgpack)

;;; reticulum-msgpack.el ends here
