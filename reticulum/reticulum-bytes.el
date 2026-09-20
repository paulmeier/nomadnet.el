;;; reticulum-bytes.el --- Byte string helpers for Reticulum  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; Byte strings are represented as unibyte Emacs strings throughout the
;; native Reticulum implementation.  This file collects the small helpers
;; that every other layer needs: hex conversion, integer conversion in
;; both byte orders, concatenation that stays unibyte, and random bytes.

;;; Code:

(require 'cl-lib)

(defun reticulum-bytes (&rest parts)
  "Concatenate PARTS into a unibyte string.
Each part may be a unibyte string, a list or vector of byte values, or
an integer byte."
  (let ((out (make-string 0 0)))
    (dolist (part parts)
      (setq out (concat out (cond ((stringp part) (string-to-unibyte part))
                                  ((integerp part) (unibyte-string part))
                                  (t (apply #'unibyte-string (append part nil)))))))
    (string-to-unibyte out)))

(defun reticulum-bytes-p (object)
  "Return non-nil if OBJECT is a unibyte string."
  (and (stringp object) (not (multibyte-string-p object))))

(defun reticulum-hex (bytes &optional delimit)
  "Return the hexadecimal representation of BYTES.
With DELIMIT, wrap it in angle brackets as RNS.prettyhexrep does."
  (let ((hex (mapconcat (lambda (b) (format "%02x" b)) bytes "")))
    (if delimit (concat "<" hex ">") hex)))

(defun reticulum-unhex (hex)
  "Return the unibyte string encoded by hexadecimal HEX."
  (let ((hex (replace-regexp-in-string "[^0-9a-fA-F]" "" hex)))
    (unless (cl-evenp (length hex))
      (error "Odd-length hex string"))
    (let ((out (make-string (/ (length hex) 2) 0)))
      (dotimes (i (length out))
        (aset out i (string-to-number (substring hex (* 2 i) (+ 2 (* 2 i))) 16)))
      out)))

(defun reticulum-bytes-to-int (bytes &optional little-endian)
  "Convert BYTES to an unsigned integer, big-endian unless LITTLE-ENDIAN."
  (let ((n 0))
    (if little-endian
        (cl-loop for i from (1- (length bytes)) downto 0
                 do (setq n (logior (ash n 8) (aref bytes i))))
      (cl-loop for b across bytes
               do (setq n (logior (ash n 8) b))))
    n))

(defun reticulum-int-to-bytes (n length &optional little-endian)
  "Encode non-negative integer N as LENGTH bytes, big-endian unless LITTLE-ENDIAN."
  (when (< n 0) (error "Cannot encode negative integer %s" n))
  (let ((out (make-string length 0)))
    (dotimes (i length)
      (let ((byte (logand (ash n (- (* 8 i))) #xff)))
        (aset out (if little-endian i (- length 1 i)) byte)))
    (when (> (ash n (- (* 8 length))) 0)
      (error "Integer %s does not fit in %d bytes" n length))
    out))

(defun reticulum-random-bytes (n)
  "Return N cryptographically random bytes from the operating system."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((status (call-process "head" nil t nil "-c" (number-to-string n) "/dev/urandom")))
      (unless (and (eq status 0) (= (buffer-size) n))
        (error "Could not read %d random bytes from /dev/urandom" n)))
    (buffer-string)))

(defun reticulum-bytes-equal (a b)
  "Return non-nil if byte strings A and B are equal."
  (and (= (length a) (length b))
       (let ((diff 0))
         (dotimes (i (length a))
           (setq diff (logior diff (logxor (aref a i) (aref b i)))))
         (zerop diff))))

(defun reticulum-utf8 (string)
  "Encode multibyte STRING as UTF-8 bytes."
  (string-to-unibyte (encode-coding-string string 'utf-8 t)))

(defun reticulum-decode-utf8 (bytes)
  "Decode UTF-8 BYTES into a multibyte string, replacing invalid sequences."
  (string-to-multibyte (decode-coding-string bytes 'utf-8 t)))

(defvar reticulum-log-buffer-name "*reticulum-log*")

(defcustom reticulum-log-level 4
  "Verbosity of the Reticulum log buffer: 0 critical … 4 info, 5 verbose, 6 debug."
  :type 'integer
  :group 'comm)

(defun reticulum-log (level format-string &rest args)
  "Log a message at LEVEL (an integer) formatted from FORMAT-STRING and ARGS.
Messages at level 2 and below are also shown in the echo area."
  (when (<= level reticulum-log-level)
    (let ((text (apply #'format format-string args)))
      (with-current-buffer (get-buffer-create reticulum-log-buffer-name)
        (goto-char (point-max))
        (insert (format-time-string "[%Y-%m-%d %H:%M:%S] ") text "\n")
        (when (> (buffer-size) 500000)
          (delete-region (point-min) (- (point-max) 400000))))
      (when (<= level 2)
        (reticulum-log 1 "%s" text)))))

(provide 'reticulum-bytes)

;;; reticulum-bytes.el ends here
