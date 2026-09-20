;;; reticulum-bz2.el --- bzip2 decompression for resources  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; Reticulum compresses resources with bzip2 when that saves space.  Emacs
;; has no built in bzip2 support, so decompression uses the `bzip2'
;; command line utility, which ships with macOS and every common Linux
;; distribution.  Set `reticulum-bz2-program' if it lives elsewhere.

;;; Code:

(defgroup reticulum nil
  "Native Reticulum implementation."
  :group 'comm)

(defcustom reticulum-bz2-program "bzip2"
  "The bzip2 executable used to decompress resources."
  :type 'string)

(defun reticulum-bz2-available-p ()
  "Return non-nil if the bzip2 program can be found."
  (and (executable-find reticulum-bz2-program) t))

(defun reticulum-bz2-decompress (data)
  "Return the bzip2 decompression of unibyte string DATA."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert data)
    (let ((coding-system-for-read 'binary)
          (coding-system-for-write 'binary)
          (process-connection-type nil))
      (let ((status (call-process-region (point-min) (point-max) reticulum-bz2-program
                                         t (list t nil) nil "-dc")))
        (unless (eq status 0)
          (error "bzip2 decompression failed with status %s" status))))
    (buffer-string)))

(defun reticulum-bz2-compress (data)
  "Return the bzip2 compression of unibyte string DATA."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert data)
    (let ((coding-system-for-read 'binary)
          (coding-system-for-write 'binary)
          (process-connection-type nil))
      (let ((status (call-process-region (point-min) (point-max) reticulum-bz2-program
                                         t (list t nil) nil "-c")))
        (unless (eq status 0)
          (error "bzip2 compression failed with status %s" status))))
    (buffer-string)))

(provide 'reticulum-bz2)

;;; reticulum-bz2.el ends here
