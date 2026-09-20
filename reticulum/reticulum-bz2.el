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
;; has no built in bzip2 support, so this file implements the decoder in
;; Emacs Lisp: Huffman decoding, move-to-front, run length decoding, the
;; inverse Burrows-Wheeler transform and the CRC check, along the lines of
;; micro-bunzip.  Multiple concatenated streams and multiple blocks per
;; stream are handled; the obsolete "randomised" block flag is not.
;;
;; The `bzip2' command line utility can be used instead for decompression
;; by setting `reticulum-bz2-program'.  Compression (only needed to build
;; test resources) always uses the utility.

;;; Code:

(defgroup reticulum nil
  "Native Reticulum implementation."
  :group 'comm)

(defcustom reticulum-bz2-program nil
  "A bzip2 executable to decompress resources with, or nil.
When nil, resources are decompressed by the Lisp decoder.  Point this at
a `bzip2' binary to use it as a faster decompressor instead.  The same
program, or `bzip2' from `exec-path' when this is nil, is used for
`reticulum-bz2-compress', which has no Lisp implementation."
  :type '(choice (const :tag "Lisp decoder" nil) (string :tag "Program")))

(defconst reticulum-bz2--block-magic #x314159265359
  "The 48 bit magic that starts a compressed block.")

(defconst reticulum-bz2--end-magic #x177245385090
  "The 48 bit magic that ends a stream, followed by the combined CRC.")

(defconst reticulum-bz2--group-size 50
  "Number of symbols coded with the same Huffman table.")

(defconst reticulum-bz2--max-code-length 20
  "The longest Huffman code bzip2 permits.")

(defconst reticulum-bz2--crc-table
  (let ((table (make-vector 256 0)))
    (dotimes (i 256)
      (let ((c (ash i 24)))
        (dotimes (_ 8)
          (setq c (if (/= 0 (logand c #x80000000))
                      (logand (logxor (ash c 1) #x04c11db7) #xffffffff)
                    (logand (ash c 1) #xffffffff))))
        (aset table i c)))
    table)
  "Table for the non reflected CRC-32 (polynomial 0x04c11db7) bzip2 uses.")

;;;; Bit reader

;; The decoder keeps its input state in the lexical variables `bz-data'
;; (unibyte string), `bz-pos' (next byte to load), `bz-buf' (loaded bits)
;; and `bz-nbits' (how many of them are unread).  These macros expand in
;; place so the inner loops do not pay for function calls.

(defmacro reticulum-bz2--bits (n)
  "Return the next N bits of input, most significant first."
  `(progn
     (while (< bz-nbits ,n)
       (when (>= bz-pos (length bz-data))
         (error "bzip2: truncated input"))
       (setq bz-buf (logior (ash bz-buf 8) (aref bz-data bz-pos))
             bz-pos (1+ bz-pos)
             bz-nbits (+ bz-nbits 8)))
     (setq bz-nbits (- bz-nbits ,n))
     (prog1 (logand (ash bz-buf (- bz-nbits)) (1- (ash 1 ,n)))
       (setq bz-buf (logand bz-buf (1- (ash 1 bz-nbits)))))))

(defmacro reticulum-bz2--bit ()
  "Return the next input bit."
  `(progn
     (when (= bz-nbits 0)
       (when (>= bz-pos (length bz-data))
         (error "bzip2: truncated input"))
       (setq bz-buf (aref bz-data bz-pos)
             bz-pos (1+ bz-pos)
             bz-nbits 8))
     (setq bz-nbits (1- bz-nbits))
     (prog1 (logand (ash bz-buf (- bz-nbits)) 1)
       (setq bz-buf (logand bz-buf (1- (ash 1 bz-nbits)))))))

;;;; Huffman tables

(defun reticulum-bz2--huffman-table (lengths)
  "Build a canonical Huffman decoding table from the vector LENGTHS.
The table is a vector [LIMIT BASE PERMUTE MIN-LEN MAX-LEN]: a code of
length L is a symbol when its value is at most LIMIT[L], and the symbol is
then PERMUTE[value + BASE[L]]."
  (let* ((alpha-size (length lengths))
         (max-code-length reticulum-bz2--max-code-length)
         (counts (make-vector (+ max-code-length 2) 0))
         (limit (make-vector (+ max-code-length 2) 0))
         (base (make-vector (+ max-code-length 2) 0))
         (permute (make-vector alpha-size 0))
         (min-len max-code-length) (max-len 1))
    (dotimes (i alpha-size)
      (let ((len (aref lengths i)))
        (setq min-len (min min-len len) max-len (max max-len len))
        (aset counts len (1+ (aref counts len)))))
    (let ((index 0))
      (dotimes (len (1+ max-len))
        (when (> len 0)
          (dotimes (i alpha-size)
            (when (= (aref lengths i) len)
              (aset permute index i)
              (setq index (1+ index)))))))
    (let ((code 0) (index 0))
      (dotimes (len (1+ max-len))
        (when (>= len min-len)
          (aset base len (- index code))
          (aset limit len (+ code (aref counts len) -1))
          (setq index (+ index (aref counts len))
                code (ash (+ code (aref counts len)) 1)))))
    (vector limit base permute min-len max-len)))

;;;; Block decoding

(defun reticulum-bz2--decode-block (bz-data bz-pos bz-buf bz-nbits block-size)
  "Decode one block from the reader state and return its contents.
BZ-DATA, BZ-POS, BZ-BUF and BZ-NBITS are the bit reader state after the
block magic; BLOCK-SIZE is the stream's maximum block size.  The value is
a list (BYTES CRC POS BUF NBITS) with the block's CRC as stored in the
stream and the reader state after the block."
  (let* ((stored-crc (reticulum-bz2--bits 32))
         (randomised (reticulum-bz2--bit))
         (orig-ptr (reticulum-bz2--bits 24))
         (seq-to-unseq (make-vector 256 0))
         (sym-total 0))
    (when (= randomised 1)
      (error "bzip2: randomised blocks are not supported"))
    ;; Which byte values occur in the block.
    (let ((used-map (reticulum-bz2--bits 16)))
      (dotimes (i 16)
        (when (/= 0 (logand used-map (ash 1 (- 15 i))))
          (let ((sub (reticulum-bz2--bits 16)))
            (dotimes (j 16)
              (when (/= 0 (logand sub (ash 1 (- 15 j))))
                (aset seq-to-unseq sym-total (+ (* i 16) j))
                (setq sym-total (1+ sym-total))))))))
    (when (= sym-total 0)
      (error "bzip2: block uses no symbols"))
    (let* ((alpha-size (+ sym-total 2))
           (n-groups (reticulum-bz2--bits 3))
           (n-selectors (reticulum-bz2--bits 15))
           (selectors (make-vector (max n-selectors 1) 0))
           (tables (make-vector (max n-groups 1) nil))
           (mtf (make-vector 256 0)))
      (unless (<= 2 n-groups 6)
        (error "bzip2: bad number of Huffman groups %d" n-groups))
      (when (< n-selectors 1)
        (error "bzip2: no selectors"))
      ;; Selectors, move-to-front coded.
      (dotimes (i n-groups) (aset mtf i i))
      (dotimes (i n-selectors)
        (let ((j 0))
          (while (= (reticulum-bz2--bit) 1)
            (setq j (1+ j))
            (when (>= j n-groups)
              (error "bzip2: bad selector")))
          (let ((v (aref mtf j)))
            (while (> j 0)
              (aset mtf j (aref mtf (1- j)))
              (setq j (1- j)))
            (aset mtf 0 v)
            (aset selectors i v))))
      ;; Delta coded code lengths, one table per group.
      (dotimes (g n-groups)
        (let ((lengths (make-vector alpha-size 0))
              (len (reticulum-bz2--bits 5)))
          (dotimes (i alpha-size)
            (while (progn
                     (unless (<= 1 len reticulum-bz2--max-code-length)
                       (error "bzip2: bad code length %d" len))
                     (= (reticulum-bz2--bit) 1))
              (setq len (if (= (reticulum-bz2--bit) 0) (1+ len) (1- len))))
            (aset lengths i len))
          (aset tables g (reticulum-bz2--huffman-table lengths))))
      ;; Huffman decode into MTF/RLE2 symbols, undoing both as we go.
      (let ((tt (make-vector block-size 0))
            (byte-count (make-vector 256 0))
            (count 0)
            (run 0) (run-pos 0)
            (group-left 0) (selector 0)
            (limit nil) (base nil) (permute nil) (min-len 0) (max-len 0)
            (eob (1- alpha-size))
            (done nil))
        (dotimes (i sym-total) (aset mtf i i))
        (while (not done)
          (when (= group-left 0)
            (when (>= selector n-selectors)
              (error "bzip2: ran out of selectors"))
            (let ((table (aref tables (aref selectors selector))))
              (setq limit (aref table 0) base (aref table 1) permute (aref table 2)
                    min-len (aref table 3) max-len (aref table 4)
                    selector (1+ selector)
                    group-left reticulum-bz2--group-size)))
          (setq group-left (1- group-left))
          (let* ((len min-len)
                 (code (reticulum-bz2--bits min-len))
                 (sym nil))
            (while (> code (aref limit len))
              (setq len (1+ len))
              (when (> len max-len)
                (error "bzip2: bad Huffman code"))
              (setq code (logior (ash code 1) (reticulum-bz2--bit))))
            (setq sym (aref permute (+ code (aref base len))))
            (cond
             ((<= sym 1)
              ;; RUNA / RUNB: bijective base 2 digits of a run length.
              (setq run (+ run (ash (1+ sym) run-pos))
                    run-pos (1+ run-pos)))
             (t
              (when (> run-pos 0)
                (when (> (+ count run) block-size)
                  (error "bzip2: block overflow"))
                (let ((byte (aref seq-to-unseq (aref mtf 0))))
                  (aset byte-count byte (+ (aref byte-count byte) run))
                  (dotimes (_ run)
                    (aset tt count byte)
                    (setq count (1+ count))))
                (setq run 0 run-pos 0))
              (if (= sym eob)
                  (setq done t)
                (when (>= count block-size)
                  (error "bzip2: block overflow"))
                (let* ((idx (1- sym))
                       (v (aref mtf idx))
                       (byte (aref seq-to-unseq v)))
                  (while (> idx 0)
                    (aset mtf idx (aref mtf (1- idx)))
                    (setq idx (1- idx)))
                  (aset mtf 0 v)
                  (aset byte-count byte (1+ (aref byte-count byte)))
                  (aset tt count byte)
                  (setq count (1+ count))))))))
        (when (>= orig-ptr (max count 1))
          (error "bzip2: bad origin pointer"))
        ;; Inverse BWT: T[i] is the row that follows row i.
        (let ((sum 0))
          (dotimes (b 256)
            (let ((n (aref byte-count b)))
              (aset byte-count b sum)
              (setq sum (+ sum n)))))
        (let ((next (make-vector count 0)))
          (dotimes (i count)
            (let ((b (aref tt i)))
              (aset next (aref byte-count b) i)
              (aset byte-count b (1+ (aref byte-count b)))))
          ;; Walk the transform, undoing the initial run length coding and
          ;; computing the CRC of the result.
          (let* ((out (make-string (max 16 (* 2 count)) 0))
                 (out-len 0)
                 (crc #xffffffff)
                 (table reticulum-bz2--crc-table)
                 (pos (if (> count 0) (aref next orig-ptr) 0))
                 (last -1) (repeat 0))
            (dotimes (_ count)
              (let ((b (aref tt pos)))
                (setq pos (aref next pos))
                (if (= repeat 4)
                    (progn
                      (when (> (+ out-len b) (length out))
                        (setq out (concat out (make-string (max (length out) b) 0))))
                      (dotimes (_ b)
                        (aset out out-len last)
                        (setq out-len (1+ out-len)
                              crc (logxor (logand (ash crc 8) #xffffffff)
                                          (aref table (logand (logxor (ash crc -24) last) #xff)))))
                      (setq repeat 0 last -1))
                  (when (>= out-len (length out))
                    (setq out (concat out (make-string (length out) 0))))
                  (aset out out-len b)
                  (setq out-len (1+ out-len)
                        crc (logxor (logand (ash crc 8) #xffffffff)
                                    (aref table (logand (logxor (ash crc -24) b) #xff))))
                  (if (= b last)
                      (setq repeat (1+ repeat))
                    (setq last b repeat 1)))))
            (setq crc (logxor crc #xffffffff))
            (unless (= crc stored-crc)
              (error "bzip2: block CRC mismatch"))
            (list (substring out 0 out-len) crc bz-pos bz-buf bz-nbits)))))))

(defun reticulum-bz2--decompress (data)
  "Decompress the unibyte bzip2 stream DATA with the Lisp decoder."
  (let ((bz-data data) (bz-pos 0) (bz-buf 0) (bz-nbits 0)
        (chunks nil))
    (while (< bz-pos (length bz-data))
      (unless (and (<= (+ bz-pos 4) (length bz-data))
                   (string-prefix-p "BZh" (substring bz-data bz-pos (+ bz-pos 3))))
        (error "bzip2: bad stream header"))
      (let ((level (- (aref bz-data (+ bz-pos 3)) ?0))
            (combined 0)
            (done nil))
        (unless (<= 1 level 9)
          (error "bzip2: bad block size level"))
        (setq bz-pos (+ bz-pos 4) bz-buf 0 bz-nbits 0)
        (while (not done)
          (let ((magic (logior (ash (reticulum-bz2--bits 24) 24) (reticulum-bz2--bits 24))))
            (cond
             ((= magic reticulum-bz2--block-magic)
              (let ((result (reticulum-bz2--decode-block bz-data bz-pos bz-buf bz-nbits
                                                         (* level 100000))))
                (push (nth 0 result) chunks)
                (setq combined (logxor (logand (logior (ash combined 1) (ash combined -31)) #xffffffff)
                                       (nth 1 result))
                      bz-pos (nth 2 result) bz-buf (nth 3 result) bz-nbits (nth 4 result))))
             ((= magic reticulum-bz2--end-magic)
              (unless (= (reticulum-bz2--bits 32) combined)
                (error "bzip2: stream CRC mismatch"))
              ;; The stream is padded to a byte boundary.
              (setq bz-buf 0 bz-nbits 0 done t))
             (t (error "bzip2: bad block magic")))))))
    (apply #'concat (nreverse chunks))))

;;;; Public interface

(defun reticulum-bz2--program ()
  "Return the bzip2 program to run for compression."
  (or reticulum-bz2-program "bzip2"))

(defun reticulum-bz2-available-p ()
  "Return non-nil if a bzip2 program can be found.
Decompression never needs one; compression does."
  (and (executable-find (reticulum-bz2--program)) t))

(defun reticulum-bz2--call (data &rest flags)
  "Run the bzip2 program with FLAGS over unibyte DATA and return its output."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert data)
    (let ((coding-system-for-read 'binary)
          (coding-system-for-write 'binary)
          (process-connection-type nil))
      (let ((status (apply #'call-process-region (point-min) (point-max) (reticulum-bz2--program)
                           t (list t nil) nil flags)))
        (unless (eq status 0)
          (error "bzip2 failed with status %s" status))))
    (buffer-string)))

(defun reticulum-bz2-decompress (data)
  "Return the bzip2 decompression of unibyte string DATA.
The Lisp decoder is used unless `reticulum-bz2-program' names a program
that can be found."
  (if (and reticulum-bz2-program (executable-find reticulum-bz2-program))
      (reticulum-bz2--call data "-dc")
    (reticulum-bz2--decompress data)))

(defun reticulum-bz2-compress (data)
  "Return the bzip2 compression of unibyte string DATA.
This runs the bzip2 program (see `reticulum-bz2-available-p')."
  (reticulum-bz2--call data "-c"))

(provide 'reticulum-bz2)

;;; reticulum-bz2.el ends here
