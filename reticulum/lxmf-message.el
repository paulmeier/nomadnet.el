;;; lxmf-message.el --- LXMF message format  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; The LXMF message format (LXMF 1.1), written from the protocol:
;;
;;   dest(16) || source(16) || signature(64) || msgpack([timestamp, title, content, fields, stamp?])
;;
;; The message hash is sha256(dest || source || packed payload without
;; the stamp).  The signature is by the source's identity over the hashed
;; part followed by the hash.  Title and content are byte strings; the
;; `-string' accessors decode them as UTF-8.  Fields is a msgpack map
;; (a hash table here) whose well known keys are the `lxmf-field-*'
;; constants.
;;
;; Also here: the peer announce app data helpers, since the format is
;; part of LXMF: msgpack `[display_name, stamp_cost, [SF_COMPRESSION]]',
;; or a plain UTF-8 display name from LXMF versions before 0.5.

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)
(require 'reticulum-crypto)
(require 'reticulum-msgpack)
(require 'reticulum-identity)

;;;; Constants

(defconst lxmf-app-name "lxmf")
(defconst lxmf-destination-length 16)
(defconst lxmf-signature-length 64)
(defconst lxmf-ticket-length 16)
(defconst lxmf-timestamp-size 8)
(defconst lxmf-struct-overhead 8)
(defconst lxmf-overhead (+ (* 2 lxmf-destination-length) lxmf-signature-length
                           lxmf-timestamp-size lxmf-struct-overhead)
  "Bytes of overhead per message: hashes, signature, timestamp, msgpack structure.")

;; Size limits with default RNS parameters.
(defconst lxmf-encrypted-packet-mdu
  (+ (1- (* 16 (floor (- reticulum-mdu reticulum-token-overhead 32) 16))) lxmf-timestamp-size)
  "Largest payload of an encrypted packet, plus the timestamp: 391 bytes.")
(defconst lxmf-encrypted-packet-max-content
  (+ (- lxmf-encrypted-packet-mdu lxmf-overhead) lxmf-destination-length)
  "Largest content that fits an opportunistic single packet message.")
(defconst lxmf-link-packet-mdu (1- (* 16 (floor (- reticulum-mtu reticulum-ifac-min-size reticulum-header-minsize
                                                   reticulum-token-overhead)
                                                16))))
(defconst lxmf-link-packet-max-content (- lxmf-link-packet-mdu lxmf-overhead)
  "Largest content that fits a single packet on a link.")

;; Delivery methods.
(defconst lxmf-method-opportunistic #x01)
(defconst lxmf-method-direct #x02)
(defconst lxmf-method-propagated #x03)
(defconst lxmf-method-paper #x05)

;; States.
(defconst lxmf-state-generating #x00)
(defconst lxmf-state-outbound #x01)
(defconst lxmf-state-sending #x02)
(defconst lxmf-state-sent #x04)
(defconst lxmf-state-delivered #x08)
(defconst lxmf-state-rejected #xfd)
(defconst lxmf-state-cancelled #xfe)
(defconst lxmf-state-failed #xff)

;; Reasons a signature could not be verified.
(defconst lxmf-source-unknown #x01)
(defconst lxmf-signature-invalid #x02)

;; Message fields.
(defconst lxmf-field-embedded-lxms #x01)
(defconst lxmf-field-telemetry #x02)
(defconst lxmf-field-telemetry-stream #x03)
(defconst lxmf-field-icon-appearance #x04)
(defconst lxmf-field-file-attachments #x05)
(defconst lxmf-field-image #x06)
(defconst lxmf-field-audio #x07)
(defconst lxmf-field-thread #x08)
(defconst lxmf-field-commands #x09)
(defconst lxmf-field-results #x0a)
(defconst lxmf-field-group #x0b)
(defconst lxmf-field-ticket #x0c)
(defconst lxmf-field-event #x0d)
(defconst lxmf-field-rnr-refs #x0e)
(defconst lxmf-field-renderer #x0f)
(defconst lxmf-field-reply-to #x30)
(defconst lxmf-field-reply-quote #x31)
(defconst lxmf-field-reaction #x40)
(defconst lxmf-field-comment #x41)
(defconst lxmf-field-continuation #x42)
(defconst lxmf-field-custom-type #xfb)
(defconst lxmf-field-custom-data #xfc)
(defconst lxmf-field-custom-meta #xfd)
(defconst lxmf-field-non-specific #xfe)
(defconst lxmf-field-debug #xff)

;; Values for `lxmf-field-renderer'.
(defconst lxmf-renderer-plain #x00)
(defconst lxmf-renderer-micron #x01)
(defconst lxmf-renderer-markdown #x02)
(defconst lxmf-renderer-bbcode #x03)

;; Supported functionality codes announced by peers.
(defconst lxmf-sf-compression #x00)

;;;; Structure

(cl-defstruct (lxmf-message (:constructor lxmf-message--make) (:copier nil))
  destination-hash source-hash
  (title "") (content "") fields
  timestamp stamp
  hash signature packed
  (signature-validated nil) unverified-reason
  ;; Delivery bookkeeping.
  (state 0) method incoming ratchet-id (transport-encrypted nil) transport-encryption
  (stamp-valid nil) (stamp-checked nil) received-at)

(defun lxmf-message--bytes (value)
  "Return VALUE as bytes: multibyte strings are UTF-8 encoded, nil is empty."
  (cond ((null value) (string-to-unibyte ""))
        ((multibyte-string-p value) (reticulum-utf8 value))
        (t value)))

(defun lxmf-message--fields (fields)
  "Return FIELDS as a hash table, creating an empty one for nil."
  (cond ((null fields) (make-hash-table :test #'equal))
        ((hash-table-p fields) fields)
        (t (error "LXMF fields must be a hash table or nil"))))

(defun lxmf-message-create (destination-hash source-hash &optional content title fields)
  "Create an outbound message from SOURCE-HASH to DESTINATION-HASH.
CONTENT and TITLE are strings or byte strings; FIELDS is a hash table
keyed by `lxmf-field-*' values or nil."
  (unless (= (length destination-hash) lxmf-destination-length)
    (error "Invalid LXMF destination hash"))
  (unless (= (length source-hash) lxmf-destination-length)
    (error "Invalid LXMF source hash"))
  (lxmf-message--make :destination-hash destination-hash :source-hash source-hash
                      :content (lxmf-message--bytes content)
                      :title (lxmf-message--bytes title)
                      :fields (lxmf-message--fields fields)))

(defun lxmf-message-title-string (message)
  "Return the title of MESSAGE decoded as UTF-8."
  (reticulum-decode-utf8 (lxmf-message-title message)))

(defun lxmf-message-content-string (message)
  "Return the content of MESSAGE decoded as UTF-8."
  (reticulum-decode-utf8 (lxmf-message-content message)))

(defun lxmf-message-field (message field)
  "Return the value of FIELD in MESSAGE, or nil."
  (let ((fields (lxmf-message-fields message)))
    (and fields (gethash field fields))))

(defun lxmf-message-set-field (message field value)
  "Set FIELD of MESSAGE to VALUE."
  (unless (lxmf-message-fields message)
    (setf (lxmf-message-fields message) (make-hash-table :test #'equal)))
  (puthash field value (lxmf-message-fields message)))

(defun lxmf-message-describe (message)
  "Return a short description of MESSAGE."
  (if (lxmf-message-hash message)
      (format "<LXMessage %s>" (reticulum-hex (lxmf-message-hash message)))
    "<LXMessage>"))

;;;; Packing

(defun lxmf-message--payload (message &optional with-stamp)
  "Return the payload list of MESSAGE, appending its stamp WITH-STAMP."
  (let ((payload (list (lxmf-message-timestamp message)
                       (lxmf-message-title message)
                       (lxmf-message-content message)
                       (lxmf-message--fields (lxmf-message-fields message)))))
    (if (and with-stamp (lxmf-message-stamp message))
        (append payload (list (lxmf-message-stamp message)))
      payload)))

(defun lxmf-message-hashed-part (message &optional packed-payload)
  "Return the hashed part of MESSAGE: dest || source || payload without stamp.
PACKED-PAYLOAD is used instead of repacking the payload when given."
  (concat (lxmf-message-destination-hash message)
          (lxmf-message-source-hash message)
          (or packed-payload (reticulum-msgpack-pack (lxmf-message--payload message)))))

(defun lxmf-message-pack (message source-identity &optional timestamp)
  "Pack MESSAGE, signing it with SOURCE-IDENTITY.  Return the packed bytes.
TIMESTAMP defaults to the message timestamp or now.  The stamp, if set on
the message, is included in the payload."
  (setf (lxmf-message-timestamp message)
        (float (or timestamp (lxmf-message-timestamp message) (float-time))))
  (let* ((hashed (lxmf-message-hashed-part message))
         (hash (reticulum-full-hash hashed))
         (signature (reticulum-identity-sign source-identity (concat hashed hash)))
         (packed (concat (lxmf-message-destination-hash message)
                         (lxmf-message-source-hash message)
                         signature
                         (reticulum-msgpack-pack (lxmf-message--payload message t)))))
    (setf (lxmf-message-hash message) hash
          (lxmf-message-signature message) signature
          (lxmf-message-signature-validated message) t
          (lxmf-message-unverified-reason message) nil
          (lxmf-message-packed message) packed)
    packed))

;;;; Unpacking

(defun lxmf-message-validate (message identity)
  "Check the signature of MESSAGE against source IDENTITY and record the result."
  (let* ((hashed (lxmf-message-hashed-part message))
         (valid (reticulum-identity-validate identity (lxmf-message-signature message)
                                             (concat hashed (lxmf-message-hash message)))))
    (setf (lxmf-message-signature-validated message) (and valid t)
          (lxmf-message-unverified-reason message) (if valid nil lxmf-signature-invalid))
    valid))

(defun lxmf-message-unpack (bytes &optional method)
  "Unpack the LXMF message in BYTES received by METHOD.
Signals an error if the bytes are not a message.  The signature is
verified when the source identity is known from an announce; otherwise
`lxmf-message-unverified-reason' is `lxmf-source-unknown'."
  (let ((min (+ (* 2 lxmf-destination-length) lxmf-signature-length)))
    (when (< (length bytes) (1+ min))
      (error "LXMF data too short"))
    (let* ((destination-hash (substring bytes 0 lxmf-destination-length))
           (source-hash (substring bytes lxmf-destination-length (* 2 lxmf-destination-length)))
           (signature (substring bytes (* 2 lxmf-destination-length) min))
           (packed-payload (substring bytes min))
           (payload (reticulum-msgpack-unpack packed-payload))
           (stamp nil))
      (unless (and (listp payload) (>= (length payload) 4))
        (error "Invalid LXMF payload"))
      (when (> (length payload) 4)
        (setq stamp (nth 4 payload)
              payload (seq-take payload 4)
              packed-payload (reticulum-msgpack-pack payload)))
      (let* ((message (lxmf-message--make
                       :destination-hash destination-hash :source-hash source-hash
                       :signature signature
                       :timestamp (nth 0 payload)
                       :title (lxmf-message--bytes (nth 1 payload))
                       :content (lxmf-message--bytes (nth 2 payload))
                       :fields (lxmf-message--fields (nth 3 payload))
                       :stamp stamp
                       :packed bytes
                       :incoming t :method method
                       :received-at (float-time)))
             (hashed (lxmf-message-hashed-part message packed-payload))
             (source (reticulum-identity-recall source-hash)))
        (setf (lxmf-message-hash message) (reticulum-full-hash hashed))
        (if source
            (lxmf-message-validate message source)
          (setf (lxmf-message-signature-validated message) nil
                (lxmf-message-unverified-reason message) lxmf-source-unknown))
        message))))

;;;; Peer announce app data

(defun lxmf-peer-app-data (display-name &optional stamp-cost)
  "Return the announce app data for a delivery destination.
DISPLAY-NAME is a string or nil; STAMP-COST an integer from 1 to 254 or nil."
  (reticulum-msgpack-pack
   (list (and display-name (reticulum-utf8 display-name))
         (and (integerp stamp-cost) (> stamp-cost 0) (< stamp-cost 255) stamp-cost)
         (list lxmf-sf-compression))))

(defun lxmf-peer-app-data-p (app-data)
  "Return non-nil if APP-DATA uses the msgpack list format of LXMF 0.5 and later."
  (and app-data (> (length app-data) 0)
       (let ((b (aref app-data 0)))
         (or (<= #x90 b #x9f) (= b #xdc)))))

(defun lxmf-peer-app-data-unpack (app-data)
  "Return the peer data list in APP-DATA, or nil if not the list format."
  (when (lxmf-peer-app-data-p app-data)
    (condition-case nil
        (let ((v (reticulum-msgpack-unpack app-data t)))
          (and (listp v) v))
      (error nil))))

(defun lxmf-display-name-from-app-data (app-data)
  "Return the display name announced in peer APP-DATA, or nil.
Handles the list format and the plain string of LXMF before 0.5."
  (cond
   ((or (null app-data) (zerop (length app-data))) nil)
   ((lxmf-peer-app-data-p app-data)
    (let ((name (car (lxmf-peer-app-data-unpack app-data))))
      (cond ((null name) nil)
            ((stringp name)
             (string-trim (replace-regexp-in-string
                           "\0" "" (if (multibyte-string-p name) name (reticulum-decode-utf8 name)))))
            (t nil))))
   (t (condition-case nil (reticulum-decode-utf8 app-data) (error nil)))))

(defun lxmf-stamp-cost-from-app-data (app-data)
  "Return the stamp cost announced in peer APP-DATA, or nil."
  (let ((data (lxmf-peer-app-data-unpack app-data)))
    (and data (>= (length data) 2) (integerp (nth 1 data)) (nth 1 data))))

(defun lxmf-compression-support-from-app-data (app-data)
  "Return non-nil if the peer announcing APP-DATA accepts compressed messages.
Peers without the list format, or without a functionality list, do."
  (let ((data (lxmf-peer-app-data-unpack app-data)))
    (cond ((null data) t)
          ((< (length data) 3) t)
          ((not (listp (nth 2 data))) t)
          (t (and (memq lxmf-sf-compression (nth 2 data)) t)))))

(provide 'lxmf-message)

;;; lxmf-message.el ends here
