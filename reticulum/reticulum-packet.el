;;; reticulum-packet.el --- Reticulum packet codec  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; Packing, unpacking and hashing of Reticulum packets (RNS.Packet).
;;
;; Wire format:
;;   flags(1) hops(1) [transport_id(16)] destination(16) context(1) data
;;   flags = header_type<<6 | context_flag<<5 | transport_type<<4 | destination_type<<2 | packet_type

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)
(require 'reticulum-crypto)

;;;; Constants

(defconst reticulum-mtu 500)
(defconst reticulum-truncated-hash-length 16 "Destination hash length in bytes.")
(defconst reticulum-header-maxsize (+ 2 1 (* 2 reticulum-truncated-hash-length)))
(defconst reticulum-header-minsize (+ 2 1 reticulum-truncated-hash-length))
(defconst reticulum-ifac-min-size 1)
(defconst reticulum-mdu (- reticulum-mtu reticulum-header-maxsize reticulum-ifac-min-size))
(defconst reticulum-pathfinder-m 128 "Maximum hop count.")

;; Packet types
(defconst reticulum-packet-data 0)
(defconst reticulum-packet-announce 1)
(defconst reticulum-packet-linkrequest 2)
(defconst reticulum-packet-proof 3)

;; Header types
(defconst reticulum-header-1 0)
(defconst reticulum-header-2 1)

;; Transport types
(defconst reticulum-transport-broadcast 0)
(defconst reticulum-transport-transport 1)

;; Destination types
(defconst reticulum-destination-single 0)
(defconst reticulum-destination-group 1)
(defconst reticulum-destination-plain 2)
(defconst reticulum-destination-link 3)

;; Contexts
(defconst reticulum-context-none #x00)
(defconst reticulum-context-resource #x01)
(defconst reticulum-context-resource-adv #x02)
(defconst reticulum-context-resource-req #x03)
(defconst reticulum-context-resource-hmu #x04)
(defconst reticulum-context-resource-prf #x05)
(defconst reticulum-context-resource-icl #x06)
(defconst reticulum-context-resource-rcl #x07)
(defconst reticulum-context-cache-request #x08)
(defconst reticulum-context-request #x09)
(defconst reticulum-context-response #x0a)
(defconst reticulum-context-path-response #x0b)
(defconst reticulum-context-command #x0c)
(defconst reticulum-context-command-status #x0d)
(defconst reticulum-context-channel #x0e)
(defconst reticulum-context-keepalive #xfa)
(defconst reticulum-context-linkidentify #xfb)
(defconst reticulum-context-linkclose #xfc)
(defconst reticulum-context-linkproof #xfd)
(defconst reticulum-context-lrrtt #xfe)
(defconst reticulum-context-lrproof #xff)

;;;; Structure

(cl-defstruct (reticulum-packet (:constructor reticulum-packet--make)
                                (:copier nil))
  (header-type 0) (context-flag 0) (transport-type 0)
  (destination-type 0) (packet-type 0)
  (hops 0)
  transport-id destination-hash
  (context 0)
  data raw hash
  ;; Bookkeeping for inbound packets.
  interface received-at
  ;; Bookkeeping for outbound packets.
  destination link sent-at receipt)

(defun reticulum-packet-flags (packet)
  "Return the packed flags byte of PACKET."
  (logior (ash (reticulum-packet-header-type packet) 6)
          (ash (reticulum-packet-context-flag packet) 5)
          (ash (reticulum-packet-transport-type packet) 4)
          (ash (reticulum-packet-destination-type packet) 2)
          (reticulum-packet-packet-type packet)))

(defun reticulum-packet-pack (packet)
  "Fill in the raw bytes and hash of PACKET from its fields.
Return the raw bytes."
  (let* ((header (reticulum-bytes (reticulum-packet-flags packet)
                                  (reticulum-packet-hops packet)))
         (transport-id (reticulum-packet-transport-id packet)))
    (when (= (reticulum-packet-header-type packet) reticulum-header-2)
      (unless (and transport-id (= (length transport-id) reticulum-truncated-hash-length))
        (error "Packet with header type 2 must have a transport ID"))
      (setq header (concat header transport-id)))
    (setq header (concat header (reticulum-packet-destination-hash packet)
                         (unibyte-string (reticulum-packet-context packet))))
    (let ((raw (reticulum-bytes header (or (reticulum-packet-data packet) ""))))
      (when (> (length raw) reticulum-mtu)
        (error "Packet size %d exceeds MTU of %d bytes" (length raw) reticulum-mtu))
      (setf (reticulum-packet-raw packet) raw)
      (setf (reticulum-packet-hash packet) (reticulum-packet--compute-hash packet))
      raw)))

(defun reticulum-packet-make (&rest args)
  "Create and pack a packet from keyword ARGS (see `reticulum-packet--make')."
  (let ((packet (apply #'reticulum-packet--make args)))
    (reticulum-packet-pack packet)
    packet))

(defun reticulum-packet-unpack (raw &optional interface)
  "Parse RAW bytes into a packet received on INTERFACE, or return nil if malformed."
  (condition-case nil
      (let* ((flags (aref raw 0))
             (hops (aref raw 1))
             (header-type (logand (ash flags -6) 1))
             (dst-len reticulum-truncated-hash-length))
        (when (>= hops reticulum-pathfinder-m)
          (error "Invalid hop count"))
        (let ((packet (reticulum-packet--make
                       :header-type header-type
                       :context-flag (logand (ash flags -5) 1)
                       :transport-type (logand (ash flags -4) 1)
                       :destination-type (logand (ash flags -2) 3)
                       :packet-type (logand flags 3)
                       :hops hops
                       :raw raw
                       :interface interface
                       :received-at (float-time))))
          (if (= header-type reticulum-header-2)
              (progn
                (when (< (length raw) (+ 3 (* 2 dst-len))) (error "Short packet"))
                (setf (reticulum-packet-transport-id packet) (substring raw 2 (+ 2 dst-len)))
                (setf (reticulum-packet-destination-hash packet) (substring raw (+ 2 dst-len) (+ 2 (* 2 dst-len))))
                (setf (reticulum-packet-context packet) (aref raw (+ 2 (* 2 dst-len))))
                (setf (reticulum-packet-data packet) (substring raw (+ 3 (* 2 dst-len)))))
            (when (< (length raw) (+ 3 dst-len)) (error "Short packet"))
            (setf (reticulum-packet-destination-hash packet) (substring raw 2 (+ 2 dst-len)))
            (setf (reticulum-packet-context packet) (aref raw (+ 2 dst-len)))
            (setf (reticulum-packet-data packet) (substring raw (+ 3 dst-len))))
          (setf (reticulum-packet-hash packet) (reticulum-packet--compute-hash packet))
          packet))
    (error nil)))

(defun reticulum-packet-hashable-part (packet)
  "Return the part of PACKET that its hash is computed over."
  (let ((raw (reticulum-packet-raw packet)))
    (concat (unibyte-string (logand (aref raw 0) #x0f))
            (if (= (reticulum-packet-header-type packet) reticulum-header-2)
                (substring raw (+ reticulum-truncated-hash-length 2))
              (substring raw 2)))))

(defun reticulum-packet--compute-hash (packet)
  "Compute the full hash of PACKET."
  (reticulum-full-hash (reticulum-packet-hashable-part packet)))

(defun reticulum-packet-truncated-hash (packet)
  "Return the truncated hash of PACKET."
  (substring (reticulum-packet-hash packet) 0 reticulum-truncated-hash-length))

(defun reticulum-packet-describe (packet)
  "Return a short human readable description of PACKET."
  (format "<%s %s hops=%d ctx=%02x dst=%s%s len=%d>"
          (pcase (reticulum-packet-packet-type packet)
            (0 "DATA") (1 "ANNOUNCE") (2 "LINKREQUEST") (3 "PROOF"))
          (if (= (reticulum-packet-header-type packet) 1) "H2" "H1")
          (reticulum-packet-hops packet)
          (reticulum-packet-context packet)
          (reticulum-hex (reticulum-packet-destination-hash packet))
          (if (reticulum-packet-transport-id packet)
              (format " via=%s" (reticulum-hex (reticulum-packet-transport-id packet)))
            "")
          (length (or (reticulum-packet-data packet) ""))))

(provide 'reticulum-packet)

;;; reticulum-packet.el ends here
