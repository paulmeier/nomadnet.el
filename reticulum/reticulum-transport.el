;;; reticulum-transport.el --- Leaf transport for Reticulum  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; The parts of RNS.Transport a client needs: a path table built from
;; announces, dispatch of inbound packets to local destinations, links
;; and packet receipts, outbound header selection, path requests and
;; announce handlers.  This node never routes traffic for others.

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)
(require 'reticulum-packet)
(require 'reticulum-identity)
(require 'reticulum-interface)

(defconst reticulum-transport-path-request-timeout 15)
(defconst reticulum-transport-default-per-hop-timeout 6)
(defconst reticulum-transport-path-expiry (* 60 60 24 7))

(defvar reticulum-transport-path-table (make-hash-table :test #'equal)
  "Destination hash -> path plist.
Keys: :timestamp :next-hop :hops :interface :expires :packet-hash.")

(defvar reticulum-transport-destinations (make-hash-table :test #'equal)
  "Destination hash -> local destination object (see `reticulum-destination').")

(defvar reticulum-transport-links (make-hash-table :test #'equal)
  "Link id -> link object, for pending and active links.")

(defvar reticulum-transport-receipts nil "Outstanding packet receipts.")

(defvar reticulum-transport-announce-handlers nil
  "List of (ASPECT-FILTER . FUNCTION).  FUNCTION is called with the announce plist.")

(defvar reticulum-transport-packet-hook nil
  "Hook run with every inbound packet after transport processing (debugging).")

(defvar reticulum-transport-path-requests (make-hash-table :test #'equal)
  "Destination hash -> time of the last path request.")

(defvar reticulum-transport-packet-hashlist (make-hash-table :test #'equal)
  "Recently seen packet hashes for duplicate suppression.")

(defvar reticulum-transport-inbound-count 0)
(defvar reticulum-transport-announce-count 0)

;;;; Destination objects

(cl-defstruct (reticulum-destination (:constructor reticulum-destination--make)
                                     (:copier nil))
  identity direction type app-name aspects name hash name-hash hexhash
  packet-callback link-established-callback
  (accepts-links t)
  ratchets ratchets-path (enforce-ratchets nil) default-app-data
  (proof-strategy 'none) (links nil) stamp-cost display-name)

(defun reticulum-destination-create (identity direction type app-name &rest aspects)
  "Create a destination.  DIRECTION is `in' or `out', TYPE is `single' or `plain'."
  (let* ((type-code (pcase type
                      ('single reticulum-destination-single)
                      ('plain reticulum-destination-plain)
                      ('group reticulum-destination-group)
                      (_ (error "Unknown destination type %s" type))))
         (destination (reticulum-destination--make
                       :identity identity :direction direction :type type-code
                       :app-name app-name :aspects aspects
                       :name (reticulum-address-expand-name identity app-name aspects)
                       :hash (apply #'reticulum-address identity app-name aspects)
                       :name-hash (reticulum-address-name-hash app-name aspects))))
    (setf (reticulum-destination-hexhash destination) (reticulum-hex (reticulum-destination-hash destination)))
    (when (eq direction 'in)
      (puthash (reticulum-destination-hash destination) destination reticulum-transport-destinations))
    destination))

(defun reticulum-destination-encrypt (destination plaintext)
  "Encrypt PLAINTEXT for DESTINATION (single type), using its ratchet if known.
Returns (CIPHERTEXT . RATCHET-ID)."
  (pcase (reticulum-destination-type destination)
    ((pred (= reticulum-destination-plain)) (cons plaintext nil))
    ((pred (= reticulum-destination-single))
     (let* ((ratchet (reticulum-identity-get-ratchet (reticulum-destination-hash destination)))
            (ciphertext (reticulum-identity-encrypt (reticulum-destination-identity destination)
                                                    plaintext ratchet)))
       (cons ciphertext (and ratchet (reticulum-identity-ratchet-id ratchet)))))
    (_ (error "Unsupported destination type for encryption"))))

(defun reticulum-destination-decrypt (destination ciphertext)
  "Decrypt CIPHERTEXT sent to inbound DESTINATION.
Returns (PLAINTEXT . RATCHET-ID) or nil."
  (pcase (reticulum-destination-type destination)
    ((pred (= reticulum-destination-plain)) (cons ciphertext nil))
    ((pred (= reticulum-destination-single))
     (reticulum-identity-decrypt (reticulum-destination-identity destination) ciphertext
                                 (reticulum-destination-ratchets destination)
                                 (reticulum-destination-enforce-ratchets destination)))
    (_ nil)))

;;;; Path table

(defun reticulum-transport-has-path (destination-hash)
  "Return non-nil if a path to DESTINATION-HASH is known."
  (and (gethash destination-hash reticulum-transport-path-table) t))

(defun reticulum-transport-hops-to (destination-hash)
  "Return the number of hops to DESTINATION-HASH, or `reticulum-pathfinder-m'."
  (let ((entry (gethash destination-hash reticulum-transport-path-table)))
    (if entry (plist-get entry :hops) reticulum-pathfinder-m)))

(defun reticulum-transport-next-hop (destination-hash)
  "Return the next hop transport id for DESTINATION-HASH, or nil."
  (plist-get (gethash destination-hash reticulum-transport-path-table) :next-hop))

(defun reticulum-transport-next-hop-interface (destination-hash)
  "Return the interface a packet for DESTINATION-HASH should leave on."
  (or (plist-get (gethash destination-hash reticulum-transport-path-table) :interface)
      (car reticulum-interfaces)))

(defun reticulum-transport-first-hop-timeout (destination-hash)
  "Return the timeout for the first hop towards DESTINATION-HASH."
  (ignore destination-hash)
  reticulum-transport-default-per-hop-timeout)

(defun reticulum-transport-drop-path (destination-hash)
  "Forget the path to DESTINATION-HASH."
  (remhash destination-hash reticulum-transport-path-table))

;;;; Announce handlers

(defun reticulum-transport-register-announce-handler (aspect-filter function)
  "Call FUNCTION with the announce plist for announces matching ASPECT-FILTER.
ASPECT-FILTER is a full name like \"lxmf.delivery\" or nil for all announces."
  (push (cons aspect-filter function) reticulum-transport-announce-handlers))

(defun reticulum-transport-deregister-announce-handler (function)
  "Stop calling FUNCTION for announces."
  (setq reticulum-transport-announce-handlers
        (cl-remove-if (lambda (h) (eq (cdr h) function)) reticulum-transport-announce-handlers)))

(defun reticulum-transport--announce-matches-p (filter announce)
  "Return non-nil if announce plist ANNOUNCE has the name hash of FILTER."
  (or (null filter)
      (let ((parts (split-string filter "\\.")))
        (reticulum-bytes-equal (plist-get announce :name-hash)
                               (reticulum-address-name-hash (car parts) (cdr parts))))))

;;;; Inbound

(defun reticulum-transport--handle-announce (packet)
  "Process announce PACKET: update the path table and notify handlers."
  (let ((announce (reticulum-announce-validate packet t)))
    (when announce
      (cl-incf reticulum-transport-announce-count)
      (let* ((destination-hash (plist-get announce :destination-hash))
             (hops (reticulum-packet-hops packet))
             (existing (gethash destination-hash reticulum-transport-path-table))
             (now (float-time)))
        (unless (gethash destination-hash reticulum-transport-destinations)
          (when (or (null existing)
                    (<= hops (plist-get existing :hops))
                    (> now (plist-get existing :expires)))
            (puthash destination-hash
                     (list :timestamp now
                           :next-hop (or (reticulum-packet-transport-id packet) destination-hash)
                           :hops hops
                           :interface (reticulum-packet-interface packet)
                           :expires (+ now reticulum-transport-path-expiry)
                           :packet-hash (reticulum-packet-hash packet))
                     reticulum-transport-path-table)))
        (dolist (handler reticulum-transport-announce-handlers)
          (when (reticulum-transport--announce-matches-p (car handler) announce)
            (condition-case err
                (funcall (cdr handler) announce)
              (error (reticulum-log 1 "announce handler error: %s" (error-message-string err))))))))))

(declare-function reticulum-link-interface "reticulum-link" (link))

(defvar reticulum-transport-link-request-function nil
  "Function called with (PACKET DESTINATION) for inbound link requests.")
(defvar reticulum-transport-link-packet-function nil
  "Function called with (PACKET LINK) for packets addressed to an active link.")
(defvar reticulum-transport-link-proof-function nil
  "Function called with (PACKET LINK) for link request proofs of pending links.")

(defun reticulum-transport--handle-proof (packet)
  "Process proof PACKET against pending links and outstanding receipts."
  (if (= (reticulum-packet-context packet) reticulum-context-lrproof)
      (let ((link (gethash (reticulum-packet-destination-hash packet) reticulum-transport-links)))
        (when (and link reticulum-transport-link-proof-function)
          (funcall reticulum-transport-link-proof-function packet link)))
    (let ((link (gethash (reticulum-packet-destination-hash packet) reticulum-transport-links)))
      (if (and link reticulum-transport-link-packet-function)
          (funcall reticulum-transport-link-packet-function packet link)
        (dolist (receipt (copy-sequence reticulum-transport-receipts))
          (when (reticulum-receipt-validate receipt packet)
            (setq reticulum-transport-receipts (delq receipt reticulum-transport-receipts))))))))

(defun reticulum-transport-inbound (raw interface)
  "Process RAW packet bytes received on INTERFACE."
  (let ((packet (reticulum-packet-unpack raw interface)))
    (when packet
      (cl-incf reticulum-transport-inbound-count)
      ;; Like RNS.Transport.inbound: count the hop that brought the packet
      ;; here, except from a shared instance, which counted it already.
      (unless (eq (reticulum-interface-kind interface) 'local)
        (cl-incf (reticulum-packet-hops packet)))
      (let ((hash (reticulum-packet-hash packet)))
        (unless (gethash hash reticulum-transport-packet-hashlist)
          (puthash hash (float-time) reticulum-transport-packet-hashlist)
          (when (> (hash-table-count reticulum-transport-packet-hashlist) 4000)
            (reticulum-transport--prune-hashlist))
          (pcase (reticulum-packet-packet-type packet)
            ((pred (= reticulum-packet-announce))
             (reticulum-transport--handle-announce packet))
            ((pred (= reticulum-packet-proof))
             (reticulum-transport--handle-proof packet))
            ((pred (= reticulum-packet-linkrequest))
             (let ((destination (gethash (reticulum-packet-destination-hash packet)
                                         reticulum-transport-destinations)))
               (when (and destination (reticulum-destination-accepts-links destination)
                          reticulum-transport-link-request-function)
                 (funcall reticulum-transport-link-request-function packet destination))))
            (_
             (let ((link (gethash (reticulum-packet-destination-hash packet) reticulum-transport-links))
                   (destination (gethash (reticulum-packet-destination-hash packet)
                                         reticulum-transport-destinations)))
               (cond
                ((and link reticulum-transport-link-packet-function)
                 (funcall reticulum-transport-link-packet-function packet link))
                ((and destination (reticulum-destination-packet-callback destination))
                 (let ((plaintext (reticulum-destination-decrypt destination (reticulum-packet-data packet))))
                   (when plaintext
                     (condition-case err
                         (funcall (reticulum-destination-packet-callback destination)
                                  (car plaintext) packet (cdr plaintext))
                       (error (reticulum-log 1 "packet callback error: %s" (error-message-string err)))))))))))
          (run-hook-with-args 'reticulum-transport-packet-hook packet))))))

(defun reticulum-transport--prune-hashlist ()
  "Drop packet hashes older than 10 minutes."
  (let ((cutoff (- (float-time) 600)))
    (maphash (lambda (k v) (when (< v cutoff) (remhash k reticulum-transport-packet-hashlist)))
             reticulum-transport-packet-hashlist)))

;;;; Receipts

(cl-defstruct (reticulum-receipt (:constructor reticulum-receipt--make) (:copier nil))
  hash truncated-hash packet destination link
  (sent-at 0) timeout (status 'sent) concluded-at
  delivery-callback timeout-callback)

(defun reticulum-receipt-validate (receipt packet)
  "Check proof PACKET against RECEIPT.  Return non-nil when delivered."
  (let* ((proof (reticulum-packet-data packet))
         (hash (reticulum-receipt-hash receipt))
         (identity (and (reticulum-receipt-destination receipt)
                        (reticulum-destination-identity (reticulum-receipt-destination receipt)))))
    (when (and identity
               (or (and (= (length proof) 96) (reticulum-bytes-equal (substring proof 0 32) hash)
                        (reticulum-identity-validate identity (substring proof 32) hash))
                   (and (= (length proof) 64)
                        (reticulum-identity-validate identity proof hash))))
      (setf (reticulum-receipt-status receipt) 'delivered
            (reticulum-receipt-concluded-at receipt) (float-time))
      (when (reticulum-receipt-delivery-callback receipt)
        (funcall (reticulum-receipt-delivery-callback receipt) receipt))
      t)))

(defun reticulum-transport-check-receipts ()
  "Time out outstanding receipts."
  (let ((now (float-time)))
    (dolist (receipt (copy-sequence reticulum-transport-receipts))
      (when (and (eq (reticulum-receipt-status receipt) 'sent)
                 (> now (+ (reticulum-receipt-sent-at receipt) (reticulum-receipt-timeout receipt))))
        (setf (reticulum-receipt-status receipt) 'failed
              (reticulum-receipt-concluded-at receipt) now)
        (setq reticulum-transport-receipts (delq receipt reticulum-transport-receipts))
        (when (reticulum-receipt-timeout-callback receipt)
          (funcall (reticulum-receipt-timeout-callback receipt) receipt))))))

;;;; Outbound

(defun reticulum-transport-outbound (packet &optional create-receipt)
  "Transmit PACKET, rewriting to header type 2 when a next hop is known.
With CREATE-RECEIPT, register and return a receipt for proof tracking.
When the packet's interface slot is set, it names the interface the packet
must leave on (RNS's attached interface); otherwise the interface is chosen
from the packet's link, the path table or the first online interface."
  (let* ((destination-hash (reticulum-packet-destination-hash packet))
         (raw (reticulum-packet-raw packet))
         (entry (and (/= (reticulum-packet-packet-type packet) reticulum-packet-announce)
                     (/= (reticulum-packet-destination-type packet) reticulum-destination-plain)
                     (gethash destination-hash reticulum-transport-path-table)))
         (link (reticulum-packet-link packet))
         (interface (cond ((reticulum-packet-interface packet))
                          ((and link (reticulum-link-interface link)))
                          (entry (plist-get entry :interface))
                          (t (car reticulum-interfaces))))
         (receipt nil))
    (unless (and interface (reticulum-interface-online interface))
      (setq interface (cl-find-if #'reticulum-interface-online reticulum-interfaces)))
    (unless interface
      (error "No online Reticulum interface"))
    (let ((wire raw))
      (when (and entry
                 (or (> (plist-get entry :hops) 1)
                     (and (= (plist-get entry :hops) 1) (eq (reticulum-interface-kind interface) 'local)))
                 (= (reticulum-packet-header-type packet) reticulum-header-1))
        (let ((flags (logior (ash reticulum-header-2 6) (ash reticulum-transport-transport 4)
                             (logand (aref raw 0) #x0f))))
          (setq wire (concat (unibyte-string flags) (substring raw 1 2)
                             (plist-get entry :next-hop) (substring raw 2)))
          (plist-put entry :timestamp (float-time))))
      (reticulum-interface-send interface wire))
    (setf (reticulum-packet-sent-at packet) (float-time))
    (when (and create-receipt (= (reticulum-packet-packet-type packet) reticulum-packet-data))
      (setq receipt (reticulum-receipt--make
                     :hash (reticulum-packet-hash packet)
                     :truncated-hash (reticulum-packet-truncated-hash packet)
                     :packet packet
                     :destination (reticulum-packet-destination packet)
                     :sent-at (float-time)
                     :timeout (+ (reticulum-transport-first-hop-timeout destination-hash)
                                 (* reticulum-transport-default-per-hop-timeout
                                    (max 1 (min (reticulum-transport-hops-to destination-hash) 20))))))
      (setf (reticulum-packet-receipt packet) receipt)
      (push receipt reticulum-transport-receipts))
    receipt))

(defun reticulum-transport-send (destination data &optional packet-type context context-flag create-receipt)
  "Build, encrypt and send DATA to DESTINATION object.  Return the packet."
  (let* ((packet-type (or packet-type reticulum-packet-data))
         (context (or context reticulum-context-none))
         (encrypt (and (= packet-type reticulum-packet-data)
                       (= (reticulum-destination-type destination) reticulum-destination-single)
                       (not (memq context (list reticulum-context-resource reticulum-context-keepalive
                                                reticulum-context-cache-request)))))
         (payload (if encrypt (car (reticulum-destination-encrypt destination data)) data))
         (packet (reticulum-packet-make :packet-type packet-type
                                        :destination-type (reticulum-destination-type destination)
                                        :context context
                                        :context-flag (or context-flag 0)
                                        :destination-hash (reticulum-destination-hash destination)
                                        :data payload
                                        :destination destination)))
    (reticulum-transport-outbound packet create-receipt)
    packet))

;;;; Proofs

(defun reticulum-transport-prove-packet (packet destination)
  "Send a proof for PACKET received on inbound DESTINATION.
The proof carries the packet hash and its signature by the destination
identity, addressed to the truncated packet hash, and leaves on the
interface the packet arrived on, as RNS.Identity.prove does."
  (let* ((identity (reticulum-destination-identity destination))
         (hash (reticulum-packet-hash packet))
         (proof (reticulum-packet-make :packet-type reticulum-packet-proof
                                       :destination-type reticulum-destination-single
                                       :destination-hash (substring hash 0 reticulum-truncated-hash-length)
                                       :data (concat hash (reticulum-identity-sign identity hash))
                                       :interface (reticulum-packet-interface packet))))
    (reticulum-transport-outbound proof)
    proof))

;;;; Path requests

(defvar reticulum-transport--path-request-destination nil)

(defun reticulum-transport-request-path (destination-hash)
  "Ask the network for a path to DESTINATION-HASH."
  (unless reticulum-transport--path-request-destination
    (setq reticulum-transport--path-request-destination
          (reticulum-destination-create nil 'out 'plain "rnstransport" "path" "request")))
  (let ((tag (reticulum-truncated-hash (reticulum-random-bytes 16))))
    (puthash destination-hash (float-time) reticulum-transport-path-requests)
    (reticulum-transport-send reticulum-transport--path-request-destination
                              (concat destination-hash tag))))

;;;; Announcing

(defun reticulum-transport-announce (destination &optional app-data)
  "Announce inbound DESTINATION with APP-DATA.
APP-DATA is bytes or a function returning bytes."
  (let* ((app-data (cond ((functionp app-data) (funcall app-data))
                         (app-data app-data)
                         ((functionp (reticulum-destination-default-app-data destination))
                          (funcall (reticulum-destination-default-app-data destination)))
                         (t (reticulum-destination-default-app-data destination))))
         (ratchets (reticulum-destination-ratchets destination))
         (ratchet (and ratchets (reticulum-identity-ratchet-public (car ratchets))))
         (packet (reticulum-announce-build (reticulum-destination-identity destination)
                                           (reticulum-destination-app-name destination)
                                           (reticulum-destination-aspects destination)
                                           app-data ratchet)))
    (when ratchet
      (reticulum-identity-remember-ratchet (reticulum-destination-hash destination) ratchet))
    (reticulum-transport-outbound packet)
    packet))

;;;; Lifecycle

(defvar reticulum-transport--job-timer nil)

(defun reticulum-transport--jobs ()
  "Periodic housekeeping."
  (reticulum-transport-check-receipts)
  (run-hooks 'reticulum-transport-job-hook))

(defvar reticulum-transport-job-hook nil "Hook run every few seconds by the transport.")

(defun reticulum-transport-start ()
  "Attach the transport to the interfaces and start housekeeping."
  (setq reticulum-interface-receive-function #'reticulum-transport-inbound)
  (unless reticulum-transport--job-timer
    (setq reticulum-transport--job-timer (run-at-time 2 2 #'reticulum-transport--jobs))))

(defun reticulum-transport-stop ()
  "Stop housekeeping and disconnect interfaces."
  (when reticulum-transport--job-timer
    (cancel-timer reticulum-transport--job-timer)
    (setq reticulum-transport--job-timer nil))
  (reticulum-interface-remove-all))

(provide 'reticulum-transport)

;;; reticulum-transport.el ends here
