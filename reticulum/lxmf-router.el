;;; lxmf-router.el --- LXMF delivery destination and inbound delivery  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; The client side of an LXMF router, written from the protocol: one
;; delivery destination on `lxmf.delivery' with ratchets, announces with
;; the current ratchet, and inbound delivery by both methods a peer can
;; use to reach us directly:
;;
;; - opportunistic: a single packet encrypted to the delivery destination,
;;   carrying the packed message without its leading destination hash;
;; - direct: a link to the delivery destination, carrying the packed
;;   message as a packet or as a resource.
;;
;; Every delivered message is checked for duplicates by message hash.  The
;; hashes of delivered messages are persisted, as the reference
;; implementation does, so that a message is not shown twice across
;; restarts.  Files follow the reference layout under the storage
;; directory: `ratchets/<hash>.ratchets' and `local_deliveries'.
;;
;; Sending, stamps and propagation node sync live in later modules.

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)
(require 'reticulum-crypto)
(require 'reticulum-msgpack)
(require 'reticulum-identity)
(require 'reticulum-transport)
(require 'reticulum-link)
(require 'reticulum-resource)
(require 'lxmf-message)

(defgroup lxmf nil "LXMF messaging over Reticulum." :group 'comm)

(defcustom lxmf-router-enforce-ratchets nil
  "When non-nil, refuse packets encrypted to the identity key.
Only packets encrypted to one of the retained ratchets are accepted.
Peers that have not yet seen an announce with a ratchet cannot deliver
opportunistic messages while this is set."
  :type 'boolean)

(defcustom lxmf-router-delivery-per-transfer-limit 1000
  "Largest message accepted as a resource on a delivery link, in kilobytes."
  :type 'integer)

(defconst lxmf-router-ratchet-count 512 "Number of retained ratchet keys.")
(defconst lxmf-router-ratchet-interval (* 30 60) "Seconds between ratchet rotations.")
(defconst lxmf-router-message-expiry (* 30 24 60 60))
(defconst lxmf-router-delivered-ids-expiry (* 6 lxmf-router-message-expiry)
  "How long delivered message hashes are remembered for duplicate suppression.")

;;;; State

(defvar lxmf-router-storage-path nil "Directory holding the router's files.")
(defvar lxmf-router-delivery-destination nil "The inbound `lxmf.delivery' destination.")
(defvar lxmf-router-delivery-callback nil
  "Function called with each delivered `lxmf-message'.")
(defvar lxmf-router-delivered-ids (make-hash-table :test #'equal)
  "Message hash -> delivery time, for duplicate suppression.")
(defvar lxmf-router-backchannel-links (make-hash-table :test #'equal)
  "Delivery destination hash -> inbound link on which that peer identified.")
(defvar lxmf-router-delivery-links nil "Inbound links on the delivery destination.")
(defvar lxmf-router--latest-ratchet-time 0)
(defvar lxmf-router--delivered-ids-dirty nil)
(defvar lxmf-router-delivered-count 0)

(defun lxmf-router--path (&rest parts)
  "Return a path inside the storage directory."
  (unless lxmf-router-storage-path (error "LXMF router storage path is not set"))
  (expand-file-name (string-join parts "/") lxmf-router-storage-path))

(defun lxmf-router--read-file (path)
  "Return the bytes of PATH, or nil."
  (when (file-exists-p path)
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (insert-file-contents-literally path)
      (buffer-string))))

(defun lxmf-router--write-file (path bytes)
  "Write BYTES to PATH atomically."
  (make-directory (file-name-directory path) t)
  (let ((tmp (concat path ".tmp"))
        (coding-system-for-write 'binary))
    (with-temp-file tmp
      (set-buffer-multibyte nil)
      (insert bytes))
    (rename-file tmp path t)))

;;;; Ratchets

(defun lxmf-router-load-ratchets (identity path)
  "Return the ratchet list persisted at PATH for IDENTITY.
The file is msgpack {\"signature\", \"ratchets\"}, where the ratchets
are a packed list of private keys signed by the identity.  Returns nil
when the file is missing; signals an error when it is invalid."
  (let ((bytes (lxmf-router--read-file path)))
    (when bytes
      (let* ((table (reticulum-msgpack-unpack bytes))
             (signature (and (hash-table-p table) (gethash "signature" table)))
             (packed (and (hash-table-p table) (gethash "ratchets" table))))
        (unless (and signature packed)
          (error "Ratchet file %s has no signature or ratchets" path))
        (unless (reticulum-identity-validate identity signature packed)
          (error "Invalid ratchet file signature in %s" path))
        (let ((ratchets (reticulum-msgpack-unpack packed)))
          (unless (and (listp ratchets)
                       (cl-every (lambda (r) (and (stringp r) (= (length r) reticulum-identity-ratchetsize)))
                                 ratchets))
            (error "Ratchet file %s holds no valid ratchets" path))
          ratchets)))))

(defun lxmf-router-save-ratchets (identity path ratchets)
  "Persist RATCHETS for IDENTITY at PATH in the reference file format."
  (let ((packed (reticulum-msgpack-pack ratchets)))
    (lxmf-router--write-file
     path
     (reticulum-msgpack-pack (reticulum-msgpack-map (reticulum-msgpack-str "signature")
                                                    (reticulum-identity-sign identity packed)
                                                    (reticulum-msgpack-str "ratchets") packed)))))

(defun lxmf-router--enable-ratchets (destination path)
  "Load the ratchets of DESTINATION from PATH, keeping none if it is unreadable."
  (setf (reticulum-destination-ratchets-path destination) path)
  (condition-case err
      (setf (reticulum-destination-ratchets destination)
            (lxmf-router-load-ratchets (reticulum-destination-identity destination) path))
    (error
     (reticulum-log 0 "could not load ratchet file %s: %s; a new one is created on the next announce"
                    path (error-message-string err))
     (setf (reticulum-destination-ratchets destination) nil)))
  (setq lxmf-router--latest-ratchet-time 0))

(defun lxmf-router-rotate-ratchets (&optional destination force)
  "Rotate the ratchets of DESTINATION when the rotation interval has passed.
With FORCE, rotate regardless.  Returns the new private ratchet, or nil."
  (let ((destination (or destination lxmf-router-delivery-destination))
        (now (float-time)))
    (when (and destination
               (or force (> now (+ lxmf-router--latest-ratchet-time lxmf-router-ratchet-interval))))
      (let ((ratchet (reticulum-identity-generate-ratchet)))
        (push ratchet (reticulum-destination-ratchets destination))
        (when (> (length (reticulum-destination-ratchets destination)) lxmf-router-ratchet-count)
          (setf (reticulum-destination-ratchets destination)
                (seq-take (reticulum-destination-ratchets destination) lxmf-router-ratchet-count)))
        (setq lxmf-router--latest-ratchet-time now)
        (when (reticulum-destination-ratchets-path destination)
          (lxmf-router-save-ratchets (reticulum-destination-identity destination)
                                     (reticulum-destination-ratchets-path destination)
                                     (reticulum-destination-ratchets destination)))
        (reticulum-log 6 "rotated ratchets for %s" (reticulum-destination-hexhash destination))
        ratchet))))

(defun lxmf-router-current-ratchet (&optional destination)
  "Return the public key of the newest ratchet of DESTINATION, or nil."
  (let* ((destination (or destination lxmf-router-delivery-destination))
         (ratchets (and destination (reticulum-destination-ratchets destination))))
    (and ratchets (reticulum-identity-ratchet-public (car ratchets)))))

;;;; Delivery identity

(defun lxmf-router-init (storage-path &optional delivery-callback)
  "Prepare the router to use STORAGE-PATH, reporting messages to DELIVERY-CALLBACK."
  (setq lxmf-router-storage-path (expand-file-name storage-path)
        lxmf-router-delivery-callback delivery-callback)
  (make-directory (lxmf-router--path "ratchets") t)
  (lxmf-router--load-delivered-ids)
  (add-hook 'reticulum-transport-job-hook #'lxmf-router--jobs)
  t)

(defun lxmf-router-announce-app-data (&optional destination)
  "Return the announce app data of DESTINATION.
It carries the destination's display name and stamp cost."
  (let ((destination (or destination lxmf-router-delivery-destination)))
    (lxmf-peer-app-data (reticulum-destination-display-name destination)
                        (reticulum-destination-stamp-cost destination))))

(defun lxmf-router-register-delivery-identity (identity &optional display-name stamp-cost)
  "Register IDENTITY's `lxmf.delivery' destination as ours and return it.
DISPLAY-NAME and STAMP-COST go into announces.  Ratchets are loaded from
`ratchets/<hash>.ratchets' under the storage path."
  (when lxmf-router-delivery-destination
    (remhash (reticulum-destination-hash lxmf-router-delivery-destination) reticulum-transport-destinations))
  (let ((destination (reticulum-destination-create identity 'in 'single lxmf-app-name "delivery")))
    (setf (reticulum-destination-packet-callback destination) #'lxmf-router--delivery-packet
          (reticulum-destination-link-established-callback destination) #'lxmf-router--delivery-link-established
          (reticulum-destination-proof-strategy destination) 'all
          (reticulum-destination-display-name destination) display-name
          (reticulum-destination-stamp-cost destination)
          (and (integerp stamp-cost) (> stamp-cost 0) (< stamp-cost 255) stamp-cost)
          (reticulum-destination-default-app-data destination) #'lxmf-router-announce-app-data
          (reticulum-destination-enforce-ratchets destination) lxmf-router-enforce-ratchets)
    (lxmf-router--enable-ratchets
     destination (lxmf-router--path "ratchets" (concat (reticulum-destination-hexhash destination) ".ratchets")))
    (setq lxmf-router-delivery-destination destination)
    (reticulum-log 4 "LXMF delivery destination %s registered with %d ratchets"
                   (reticulum-destination-hexhash destination)
                   (length (reticulum-destination-ratchets destination)))
    destination))

(defun lxmf-router-set-display-name (display-name)
  "Set the DISPLAY-NAME announced with the delivery destination."
  (when lxmf-router-delivery-destination
    (setf (reticulum-destination-display-name lxmf-router-delivery-destination) display-name)))

(defun lxmf-router-announce (&optional destination)
  "Announce DESTINATION (default ours) with a fresh ratchet when due.
Returns the announce packet."
  (let ((destination (or destination lxmf-router-delivery-destination)))
    (unless destination (error "No LXMF delivery destination registered"))
    (lxmf-router-rotate-ratchets destination)
    (reticulum-transport-announce destination)))

;;;; Delivered message ids

(defun lxmf-router--load-delivered-ids ()
  "Load the persisted hashes of delivered messages."
  (clrhash lxmf-router-delivered-ids)
  (condition-case err
      (let* ((bytes (lxmf-router--read-file (lxmf-router--path "local_deliveries")))
             (table (and bytes (reticulum-msgpack-unpack bytes))))
        (when (hash-table-p table)
          (maphash (lambda (k v) (when (and (stringp k) (numberp v)) (puthash k v lxmf-router-delivered-ids)))
                   table)))
    (error (reticulum-log 1 "could not load local deliveries: %s" (error-message-string err))))
  (setq lxmf-router--delivered-ids-dirty nil))

(defun lxmf-router-save-delivered-ids ()
  "Persist the hashes of delivered messages when they changed."
  (when (and lxmf-router--delivered-ids-dirty lxmf-router-storage-path
             (> (hash-table-count lxmf-router-delivered-ids) 0))
    (lxmf-router--write-file (lxmf-router--path "local_deliveries")
                             (reticulum-msgpack-pack lxmf-router-delivered-ids))
    (setq lxmf-router--delivered-ids-dirty nil)))

(defun lxmf-router-clean-delivered-ids ()
  "Forget delivered message hashes older than the retention period.
The period is `lxmf-router-delivered-ids-expiry'."
  (let ((cutoff (- (float-time) lxmf-router-delivered-ids-expiry)))
    (maphash (lambda (k v)
               (when (< v cutoff)
                 (remhash k lxmf-router-delivered-ids)
                 (setq lxmf-router--delivered-ids-dirty t)))
             lxmf-router-delivered-ids)))

(defun lxmf-router-has-message (hash)
  "Return non-nil if the message with HASH was already delivered."
  (and (gethash hash lxmf-router-delivered-ids) t))

;;;; Delivery

(defun lxmf-router-deliver (lxmf-data destination-type &optional ratchet-id method allow-duplicate)
  "Unpack LXMF-DATA received on a DESTINATION-TYPE destination and deliver it.
RATCHET-ID and METHOD are recorded on the message.  Returns the message,
or nil when it was malformed, not for us, or a duplicate (unless
ALLOW-DUPLICATE)."
  (let ((message (condition-case err
                     (lxmf-message-unpack lxmf-data method)
                   (error (reticulum-log 3 "could not assemble LXMF message: %s" (error-message-string err))
                          nil))))
    (when message
      (cond
       ((not (and lxmf-router-delivery-destination
                  (equal (lxmf-message-destination-hash message)
                         (reticulum-destination-hash lxmf-router-delivery-destination))))
        (reticulum-log 3 "dropping %s addressed to %s, not our delivery destination"
                       (lxmf-message-describe message) (reticulum-hex (lxmf-message-destination-hash message)))
        nil)
       ((and (not allow-duplicate) (lxmf-router-has-message (lxmf-message-hash message)))
        (reticulum-log 5 "ignoring already received %s from %s" (lxmf-message-describe message)
                       (reticulum-hex (lxmf-message-source-hash message)))
        nil)
       (t
        (setf (lxmf-message-ratchet-id message) ratchet-id
              (lxmf-message-transport-encrypted message)
              (and (memq destination-type (list reticulum-destination-single reticulum-destination-link
                                                reticulum-destination-group))
                   t)
              (lxmf-message-transport-encryption message)
              (cond ((memq destination-type (list reticulum-destination-single reticulum-destination-link))
                     "Curve25519")
                    ((eq destination-type reticulum-destination-group) "AES-128")))
        (puthash (lxmf-message-hash message) (float-time) lxmf-router-delivered-ids)
        (setq lxmf-router--delivered-ids-dirty t)
        (cl-incf lxmf-router-delivered-count)
        (reticulum-log 4 "delivered %s from %s (%s)" (lxmf-message-describe message)
                       (reticulum-hex (lxmf-message-source-hash message))
                       (cond ((lxmf-message-signature-validated message) "signature valid")
                             ((eq (lxmf-message-unverified-reason message) lxmf-source-unknown) "source unknown")
                             (t "signature invalid")))
        (when lxmf-router-delivery-callback
          (condition-case err
              (funcall lxmf-router-delivery-callback message)
            (error (reticulum-log 1 "delivery callback error: %s" (error-message-string err)))))
        message)))))

(defun lxmf-router--delivery-packet (plaintext packet &optional context)
  "Handle PLAINTEXT of PACKET received on the delivery destination or a link.
CONTEXT is the ratchet id for destination packets, or the link for link packets."
  (if (= (reticulum-packet-destination-type packet) reticulum-destination-link)
      ;; Links prove packets themselves (proof strategy `all').
      (lxmf-router-deliver plaintext reticulum-destination-link
                           (and (reticulum-link-p context) (reticulum-link-id context))
                           lxmf-method-direct)
    (condition-case err
        (reticulum-transport-prove-packet packet lxmf-router-delivery-destination)
      (error (reticulum-log 1 "could not prove delivery packet: %s" (error-message-string err))))
    (lxmf-router-deliver (concat (reticulum-packet-destination-hash packet) plaintext)
                         (reticulum-packet-destination-type packet)
                         (and (stringp context) context)
                         lxmf-method-opportunistic)))

(defun lxmf-router--delivery-link-established (link)
  "Prepare inbound LINK on the delivery destination to receive messages."
  (push link lxmf-router-delivery-links)
  (setf (reticulum-link-packet-callback link) #'lxmf-router--delivery-packet
        (reticulum-link-resource-strategy link) 'app
        (reticulum-link-resource-callback link) #'lxmf-router--delivery-resource-advertised
        (reticulum-link-resource-concluded-callback link) #'lxmf-router--delivery-resource-concluded
        (reticulum-link-remote-identified-callback link) #'lxmf-router--delivery-remote-identified
        (reticulum-link-closed-callback link) #'lxmf-router--delivery-link-closed)
  (reticulum-log 5 "delivery link %s established" (reticulum-link-describe link)))

(defun lxmf-router--delivery-resource-advertised (advertisement _link)
  "Accept resource ADVERTISEMENT on a delivery link unless it exceeds the limit."
  (let ((size (or (plist-get advertisement :data-size) 0))
        (limit (* lxmf-router-delivery-per-transfer-limit 1000)))
    (if (> size limit)
        (progn (reticulum-log 4 "rejecting %d byte LXMF delivery resource over the %d byte limit" size limit)
               nil)
      t)))

(defun lxmf-router--delivery-resource-concluded (resource)
  "Deliver the message carried by RESOURCE when it completed."
  (when (eq (reticulum-resource-status resource) 'complete)
    (let ((link (reticulum-resource-link resource)))
      (lxmf-router-deliver (reticulum-resource-data resource) reticulum-destination-link
                           (and link (reticulum-link-id link)) lxmf-method-direct))))

(defun lxmf-router--delivery-remote-identified (link identity)
  "Record LINK as a backchannel to the peer that identified as IDENTITY."
  (let ((hash (reticulum-address identity lxmf-app-name "delivery")))
    (puthash hash link lxmf-router-backchannel-links)
    (reticulum-log 5 "backchannel available for %s on %s" (reticulum-hex hash) (reticulum-link-describe link))))

(defun lxmf-router--delivery-link-closed (link)
  "Forget closed delivery LINK."
  (setq lxmf-router-delivery-links (delq link lxmf-router-delivery-links))
  (maphash (lambda (k v) (when (eq v link) (remhash k lxmf-router-backchannel-links)))
           lxmf-router-backchannel-links))

(defun lxmf-router-backchannel-link (destination-hash)
  "Return an active inbound link from the peer at DESTINATION-HASH, or nil."
  (let ((link (gethash destination-hash lxmf-router-backchannel-links)))
    (if (and link (reticulum-link-active-p link))
        link
      (when link (remhash destination-hash lxmf-router-backchannel-links))
      nil)))

;;;; Lifecycle

(defvar lxmf-router--last-cleanup 0)

(defun lxmf-router--jobs ()
  "Periodic housekeeping: persist and prune delivered message ids."
  (when (> (- (float-time) lxmf-router--last-cleanup) 300)
    (setq lxmf-router--last-cleanup (float-time))
    (lxmf-router-clean-delivered-ids))
  (condition-case err
      (lxmf-router-save-delivered-ids)
    (error (reticulum-log 1 "could not save local deliveries: %s" (error-message-string err)))))

(defun lxmf-router-stop ()
  "Persist state, close delivery links and unregister the destination."
  (remove-hook 'reticulum-transport-job-hook #'lxmf-router--jobs)
  (ignore-errors (lxmf-router-save-delivered-ids))
  (dolist (link (copy-sequence lxmf-router-delivery-links))
    (ignore-errors (reticulum-link-teardown link)))
  (setq lxmf-router-delivery-links nil)
  (clrhash lxmf-router-backchannel-links)
  (when lxmf-router-delivery-destination
    (remhash (reticulum-destination-hash lxmf-router-delivery-destination) reticulum-transport-destinations)
    (setq lxmf-router-delivery-destination nil)))

(provide 'lxmf-router)

;;; lxmf-router.el ends here
