;;; reticulum-resource.el --- Inbound Reticulum resources  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; Receiving side of RNS.Resource: accept an advertisement on a link,
;; request parts by map hash in windows, reassemble, decrypt, decompress
;; and prove.  Used for page responses larger than one packet and for
;; LXMF messages delivered as resources.

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)
(require 'reticulum-crypto)
(require 'reticulum-msgpack)
(require 'reticulum-packet)
(require 'reticulum-link)
(require 'reticulum-bz2)

(defconst reticulum-resource-window 4)
(defconst reticulum-resource-window-min 2)
(defconst reticulum-resource-window-max-slow 10)
(defconst reticulum-resource-window-max-fast 75)
(defconst reticulum-resource-window-flexibility 4)
(defconst reticulum-resource-maphash-len 4)
(defconst reticulum-resource-random-hash-size 4)
(defconst reticulum-resource-max-retries 16)
(defconst reticulum-resource-max-efficient-size (1- (* 1024 1024)))
(defconst reticulum-resource-hashmap-max-len
  (floor (/ (- (1- (* 16 (floor (- reticulum-mtu reticulum-ifac-min-size reticulum-header-minsize
                                   reticulum-token-overhead)
                                16)))
               134)
            reticulum-resource-maphash-len)))

(cl-defstruct (reticulum-resource (:constructor reticulum-resource--make) (:copier nil))
  link hash random-hash original-hash size total-size
  encrypted compressed split is-request is-response has-metadata
  segment-index total-segments request-id
  (status 'transferring)
  sdu total-parts hashmap (hashmap-height 0) parts (received-count 0) (outstanding-parts 0)
  (consecutive-height -1)
  (window 4) (window-max 10) (window-min 2)
  waiting-for-hmu
  last-activity started-at request-sent
  (retries-left 16)
  data metadata
  callback progress-callback)

;;;; Advertisements

(defun reticulum-resource-parse-advertisement (plaintext)
  "Parse advertisement PLAINTEXT into a plist, or nil if invalid."
  (condition-case nil
      (let* ((table (reticulum-msgpack-unpack plaintext))
             (get (lambda (k) (gethash (reticulum-msgpack-str k) table)))
             (flags (funcall get "f")))
        (when (and (hash-table-p table) (integerp flags))
          (let ((transfer-size (funcall get "t")))
            (when (> transfer-size (* 3 reticulum-resource-max-efficient-size))
              (error "Invalid transfer size"))
            (list :transfer-size transfer-size
                  :data-size (funcall get "d")
                  :parts (funcall get "n")
                  :hash (funcall get "h")
                  :random-hash (funcall get "r")
                  :original-hash (funcall get "o")
                  :segment-index (funcall get "i")
                  :total-segments (funcall get "l")
                  :request-id (funcall get "q")
                  :hashmap (funcall get "m")
                  :flags flags
                  :encrypted (= (logand flags 1) 1)
                  :compressed (= (logand (ash flags -1) 1) 1)
                  :split (= (logand (ash flags -2) 1) 1)
                  :is-request (= (logand (ash flags -3) 1) 1)
                  :is-response (= (logand (ash flags -4) 1) 1)
                  :has-metadata (= (logand (ash flags -5) 1) 1)))))
    (error nil)))

(defun reticulum-resource-accept (link advertisement &optional callback progress-callback request-id)
  "Accept resource ADVERTISEMENT plist on LINK and start requesting parts.
CALLBACK is called with the resource when it concludes."
  (let* ((sdu (- (reticulum-link-mtu link) reticulum-header-maxsize reticulum-ifac-min-size))
         (size (plist-get advertisement :transfer-size))
         (total-parts (ceiling (/ (float size) sdu)))
         (resource (reticulum-resource--make
                    :link link
                    :hash (plist-get advertisement :hash)
                    :random-hash (plist-get advertisement :random-hash)
                    :original-hash (plist-get advertisement :original-hash)
                    :size size
                    :total-size (plist-get advertisement :data-size)
                    :encrypted (plist-get advertisement :encrypted)
                    :compressed (plist-get advertisement :compressed)
                    :split (plist-get advertisement :split)
                    :is-request (plist-get advertisement :is-request)
                    :is-response (plist-get advertisement :is-response)
                    :has-metadata (plist-get advertisement :has-metadata)
                    :segment-index (plist-get advertisement :segment-index)
                    :total-segments (plist-get advertisement :total-segments)
                    :request-id (or request-id (plist-get advertisement :request-id))
                    :sdu sdu
                    :total-parts total-parts
                    :hashmap (make-vector total-parts nil)
                    :parts (make-vector total-parts nil)
                    :last-activity (float-time)
                    :started-at (float-time)
                    :callback callback
                    :progress-callback progress-callback)))
    (when (> (plist-get advertisement :total-segments) 1)
      (reticulum-log 1 "multi-segment resources are not supported; rejecting"))
    (if (cl-find-if (lambda (r) (equal (reticulum-resource-hash r) (reticulum-resource-hash resource)))
                    (reticulum-link-incoming-resources link))
        nil
      (push resource (reticulum-link-incoming-resources link))
      (when (reticulum-link-resource-started-callback link)
        (condition-case nil (funcall (reticulum-link-resource-started-callback link) resource) (error nil)))
      (reticulum-resource--hashmap-update resource 0 (plist-get advertisement :hashmap))
      resource)))

(defun reticulum-resource--hashmap-update (resource segment hashmap)
  "Merge HASHMAP bytes for SEGMENT into RESOURCE and request parts."
  (unless (eq (reticulum-resource-status resource) 'failed)
    (let ((count (/ (length hashmap) reticulum-resource-maphash-len))
          (offset (* segment reticulum-resource-hashmap-max-len))
          (map (reticulum-resource-hashmap resource)))
      (dotimes (i count)
        (let ((index (+ i offset)))
          (when (< index (length map))
            (unless (aref map index) (cl-incf (reticulum-resource-hashmap-height resource)))
            (aset map index (substring hashmap (* i reticulum-resource-maphash-len)
                                       (* (1+ i) reticulum-resource-maphash-len))))))
      (if (< count 1)
          (reticulum-resource-cancel resource)
        (setf (reticulum-resource-waiting-for-hmu resource) nil)
        (reticulum-resource--request-next resource)))))

;;;; Part requests

(defun reticulum-resource--request-next (resource)
  "Request the next window of missing parts of RESOURCE."
  (unless (or (eq (reticulum-resource-status resource) 'failed)
              (reticulum-resource-waiting-for-hmu resource))
    (let* ((parts (reticulum-resource-parts resource))
           (map (reticulum-resource-hashmap resource))
           (start (1+ (reticulum-resource-consecutive-height resource)))
           (window (reticulum-resource-window resource))
           (requested "")
           (count 0)
           (exhausted nil)
           (i start))
      (setf (reticulum-resource-outstanding-parts resource) 0)
      (while (and (< i (length parts)) (< count window) (not exhausted))
        (unless (aref parts i)
          (let ((hash (aref map i)))
            (if hash
                (progn (setq requested (concat requested hash))
                       (cl-incf count)
                       (cl-incf (reticulum-resource-outstanding-parts resource)))
              (setq exhausted t))))
        (cl-incf i))
      (let ((request (if exhausted
                         (concat (unibyte-string #xff)
                                 (aref map (1- (reticulum-resource-hashmap-height resource))))
                       (unibyte-string #x00))))
        (when exhausted (setf (reticulum-resource-waiting-for-hmu resource) t))
        (setq request (concat request (reticulum-resource-hash resource) requested))
        (condition-case err
            (progn
              (reticulum-link-send (reticulum-resource-link resource) request reticulum-context-resource-req)
              (setf (reticulum-resource-last-activity resource) (float-time)
                    (reticulum-resource-request-sent resource) (float-time)))
          (error (reticulum-log 1 "could not request resource parts: %s" (error-message-string err))
                 (reticulum-resource-cancel resource)))))))

(defun reticulum-resource--map-hash (resource data)
  "Return the map hash of part DATA for RESOURCE."
  (substring (reticulum-full-hash (concat data (reticulum-resource-random-hash resource)))
             0 reticulum-resource-maphash-len))

(defun reticulum-resource--receive-part (resource packet)
  "Store the part carried by PACKET in RESOURCE if it is expected.
Return non-nil if the part was used."
  (let* ((data (reticulum-packet-data packet))
         (part-hash (reticulum-resource--map-hash resource data))
         (map (reticulum-resource-hashmap resource))
         (parts (reticulum-resource-parts resource))
         (used nil))
    (cl-loop for i from 0 below (length map)
             when (and (aref map i) (equal (aref map i) part-hash))
             do (unless (aref parts i)
                  (aset parts i data)
                  (setq used t)
                  (cl-incf (reticulum-resource-received-count resource))
                  (when (> (reticulum-resource-outstanding-parts resource) 0)
                    (cl-decf (reticulum-resource-outstanding-parts resource)))
                  (let ((cp (1+ (reticulum-resource-consecutive-height resource))))
                    (while (and (< cp (length parts)) (aref parts cp))
                      (setf (reticulum-resource-consecutive-height resource) cp)
                      (cl-incf cp))))
             and return nil)
    (when used
      (setf (reticulum-resource-last-activity resource) (float-time)
            (reticulum-resource-retries-left resource) reticulum-resource-max-retries)
      (when (reticulum-resource-progress-callback resource)
        (condition-case nil (funcall (reticulum-resource-progress-callback resource) resource) (error nil)))
      (cond
       ((= (reticulum-resource-received-count resource) (reticulum-resource-total-parts resource))
        (reticulum-resource--assemble resource))
       ((= (reticulum-resource-outstanding-parts resource) 0)
        (when (< (reticulum-resource-window resource) (reticulum-resource-window-max resource))
          (cl-incf (reticulum-resource-window resource))
          (when (> (- (reticulum-resource-window resource) (reticulum-resource-window-min resource))
                   (1- reticulum-resource-window-flexibility))
            (cl-incf (reticulum-resource-window-min resource))))
        (reticulum-resource--request-next resource))))
    used))

(defun reticulum-resource-progress (resource)
  "Return the fraction of RESOURCE received."
  (if (> (reticulum-resource-total-parts resource) 0)
      (/ (float (reticulum-resource-received-count resource)) (reticulum-resource-total-parts resource))
    0.0))

;;;; Assembly

(defun reticulum-resource--assemble (resource)
  "Reassemble RESOURCE, verify it and deliver it."
  (unless (eq (reticulum-resource-status resource) 'failed)
    (setf (reticulum-resource-status resource) 'assembling)
    (condition-case err
        (let* ((link (reticulum-resource-link resource))
               (stream (apply #'concat (append (reticulum-resource-parts resource) nil)))
               (data (if (reticulum-resource-encrypted resource)
                         (or (reticulum-link-decrypt link stream) (error "Resource decryption failed"))
                       stream)))
          (setq data (substring data reticulum-resource-random-hash-size))
          (when (reticulum-resource-compressed resource)
            (setq data (reticulum-bz2-decompress data)))
          (unless (reticulum-bytes-equal (reticulum-full-hash (concat data (reticulum-resource-random-hash resource)))
                                         (reticulum-resource-hash resource))
            (error "Resource hash mismatch"))
          (setf (reticulum-resource-data resource) data)
          (when (reticulum-resource-has-metadata resource)
            (let* ((size (logior (ash (aref data 0) 16) (ash (aref data 1) 8) (aref data 2)))
                   (packed (substring data 3 (+ 3 size))))
              (setf (reticulum-resource-metadata resource) (reticulum-msgpack-unpack packed))
              (setf (reticulum-resource-data resource) (substring data (+ 3 size)))))
          (setf (reticulum-resource-status resource) 'complete)
          (reticulum-resource--prove resource))
      (error
       (reticulum-log 1 "resource assembly failed: %s" (error-message-string err))
       (setf (reticulum-resource-status resource) 'corrupt)))
    (reticulum-resource--conclude resource)))

(defun reticulum-resource--prove (resource)
  "Send the proof of receipt for RESOURCE."
  (let* ((hash (reticulum-resource-hash resource))
         (proof (reticulum-full-hash (concat (reticulum-resource-data resource) hash))))
    (condition-case nil
        (reticulum-link--send-raw (reticulum-resource-link resource) (concat hash proof)
                                  reticulum-context-resource-prf reticulum-packet-proof)
      (error nil))))

(defun reticulum-resource--conclude (resource)
  "Remove RESOURCE from its link and run callbacks."
  (let ((link (reticulum-resource-link resource)))
    (setf (reticulum-link-incoming-resources link)
          (delq resource (reticulum-link-incoming-resources link)))
    (when (reticulum-resource-callback resource)
      (condition-case err
          (funcall (reticulum-resource-callback resource) resource)
        (error (reticulum-log 1 "resource callback error: %s" (error-message-string err)))))
    (when (reticulum-link-resource-concluded-callback link)
      (condition-case nil (funcall (reticulum-link-resource-concluded-callback link) resource) (error nil)))))

(defun reticulum-resource-cancel (resource)
  "Cancel RESOURCE."
  (unless (memq (reticulum-resource-status resource) '(failed complete corrupt))
    (setf (reticulum-resource-status resource) 'failed)
    (condition-case nil
        (reticulum-link-send (reticulum-resource-link resource) (reticulum-resource-hash resource)
                             reticulum-context-resource-rcl)
      (error nil))
    (reticulum-resource--conclude resource)))

;;;; Packet dispatch from links

(defun reticulum-resource--handle-packet (packet link)
  "Handle resource related PACKET received on LINK."
  (let ((context (reticulum-packet-context packet)))
    (cond
     ((= context reticulum-context-resource-adv)
      (let* ((plaintext (reticulum-link-decrypt link (reticulum-packet-data packet)))
             (advertisement (and plaintext (reticulum-resource-parse-advertisement plaintext))))
        (when advertisement
          (cond
           ((and (plist-get advertisement :is-response) (plist-get advertisement :request-id))
            (let ((request (reticulum-link-find-request link (plist-get advertisement :request-id))))
              (when request
                (setf (reticulum-request-status request) 'receiving
                      (reticulum-request-response-size request) (plist-get advertisement :data-size)
                      (reticulum-request-response-transfer-size request)
                      (+ (or (reticulum-request-response-transfer-size request) 0)
                         (plist-get advertisement :transfer-size)))
                (reticulum-resource-accept
                 link advertisement
                 (lambda (resource) (reticulum-resource--response-concluded link resource))
                 (lambda (resource)
                   (setf (reticulum-request-progress request) (reticulum-resource-progress resource))
                   (when (reticulum-request-progress-callback request)
                     (condition-case nil (funcall (reticulum-request-progress-callback request) request)
                       (error nil))))
                 (plist-get advertisement :request-id)))))
           ;; The link's resource-concluded callback runs from
           ;; `reticulum-resource--conclude' for every resource, so it is
           ;; not passed again as the resource's own callback.
           ((eq (reticulum-link-resource-strategy link) 'app)
            (when (and (reticulum-link-resource-callback link)
                       (funcall (reticulum-link-resource-callback link) advertisement link))
              (reticulum-resource-accept link advertisement)))
           ((eq (reticulum-link-resource-strategy link) 'all)
            (reticulum-resource-accept link advertisement))))))
     ((= context reticulum-context-resource)
      (cl-loop for resource in (reticulum-link-incoming-resources link)
               until (reticulum-resource--receive-part resource packet)))
     ((= context reticulum-context-resource-hmu)
      (let ((plaintext (reticulum-link-decrypt link (reticulum-packet-data packet))))
        (when plaintext
          (let* ((hash (substring plaintext 0 32))
                 (update (reticulum-msgpack-unpack (substring plaintext 32)))
                 (resource (cl-find-if (lambda (r) (equal (reticulum-resource-hash r) hash))
                                       (reticulum-link-incoming-resources link))))
            (when (and resource (reticulum-resource-waiting-for-hmu resource))
              (setf (reticulum-resource-last-activity resource) (float-time)
                    (reticulum-resource-retries-left resource) reticulum-resource-max-retries)
              (reticulum-resource--hashmap-update resource (nth 0 update) (nth 1 update)))))))
     ((= context reticulum-context-resource-icl)
      (let ((plaintext (reticulum-link-decrypt link (reticulum-packet-data packet))))
        (when plaintext
          (let ((resource (cl-find-if (lambda (r) (equal (reticulum-resource-hash r) (substring plaintext 0 32)))
                                      (reticulum-link-incoming-resources link))))
            (when resource
              (setf (reticulum-resource-status resource) 'failed)
              (reticulum-resource--conclude resource)))))))))

(defun reticulum-resource--response-concluded (link resource)
  "Deliver the response carried by RESOURCE to its request on LINK."
  (if (eq (reticulum-resource-status resource) 'complete)
      (if (reticulum-resource-has-metadata resource)
          (reticulum-link--handle-response link (reticulum-resource-request-id resource)
                                           (reticulum-resource-data resource)
                                           (reticulum-resource-total-size resource)
                                           (reticulum-resource-size resource)
                                           (reticulum-resource-metadata resource))
        (condition-case err
            (let* ((unpacked (reticulum-msgpack-unpack (reticulum-resource-data resource)))
                   (request-id (nth 0 unpacked))
                   (response (nth 1 unpacked)))
              (reticulum-link--handle-response link request-id response
                                               (reticulum-resource-total-size resource)
                                               (reticulum-resource-size resource)))
          (error (reticulum-log 1 "could not unpack response resource: %s" (error-message-string err)))))
    (let ((request (reticulum-link-find-request link (reticulum-resource-request-id resource))))
      (when request (reticulum-link--request-failed link request)))))

;;;; Housekeeping

(defun reticulum-resource--watchdog ()
  "Retry or fail stalled resource transfers."
  (let ((now (float-time)))
    (maphash
     (lambda (_id link)
       (dolist (resource (copy-sequence (reticulum-link-incoming-resources link)))
         (when (eq (reticulum-resource-status resource) 'transferring)
           (let* ((rtt (or (reticulum-link-rtt link) 1.0))
                  (timeout (+ (* 4 (max rtt 0.25)) 2.0)))
             (when (> now (+ (reticulum-resource-last-activity resource) timeout))
               (if (> (reticulum-resource-retries-left resource) 0)
                   (progn
                     (cl-decf (reticulum-resource-retries-left resource))
                     (setf (reticulum-resource-waiting-for-hmu resource) nil
                           (reticulum-resource-last-activity resource) now)
                     (reticulum-resource--request-next resource))
                 (reticulum-log 1 "resource transfer timed out")
                 (reticulum-resource-cancel resource)))))))
     reticulum-transport-links)))

(defun reticulum-resource-install ()
  "Connect the resource layer to the link layer."
  (setq reticulum-link-resource-packet-function #'reticulum-resource--handle-packet)
  (add-hook 'reticulum-transport-job-hook #'reticulum-resource--watchdog))

(reticulum-resource-install)

(provide 'reticulum-resource)

;;; reticulum-resource.el ends here
