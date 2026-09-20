;;; reticulum-link.el --- Reticulum links  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; Port of RNS.Link: encrypted, forward-secret links between two peers.
;; Both sides are implemented: the initiator (used to browse nodes and
;; deliver messages) and the responder (needed to receive messages on
;; the local LXMF delivery destination).
;;
;; Also contains requests and responses (RNS.RequestReceipt) and the glue
;; that hands resource packets to `reticulum-resource'.

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)
(require 'reticulum-crypto)
(require 'reticulum-msgpack)
(require 'reticulum-packet)
(require 'reticulum-identity)
(require 'reticulum-transport)

(defconst reticulum-link-ecpubsize 64)
(defconst reticulum-link-mode-aes256-cbc 1)
(defconst reticulum-link-mtu-bytemask #x1fffff)
(defconst reticulum-link-mode-bytemask #xe0)
(defconst reticulum-link-keepalive-max 360)
(defconst reticulum-link-keepalive-min 5)
(defconst reticulum-link-keepalive-max-rtt 1.75)
(defconst reticulum-link-stale-factor 2)
(defconst reticulum-link-stale-grace 5)
(defconst reticulum-link-traffic-timeout-factor 6)
(defconst reticulum-link-establishment-timeout-per-hop 6)
(defconst reticulum-link-response-max-grace-time 10)

(defvar reticulum-link-resource-packet-function nil
  "Function called with (PACKET LINK) for resource related packets.")
(defvar reticulum-link-resource-advertisement-function nil
  "Function called with (LINK ADVERTISEMENT PACKET) for resource advertisements.")

;;;; Structure

(cl-defstruct (reticulum-link (:constructor reticulum-link--make) (:copier nil))
  id destination owner initiator
  (status 'pending)
  prv pub sig-prv sig-pub
  peer-pub peer-sig-pub
  derived-key
  (mode 1) (mtu 500) mdu
  rtt request-time activated-at establishment-timeout
  (last-inbound 0) (last-outbound 0) (last-keepalive 0) (last-proof 0)
  (keepalive 360) (stale-time 720)
  interface
  established-callback closed-callback packet-callback remote-identified-callback
  resource-callback resource-concluded-callback resource-started-callback
  (resource-strategy 'none)
  pending-requests incoming-resources outgoing-resources receipts
  remote-identity teardown-reason
  (tx 0) (rx 0))

(defun reticulum-link-signalling-bytes (mtu mode)
  "Return the 3 signalling bytes for MTU and MODE."
  (let ((value (+ (logand mtu reticulum-link-mtu-bytemask)
                  (ash (logand (ash mode 5) reticulum-link-mode-bytemask) 16))))
    (substring (reticulum-int-to-bytes value 4) 1)))

(defun reticulum-link--update-mdu (link)
  "Recompute the MDU of LINK from its MTU."
  (setf (reticulum-link-mdu link)
        (1- (* 16 (floor (- (reticulum-link-mtu link) reticulum-ifac-min-size
                            reticulum-header-minsize reticulum-token-overhead)
                         16)))))

(defun reticulum-link--update-keepalive (link)
  "Derive keepalive timing of LINK from its RTT."
  (let ((rtt (or (reticulum-link-rtt link) 1.0)))
    (setf (reticulum-link-keepalive link)
          (max (min (* rtt (/ reticulum-link-keepalive-max reticulum-link-keepalive-max-rtt))
                    reticulum-link-keepalive-max)
               reticulum-link-keepalive-min))
    (setf (reticulum-link-stale-time link)
          (* (reticulum-link-keepalive link) reticulum-link-stale-factor))))

(defun reticulum-link-active-p (link)
  "Return non-nil if LINK is active."
  (eq (reticulum-link-status link) 'active))

(defun reticulum-link-describe (link)
  "Return a short description of LINK."
  (format "<link %s %s>" (reticulum-hex (reticulum-link-id link)) (reticulum-link-status link)))

;;;; Encryption

(defun reticulum-link-encrypt (link plaintext)
  "Encrypt PLAINTEXT for LINK."
  (reticulum-token-encrypt (reticulum-link-derived-key link) plaintext))

(defun reticulum-link-decrypt (link ciphertext)
  "Decrypt CIPHERTEXT received on LINK, or return nil."
  (condition-case nil
      (reticulum-token-decrypt (reticulum-link-derived-key link) ciphertext)
    (error nil)))

(defun reticulum-link-sign (link message)
  "Sign MESSAGE with LINK's signing key."
  (reticulum-ed25519-sign (reticulum-link-sig-prv link) message (reticulum-link-sig-pub link)))

(defun reticulum-link-validate (link signature message)
  "Validate SIGNATURE over MESSAGE with the peer signing key of LINK."
  (reticulum-ed25519-verify (reticulum-link-peer-sig-pub link) signature message))

(defun reticulum-link--handshake (link)
  "Derive the shared key of LINK from the peer's public key."
  (setf (reticulum-link-status link) 'handshake)
  (let ((shared (reticulum-x25519-shared (reticulum-link-prv link) (reticulum-link-peer-pub link))))
    (setf (reticulum-link-derived-key link)
          (reticulum-hkdf 64 shared (reticulum-link-id link) nil))))

;;;; Sending

(defun reticulum-link--send-raw (link data context &optional packet-type create-receipt)
  "Send DATA on LINK with CONTEXT and PACKET-TYPE without encryption."
  (let ((packet (reticulum-packet-make :packet-type (or packet-type reticulum-packet-data)
                                       :destination-type reticulum-destination-link
                                       :destination-hash (reticulum-link-id link)
                                       :context context
                                       :data data
                                       :link link)))
    (reticulum-transport-outbound packet)
    (setf (reticulum-link-last-outbound link) (float-time))
    (cl-incf (reticulum-link-tx link))
    (when create-receipt
      (let ((receipt (reticulum-receipt--make
                      :hash (reticulum-packet-hash packet)
                      :truncated-hash (reticulum-packet-truncated-hash packet)
                      :packet packet :link link
                      :sent-at (float-time)
                      :timeout (max (* (or (reticulum-link-rtt link) 1.0) reticulum-link-traffic-timeout-factor) 0.005))))
        (setf (reticulum-packet-receipt packet) receipt)
        (push receipt (reticulum-link-receipts link))))
    packet))

(defun reticulum-link-send (link data &optional context create-receipt)
  "Encrypt and send DATA on LINK with CONTEXT (default none).  Return the packet."
  (unless (memq (reticulum-link-status link) '(active stale))
    (error "Link %s is not active" (reticulum-link-describe link)))
  (reticulum-link--send-raw link (reticulum-link-encrypt link data)
                            (or context reticulum-context-none) nil create-receipt))

(defun reticulum-link-send-keepalive (link)
  "Send a keepalive on LINK."
  (reticulum-link--send-raw link (unibyte-string #xff) reticulum-context-keepalive)
  (setf (reticulum-link-last-keepalive link) (float-time)))

(defun reticulum-link-identify (link identity)
  "Identify to the peer of LINK as IDENTITY."
  (when (and (reticulum-link-initiator link) (reticulum-link-active-p link))
    (let* ((public (reticulum-identity-public-bytes identity))
           (signature (reticulum-identity-sign identity (concat (reticulum-link-id link) public))))
      (reticulum-link-send link (concat public signature) reticulum-context-linkidentify))))

;;;; Establishment (initiator)

(defun reticulum-link-establish (destination &optional established-callback closed-callback)
  "Establish a link to DESTINATION object.  Callbacks receive the link."
  (unless (= (reticulum-destination-type destination) reticulum-destination-single)
    (error "Links can only be established to single destinations"))
  (let* ((prv (reticulum-x25519-generate-private))
         (sig-prv (reticulum-ed25519-generate-private))
         (link (reticulum-link--make :destination destination :initiator t
                                     :prv prv :pub (reticulum-x25519-public prv)
                                     :sig-prv sig-prv :sig-pub (reticulum-ed25519-public sig-prv)
                                     :established-callback established-callback
                                     :closed-callback closed-callback))
         (hops (reticulum-transport-hops-to (reticulum-destination-hash destination)))
         (signalling (reticulum-link-signalling-bytes reticulum-mtu reticulum-link-mode-aes256-cbc))
         (request-data (concat (reticulum-link-pub link) (reticulum-link-sig-pub link) signalling))
         (packet (reticulum-packet-make :packet-type reticulum-packet-linkrequest
                                        :destination-type reticulum-destination-single
                                        :destination-hash (reticulum-destination-hash destination)
                                        :data request-data
                                        :destination destination)))
    (reticulum-link--update-mdu link)
    (setf (reticulum-link-establishment-timeout link)
          (+ (reticulum-transport-first-hop-timeout (reticulum-destination-hash destination))
             (* reticulum-link-establishment-timeout-per-hop (max 1 (min hops 20)))))
    ;; The link id is the truncated hash of the request without signalling bytes.
    (let ((hashable (reticulum-packet-hashable-part packet)))
      (setf (reticulum-link-id link)
            (reticulum-truncated-hash (substring hashable 0 (- (length hashable) (length signalling))))))
    (puthash (reticulum-link-id link) link reticulum-transport-links)
    (setf (reticulum-link-request-time link) (float-time))
    (setf (reticulum-link-interface link) (reticulum-transport-next-hop-interface
                                           (reticulum-destination-hash destination)))
    (reticulum-transport-outbound packet)
    (setf (reticulum-link-last-outbound link) (float-time))
    link))

(defun reticulum-link--validate-proof (packet link)
  "Validate link request proof PACKET for pending LINK."
  (when (and (eq (reticulum-link-status link) 'pending) (reticulum-link-initiator link))
    (let* ((data (reticulum-packet-data packet))
           (siglen reticulum-identity-siglength)
           (destination (reticulum-link-destination link))
           (identity (reticulum-destination-identity destination))
           (signalling "")
           (confirmed-mtu nil))
      (when (> (length data) (+ siglen 32))
        (let ((mode (ash (aref data (+ siglen 32)) -5)))
          (unless (= mode reticulum-link-mode-aes256-cbc)
            (reticulum-log 1 "unsupported link mode %d in proof" mode))))
      (when (= (length data) (+ siglen 32 3))
        (let ((mtu-bytes (substring data (+ siglen 32))))
          (setq confirmed-mtu (logand (reticulum-bytes-to-int mtu-bytes) reticulum-link-mtu-bytemask))
          (setq signalling (reticulum-link-signalling-bytes confirmed-mtu reticulum-link-mode-aes256-cbc))
          (setq data (substring data 0 (+ siglen 32)))))
      (when (= (length data) (+ siglen 32))
        (let* ((signature (substring data 0 siglen))
               (peer-pub (substring data siglen))
               (peer-sig-pub (reticulum-identity-sig-pub identity))
               (signed (concat (reticulum-link-id link) peer-pub peer-sig-pub signalling)))
          (setf (reticulum-link-peer-pub link) peer-pub
                (reticulum-link-peer-sig-pub link) peer-sig-pub)
          (if (not (reticulum-identity-validate identity signature signed))
              (reticulum-log 1 "invalid link proof signature on %s" (reticulum-link-describe link))
            (reticulum-link--handshake link)
            (setf (reticulum-link-rtt link) (- (float-time) (reticulum-link-request-time link))
                  (reticulum-link-interface link) (reticulum-packet-interface packet)
                  (reticulum-link-remote-identity link) identity
                  (reticulum-link-mtu link) (or confirmed-mtu reticulum-mtu)
                  (reticulum-link-status link) 'active
                  (reticulum-link-activated-at link) (float-time)
                  (reticulum-link-last-proof link) (float-time))
            (reticulum-link--update-mdu link)
            (reticulum-link--update-keepalive link)
            (reticulum-link-send link (reticulum-msgpack-pack (reticulum-link-rtt link))
                                 reticulum-context-lrrtt)
            (when (reticulum-link-established-callback link)
              (condition-case err
                  (funcall (reticulum-link-established-callback link) link)
                (error (reticulum-log 1 "link established callback error: %s"
                                (error-message-string err)))))))))))

;;;; Establishment (responder)

(defun reticulum-link--handle-request (packet destination)
  "Answer link request PACKET for local DESTINATION."
  (let* ((data (reticulum-packet-data packet))
         (identity (reticulum-destination-identity destination)))
    (when (memq (length data) (list reticulum-link-ecpubsize (+ reticulum-link-ecpubsize 3)))
      (let* ((prv (reticulum-x25519-generate-private))
             (link (reticulum-link--make :destination destination :owner destination :initiator nil
                                         :prv prv :pub (reticulum-x25519-public prv)
                                         :sig-prv (reticulum-identity-sig-prv identity)
                                         :sig-pub (reticulum-identity-sig-pub identity)
                                         :peer-pub (substring data 0 32)
                                         :peer-sig-pub (substring data 32 64)
                                         :interface (reticulum-packet-interface packet)))
             (hashable (reticulum-packet-hashable-part packet)))
        (when (> (length data) reticulum-link-ecpubsize)
          (setq hashable (substring hashable 0 (- (length hashable) 3)))
          (setf (reticulum-link-mtu link)
                (or (let ((m (logand (reticulum-bytes-to-int (substring data 64 67)) reticulum-link-mtu-bytemask)))
                      (and (> m 0) m))
                    reticulum-mtu)))
        (setf (reticulum-link-id link) (reticulum-truncated-hash hashable))
        (reticulum-link--update-mdu link)
        (setf (reticulum-link-establishment-timeout link)
              (+ (* reticulum-link-establishment-timeout-per-hop (max 1 (reticulum-packet-hops packet)))
                 reticulum-link-keepalive-max))
        (setf (reticulum-link-request-time link) (float-time))
        (reticulum-link--handshake link)
        (puthash (reticulum-link-id link) link reticulum-transport-links)
        ;; Prove.
        (let* ((signalling (reticulum-link-signalling-bytes (reticulum-link-mtu link) reticulum-link-mode-aes256-cbc))
               (signed (concat (reticulum-link-id link) (reticulum-link-pub link)
                               (reticulum-link-sig-pub link) signalling))
               (signature (reticulum-identity-sign identity signed))
               (proof (concat signature (reticulum-link-pub link) signalling))
               (proof-packet (reticulum-packet-make :packet-type reticulum-packet-proof
                                                    :destination-type reticulum-destination-link
                                                    :destination-hash (reticulum-link-id link)
                                                    :context reticulum-context-lrproof
                                                    :data proof :link link)))
          (reticulum-transport-outbound proof-packet)
          (setf (reticulum-link-last-outbound link) (float-time)))
        link))))

(defun reticulum-link--rtt-packet (packet link)
  "Handle the RTT PACKET from the initiator of responder LINK."
  (let ((plaintext (reticulum-link-decrypt link (reticulum-packet-data packet))))
    (if (null plaintext)
        (reticulum-link-teardown link)
      (let ((measured (- (float-time) (reticulum-link-request-time link)))
            (rtt (reticulum-msgpack-unpack plaintext)))
        (setf (reticulum-link-rtt link) (max measured (if (numberp rtt) (float rtt) 0.0))
              (reticulum-link-status link) 'active
              (reticulum-link-activated-at link) (float-time))
        (reticulum-link--update-keepalive link)
        (let ((callback (reticulum-destination-link-established-callback (reticulum-link-owner link))))
          (when callback
            (condition-case err
                (funcall callback link)
              (error (reticulum-log 1 "link established callback error: %s"
                              (error-message-string err))))))))))

;;;; Teardown

(defun reticulum-link--closed (link)
  "Mark LINK closed and notify."
  (setf (reticulum-link-status link) 'closed)
  (remhash (reticulum-link-id link) reticulum-transport-links)
  (dolist (request (reticulum-link-pending-requests link))
    (reticulum-link--request-failed link request))
  (when (reticulum-link-closed-callback link)
    (condition-case err
        (funcall (reticulum-link-closed-callback link) link)
      (error (reticulum-log 1 "link closed callback error: %s" (error-message-string err))))))

(defun reticulum-link-teardown (link)
  "Close LINK, informing the peer when the link was established."
  (unless (eq (reticulum-link-status link) 'closed)
    (when (memq (reticulum-link-status link) '(active stale handshake))
      (condition-case nil
          (reticulum-link--send-raw link (reticulum-link-encrypt link (reticulum-link-id link))
                                    reticulum-context-linkclose)
        (error nil)))
    (setf (reticulum-link-teardown-reason link)
          (if (reticulum-link-initiator link) 'initiator-closed 'destination-closed))
    (reticulum-link--closed link)))

;;;; Requests

(define-error 'reticulum-request-too-large
  "Request exceeds the link MDU; outbound resources are not implemented yet")

(cl-defstruct (reticulum-request (:constructor reticulum-request--make) (:copier nil))
  id link path (status 'sent) sent-at timeout started-at
  response response-size response-transfer-size (progress 0.0) metadata
  response-callback failed-callback progress-callback)

(defun reticulum-link-request (link path &optional data response-callback failed-callback
                                    progress-callback timeout)
  "Send a request for PATH with DATA over LINK.
Callbacks receive the `reticulum-request' object.  Returns the request."
  (unless (reticulum-link-active-p link)
    (error "Link is not active"))
  (let* ((path-hash (reticulum-truncated-hash (reticulum-utf8 path)))
         (packed (reticulum-msgpack-pack (list (float-time) path-hash data)))
         (timeout (or timeout (+ (* (reticulum-link-rtt link) reticulum-link-traffic-timeout-factor)
                                 (* reticulum-link-response-max-grace-time 1.125)))))
    (when (> (length packed) (reticulum-link-mdu link))
      (signal 'reticulum-request-too-large (list (length packed) (reticulum-link-mdu link))))
    (let* ((packet (reticulum-link-send link packed reticulum-context-request t))
           (request (reticulum-request--make :id (reticulum-packet-truncated-hash packet)
                                             :link link :path path
                                             :sent-at (float-time) :timeout timeout
                                             :started-at (float-time)
                                             :response-callback response-callback
                                             :failed-callback failed-callback
                                             :progress-callback progress-callback)))
      (push request (reticulum-link-pending-requests link))
      request)))

(defun reticulum-link--request-failed (link request)
  "Mark REQUEST on LINK as failed."
  (setf (reticulum-link-pending-requests link) (delq request (reticulum-link-pending-requests link)))
  (unless (memq (reticulum-request-status request) '(ready failed))
    (setf (reticulum-request-status request) 'failed)
    (when (reticulum-request-failed-callback request)
      (condition-case err
          (funcall (reticulum-request-failed-callback request) request)
        (error (reticulum-log 1 "request failed callback error: %s" (error-message-string err)))))))

(defun reticulum-link--handle-response (link request-id response &optional size transfer-size metadata)
  "Deliver RESPONSE for REQUEST-ID received on LINK."
  (let ((request (cl-find-if (lambda (r) (equal (reticulum-request-id r) request-id))
                             (reticulum-link-pending-requests link))))
    (when request
      (setf (reticulum-link-pending-requests link) (delq request (reticulum-link-pending-requests link)))
      (setf (reticulum-request-response request) response
            (reticulum-request-metadata request) metadata
            (reticulum-request-progress request) 1.0
            (reticulum-request-status request) 'ready)
      (when size (setf (reticulum-request-response-size request) size))
      (when transfer-size (setf (reticulum-request-response-transfer-size request) transfer-size))
      (when (reticulum-request-response-callback request)
        (condition-case err
            (funcall (reticulum-request-response-callback request) request)
          (error (reticulum-log 1 "response callback error: %s" (error-message-string err))))))))

(defun reticulum-link-find-request (link request-id)
  "Return the pending request with REQUEST-ID on LINK, or nil."
  (cl-find-if (lambda (r) (equal (reticulum-request-id r) request-id))
              (reticulum-link-pending-requests link)))

(defun reticulum-request-response-time (request)
  "Return how long REQUEST took, or nil."
  (when (and (reticulum-request-started-at request) (eq (reticulum-request-status request) 'ready))
    (- (float-time) (reticulum-request-started-at request))))

;;;; Receiving

(defun reticulum-link--validate-link-proof (packet link)
  "Validate a packet proof received on LINK for one of its receipts."
  (let ((proof (reticulum-packet-data packet)))
    (when (= (length proof) 96)
      (let ((hash (substring proof 0 32))
            (signature (substring proof 32)))
        (dolist (receipt (copy-sequence (reticulum-link-receipts link)))
          (when (and (equal (reticulum-receipt-hash receipt) hash)
                     (reticulum-link-validate link signature hash))
            (setf (reticulum-receipt-status receipt) 'delivered
                  (reticulum-receipt-concluded-at receipt) (float-time)
                  (reticulum-link-last-proof link) (float-time))
            (setf (reticulum-link-receipts link) (delq receipt (reticulum-link-receipts link)))
            (when (reticulum-receipt-delivery-callback receipt)
              (funcall (reticulum-receipt-delivery-callback receipt) receipt))))))))

(defun reticulum-link-receive (packet link)
  "Process PACKET addressed to LINK."
  (unless (eq (reticulum-link-status link) 'closed)
    (let ((context (reticulum-packet-context packet))
          (type (reticulum-packet-packet-type packet)))
      (unless (and (reticulum-link-initiator link) (= context reticulum-context-keepalive)
                   (equal (reticulum-packet-data packet) (unibyte-string #xff)))
        (setf (reticulum-link-last-inbound link) (float-time))
        (cl-incf (reticulum-link-rx link))
        (when (eq (reticulum-link-status link) 'stale)
          (setf (reticulum-link-status link) 'active))
        (cond
         ((= type reticulum-packet-proof)
          (reticulum-link--validate-link-proof packet link))
         ((= type reticulum-packet-data)
          (cond
           ((= context reticulum-context-none)
            (let ((plaintext (reticulum-link-decrypt link (reticulum-packet-data packet))))
              (when plaintext
                (when (reticulum-link-packet-callback link)
                  (condition-case err
                      (funcall (reticulum-link-packet-callback link) plaintext packet link)
                    (error (reticulum-log 1 "link packet callback error: %s" (error-message-string err)))))
                (when (and (not (reticulum-link-initiator link))
                           (eq (reticulum-destination-proof-strategy (reticulum-link-owner link)) 'all))
                  (reticulum-link-prove-packet link packet)))))
           ((= context reticulum-context-lrrtt)
            (unless (reticulum-link-initiator link)
              (reticulum-link--rtt-packet packet link)))
           ((= context reticulum-context-linkclose)
            (setf (reticulum-link-teardown-reason link)
                  (if (reticulum-link-initiator link) 'destination-closed 'initiator-closed))
            (reticulum-link--closed link))
           ((= context reticulum-context-keepalive)
            (when (and (not (reticulum-link-initiator link))
                       (equal (reticulum-packet-data packet) (unibyte-string #xff))
                       (>= (float-time) (+ (reticulum-link-last-outbound link) (reticulum-link-keepalive link))))
              (reticulum-link--send-raw link (unibyte-string #xfe) reticulum-context-keepalive)))
           ((= context reticulum-context-linkidentify)
            (let ((plaintext (reticulum-link-decrypt link (reticulum-packet-data packet))))
              (when (and plaintext (not (reticulum-link-initiator link)) (= (length plaintext) 128))
                (let* ((public (substring plaintext 0 64))
                       (signature (substring plaintext 64))
                       (identity (reticulum-identity-from-public public)))
                  (when (reticulum-identity-validate identity signature (concat (reticulum-link-id link) public))
                    (unless (reticulum-link-remote-identity link)
                      (setf (reticulum-link-remote-identity link) identity)
                      (when (reticulum-link-remote-identified-callback link)
                        (funcall (reticulum-link-remote-identified-callback link) link identity))))))))
           ((= context reticulum-context-response)
            (let ((plaintext (reticulum-link-decrypt link (reticulum-packet-data packet))))
              (when plaintext
                (let* ((unpacked (reticulum-msgpack-unpack plaintext))
                       (request-id (nth 0 unpacked))
                       (response (nth 1 unpacked))
                       (size (- (length (reticulum-msgpack-pack response)) 2)))
                  (reticulum-link--handle-response link request-id response size size)))))
           ((memq context (list reticulum-context-resource reticulum-context-resource-adv
                                reticulum-context-resource-req reticulum-context-resource-hmu
                                reticulum-context-resource-icl reticulum-context-resource-rcl))
            (when reticulum-link-resource-packet-function
              (funcall reticulum-link-resource-packet-function packet link)))
           ((= context reticulum-context-request)
            ;; This client does not serve requests.
            nil))))))))

(defun reticulum-link-prove-packet (link packet)
  "Send a proof for PACKET received on LINK."
  (let* ((hash (reticulum-packet-hash packet))
         (signature (reticulum-link-sign link hash)))
    (reticulum-link--send-raw link (concat hash signature) reticulum-context-none reticulum-packet-proof)))

;;;; Housekeeping

(defun reticulum-link--watchdog ()
  "Time out establishment, send keepalives and detect stale links."
  (let ((now (float-time)))
    (maphash
     (lambda (_id link)
       (pcase (reticulum-link-status link)
         ((or 'pending 'handshake)
          (when (>= now (+ (reticulum-link-request-time link) (reticulum-link-establishment-timeout link)))
            (setf (reticulum-link-teardown-reason link) 'timeout)
            (reticulum-link--closed link)))
         ('active
          (let ((last-inbound (max (reticulum-link-last-inbound link) (reticulum-link-last-proof link)
                                   (or (reticulum-link-activated-at link) 0))))
            (when (or (>= now (+ last-inbound (reticulum-link-keepalive link)))
                      (>= now (+ (reticulum-link-last-outbound link) (reticulum-link-keepalive link))))
              (when (and (reticulum-link-initiator link)
                         (>= now (+ (reticulum-link-last-keepalive link) (reticulum-link-keepalive link))))
                (reticulum-link-send-keepalive link))
              (when (>= now (+ last-inbound (reticulum-link-stale-time link)))
                (setf (reticulum-link-status link) 'stale)))
            ;; Request timeouts.
            (dolist (request (copy-sequence (reticulum-link-pending-requests link)))
              (when (and (eq (reticulum-request-status request) 'sent)
                         (> now (+ (reticulum-request-sent-at request) (reticulum-request-timeout request))))
                (reticulum-link--request-failed link request)))
            ;; Packet receipt timeouts.
            (dolist (receipt (copy-sequence (reticulum-link-receipts link)))
              (when (> now (+ (reticulum-receipt-sent-at receipt) (reticulum-receipt-timeout receipt) 1.0))
                (setf (reticulum-receipt-status receipt) 'failed)
                (setf (reticulum-link-receipts link) (delq receipt (reticulum-link-receipts link)))
                (when (reticulum-receipt-timeout-callback receipt)
                  (funcall (reticulum-receipt-timeout-callback receipt) receipt))))))
         ('stale
          (when (>= now (+ (reticulum-link-last-inbound link) (reticulum-link-stale-time link)
                           (* (or (reticulum-link-rtt link) 1) 4) reticulum-link-stale-grace))
            (setf (reticulum-link-teardown-reason link) 'timeout)
            (reticulum-link-teardown link)))))
     reticulum-transport-links)))

;;;; Wiring into the transport

(defun reticulum-link-install ()
  "Connect the link layer to the transport dispatch functions."
  (setq reticulum-transport-link-proof-function #'reticulum-link--validate-proof
        reticulum-transport-link-packet-function #'reticulum-link-receive
        reticulum-transport-link-request-function #'reticulum-link--handle-request)
  (add-hook 'reticulum-transport-job-hook #'reticulum-link--watchdog))

(reticulum-link-install)

(provide 'reticulum-link)

;;; reticulum-link.el ends here
