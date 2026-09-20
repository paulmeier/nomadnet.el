;;; reticulum-test.el --- Tests for the native Reticulum layers  -*- lexical-binding: t; coding: utf-8; -*-

;;; Commentary:

;; Vectors in test/vectors.json are generated from the reference Python
;; implementation by test/gen_vectors.py.

;;; Code:

(require 'ert)
(require 'reticulum-bytes)
(require 'reticulum-msgpack)
(require 'reticulum-crypto)
(require 'reticulum-packet)
(require 'reticulum-identity)
(require 'reticulum-interface)
(require 'reticulum-transport)
(require 'reticulum-bz2)
(require 'reticulum-link)
(require 'reticulum-resource)

(defvar reticulum-test--vectors
  (let ((file (expand-file-name "vectors.json"
                                (file-name-directory (or load-file-name buffer-file-name)))))
    (with-temp-buffer
      (insert-file-contents file)
      (json-parse-buffer :object-type 'plist :array-type 'list :null-object nil :false-object :false))))

(defun reticulum-test--vec (key)
  "Return the vector list stored under KEY."
  (plist-get reticulum-test--vectors key))

(defun reticulum-test--hex (plist key)
  "Return the hex field KEY of PLIST as bytes, or nil."
  (let ((v (plist-get plist key)))
    (and v (not (eq v :false)) (reticulum-unhex v))))

;;;; bytes

(ert-deftest reticulum-bytes-int-roundtrip ()
  (should (equal (reticulum-hex (reticulum-int-to-bytes 258 4)) "00000102"))
  (should (equal (reticulum-hex (reticulum-int-to-bytes 258 4 t)) "02010000"))
  (should (= (reticulum-bytes-to-int (reticulum-unhex "00000102")) 258))
  (should (= (reticulum-bytes-to-int (reticulum-unhex "02010000") t) 258))
  (let ((big (- (ash 1 255) 19)))
    (should (= (reticulum-bytes-to-int (reticulum-int-to-bytes big 32 t) t) big))))

(ert-deftest reticulum-bytes-random ()
  (let ((a (reticulum-random-bytes 32)) (b (reticulum-random-bytes 32)))
    (should (= (length a) 32))
    (should (reticulum-bytes-p a))
    (should-not (equal a b))))

;;;; msgpack

(ert-deftest reticulum-msgpack-vectors ()
  (dolist (case (reticulum-test--vec :msgpack))
    (let* ((packed (reticulum-unhex (plist-get case :packed)))
           (value (reticulum-msgpack-unpack packed))
           (repacked (reticulum-msgpack-pack value)))
      (should (equal (reticulum-hex repacked) (plist-get case :packed))))))

(ert-deftest reticulum-msgpack-types ()
  (should (equal (reticulum-msgpack-unpack (reticulum-msgpack-pack '(1 "two" :false nil t))) '(1 "two" :false nil t)))
  (let ((bin (reticulum-msgpack-unpack (reticulum-msgpack-pack (reticulum-bytes 1 2 3)))))
    (should (reticulum-bytes-p bin))
    (should (equal bin (reticulum-bytes 1 2 3))))
  (let* ((table (reticulum-msgpack-map (reticulum-msgpack-str "k") 5 7 "v"))
         (back (reticulum-msgpack-unpack (reticulum-msgpack-pack table))))
    (should (hash-table-p back))
    (should (= (gethash "k" back) 5))
    (should (equal (gethash 7 back) "v")))
  (should (= (reticulum-msgpack-unpack (reticulum-msgpack-pack (ash 1 63))) (ash 1 63)))
  (should (= (reticulum-msgpack-unpack (reticulum-msgpack-pack 1758380000.25)) 1758380000.25))
  (should (equal (reticulum-msgpack-unpack (reticulum-unhex "ca3fc00000")) 1.5)))

;;;; hashes, hkdf, token

(ert-deftest reticulum-hash ()
  (should (equal (reticulum-hex (reticulum-sha256 "abc"))
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
  (should (= (length (reticulum-truncated-hash "abc")) 16)))

(ert-deftest reticulum-hkdf-vectors ()
  (dolist (case (reticulum-test--vec :hkdf))
    (should (equal (reticulum-hex (reticulum-hkdf (plist-get case :length)
                                                  (reticulum-test--hex case :ikm)
                                                  (reticulum-test--hex case :salt)
                                                  (reticulum-test--hex case :context)))
                   (plist-get case :okm)))))

(ert-deftest reticulum-token-vectors ()
  (dolist (case (reticulum-test--vec :token))
    (let ((key (reticulum-test--hex case :key))
          (plaintext (reticulum-test--hex case :plaintext))
          (token (reticulum-test--hex case :token)))
      (should (equal (reticulum-token-decrypt key token) plaintext))
      (should (equal (reticulum-token-decrypt key (reticulum-token-encrypt key plaintext)) plaintext))
      (let ((bad (copy-sequence token)))
        (aset bad 20 (logxor (aref bad 20) 1))
        (should-error (reticulum-token-decrypt key bad))))))

;;;; curves

(ert-deftest reticulum-x25519-vectors ()
  (dolist (case (reticulum-test--vec :x25519))
    (let ((priv (reticulum-test--hex case :private))
          (peer-priv (reticulum-test--hex case :peer_private))
          (peer-pub (reticulum-test--hex case :peer_public)))
      (should (equal (reticulum-hex (reticulum-x25519-public priv)) (plist-get case :public)))
      (should (equal (reticulum-hex (reticulum-x25519-shared priv peer-pub)) (plist-get case :shared)))
      (should (equal (reticulum-hex (reticulum-x25519-shared peer-priv (reticulum-x25519-public priv)))
                     (plist-get case :shared))))))

(ert-deftest reticulum-ed25519-vectors ()
  (dolist (case (reticulum-test--vec :ed25519))
    (let ((seed (reticulum-test--hex case :seed))
          (public (reticulum-test--hex case :public))
          (message (reticulum-unhex (plist-get case :message)))
          (signature (reticulum-test--hex case :signature)))
      (should (equal (reticulum-hex (reticulum-ed25519-public seed)) (plist-get case :public)))
      (should (equal (reticulum-hex (reticulum-ed25519-sign seed message)) (plist-get case :signature)))
      (should (reticulum-ed25519-verify public signature message))
      (should-not (reticulum-ed25519-verify public signature (concat message "x")))
      (let ((bad (copy-sequence signature)))
        (aset bad 3 (logxor (aref bad 3) 1))
        (should-not (reticulum-ed25519-verify public bad message))))))

(ert-deftest reticulum-ed25519-fresh-keys ()
  (let* ((seed (reticulum-ed25519-generate-private))
         (public (reticulum-ed25519-public seed))
         (sig (reticulum-ed25519-sign seed "payload")))
    (should (reticulum-ed25519-verify public sig "payload"))))

;;;; identity and destinations

(ert-deftest reticulum-identity-vectors ()
  (dolist (case (reticulum-test--vec :identity))
    (let* ((identity (reticulum-identity-from-private (reticulum-test--hex case :private)))
           (public (reticulum-identity-from-public (reticulum-test--hex case :public)))
           (message (reticulum-test--hex case :message)))
      (should (equal (reticulum-hex (reticulum-identity-public-bytes identity)) (plist-get case :public)))
      (should (equal (reticulum-identity-hexhash identity) (plist-get case :hash)))
      (should (equal (reticulum-identity-hexhash public) (plist-get case :hash)))
      (should (equal (reticulum-hex (reticulum-address identity "lxmf" "delivery"))
                     (plist-get case :lxmf_delivery_hash)))
      (should (equal (reticulum-hex (reticulum-address-from-name "nomadnetwork.node" identity))
                     (plist-get case :node_hash)))
      (should (equal (reticulum-hex (reticulum-address-name-hash "lxmf" '("delivery")))
                     (plist-get case :name_hash_lxmf_delivery)))
      (should (equal (reticulum-hex (reticulum-identity-sign identity message)) (plist-get case :signature)))
      (should (reticulum-identity-validate public (reticulum-test--hex case :signature) message))
      ;; Decrypt what Python encrypted, with and without a ratchet.
      (should (equal (car (reticulum-identity-decrypt identity (reticulum-test--hex case :ciphertext)))
                     (reticulum-test--hex case :plaintext)))
      (let ((result (reticulum-identity-decrypt identity (reticulum-test--hex case :ciphertext_ratchet)
                                                (list (reticulum-test--hex case :ratchet_private)))))
        (should (equal (car result) (reticulum-test--hex case :plaintext)))
        (should (equal (reticulum-hex (cdr result)) (plist-get case :ratchet_id))))
      (should (equal (reticulum-hex (reticulum-identity-ratchet-public (reticulum-test--hex case :ratchet_private)))
                     (plist-get case :ratchet_public)))
      ;; Our own encryption round-trips, with and without ratchet.
      (should (equal (car (reticulum-identity-decrypt identity (reticulum-identity-encrypt public "secret")))
                     "secret"))
      (should (equal (car (reticulum-identity-decrypt identity
                                                      (reticulum-identity-encrypt public "secret" (reticulum-test--hex case :ratchet_public))
                                                      (list (reticulum-test--hex case :ratchet_private))))
                     "secret")))))

(ert-deftest reticulum-identity-file-roundtrip ()
  (let* ((identity (reticulum-identity-create))
         (path (make-temp-file "reticulum-identity")))
    (unwind-protect
        (progn
          (reticulum-identity-to-file identity path)
          (should (equal (reticulum-identity-hash (reticulum-identity-from-file path))
                         (reticulum-identity-hash identity))))
      (delete-file path))))

;;;; packets and announces

(ert-deftest reticulum-packet-roundtrip ()
  (let* ((dest (reticulum-random-bytes 16))
         (via (reticulum-random-bytes 16))
         (p1 (reticulum-packet-make :packet-type reticulum-packet-data :destination-hash dest
                                    :context reticulum-context-request :data "payload"))
         (u1 (reticulum-packet-unpack (reticulum-packet-raw p1)))
         (p2 (reticulum-packet-make :header-type reticulum-header-2 :transport-id via
                                    :packet-type reticulum-packet-data :destination-hash dest
                                    :context reticulum-context-request
                                    :hops 3 :data "payload"))
         (u2 (reticulum-packet-unpack (reticulum-packet-raw p2))))
    (should (equal (reticulum-packet-destination-hash u1) dest))
    (should (equal (reticulum-packet-data u1) "payload"))
    (should (= (reticulum-packet-context u1) reticulum-context-request))
    (should (equal (reticulum-packet-hash u1) (reticulum-packet-hash p1)))
    (should (equal (reticulum-packet-transport-id u2) via))
    (should (= (reticulum-packet-hops u2) 3))
    ;; Header type does not change the packet hash.
    (should (equal (reticulum-packet-hash u2) (reticulum-packet-hash p1)))))

(ert-deftest reticulum-announce-vectors ()
  (clrhash reticulum-known-destinations)
  (dolist (case (reticulum-test--vec :announce))
    (let* ((packet (reticulum-packet-unpack (reticulum-test--hex case :raw)))
           (announce (reticulum-announce-validate packet t)))
      (if (plist-get case :invalid)
          (should-not announce)
        (should announce)
        (should (equal (reticulum-hex (reticulum-packet-hash packet)) (plist-get case :packet_hash)))
        (should (equal (reticulum-identity-hexhash (plist-get announce :identity)) (plist-get case :identity_hash)))
        (should (equal (reticulum-hex (plist-get announce :app-data)) (plist-get case :app_data)))
        (should (eq (and (plist-get announce :ratchet) t) (eq (plist-get case :with_ratchet) t)))
        (should (equal (reticulum-hex (reticulum-identity-hash (reticulum-identity-recall (plist-get announce :destination-hash))))
                       (plist-get case :identity_hash)))
        (when (plist-get announce :ratchet)
          (should (equal (reticulum-hex (reticulum-identity-get-ratchet (plist-get announce :destination-hash)))
                         (plist-get case :ratchet))))
        (should (equal (car (reticulum-msgpack-unpack (plist-get announce :app-data))) "Test Peer"))))))

(ert-deftest reticulum-announce-build-and-validate ()
  (let* ((identity (reticulum-identity-create))
         (ratchet (reticulum-identity-generate-ratchet))
         (packet (reticulum-announce-build identity "lxmf" '("delivery")
                                           (reticulum-msgpack-pack (list "Emacs" nil (list 0)))
                                           (reticulum-identity-ratchet-public ratchet)))
         (parsed (reticulum-packet-unpack (reticulum-packet-raw packet)))
         (announce (reticulum-announce-validate parsed)))
    (should announce)
    (should (equal (plist-get announce :destination-hash) (reticulum-address identity "lxmf" "delivery")))
    (should (equal (plist-get announce :ratchet) (reticulum-identity-ratchet-public ratchet)))))

;;;; HDLC framing

(ert-deftest reticulum-hdlc-roundtrip ()
  (let* ((data (reticulum-bytes 1 #x7e 2 #x7d 3 #x5e #x5d))
         (frame (reticulum-hdlc-frame data)))
    (should (= (aref frame 0) #x7e))
    (should (= (aref frame (1- (length frame))) #x7e))
    (should (equal (reticulum-hdlc-unescape (substring frame 1 -1)) data))))

(ert-deftest reticulum-hdlc-filter-splits-frames ()
  (let* ((received nil)
         (reticulum-interface-receive-function (lambda (raw _iface) (push raw received)))
         (iface (reticulum-interface--make :name "test" :hw-mtu 1064))
         (p1 (reticulum-packet-raw (reticulum-packet-make :destination-hash (make-string 16 1) :data (make-string 30 ?a))))
         (p2 (reticulum-packet-raw (reticulum-packet-make :destination-hash (make-string 16 2) :data (make-string 30 ?b))))
         (stream (concat (reticulum-hdlc-frame p1) (reticulum-hdlc-frame p2))))
    ;; Deliver in awkward chunks.
    (reticulum-interface--filter iface (substring stream 0 10))
    (reticulum-interface--filter iface (substring stream 10 40))
    (reticulum-interface--filter iface (substring stream 40))
    (should (equal (nreverse received) (list p1 p2)))))

;;;; transport

(ert-deftest reticulum-transport-path-table-from-announce ()
  (clrhash reticulum-transport-path-table)
  (let* ((identity (reticulum-identity-create))
         (via (reticulum-random-bytes 16))
         (announce (reticulum-announce-build identity "nomadnetwork" '("node") "Node"))
         (raw (reticulum-packet-raw announce))
         ;; Simulate transport: header 2 with a transport id and 2 hops.
         (flags (logior (ash reticulum-header-2 6) (ash reticulum-transport-transport 4) (logand (aref raw 0) #x0f)))
         (wire (concat (unibyte-string flags 2) via (substring raw 2)))
         (iface (reticulum-interface--make :name "test" :online t))
         (seen nil))
    (reticulum-transport-register-announce-handler "nomadnetwork.node" (lambda (a) (push a seen)))
    (unwind-protect
        (progn
          (reticulum-transport-inbound wire iface)
          (let ((dest (reticulum-address identity "nomadnetwork" "node")))
            (should (reticulum-transport-has-path dest))
            ;; Wire hops 2, plus the hop that brought it here.
            (should (= (reticulum-transport-hops-to dest) 3))
            (should (equal (reticulum-transport-next-hop dest) via))
            (should (= (length seen) 1))
            (should (equal (plist-get (car seen) :app-data) "Node"))))
      (setq reticulum-transport-announce-handlers nil))))

;;;; bz2

(ert-deftest reticulum-bz2-vectors ()
  (skip-unless (reticulum-bz2-available-p))
  (dolist (case (reticulum-test--vec :bz2))
    (should (equal (reticulum-bz2-decompress (reticulum-unhex (plist-get case :compressed)))
                   (reticulum-unhex (plist-get case :data))))))

;;;; links

(ert-deftest reticulum-link-signalling ()
  ;; MTU 500, mode AES-256-CBC (1): value = 500 + ((1<<5)<<16) = 0x2001f4
  (should (equal (reticulum-hex (reticulum-link-signalling-bytes 500 1)) "2001f4"))
  (let ((link (reticulum-link--make :mtu 500)))
    (reticulum-link--update-mdu link)
    (should (= (reticulum-link-mdu link) 431))))

(ert-deftest reticulum-link-request-packet-format ()
  ;; A link with a derived key can encrypt a request; the peer must be able
  ;; to decrypt it with the same key and see [time path-hash data].
  (let* ((key (reticulum-random-bytes 64))
         (link (reticulum-link--make :id (reticulum-random-bytes 16) :status 'active
                                     :derived-key key :rtt 0.1 :mtu 500 :interface nil)))
    (reticulum-link--update-mdu link)
    (cl-letf (((symbol-function 'reticulum-transport-outbound)
               (lambda (packet &optional _receipt)
                 (let* ((plain (reticulum-token-decrypt key (reticulum-packet-data packet)))
                        (unpacked (reticulum-msgpack-unpack plain)))
                   (should (= (reticulum-packet-context packet) reticulum-context-request))
                   (should (= (reticulum-packet-destination-type packet) reticulum-destination-link))
                   (should (equal (nth 1 unpacked) (reticulum-truncated-hash "/page/index.mu")))
                   (should (equal (gethash "field_user" (nth 2 unpacked)) "bob"))
                   nil))))
      (let ((request (reticulum-link-request link "/page/index.mu"
                                             (reticulum-msgpack-map (reticulum-msgpack-str "field_user")
                                                                    (reticulum-msgpack-str "bob")))))
        (should (eq (reticulum-request-status request) 'sent))
        (should (memq request (reticulum-link-pending-requests link)))
        ;; Deliver a packet response for it.
        (reticulum-link--handle-response link (reticulum-request-id request) "page data")
        (should (eq (reticulum-request-status request) 'ready))
        (should (equal (reticulum-request-response request) "page data"))))))

;;;; resources

(ert-deftest reticulum-resource-advertisement-parse ()
  (let* ((table (reticulum-msgpack-map (reticulum-msgpack-str "t") 1000 (reticulum-msgpack-str "d") 5000
                                       (reticulum-msgpack-str "n") 3 (reticulum-msgpack-str "h") (make-string 32 1)
                                       (reticulum-msgpack-str "r") (make-string 4 2) (reticulum-msgpack-str "o") (make-string 32 1)
                                       (reticulum-msgpack-str "i") 1 (reticulum-msgpack-str "l") 1
                                       (reticulum-msgpack-str "q") (make-string 16 3)
                                       (reticulum-msgpack-str "f") (logior 1 2 16)
                                       (reticulum-msgpack-str "m") (make-string 12 4)))
         (adv (reticulum-resource-parse-advertisement (reticulum-msgpack-pack table))))
    (should adv)
    (should (= (plist-get adv :transfer-size) 1000))
    (should (plist-get adv :encrypted))
    (should (plist-get adv :compressed))
    (should (plist-get adv :is-response))
    (should-not (plist-get adv :is-request))
    (should (equal (plist-get adv :request-id) (make-string 16 3)))))

(ert-deftest reticulum-resource-reassembly ()
  "Build a compressed, encrypted resource the way a sender does and receive it."
  (skip-unless (reticulum-bz2-available-p))
  (let* ((key (reticulum-random-bytes 64))
         (link (reticulum-link--make :id (reticulum-random-bytes 16) :status 'active
                                     :derived-key key :rtt 0.05 :mtu 500))
         (payload (apply #'concat (make-list 300 "micron page line `!bold`!\n")))
         (random-hash (reticulum-random-bytes 4))
         (compressed (reticulum-bz2-compress payload))
         (resource-hash (reticulum-full-hash (concat payload random-hash)))
         (data (reticulum-token-encrypt key (concat random-hash compressed)))
         (sdu (- 500 reticulum-header-maxsize reticulum-ifac-min-size))
         (parts (let ((out nil) (i 0))
                  (while (< i (length data))
                    (push (substring data i (min (length data) (+ i sdu))) out)
                    (cl-incf i sdu))
                  (nreverse out)))
         (hashmap (apply #'concat (mapcar (lambda (p) (substring (reticulum-full-hash (concat p random-hash)) 0 4)) parts)))
         (adv (list :transfer-size (length data) :data-size (length payload) :parts (length parts)
                    :hash resource-hash :random-hash random-hash :original-hash resource-hash
                    :segment-index 1 :total-segments 1 :request-id nil
                    :encrypted t :compressed t :split nil :is-request nil :is-response nil :has-metadata nil
                    :hashmap hashmap))
         (sent nil) (concluded nil))
    (reticulum-link--update-mdu link)
    (cl-letf (((symbol-function 'reticulum-transport-outbound)
               (lambda (packet &optional _r) (push packet sent) nil)))
      (let ((resource (reticulum-resource-accept link adv (lambda (r) (setq concluded r)))))
        (should resource)
        ;; The receiver asked for the first window of parts.
        (should (= (reticulum-packet-context (car sent)) reticulum-context-resource-req))
        (should (= (reticulum-resource-outstanding-parts resource) (min 4 (length parts))))
        ;; Deliver all parts, out of order.
        (dolist (part (reverse parts))
          (reticulum-resource--handle-packet
           (reticulum-packet-make :destination-type reticulum-destination-link
                                  :destination-hash (reticulum-link-id link)
                                  :context reticulum-context-resource :data part)
           link))
        (should concluded)
        (should (eq (reticulum-resource-status concluded) 'complete))
        (should (equal (reticulum-resource-data concluded) payload))
        ;; A proof was sent.
        (should (cl-find-if (lambda (p) (= (reticulum-packet-context p) reticulum-context-resource-prf)) sent))))))

(provide 'reticulum-test)

;;; reticulum-test.el ends here
