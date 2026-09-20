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
(require 'lxmf-message)
(require 'lxmf-router)

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
  "The Lisp decoder reproduces the reference data."
  (let ((reticulum-bz2-program nil))
    (dolist (case (reticulum-test--vec :bz2))
      (should (equal (reticulum-bz2-decompress (reticulum-unhex (plist-get case :compressed)))
                     (reticulum-unhex (plist-get case :data)))))))

(ert-deftest reticulum-bz2-program-vectors ()
  "The optional program fast path reproduces the reference data."
  (let ((reticulum-bz2-program "bzip2"))
    (skip-unless (reticulum-bz2-available-p))
    (dolist (case (reticulum-test--vec :bz2))
      (should (equal (reticulum-bz2-decompress (reticulum-unhex (plist-get case :compressed)))
                     (reticulum-unhex (plist-get case :data)))))))

(ert-deftest reticulum-bz2-errors ()
  "Corrupt input is rejected rather than decoded to garbage."
  (let* ((reticulum-bz2-program nil)
         (case (seq-find (lambda (c) (equal (plist-get c :name) "short")) (reticulum-test--vec :bz2)))
         (good (reticulum-unhex (plist-get case :compressed))))
    (should-error (reticulum-bz2-decompress (substring good 0 20)))
    (should-error (reticulum-bz2-decompress (concat "XX" (substring good 2))))
    ;; Bytes 10..13 hold the block CRC.
    (let ((bad (copy-sequence good)))
      (aset bad 12 (logxor (aref bad 12) 1))
      (should (equal (cadr (should-error (reticulum-bz2-decompress bad))) "bzip2: block CRC mismatch")))
    ;; Bytes 4..9 hold the block magic.
    (let ((bad (copy-sequence good)))
      (aset bad 6 0)
      (should-error (reticulum-bz2-decompress bad)))))

(ert-deftest reticulum-bz2-multiple-blocks ()
  "Small blocks, several per stream, and concatenated streams all decode."
  (skip-unless (reticulum-bz2-available-p))
  (let* ((reticulum-bz2-program nil)
         (words ["reticulum" "nomadnet" "micron" "page\n" "`!bold`!" " " "\n"])
         (state 12345)
         (payload (with-temp-buffer
                    (set-buffer-multibyte nil)
                    (dotimes (_ 60000)
                      ;; A small LCG keeps the input deterministic.
                      (setq state (% (+ (* state 1103515245) 12345) 2147483648))
                      (insert (aref words (% (ash state -16) (length words)))))
                    (buffer-string)))
         (compressed (reticulum-bz2--call payload "-1c")))
    (should (> (length payload) 200000))
    (should (equal (reticulum-bz2-decompress compressed) payload))
    (should (equal (reticulum-bz2-decompress (concat compressed compressed))
                   (concat payload payload)))))

(ert-deftest reticulum-bz2-incompressible ()
  "Random data, which stresses long Huffman codes, round trips."
  (skip-unless (reticulum-bz2-available-p))
  (let* ((reticulum-bz2-program nil)
         (payload (concat (reticulum-random-bytes 50000) (make-string 3000 ?z) (reticulum-random-bytes 5000))))
    (should (equal (reticulum-bz2-decompress (reticulum-bz2-compress payload)) payload))))

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

;;;; LXMF message codec

(defun reticulum-test--lxmf ()
  "Return the LXMF vector section."
  (plist-get reticulum-test--vectors :lxmf))

(defun reticulum-test--lxmf-identity (key)
  "Return the identity stored under KEY (:source_private or :destination_private)."
  (reticulum-identity-from-private (reticulum-test--hex (reticulum-test--lxmf) key)))

(defmacro reticulum-test--with-known-lxmf-source (&rest body)
  "Run BODY with fresh known destinations holding the vector source identity."
  `(let ((reticulum-known-destinations (make-hash-table :test #'equal))
         (reticulum-known-ratchets (make-hash-table :test #'equal)))
     (let ((source (reticulum-test--lxmf-identity :source_private)))
       (reticulum-identity-remember nil (reticulum-address source "lxmf" "delivery")
                                    (reticulum-identity-public-bytes source) nil))
     ,@body))

(ert-deftest lxmf-message-vector-identities ()
  (let ((lxmf (reticulum-test--lxmf)))
    (should (equal (reticulum-address (reticulum-test--lxmf-identity :source_private) "lxmf" "delivery")
                   (reticulum-test--hex lxmf :source_hash)))
    (should (equal (reticulum-address (reticulum-test--lxmf-identity :destination_private) "lxmf" "delivery")
                   (reticulum-test--hex lxmf :destination_hash)))))

(ert-deftest lxmf-message-unpack-vectors ()
  (reticulum-test--with-known-lxmf-source
   (let ((lxmf (reticulum-test--lxmf)))
     (dolist (case (plist-get lxmf :messages))
       (let ((message (lxmf-message-unpack (reticulum-test--hex case :packed))))
         (should (equal (lxmf-message-hash message) (reticulum-test--hex case :hash)))
         (should (equal (lxmf-message-signature message) (reticulum-test--hex case :signature)))
         (should (equal (lxmf-message-destination-hash message) (reticulum-test--hex lxmf :destination_hash)))
         (should (equal (lxmf-message-source-hash message) (reticulum-test--hex lxmf :source_hash)))
         (should (= (lxmf-message-timestamp message) (plist-get case :timestamp)))
         (should (equal (lxmf-message-title message) (reticulum-test--hex case :title)))
         (should (equal (lxmf-message-content message) (reticulum-test--hex case :content)))
         (should (equal (reticulum-msgpack-pack (lxmf-message-fields message)) (reticulum-test--hex case :fields)))
         (should (equal (lxmf-message-stamp message) (reticulum-test--hex case :stamp)))
         (should (lxmf-message-signature-validated message))
         (should-not (lxmf-message-unverified-reason message))
         (should (lxmf-message-incoming message)))))))

(ert-deftest lxmf-message-repack-vectors ()
  ;; Ed25519 signatures are deterministic, so packing the same message
  ;; with the same timestamp and stamp reproduces the Python bytes.
  (let* ((lxmf (reticulum-test--lxmf))
         (source (reticulum-test--lxmf-identity :source_private)))
    (dolist (case (plist-get lxmf :messages))
      (let* ((fields (reticulum-msgpack-unpack (reticulum-test--hex case :fields)))
             (message (lxmf-message-create (reticulum-test--hex lxmf :destination_hash)
                                           (reticulum-test--hex lxmf :source_hash)
                                           (reticulum-test--hex case :content)
                                           (reticulum-test--hex case :title)
                                           fields)))
        (setf (lxmf-message-stamp message) (reticulum-test--hex case :stamp))
        (let ((packed (lxmf-message-pack message source (plist-get case :timestamp))))
          (should (equal (reticulum-hex packed) (plist-get case :packed)))
          (should (equal (lxmf-message-hash message) (reticulum-test--hex case :hash)))
          (should (lxmf-message-signature-validated message)))))))

(ert-deftest lxmf-message-unverified-reasons ()
  (let* ((lxmf (reticulum-test--lxmf))
         (packed (reticulum-test--hex (car (plist-get lxmf :messages)) :packed)))
    ;; Unknown source: cannot verify.
    (let ((reticulum-known-destinations (make-hash-table :test #'equal)))
      (let ((message (lxmf-message-unpack packed)))
        (should-not (lxmf-message-signature-validated message))
        (should (= (lxmf-message-unverified-reason message) lxmf-source-unknown))))
    ;; Known source, tampered content: invalid signature.
    (reticulum-test--with-known-lxmf-source
     (let ((tampered (copy-sequence packed)))
       ;; Flip a bit inside the timestamp float, keeping the msgpack valid.
       (aset tampered 100 (logxor (aref tampered 100) 1))
       (let ((message (lxmf-message-unpack tampered)))
         (should-not (lxmf-message-signature-validated message))
         (should (= (lxmf-message-unverified-reason message) lxmf-signature-invalid))))
     ;; Known source, tampered signature: invalid signature.
     (let ((tampered (copy-sequence packed)))
       (aset tampered 40 (logxor (aref tampered 40) 1))
       (should (= (lxmf-message-unverified-reason (lxmf-message-unpack tampered)) lxmf-signature-invalid))))
    ;; Not a message at all.
    (should-error (lxmf-message-unpack (reticulum-random-bytes 50)))
    (should-error (lxmf-message-unpack (concat (substring packed 0 96) (reticulum-msgpack-pack 5))))))

(ert-deftest lxmf-message-strings-and-fields ()
  (reticulum-test--with-known-lxmf-source
   (let* ((lxmf (reticulum-test--lxmf))
          (source (reticulum-test--lxmf-identity :source_private))
          (message (lxmf-message-create (reticulum-test--hex lxmf :destination_hash)
                                        (reticulum-test--hex lxmf :source_hash)
                                        "Grüße 🌍" "Tïtle")))
     (lxmf-message-set-field message lxmf-field-renderer lxmf-renderer-micron)
     (should (reticulum-bytes-p (lxmf-message-title message)))
     (should (reticulum-bytes-p (lxmf-message-content message)))
     (let ((back (lxmf-message-unpack (lxmf-message-pack message source))))
       (should (equal (lxmf-message-title-string back) "Tïtle"))
       (should (equal (lxmf-message-content-string back) "Grüße 🌍"))
       (should (= (lxmf-message-field back lxmf-field-renderer) lxmf-renderer-micron))
       (should-not (lxmf-message-field back lxmf-field-reply-to))
       (should (lxmf-message-signature-validated back))
       (should (floatp (lxmf-message-timestamp back)))))))

(ert-deftest lxmf-message-size-constants ()
  ;; Values from the reference implementation with default parameters.
  (should (= lxmf-overhead 112))
  (should (= lxmf-encrypted-packet-mdu 391))
  (should (= lxmf-encrypted-packet-max-content 295))
  (should (= lxmf-link-packet-mdu 431))
  (should (= lxmf-link-packet-max-content 319)))

(ert-deftest lxmf-peer-app-data-vectors ()
  (dolist (case (plist-get (reticulum-test--lxmf) :app_data))
    (let ((packed (reticulum-test--hex case :packed))
          (name (plist-get case :display_name))
          (cost (plist-get case :stamp_cost)))
      (should (equal (lxmf-display-name-from-app-data packed) name))
      (should (equal (lxmf-stamp-cost-from-app-data packed) cost))
      (should (lxmf-compression-support-from-app-data packed))
      (unless (plist-get case :legacy)
        (should (equal (lxmf-peer-app-data name cost) packed)))))
  (should-not (lxmf-display-name-from-app-data nil))
  (should-not (lxmf-display-name-from-app-data ""))
  (should-not (lxmf-stamp-cost-from-app-data (reticulum-utf8 "Old Peer")))
  ;; Out of range stamp costs are not announced.
  (should (equal (lxmf-peer-app-data "x" 300) (lxmf-peer-app-data "x" nil)))
  (should-not (lxmf-compression-support-from-app-data
               (reticulum-msgpack-pack (list (reticulum-utf8 "x") nil (list 7))))))

;;;; LXMF router

(defmacro reticulum-test--with-lxmf-router (&rest body)
  "Run BODY with a router registered on the vector destination identity in a temp dir."
  `(let* ((dir (make-temp-file "lxmf-test" t))
          (reticulum-known-destinations (make-hash-table :test #'equal))
          (reticulum-known-ratchets (make-hash-table :test #'equal))
          (reticulum-transport-destinations (make-hash-table :test #'equal))
          (reticulum-transport-links (make-hash-table :test #'equal))
          (reticulum-transport-packet-hashlist (make-hash-table :test #'equal))
          (reticulum-transport-path-table (make-hash-table :test #'equal))
          (reticulum-transport-job-hook nil)
          (lxmf-router-delivered-ids (make-hash-table :test #'equal))
          (lxmf-router-backchannel-links (make-hash-table :test #'equal))
          (lxmf-router-delivery-links nil)
          (lxmf-router-delivery-destination nil)
          (lxmf-router-enforce-ratchets nil)
          (iface (reticulum-interface--make :name "test" :online t))
          (reticulum-interfaces (list iface))
          (sent nil)
          (delivered nil)
          (source (reticulum-test--lxmf-identity :source_private))
          (destination-identity (reticulum-test--lxmf-identity :destination_private)))
     (ignore source iface)
     (reticulum-identity-remember nil (reticulum-address source "lxmf" "delivery")
                                  (reticulum-identity-public-bytes source) nil)
     (unwind-protect
         (cl-letf (((symbol-function 'reticulum-interface-send)
                    (lambda (_interface raw) (push raw sent) t)))
           (lxmf-router-init dir (lambda (m) (push m delivered)))
           (lxmf-router-register-delivery-identity destination-identity "Emacs Test" nil)
           ,@body)
       (lxmf-router-stop)
       (delete-directory dir t))))

(ert-deftest lxmf-router-ratchet-file-vectors ()
  (let* ((vector (plist-get (reticulum-test--lxmf) :ratchet_file))
         (identity (reticulum-test--lxmf-identity :destination_private))
         (expected (mapcar #'reticulum-unhex (plist-get vector :ratchets)))
         (path (make-temp-file "ratchets")))
    (unwind-protect
        (progn
          (lxmf-router--write-file path (reticulum-test--hex vector :packed))
          (should (equal (lxmf-router-load-ratchets identity path) expected))
          (lxmf-router--write-file path (reticulum-test--hex vector :tampered))
          (should-error (lxmf-router-load-ratchets identity path))
          ;; Another identity cannot load the file either.
          (lxmf-router--write-file path (reticulum-test--hex vector :packed))
          (should-error (lxmf-router-load-ratchets (reticulum-test--lxmf-identity :source_private) path))
          ;; Files written here load back, and are byte identical to the
          ;; reference format (Ed25519 signatures are deterministic).
          (lxmf-router-save-ratchets identity path expected)
          (should (equal (lxmf-router--read-file path) (reticulum-test--hex vector :packed)))
          (should (equal (lxmf-router-load-ratchets identity path) expected)))
      (delete-file path))
    (should-not (lxmf-router-load-ratchets identity path))))

(ert-deftest lxmf-router-announce-with-ratchets ()
  (reticulum-test--with-lxmf-router
   (let ((destination lxmf-router-delivery-destination))
     (should (equal (reticulum-destination-hash destination) (reticulum-test--hex (reticulum-test--lxmf) :destination_hash)))
     (should-not (reticulum-destination-ratchets destination))
     (lxmf-router-announce)
     (should (= (length (reticulum-destination-ratchets destination)) 1))
     (let* ((packet (reticulum-packet-unpack (car sent) iface))
            (announce (reticulum-announce-validate packet)))
       (should announce)
       (should (equal (plist-get announce :ratchet) (lxmf-router-current-ratchet)))
       (should (equal (lxmf-display-name-from-app-data (plist-get announce :app-data)) "Emacs Test"))
       (should-not (lxmf-stamp-cost-from-app-data (plist-get announce :app-data))))
     ;; The ratchet file is on disk in the reference format and location.
     (let ((path (expand-file-name (concat "ratchets/" (reticulum-destination-hexhash destination) ".ratchets") dir)))
       (should (file-exists-p path))
       (should (equal (lxmf-router-load-ratchets destination-identity path)
                      (reticulum-destination-ratchets destination))))
     ;; No rotation within the interval, rotation when forced, bounded count.
     (lxmf-router-announce)
     (should (= (length (reticulum-destination-ratchets destination)) 1))
     (lxmf-router-rotate-ratchets destination t)
     (should (= (length (reticulum-destination-ratchets destination)) 2))
     (let ((lxmf-router-ratchet-count 3))
       (dotimes (_ 4) (lxmf-router-rotate-ratchets destination t))
       (should (= (length (reticulum-destination-ratchets destination)) 3)))
     ;; A new registration reloads the persisted ratchets.
     (let ((ratchets (reticulum-destination-ratchets destination)))
       (lxmf-router-register-delivery-identity destination-identity "Emacs Test" nil)
       (should (equal (reticulum-destination-ratchets lxmf-router-delivery-destination) ratchets))))))

(defun reticulum-test--opportunistic-packet (destination-hash encrypted)
  "Return raw bytes of a DATA packet carrying ENCRYPTED to DESTINATION-HASH."
  (reticulum-packet-raw (reticulum-packet-make :packet-type reticulum-packet-data
                                               :destination-type reticulum-destination-single
                                               :destination-hash destination-hash
                                               :data encrypted)))

(ert-deftest lxmf-router-opportunistic-delivery-vectors ()
  (reticulum-test--with-lxmf-router
   (let* ((lxmf (reticulum-test--lxmf))
          (vector (plist-get lxmf :opportunistic))
          (case (cl-find (plist-get vector :message) (plist-get lxmf :messages)
                         :key (lambda (c) (plist-get c :name)) :test #'equal))
          (destination-hash (reticulum-test--hex lxmf :destination_hash)))
     ;; Install the ratchet the Python side encrypted to.
     (setf (reticulum-destination-ratchets lxmf-router-delivery-destination)
           (list (reticulum-test--hex vector :ratchet_private)))
     (should (equal (lxmf-router-current-ratchet) (reticulum-test--hex vector :ratchet_public)))
     ;; Ratchet encrypted packet arrives, is proven and delivered.
     (reticulum-transport-inbound (reticulum-test--opportunistic-packet
                                   destination-hash (reticulum-test--hex vector :encrypted_ratchet))
                                  iface)
     (should (= (length delivered) 1))
     (let ((message (car delivered)))
       (should (equal (lxmf-message-hash message) (reticulum-test--hex case :hash)))
       (should (lxmf-message-signature-validated message))
       (should (equal (lxmf-message-ratchet-id message) (reticulum-test--hex vector :ratchet_id)))
       (should (= (lxmf-message-method message) lxmf-method-opportunistic))
       (should (lxmf-message-transport-encrypted message))
       (should (equal (lxmf-message-content-string message) "Hello from Python")))
     (should (= (length sent) 1))
     (let* ((proof (reticulum-packet-unpack (car sent) iface))
            (data (reticulum-packet-data proof))
            (packet-hash (reticulum-packet-hash
                          (reticulum-packet-unpack (reticulum-test--opportunistic-packet
                                                    destination-hash (reticulum-test--hex vector :encrypted_ratchet))))))
       (should (= (reticulum-packet-packet-type proof) reticulum-packet-proof))
       (should (equal (reticulum-packet-destination-hash proof) (substring packet-hash 0 16)))
       (should (= (length data) 96))
       (should (equal (substring data 0 32) packet-hash))
       (should (reticulum-identity-validate destination-identity (substring data 32) packet-hash)))
     ;; The same message encrypted to the identity key is a duplicate: proven, not delivered.
     (reticulum-transport-inbound (reticulum-test--opportunistic-packet
                                   destination-hash (reticulum-test--hex vector :encrypted))
                                  iface)
     (should (= (length delivered) 1))
     (should (= (length sent) 2))
     (should (lxmf-router-has-message (reticulum-test--hex case :hash)))
     ;; Identity key encryption is accepted when ratchets are not enforced...
     (let* ((message (lxmf-message-create destination-hash (reticulum-test--hex lxmf :source_hash) "fresh" ""))
            (packed (lxmf-message-pack message source))
            (encrypted (reticulum-identity-encrypt destination-identity (substring packed 16))))
       (reticulum-transport-inbound (reticulum-test--opportunistic-packet destination-hash encrypted) iface)
       (should (= (length delivered) 2))
       (should-not (lxmf-message-ratchet-id (car delivered))))
     ;; ...and refused when they are.
     (setf (reticulum-destination-enforce-ratchets lxmf-router-delivery-destination) t)
     (let* ((message (lxmf-message-create destination-hash (reticulum-test--hex lxmf :source_hash) "enforced" ""))
            (packed (lxmf-message-pack message source))
            (encrypted (reticulum-identity-encrypt destination-identity (substring packed 16))))
       (reticulum-transport-inbound (reticulum-test--opportunistic-packet destination-hash encrypted) iface)
       (should (= (length delivered) 2))
       (let ((with-ratchet (reticulum-identity-encrypt destination-identity (substring packed 16)
                                                       (lxmf-router-current-ratchet))))
         (reticulum-transport-inbound (reticulum-test--opportunistic-packet destination-hash with-ratchet) iface)
         (should (= (length delivered) 3))))
     ;; A message for another destination is dropped.
     (let* ((other (reticulum-identity-create))
            (message (lxmf-message-create (reticulum-address other "lxmf" "delivery")
                                          (reticulum-test--hex lxmf :source_hash) "wrong" ""))
            (packed (lxmf-message-pack message source)))
       (should-not (lxmf-router-deliver packed reticulum-destination-single))
       (should (= (length delivered) 3))))))

(ert-deftest lxmf-router-direct-delivery-over-link ()
  ;; Both link sides run in this Emacs: the initiator (the peer) and the
  ;; responder (our delivery destination).  Each side has its own link
  ;; table; packets sent by one side are queued and fed to the other.
  (reticulum-test--with-lxmf-router
   (let* ((lxmf (reticulum-test--lxmf))
          (peer-links (make-hash-table :test #'equal))
          (our-links reticulum-transport-links)
          (side 'peer)
          (queue nil)
          (established nil)
          (out (reticulum-destination-create destination-identity 'out 'single "lxmf" "delivery"))
          link)
     (cl-letf (((symbol-function 'reticulum-interface-send)
                (lambda (_interface raw) (push (cons (if (eq side 'peer) 'us 'peer) raw) queue) t)))
       (cl-flet ((pump ()
                   (while queue
                     (let ((item (car (last queue))))
                       (setq queue (butlast queue))
                       (setq side (car item))
                       (let ((reticulum-transport-links (if (eq side 'peer) peer-links our-links)))
                         (reticulum-transport-inbound (cdr item) iface)))))
                 (as-peer (thunk)
                   (setq side 'peer)
                   (let ((reticulum-transport-links peer-links)) (funcall thunk))))
         ;; Establish the link from the peer.
         (as-peer (lambda () (setq link (reticulum-link-establish out (lambda (l) (push l established))))))
         (pump)
         (should (reticulum-link-active-p link))
         (should (= (length established) 1))
         (should (= (length lxmf-router-delivery-links) 1))
         (let ((ours (car lxmf-router-delivery-links)))
           (should (reticulum-link-active-p ours))
           (should (equal (reticulum-link-id ours) (reticulum-link-id link)))
           (should (eq (reticulum-link-resource-strategy ours) 'app))
           ;; Deliver a message as a single link packet.
           (let* ((message (lxmf-message-create (reticulum-test--hex lxmf :destination_hash)
                                                (reticulum-test--hex lxmf :source_hash) "over a link" "Direct"))
                  (packed (lxmf-message-pack message source)))
             (as-peer (lambda () (reticulum-link-send link packed)))
             (pump)
             (should (= (length delivered) 1))
             (should (equal (lxmf-message-hash (car delivered)) (lxmf-message-hash message)))
             (should (lxmf-message-signature-validated (car delivered)))
             (should (= (lxmf-message-method (car delivered)) lxmf-method-direct))
             (should (equal (lxmf-message-ratchet-id (car delivered)) (reticulum-link-id link)))
             ;; Sent again on the link: proven by the link, not delivered twice.
             (as-peer (lambda () (reticulum-link-send link packed)))
             (pump)
             (should (= (length delivered) 1)))
           ;; The peer identifies on the link: it becomes a backchannel.
           (as-peer (lambda () (reticulum-link-identify link source)))
           (pump)
           (should (eq (lxmf-router-backchannel-link (reticulum-test--hex lxmf :source_hash)) ours))
           ;; A message arriving as a resource on the link.
           (let* ((message (lxmf-message-create (reticulum-test--hex lxmf :destination_hash)
                                                (reticulum-test--hex lxmf :source_hash)
                                                (make-string 2000 ?x) "Resource"))
                  (packed (lxmf-message-pack message source))
                  (resource (reticulum-resource--make :link ours :status 'complete :data packed)))
             (should (lxmf-router--delivery-resource-advertised (list :data-size (length packed)) ours))
             (should-not (lxmf-router--delivery-resource-advertised
                          (list :data-size (1+ (* 1000 lxmf-router-delivery-per-transfer-limit))) ours))
             (lxmf-router--delivery-resource-concluded resource)
             (should (= (length delivered) 2))
             (should (equal (lxmf-message-hash (car delivered)) (lxmf-message-hash message)))
             (should (equal (lxmf-message-ratchet-id (car delivered)) (reticulum-link-id ours)))
             (setf (reticulum-resource-status resource) 'corrupt)
             (lxmf-router--delivery-resource-concluded resource)
             (should (= (length delivered) 2)))
           ;; Closing the link from the peer drops the backchannel.
           (as-peer (lambda () (reticulum-link-teardown link)))
           (pump)
           (should-not (lxmf-router-backchannel-link (reticulum-test--hex lxmf :source_hash)))
           (should-not lxmf-router-delivery-links)))))))

(ert-deftest lxmf-router-delivered-ids-persist ()
  (reticulum-test--with-lxmf-router
   (let* ((lxmf (reticulum-test--lxmf))
          (case (car (plist-get lxmf :messages)))
          (packed (reticulum-test--hex case :packed)))
     (should (lxmf-router-deliver packed reticulum-destination-link))
     (should-not (lxmf-router-deliver packed reticulum-destination-link))
     (should (lxmf-router-deliver packed reticulum-destination-link nil nil t))
     (should (= (length delivered) 2))
     (lxmf-router-save-delivered-ids)
     (should (file-exists-p (expand-file-name "local_deliveries" dir)))
     ;; The file is a msgpack map of hash -> time, as the reference writes it.
     (let ((table (reticulum-msgpack-unpack (lxmf-router--read-file (expand-file-name "local_deliveries" dir)))))
       (should (hash-table-p table))
       (should (floatp (gethash (reticulum-test--hex case :hash) table))))
     (clrhash lxmf-router-delivered-ids)
     (should-not (lxmf-router-has-message (reticulum-test--hex case :hash)))
     (lxmf-router--load-delivered-ids)
     (should (lxmf-router-has-message (reticulum-test--hex case :hash)))
     ;; Old entries are pruned.
     (puthash (reticulum-test--hex case :hash) 1.0 lxmf-router-delivered-ids)
     (lxmf-router-clean-delivered-ids)
     (should-not (lxmf-router-has-message (reticulum-test--hex case :hash))))))

(provide 'reticulum-test)

;;; reticulum-test.el ends here
