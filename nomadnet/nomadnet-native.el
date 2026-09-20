;;; nomadnet-native.el --- Native Nomad Network backend  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;;; Commentary:

;; The Nomad Network client application core, in Emacs Lisp, on top of the
;; reticulum.el library.  The user interface modules talk to it through
;; `nomadnet-request' with named methods and plist arguments.
;;
;; It shares nomadnet's configuration directory: the identity file, the
;; directory of known nodes and peers with the announce stream, peer
;; settings and the page cache use nomadnet's own on-disk formats.
;;
;; Implemented so far: status, announce stream, directory, peer info, path
;; requests and the node browser.  LXMF messaging is tracked in the
;; repository issues; those requests report an error until then.

;;; Code:

(require 'cl-lib)
(require 'subr-x)
(require 'reticulum)
(require 'lxmf-message)
(require 'lxmf-router)
(require 'nomadnet-core)

(defgroup nomadnet-native nil
  "Native Emacs Lisp Nomad Network backend."
  :group 'nomadnet)

(defcustom nomadnet-native-config-directory "~/.nomadnetwork"
  "Nomad Network configuration directory used by the native backend."
  :type 'directory)

(defcustom nomadnet-native-reticulum-config "~/.reticulum/config"
  "Reticulum configuration file whose TCP client interfaces are used."
  :type 'file)

(defcustom nomadnet-native-interfaces 'auto
  "Interfaces for the native backend.
Either `auto' to use every enabled TCPClientInterface from
`nomadnet-native-reticulum-config', or a list of (NAME HOST PORT)."
  :type '(choice (const auto) (repeat (list string string integer))))

(defcustom nomadnet-native-use-local-instance nil
  "When non-nil, also connect to a running rnsd shared instance on PORT."
  :type '(choice (const nil) integer))

(defcustom nomadnet-native-enforce-ratchets nil
  "When non-nil, only accept messages encrypted to one of our ratchet keys.
Messages encrypted to the identity key itself, as sent by peers that have
not seen an announce with a ratchet, are dropped."
  :type 'boolean)

(defcustom nomadnet-native-display-name "Anonymous Peer"
  "Display name used when no peer settings file exists."
  :type 'string)

(defconst nomadnet-native-announce-stream-maxlength 256)
(defconst nomadnet-native-browser-timeout 15)
(defconst nomadnet-native-default-cache-time (* 12 60 60))
(defconst nomadnet-native-default-path "/page/index.mu")

;;;; State

(defvar nomadnet-native--identity nil)
(defvar nomadnet-native--lxmf-hash nil "Hash of our lxmf.delivery destination.")
(defvar nomadnet-native--peer-settings nil "Hash table of peer settings.")
(defvar nomadnet-native--entries (make-hash-table :test #'equal)
  "Directory: source hash -> plist.")
(defvar nomadnet-native--announces nil "Announce stream, newest first: list of plists.")
(defvar nomadnet-native--messages nil
  "Messages received since start, newest first: list of `lxmf-message'.")
(defvar nomadnet-native--ready nil)
(defvar nomadnet-native--event-function nil "Called with (EVENT DATA) for events.")
(defvar nomadnet-native--link nil "The browser's current link.")
(defvar nomadnet-native--save-timer nil)
(defvar nomadnet-native--running nil)

(defun nomadnet-native--path (&rest parts)
  "Return a path inside the configuration directory."
  (expand-file-name (string-join parts "/") nomadnet-native-config-directory))

(defun nomadnet-native--event (name &rest data)
  "Emit event NAME with DATA plist."
  (when nomadnet-native--event-function
    (funcall nomadnet-native--event-function name data)))

;;;; Persistence in nomadnet's formats

(defun nomadnet-native--read-msgpack (path)
  "Read the msgpack file at PATH, or nil."
  (when (file-exists-p path)
    (condition-case err
        (with-temp-buffer
          (set-buffer-multibyte nil)
          (insert-file-contents-literally path)
          (reticulum-msgpack-unpack (buffer-string)))
      (error (message "nomadnet: could not read %s: %s" path (error-message-string err)) nil))))

(defun nomadnet-native--write-msgpack (path object)
  "Write OBJECT as msgpack to PATH atomically."
  (let ((tmp (concat path ".tmp"))
        (coding-system-for-write 'binary))
    (with-temp-file tmp
      (set-buffer-multibyte nil)
      (insert (reticulum-msgpack-pack object)))
    (rename-file tmp path t)))

(defun nomadnet-native--load-identity ()
  "Load or create the primary identity."
  (let ((path (nomadnet-native--path "storage" "identity")))
    (make-directory (file-name-directory path) t)
    (if (file-exists-p path)
        (setq nomadnet-native--identity (reticulum-identity-from-file path))
      (setq nomadnet-native--identity (reticulum-identity-create))
      (reticulum-identity-to-file nomadnet-native--identity path)
      (message "nomadnet: created new identity %s" (reticulum-identity-hexhash nomadnet-native--identity)))
    (setq nomadnet-native--lxmf-hash (reticulum-address nomadnet-native--identity "lxmf" "delivery"))))

(defun nomadnet-native--load-peer-settings ()
  "Load peer settings or create defaults."
  (let ((table (nomadnet-native--read-msgpack (nomadnet-native--path "storage" "peersettings"))))
    (unless (hash-table-p table)
      (setq table (reticulum-msgpack-map (reticulum-msgpack-str "display_name") (reticulum-msgpack-str nomadnet-native-display-name)
                                         (reticulum-msgpack-str "announce_interval") 21600
                                         (reticulum-msgpack-str "last_announce") nil
                                         (reticulum-msgpack-str "node_last_announce") nil
                                         (reticulum-msgpack-str "propagation_node") nil
                                         (reticulum-msgpack-str "last_lxmf_sync") 0
                                         (reticulum-msgpack-str "node_connects") 0
                                         (reticulum-msgpack-str "served_page_requests") 0
                                         (reticulum-msgpack-str "served_file_requests") 0)))
    (setq nomadnet-native--peer-settings table)))

(defun nomadnet-native--setting (key)
  "Return peer setting KEY."
  (gethash key nomadnet-native--peer-settings))

(defun nomadnet-native--set-setting (key value)
  "Set peer setting KEY to VALUE and save."
  (puthash (reticulum-msgpack-str key) value nomadnet-native--peer-settings)
  (nomadnet-native--write-msgpack (nomadnet-native--path "storage" "peersettings") nomadnet-native--peer-settings))

(defun nomadnet-native--load-directory ()
  "Load the directory and announce stream from nomadnet's directory file."
  (clrhash nomadnet-native--entries)
  (setq nomadnet-native--announces nil)
  (let ((data (nomadnet-native--read-msgpack (nomadnet-native--path "storage" "directory"))))
    (when (hash-table-p data)
      (dolist (e (gethash "entry_list" data))
        (when (and (listp e) (>= (length e) 3) (= (length (nth 0 e)) 16))
          (puthash (nth 0 e)
                   (list :hash (nth 0 e)
                         :display_name (let ((n (nth 1 e))) (if (stringp n) n nil))
                         :trust_level (or (nth 2 e) 2)
                         :hosts_node (and (nth 3 e) (not (eq (nth 3 e) :false)))
                         :preferred_delivery (or (nth 4 e) 1)
                         :identify (and (nth 5 e) (not (eq (nth 5 e) :false)))
                         :sort_rank (nth 6 e)
                         :notes (or (nth 7 e) ""))
                   nomadnet-native--entries)))
      (dolist (a (gethash "announce_stream" data))
        (when (and (listp a) (= (length a) 4))
          (push (list :time (nth 0 a) :hash (nth 1 a) :app_data (nth 2 a) :kind (nth 3 a))
                nomadnet-native--announces)))
      (setq nomadnet-native--announces
            (sort nomadnet-native--announces (lambda (a b) (> (plist-get a :time) (plist-get b :time))))))))

(defun nomadnet-native--save-directory ()
  "Persist the directory and announce stream in nomadnet's format."
  (let ((entries nil) (stream nil))
    (maphash (lambda (_k e)
               (push (list (plist-get e :hash)
                           (and (plist-get e :display_name) (reticulum-msgpack-str (plist-get e :display_name)))
                           (plist-get e :trust_level)
                           (if (plist-get e :hosts_node) t :false)
                           (plist-get e :preferred_delivery)
                           (if (plist-get e :identify) t :false)
                           (plist-get e :sort_rank)
                           (reticulum-msgpack-str (or (plist-get e :notes) "")))
                     entries))
             nomadnet-native--entries)
    (dolist (a nomadnet-native--announces)
      (push (list (plist-get a :time) (plist-get a :hash) (plist-get a :app_data)
                  (reticulum-msgpack-str (plist-get a :kind)))
            stream))
    (nomadnet-native--write-msgpack
     (nomadnet-native--path "storage" "directory")
     (reticulum-msgpack-map (reticulum-msgpack-str "entry_list") (nreverse entries)
                            (reticulum-msgpack-str "announce_stream") (nreverse stream)))))

(defun nomadnet-native--schedule-save ()
  "Save the directory soon."
  (unless nomadnet-native--save-timer
    (setq nomadnet-native--save-timer
          (run-at-time 5 nil (lambda ()
                               (setq nomadnet-native--save-timer nil)
                               (when nomadnet-native--running
                                 (condition-case err
                                     (progn (nomadnet-native--save-directory)
                                            (reticulum-identity-save-known (nomadnet-native--path "storage" "emacs_known_destinations")))
                                   (error (message "nomadnet: save failed: %s" (error-message-string err))))))))))

;;;; Reticulum configuration

(defun nomadnet-native-interfaces-from-config (path)
  "Return (NAME HOST PORT) for enabled TCPClientInterface entries.
PATH is a Reticulum configuration file."
  (when (file-readable-p path)
    (with-temp-buffer
      (insert-file-contents path)
      (let ((interfaces nil) (current nil))
        (cl-flet ((flush ()
                    (when (and current (equal (plist-get current :type) "TCPClientInterface")
                               (not (member (downcase (or (plist-get current :enabled) "yes")) '("no" "false" "off")))
                               (plist-get current :host) (plist-get current :port))
                      (push (list (plist-get current :name) (plist-get current :host)
                                  (string-to-number (plist-get current :port)))
                            interfaces))))
          (dolist (line (split-string (buffer-string) "\n"))
            (let ((line (string-trim line)))
              (cond
               ((string-match "\\`\\[\\[\\(.*\\)\\]\\]\\'" line)
                (flush)
                (setq current (list :name (match-string 1 line))))
               ((string-match "\\`\\[.*\\]\\'" line)
                (flush) (setq current nil))
               ((and current (string-match "\\`\\([a-z_]+\\)\\s-*=\\s-*\\(.*\\)\\'" line))
                (let ((key (match-string 1 line)) (value (string-trim (match-string 2 line))))
                  (pcase key
                    ("type" (setq current (plist-put current :type value)))
                    ("enabled" (setq current (plist-put current :enabled value)))
                    ("interface_enabled" (setq current (plist-put current :enabled value)))
                    ("target_host" (setq current (plist-put current :host value)))
                    ("target_port" (setq current (plist-put current :port value)))))))))
          (flush))
        (nreverse interfaces)))))

;;;; Announces

(defun nomadnet-native--kind-of (announce)
  "Return \"node\", \"peer\", \"pn\" or nil for announce plist ANNOUNCE."
  (let ((name-hash (plist-get announce :name-hash)))
    (cond ((equal name-hash (reticulum-address-name-hash "nomadnetwork" '("node"))) "node")
          ((equal name-hash (reticulum-address-name-hash "lxmf" '("delivery"))) "peer")
          ((equal name-hash (reticulum-address-name-hash "lxmf" '("propagation"))) "pn"))))

(defun nomadnet-native--display-name-from-app-data (app-data kind)
  "Return the display name carried in APP-DATA for announce KIND."
  (condition-case nil
      (cond
       ((null app-data) nil)
       ((equal kind "node") (reticulum-decode-utf8 app-data))
       ((equal kind "peer") (lxmf-display-name-from-app-data app-data))
       ((equal kind "pn")
        (let ((v (reticulum-msgpack-unpack app-data t)))
          (let ((meta (and (listp v) (nth 6 v))))
            (and (hash-table-p meta)
                 (let ((n (gethash 1 meta)))
                   (and n (if (multibyte-string-p n) n (reticulum-decode-utf8 n)))))))))
    (error nil)))

(defun nomadnet-native--stamp-cost-from-app-data (app-data)
  "Return the stamp cost announced in peer APP-DATA, or nil."
  (lxmf-stamp-cost-from-app-data app-data))

(defun nomadnet-native--on-announce (announce)
  "Record ANNOUNCE plist in the stream and notify the UI."
  (let ((kind (nomadnet-native--kind-of announce)))
    (when kind
      (let* ((hash (plist-get announce :destination-hash))
             (app-data (plist-get announce :app-data))
             (stored-app-data (if (equal kind "peer")
                                  ;; nomadnet stores only the display name for peers.
                                  (let ((name (nomadnet-native--display-name-from-app-data app-data "peer")))
                                    (and name (reticulum-utf8 name)))
                                app-data)))
        (when (or stored-app-data (equal kind "pn"))
          (setq nomadnet-native--announces
                (cl-remove-if (lambda (a) (and (equal (plist-get a :hash) hash) (equal (plist-get a :kind) kind)))
                              nomadnet-native--announces))
          (push (list :time (float-time) :hash hash :app_data (or stored-app-data "") :kind kind)
                nomadnet-native--announces)
          (when (> (length nomadnet-native--announces) (* 3 nomadnet-native-announce-stream-maxlength))
            (setq nomadnet-native--announces (seq-take nomadnet-native--announces
                                                       (* 3 nomadnet-native-announce-stream-maxlength))))
          (nomadnet-native--schedule-save)
          (nomadnet-native--event "announce" :kind kind :destination (reticulum-hex hash)
                                  :name (nomadnet-native--display-name-from-app-data app-data kind)
                                  :hops (plist-get announce :hops)))))))

;;;; Directory helpers

(defun nomadnet-native--trust-level (hash &optional announced-name)
  "Return the trust level of HASH, checking name collisions with ANNOUNCED-NAME."
  (let ((entry (gethash hash nomadnet-native--entries)))
    (cond
     ((null entry) 2)
     ((and announced-name (/= (plist-get entry :trust_level) 255)
           (cl-some (lambda (e) (and (equal (plist-get e :display_name) announced-name)
                                     (not (equal (plist-get e :hash) hash))))
                    (hash-table-values nomadnet-native--entries)))
      0)
     (t (plist-get entry :trust_level)))))

(defun nomadnet-native--entry-result (entry)
  "Convert directory ENTRY plist to the wire shape used by the UI."
  (let ((hash (plist-get entry :hash)))
    (list :hash (reticulum-hex hash)
          :display_name (plist-get entry :display_name)
          :trust_level (plist-get entry :trust_level)
          :hosts_node (plist-get entry :hosts_node)
          :preferred_delivery (plist-get entry :preferred_delivery)
          :identify (plist-get entry :identify)
          :sort_rank (plist-get entry :sort_rank)
          :notes (plist-get entry :notes)
          :hops (let ((h (reticulum-transport-hops-to hash))) (and (< h reticulum-pathfinder-m) h))
          :has_path (reticulum-transport-has-path hash))))

(defun nomadnet-native--simplest-display (hash)
  "Return the display string nomadnet would show for HASH."
  (let* ((entry (gethash hash nomadnet-native--entries))
         (trust (nomadnet-native--trust-level hash))
         (name (and entry (plist-get entry :display_name))))
    (cond ((and name (memq trust '(0 1))) (format "%s <%s>" name (reticulum-hex hash)))
          (name name)
          (t (format "<%s>" (reticulum-hex hash))))))

(defun nomadnet-native--recall-name (hash)
  "Return a display name for HASH from the directory or announce data."
  (or (let ((entry (gethash hash nomadnet-native--entries))) (and entry (plist-get entry :display_name)))
      (let ((app-data (reticulum-identity-recall-app-data hash)))
        (and app-data
             (or (nomadnet-native--display-name-from-app-data app-data "peer")
                 (nomadnet-native--display-name-from-app-data app-data "node"))))))

;;;; LXMF delivery

(defun nomadnet-native--message-result (message)
  "Return the plist describing `lxmf-message' MESSAGE for the UI."
  (let ((source (lxmf-message-source-hash message)))
    (list :hash (reticulum-hex (lxmf-message-hash message))
          :source (reticulum-hex source)
          :source_name (or (nomadnet-native--recall-name source) (format "<%s>" (reticulum-hex source)))
          :destination (reticulum-hex (lxmf-message-destination-hash message))
          :title (lxmf-message-title-string message)
          :content (lxmf-message-content-string message)
          :timestamp (lxmf-message-timestamp message)
          :received (lxmf-message-received-at message)
          :method (lxmf-message-method message)
          :signature_validated (and (lxmf-message-signature-validated message) t)
          :unverified_reason (lxmf-message-unverified-reason message)
          :transport_encryption (lxmf-message-transport-encryption message)
          :fields (lxmf-message-fields message))))

(defun nomadnet-native--on-message (message)
  "Record delivered `lxmf-message' MESSAGE and notify the UI."
  (push message nomadnet-native--messages)
  (let ((result (nomadnet-native--message-result message)))
    (reticulum-log 4 "LXMF message %s from %s: %s" (plist-get result :hash)
                   (plist-get result :source_name)
                   (cond ((plist-get result :signature_validated) "signature valid")
                         ((eql (plist-get result :unverified_reason) lxmf-source-unknown) "source unknown")
                         (t "signature invalid")))
    (apply #'nomadnet-native--event "message_received" result)))

(defun nomadnet-native--start-lxmf ()
  "Register our delivery destination with the LXMF router."
  (setq lxmf-router-enforce-ratchets nomadnet-native-enforce-ratchets)
  (lxmf-router-init (nomadnet-native--path "storage" "lxmf") #'nomadnet-native--on-message)
  (lxmf-router-register-delivery-identity nomadnet-native--identity
                                          (nomadnet-native--setting "display_name") nil))

(defun nomadnet-native--announce ()
  "Announce our LXMF delivery destination and record the time."
  (lxmf-router-announce)
  (nomadnet-native--set-setting "last_announce" (float-time))
  (list :announced t :lxmf_address (reticulum-hex nomadnet-native--lxmf-hash)))

;;;; Lifecycle

(defun nomadnet-native-start (event-function)
  "Start the native backend, reporting events through EVENT-FUNCTION."
  (setq nomadnet-native--event-function event-function
        nomadnet-native--running t)
  (nomadnet-native--load-identity)
  (nomadnet-native--load-peer-settings)
  (nomadnet-native--load-directory)
  (reticulum-identity-load-known (nomadnet-native--path "storage" "emacs_known_destinations"))
  (make-directory (nomadnet-native--path "storage" "cache") t)
  (nomadnet-native--start-lxmf)
  (reticulum-transport-register-announce-handler nil #'nomadnet-native--on-announce)
  (reticulum-transport-start)
  (let ((interfaces (if (eq nomadnet-native-interfaces 'auto)
                        (nomadnet-native-interfaces-from-config
                         (expand-file-name nomadnet-native-reticulum-config))
                      nomadnet-native-interfaces)))
    (when nomadnet-native-use-local-instance
      (reticulum-interface-add-local (if (integerp nomadnet-native-use-local-instance)
                                         nomadnet-native-use-local-instance
                                       37428)))
    (dolist (spec interfaces)
      (reticulum-interface-add-tcp (nth 0 spec) (nth 1 spec) (nth 2 spec)))
    (when (and (null interfaces) (not nomadnet-native-use-local-instance))
      (message "nomadnet: no TCP interfaces found in %s; set `nomadnet-native-interfaces'"
               nomadnet-native-reticulum-config)))
  (setq nomadnet-native--ready t)
  (run-at-time 0.1 nil (lambda () (apply #'nomadnet-native--event "ready" (nomadnet-native-status))))
  t)

(defun nomadnet-native-stop ()
  "Stop the native backend."
  (when nomadnet-native--running
    (when nomadnet-native--link
      (ignore-errors (reticulum-link-teardown nomadnet-native--link))
      (setq nomadnet-native--link nil))
    (ignore-errors (nomadnet-native--save-directory))
    (ignore-errors (reticulum-identity-save-known (nomadnet-native--path "storage" "emacs_known_destinations")))
    (reticulum-transport-deregister-announce-handler #'nomadnet-native--on-announce)
    (ignore-errors (lxmf-router-stop))
    (reticulum-transport-stop)
    (setq nomadnet-native--running nil
          nomadnet-native--ready nil)))

(defun nomadnet-native-ready-p ()
  "Return non-nil when the native backend is running."
  (and nomadnet-native--running nomadnet-native--ready))

(defun nomadnet-native-status ()
  "Return the status plist."
  (list :protocol 1
        :backend "native"
        :version "native"
        :rns_version "reticulum.el"
        :lxmf_version "lxmf.el"
        :configdir (expand-file-name nomadnet-native-config-directory)
        :display_name (nomadnet-native--setting "display_name")
        :lxmf_address (reticulum-hex nomadnet-native--lxmf-hash)
        :identity (reticulum-identity-hexhash nomadnet-native--identity)
        :node_enabled nil
        :propagation_node (let ((pn (nomadnet-native--setting "propagation_node")))
                            (and (stringp pn) (= (length pn) 16) (reticulum-hex pn)))
        :downloads_path (expand-file-name "~/Downloads")
        :logfile (nomadnet-native--path "logfile")
        :interfaces (mapcar (lambda (i) (list :name (reticulum-interface-name i)
                                              :online (reticulum-interface-online i)
                                              :rx (reticulum-interface-rx i) :tx (reticulum-interface-tx i)
                                              :rxbytes (reticulum-interface-rxbytes i)
                                              :txbytes (reticulum-interface-txbytes i)))
                            reticulum-interfaces)
        :paths (hash-table-count reticulum-transport-path-table)))

;;;; Browser

(defun nomadnet-native--parse-url (url current)
  "Split URL into (DESTINATION-HASH PATH REQUEST-DATA-ALIST).
CURRENT is the connected destination for relative URLs."
  (let ((request-data nil))
    (when (string-search "`" url)
      (let ((parts (split-string url "`")))
        (setq url (car parts))
        (dolist (item (split-string (or (cadr parts) "") "|" t))
          (when (string-search "=" item)
            (let ((kv (split-string item "=")))
              (when (= (length kv) 2)
                (push (cons (concat "var_" (car kv)) (cadr kv)) request-data)))))))
    (let ((components (split-string url ":")))
      (pcase (length components)
        (1 (unless (and (= (length (car components)) 32) (string-match-p "\\`[0-9a-fA-F]+\\'" (car components)))
             (error "Malformed URL"))
           (list (reticulum-unhex (car components)) nomadnet-native-default-path (nreverse request-data)))
        (2 (let ((dest (car components)) (path (cadr components)))
             (cond ((and (= (length dest) 32) (string-match-p "\\`[0-9a-fA-F]+\\'" dest))
                    (list (reticulum-unhex dest) (if (string-empty-p path) nomadnet-native-default-path path)
                          (nreverse request-data)))
                   ((and (string-empty-p dest) current)
                    (list (reticulum-unhex current) (if (string-empty-p path) nomadnet-native-default-path path)
                          (nreverse request-data)))
                   (t (error "Malformed URL")))))
        (_ (error "Malformed URL"))))))

(defun nomadnet-native--url-string (dest path request-data)
  "Return the cache key URL for DEST hash, PATH and REQUEST-DATA alist."
  (let ((url (concat (reticulum-hex dest) ":" path))
        (vars (cl-remove-if-not (lambda (kv) (string-prefix-p "var_" (car kv))) request-data)))
    (when vars
      (setq url (concat url "`" (mapconcat (lambda (kv) (concat (substring (car kv) 4) "=" (cdr kv))) vars "|"))))
    url))

(defun nomadnet-native--cache-dir () (nomadnet-native--path "storage" "cache"))

(defun nomadnet-native--cache-get (url)
  "Return cached page bytes for URL, or nil, removing stale entries."
  (let ((prefix (reticulum-hex (reticulum-full-hash (reticulum-utf8 url))))
        (result nil))
    (dolist (file (directory-files (nomadnet-native--cache-dir) nil "\\`[0-9a-f]\\{64\\}_"))
      (let* ((parts (split-string file "_"))
             (expires (string-to-number (nth 1 parts)))
             (path (expand-file-name file (nomadnet-native--cache-dir))))
        (cond ((> (float-time) expires) (ignore-errors (delete-file path)))
              ((string-prefix-p prefix file)
               (setq result (with-temp-buffer (set-buffer-multibyte nil)
                                              (insert-file-contents-literally path) (buffer-string)))))))
    result))

(defun nomadnet-native--cache-remove (url)
  "Remove cached pages for URL."
  (let ((prefix (reticulum-hex (reticulum-full-hash (reticulum-utf8 url)))))
    (dolist (file (directory-files (nomadnet-native--cache-dir) nil (concat "\\`" prefix)))
      (ignore-errors (delete-file (expand-file-name file (nomadnet-native--cache-dir)))))))

(defun nomadnet-native--cache-put (url data cache-time)
  "Cache page DATA for URL for CACHE-TIME seconds."
  (nomadnet-native--cache-remove url)
  (let ((coding-system-for-write 'binary)
        (path (expand-file-name (format "%s_%s" (reticulum-hex (reticulum-full-hash (reticulum-utf8 url)))
                                        (+ (float-time) cache-time))
                                (nomadnet-native--cache-dir))))
    (with-temp-file path (set-buffer-multibyte nil) (insert data))))

(defun nomadnet-native--browser-status (state &rest extra)
  "Emit a browser status event STATE with EXTRA data."
  (apply #'nomadnet-native--event "browser_status" :state state extra))

(defun nomadnet-native--with-path (dest-hash callback)
  "Ensure a path to DEST-HASH exists, then call CALLBACK with non-nil on success."
  (if (and (reticulum-transport-has-path dest-hash) (reticulum-identity-recall dest-hash))
      (funcall callback t)
    (nomadnet-native--browser-status "path_requested")
    (reticulum-transport-request-path dest-hash)
    (let ((deadline (+ (float-time) nomadnet-native-browser-timeout)))
      (cl-labels ((poll ()
                    (cond ((and (reticulum-transport-has-path dest-hash) (reticulum-identity-recall dest-hash))
                           (funcall callback t))
                          ((> (float-time) deadline) (funcall callback nil))
                          (t (run-at-time 0.25 nil #'poll)))))
        (run-at-time 0.25 nil #'poll)))))

(defun nomadnet-native--with-link (dest-hash callback)
  "Ensure an active link to DEST-HASH and call CALLBACK with the link or nil."
  (let ((link nomadnet-native--link))
    (if (and link (reticulum-link-active-p link)
             (equal (reticulum-destination-hash (reticulum-link-destination link)) dest-hash))
        (funcall callback link)
      (when link (ignore-errors (reticulum-link-teardown link)))
      (setq nomadnet-native--link nil)
      (nomadnet-native--with-path
       dest-hash
       (lambda (ok)
         (if (not ok)
             (funcall callback nil)
           (nomadnet-native--browser-status "establishing_link")
           (let* ((identity (reticulum-identity-recall dest-hash))
                  (destination (reticulum-destination-create identity 'out 'single "nomadnetwork" "node"))
                  (done nil))
             (setq nomadnet-native--link
                   (reticulum-link-establish
                    destination
                    (lambda (link)
                      (unless done
                        (setq done t)
                        (nomadnet-native--browser-status "link_established")
                        (let ((entry (gethash dest-hash nomadnet-native--entries)))
                          (when (and entry (plist-get entry :identify))
                            (reticulum-link-identify link nomadnet-native--identity)))
                        (funcall callback link)))
                    (lambda (link)
                      (when (eq nomadnet-native--link link) (setq nomadnet-native--link nil))
                      (nomadnet-native--event "browser_link_closed" :destination (reticulum-hex dest-hash))
                      (unless done
                        (setq done t)
                        (funcall callback nil))))))))))))

(defun nomadnet-native-request-too-large-message (size mdu)
  "Return the error message for a request of SIZE bytes on a link with MDU."
  (format "%s: the submitted fields need %d bytes but a single packet carries at most %d.  Sending larger requests needs outbound resources, which are not implemented yet (see issue #5).  Shorten the field values and try again"
          nomadnet-request-too-large-prefix size mdu))

(defun nomadnet-native--browser-get (params callback)
  "Fetch the page described by PARAMS and call CALLBACK with (RESULT ERROR)."
  (condition-case err
      (pcase-let* ((`(,dest ,path ,url-data) (nomadnet-native--parse-url (plist-get params :url) (plist-get params :current)))
                   (request-plist (plist-get params :request_data))
                   (request-data (append url-data
                                         (let (out)
                                           (while request-plist
                                             (let ((k (pop request-plist)) (v (pop request-plist)))
                                               (push (cons (substring (symbol-name k) 1) v) out)))
                                           (nreverse out))))
                   (url (nomadnet-native--url-string dest path request-data))
                   (use-cache (not (memq (plist-get params :use_cache) '(nil :false)))))
        (cond
         ((string-prefix-p "/file/" path)
          (funcall callback nil "File downloads are not supported yet (see the repository issues)"))
         ((and (null request-data) use-cache (nomadnet-native--cache-get url))
          (funcall callback (list :url url :destination (reticulum-hex dest) :path path :cached t
                                  :markup (reticulum-decode-utf8 (nomadnet-native--cache-get url)))
                   nil))
         (t
          (nomadnet-native--with-link
           dest
           (lambda (link)
             (if (null link)
                 (funcall callback nil (if (reticulum-transport-has-path dest)
                                           "Link establishment timed out"
                                         "No path to destination known"))
               (let ((data (when request-data
                             (let ((table (make-hash-table :test #'equal)))
                               (dolist (kv request-data)
                                 (puthash (reticulum-msgpack-str (car kv)) (reticulum-msgpack-str (cdr kv)) table))
                               table)))
                     (started (float-time)))
                 (nomadnet-native--browser-status "requesting" :path path)
                 (condition-case err2
                     (reticulum-link-request
                      link path data
                      (lambda (req)
                        (let* ((response (reticulum-request-response req))
                               (bytes (cond ((stringp response) (if (multibyte-string-p response) (reticulum-utf8 response) response))
                                            (t (reticulum-utf8 (format "%S" response)))))
                               (markup (reticulum-decode-utf8 bytes))
                               (cache-time nomadnet-native-default-cache-time))
                          (when (string-prefix-p "#!c=" markup)
                            (let ((end (or (string-search "\n" markup) (length markup))))
                              (setq cache-time (string-to-number (substring markup 4 end)))))
                          (when (> cache-time 0)
                            (ignore-errors (nomadnet-native--cache-put url bytes cache-time)))
                          (funcall callback (list :url url :destination (reticulum-hex dest) :path path
                                                  :cached nil :markup markup
                                                  :response_time (or (reticulum-request-response-time req)
                                                                     (- (float-time) started))
                                                  :size (reticulum-request-response-size req)
                                                  :transfer_size (reticulum-request-response-transfer-size req))
                                   nil)))
                      (lambda (_req) (funcall callback nil "Request failed"))
                      (lambda (req)
                        (nomadnet-native--browser-status "receiving" :progress (reticulum-request-progress req)
                                                         :size (reticulum-request-response-size req)
                                                         :transfer_size (reticulum-request-response-transfer-size req)))
                      (plist-get params :timeout))
                   (reticulum-request-too-large
                    (funcall callback nil (apply #'nomadnet-native-request-too-large-message (cdr err2))))
                   (error (funcall callback nil (error-message-string err2))))
                 (nomadnet-native--browser-status "request_sent" :path path))))))))
    (error (funcall callback nil (error-message-string err)))))

;;;; Request dispatch

(defun nomadnet-native--announce-result (a)
  "Convert stored announce plist A to the wire shape."
  (let* ((hash (plist-get a :hash))
         (kind (plist-get a :kind))
         (app-data (plist-get a :app_data))
         (name (cond ((equal kind "peer") (and (stringp app-data) (> (length app-data) 0) (reticulum-decode-utf8 app-data)))
                     (t (nomadnet-native--display-name-from-app-data app-data kind)))))
    (list :time (plist-get a :time) :hash (reticulum-hex hash) :kind kind :name name
          :trust_level (nomadnet-native--trust-level hash name)
          :known (and (gethash hash nomadnet-native--entries) t)
          :hops (let ((h (reticulum-transport-hops-to hash))) (and (< h reticulum-pathfinder-m) h))
          :stamp_cost (and (equal kind "peer") (nomadnet-native--stamp-cost-from-app-data
                                                (reticulum-identity-recall-app-data hash))))))

(defun nomadnet-native--peer-info (hash)
  "Return the peer info plist for HASH bytes."
  (let* ((identity (reticulum-identity-recall hash))
         (entry (gethash hash nomadnet-native--entries))
         (info (list :hash (reticulum-hex hash)
                     :known_identity (and identity t)
                     :hops (let ((h (reticulum-transport-hops-to hash))) (and (< h reticulum-pathfinder-m) h))
                     :has_path (reticulum-transport-has-path hash)
                     :display_name (nomadnet-native--simplest-display hash)
                     :trust_level (nomadnet-native--trust-level hash))))
    (when identity
      (setq info (append info (list :identity (reticulum-identity-hexhash identity)
                                    :lxmf_address (reticulum-hex (reticulum-address identity "lxmf" "delivery"))
                                    :node_address (reticulum-hex (reticulum-address identity "nomadnetwork" "node"))))))
    (when entry
      (setq info (append info (list :entry (nomadnet-native--entry-result entry)))))
    info))

(defun nomadnet-native--remember (params)
  "Create or update a directory entry from PARAMS and return it."
  (let* ((hash (reticulum-unhex (plist-get params :hash)))
         (existing (gethash hash nomadnet-native--entries))
         (get (lambda (key default) (if (plist-member params key)
                                        (let ((v (plist-get params key))) (if (eq v :false) nil v))
                                      default)))
         (entry (list :hash hash
                      :display_name (or (funcall get :display_name nil)
                                        (and existing (plist-get existing :display_name))
                                        (nomadnet-native--recall-name hash))
                      :trust_level (funcall get :trust_level (if existing (plist-get existing :trust_level) 2))
                      :hosts_node (funcall get :hosts_node (and existing (plist-get existing :hosts_node)))
                      :preferred_delivery (funcall get :preferred_delivery (if existing (plist-get existing :preferred_delivery) 1))
                      :identify (funcall get :identify (and existing (plist-get existing :identify)))
                      :sort_rank (funcall get :sort_rank (and existing (plist-get existing :sort_rank)))
                      :notes (funcall get :notes (if existing (plist-get existing :notes) "")))))
    (puthash hash entry nomadnet-native--entries)
    ;; Keep the trust of the node entry in sync with its peer, as nomadnet does.
    (let ((identity (reticulum-identity-recall hash)))
      (when identity
        (let* ((node-hash (reticulum-address identity "nomadnetwork" "node"))
               (node (gethash node-hash nomadnet-native--entries)))
          (when (and node (not (equal node-hash hash)))
            (puthash node-hash (plist-put node :trust_level (plist-get entry :trust_level)) nomadnet-native--entries)))))
    (nomadnet-native--save-directory)
    (nomadnet-native--entry-result entry)))

(defun nomadnet-native-handle (method params callback)
  "Handle request METHOD with PARAMS plist; CALLBACK receives (RESULT ERROR)."
  (condition-case err
      (pcase method
        ("ping" (funcall callback (list :pong t :time (float-time)) nil))
        ("status" (funcall callback (nomadnet-native-status) nil))
        ("announces.list"
         (let ((kind (plist-get params :kind)))
           (funcall callback
                    (mapcar #'nomadnet-native--announce-result
                            (cl-remove-if-not (lambda (a) (or (null kind) (equal (plist-get a :kind) kind)))
                                              nomadnet-native--announces))
                    nil)))
        ("announces.remove"
         (let ((time (plist-get params :time)))
           (setq nomadnet-native--announces
                 (cl-remove-if (lambda (a) (equal (plist-get a :time) time)) nomadnet-native--announces))
           (nomadnet-native--schedule-save)
           (funcall callback (list :removed t) nil)))
        ("directory.list"
         (funcall callback (sort (mapcar #'nomadnet-native--entry-result (hash-table-values nomadnet-native--entries))
                                 (lambda (a b) (string< (downcase (or (plist-get a :display_name) ""))
                                                        (downcase (or (plist-get b :display_name) "")))))
                  nil))
        ("directory.known_nodes"
         (funcall callback
                  (mapcar #'nomadnet-native--entry-result
                          (sort (cl-remove-if-not (lambda (e) (plist-get e :hosts_node))
                                                  (hash-table-values nomadnet-native--entries))
                                (lambda (a b)
                                  (let ((ra (or (plist-get a :sort_rank) 4294967296))
                                        (rb (or (plist-get b :sort_rank) 4294967296)))
                                    (if (/= ra rb) (< ra rb)
                                      (let ((ta (- 255 (plist-get a :trust_level))) (tb (- 255 (plist-get b :trust_level))))
                                        (if (/= ta tb) (< ta tb)
                                          (string< (or (plist-get a :display_name) "_")
                                                   (or (plist-get b :display_name) "_")))))))))
                  nil))
        ("directory.entry"
         (let ((entry (gethash (reticulum-unhex (plist-get params :hash)) nomadnet-native--entries)))
           (funcall callback (and entry (nomadnet-native--entry-result entry)) nil)))
        ("directory.remember" (funcall callback (nomadnet-native--remember params) nil))
        ("directory.forget"
         (remhash (reticulum-unhex (plist-get params :hash)) nomadnet-native--entries)
         (nomadnet-native--save-directory)
         (funcall callback (list :forgotten t) nil))
        ("peer.info" (funcall callback (nomadnet-native--peer-info (reticulum-unhex (plist-get params :hash))) nil))
        ("peer.request_path"
         (reticulum-transport-request-path (reticulum-unhex (plist-get params :hash)))
         (funcall callback (list :requested t) nil))
        ("set_display_name"
         (let ((name (string-trim (or (plist-get params :name) ""))))
           (when (string-empty-p name) (error "A display name is required"))
           (nomadnet-native--set-setting "display_name" (reticulum-msgpack-str name))
           (lxmf-router-set-display-name name)
           (funcall callback (list :display_name name) nil)))
        ("announce" (funcall callback (nomadnet-native--announce) nil))
        ("browser.get" (nomadnet-native--browser-get params callback))
        ("browser.disconnect"
         (when nomadnet-native--link
           (ignore-errors (reticulum-link-teardown nomadnet-native--link))
           (setq nomadnet-native--link nil))
         (funcall callback (list :disconnected t) nil))
        ("browser.uncache"
         (nomadnet-native--cache-remove (plist-get params :url))
         (funcall callback (list :uncached t) nil))
        ("node.info" (funcall callback (list :enabled nil) nil))
        ("log.path" (funcall callback (list :path (nomadnet-native--path "logfile")) nil))
        ("pn.get"
         (let ((pn (nomadnet-native--setting "propagation_node")))
           (funcall callback (list :selected (and (stringp pn) (= (length pn) 16) (reticulum-hex pn))
                                   :active nil)
                    nil)))
        ("quit" (funcall callback (list :quitting t) nil))
        ((or "guide.topics" "guide.get")
         (funcall callback nil "The guide is not available yet (see the repository issues)"))
        ((or "conversations.list" "conversation.messages" "conversation.send"
             "conversation.new" "conversation.mark_read" "conversation.delete"
             "conversation.purge_failed" "conversation.clear_history" "conversation.save_attachments"
             "lxmf.sync" "lxmf.sync_status" "lxmf.cancel_sync" "pn.set" "node.announce")
         (funcall callback nil "LXMF messaging is not implemented yet (see the repository issues)"))
        (_ (funcall callback nil (format "Unknown method: %s" method))))
    (error (funcall callback nil (error-message-string err)))))

(provide 'nomadnet-native)

;;; nomadnet-native.el ends here
