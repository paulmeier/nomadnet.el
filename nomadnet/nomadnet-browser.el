;;; nomadnet-browser.el --- Browser for Nomad Network nodes  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;;; Commentary:

;; A port of the Nomad Network node browser.  Pages are fetched by the
;; reticulum.el library over Reticulum links and rendered with `nomadnet-micron'.
;;
;; URLs have the form <destination hash>[:<path>][`<request vars>], e.g.
;; abb3ebcd03cb2388a838e70c001291f9:/page/index.mu.  A URL starting with a
;; colon is relative to the connected node.  Links may carry request
;; variables and field lists, which are submitted to node-side scripts.
;;
;; Keys (mirroring nomadnet where sensible):
;;   u   open URL          l / r  back / forward      g   reload
;;   d   disconnect        s      save node           c   copy URL
;;   TAB / S-TAB           next / previous link or field
;;   RET                   follow link, edit field, toggle box
;;   m                     message the node operator

;;; Code:

(require 'nomadnet-core)
(require 'nomadnet-micron)
(require 'face-remap)

(defgroup nomadnet-browser nil
  "Browser for Nomad Network nodes."
  :group 'nomadnet)

(defcustom nomadnet-browser-timeout 60
  "Seconds to wait for a page response."
  :type 'integer)

(defcustom nomadnet-browser-partial-refresh t
  "When non-nil, honour auto-refresh intervals declared by page partials."
  :type 'boolean)

(defconst nomadnet-browser-buffer-name "*NomadNet Browser*")
(defconst nomadnet-browser-default-path "/page/index.mu")

(defvar-local nomadnet-browser--destination nil "Hash of the connected node.")
(defvar-local nomadnet-browser--path nil "Path of the displayed page.")
(defvar-local nomadnet-browser--request-data nil "Alist of request data sent with the page.")
(defvar-local nomadnet-browser--url nil "URL string of the displayed page.")
(defvar-local nomadnet-browser--markup nil "Raw markup of the displayed page.")
(defvar-local nomadnet-browser--history nil "List of (DESTINATION PATH REQUEST-DATA).")
(defvar-local nomadnet-browser--history-ptr 0)
(defvar-local nomadnet-browser--history-nav nil "Non-nil while navigating history.")
(defvar-local nomadnet-browser--reloading nil)
(defvar-local nomadnet-browser--loading nil)
(defvar-local nomadnet-browser--status "Disconnected")
(defvar-local nomadnet-browser--page-fg nil)
(defvar-local nomadnet-browser--page-bg nil)
(defvar-local nomadnet-browser--partials nil "List of partial overlays on the page.")
(defvar-local nomadnet-browser--timers nil)
(defvar-local nomadnet-browser--stats nil "Plist with transfer statistics.")

(defvar nomadnet-browser-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map (kbd "u") #'nomadnet-browser-open-url)
    (define-key map (kbd "o") #'nomadnet-browser-open-url)
    (define-key map (kbd "l") #'nomadnet-browser-back)
    (define-key map (kbd "r") #'nomadnet-browser-forward)
    (define-key map (kbd "g") #'nomadnet-browser-reload)
    (define-key map (kbd "d") #'nomadnet-browser-disconnect)
    (define-key map (kbd "s") #'nomadnet-browser-save-node)
    (define-key map (kbd "c") #'nomadnet-browser-copy-url)
    (define-key map (kbd "w") #'nomadnet-browser-copy-url)
    (define-key map (kbd "m") #'nomadnet-browser-message-operator)
    (define-key map (kbd "i") #'nomadnet-browser-node-info)
    (define-key map (kbd "v") #'nomadnet-browser-view-source)
    (define-key map (kbd "TAB") #'forward-button)
    (define-key map (kbd "<tab>") #'forward-button)
    (define-key map (kbd "<backtab>") #'backward-button)
    (define-key map (kbd "S-TAB") #'backward-button)
    (define-key map (kbd "n") #'forward-button)
    (define-key map (kbd "p") #'backward-button)
    map)
  "Keymap for `nomadnet-browser-mode'.")

(nomadnet-evil-integrate 'nomadnet-browser-mode nomadnet-browser-mode-map
 '(("u" . nomadnet-browser-open-url) ("o" . nomadnet-browser-open-url) ("l" . nomadnet-browser-back)
   ("r" . nomadnet-browser-forward) ("g" . nomadnet-browser-reload) ("d" . nomadnet-browser-disconnect)
   ("s" . nomadnet-browser-save-node) ("c" . nomadnet-browser-copy-url) ("w" . nomadnet-browser-copy-url)
   ("m" . nomadnet-browser-message-operator) ("i" . nomadnet-browser-node-info) ("v" . nomadnet-browser-view-source)
   ("TAB" . forward-button) ("<tab>" . forward-button) ("<backtab>" . backward-button)
   ("S-TAB" . backward-button) ("n" . forward-button) ("p" . backward-button)
   ("q" . quit-window)))

(define-derived-mode nomadnet-browser-mode special-mode "NomadNet-Browser"
  "Major mode for browsing Nomad Network nodes."
  (setq buffer-read-only t
        truncate-lines nil
        word-wrap t
        header-line-format '(:eval (nomadnet-browser--header-line))
        mode-line-process '(:eval (concat " " nomadnet-browser--status)))
  (setq-local nomadnet-micron-link-function #'nomadnet-browser-handle-link)
  (add-hook 'kill-buffer-hook #'nomadnet-browser--cancel-timers nil t)
  (add-hook 'nomadnet-event-hook #'nomadnet-browser--on-event))

(defun nomadnet-browser--header-line ()
  "Return the header line showing the current URL."
  (if nomadnet-browser--url
      (concat " " (propertize nomadnet-browser--url 'face 'nomadnet-hash-face))
    " Disconnected"))

(defun nomadnet-browser--buffer ()
  "Return the browser buffer, creating it if necessary."
  (let ((buffer (get-buffer-create nomadnet-browser-buffer-name)))
    (with-current-buffer buffer
      (unless (derived-mode-p 'nomadnet-browser-mode)
        (nomadnet-browser-mode)))
    buffer))

(defun nomadnet-browser--set-status (text)
  "Set the browser status to TEXT and update the mode line."
  (setq nomadnet-browser--status text)
  (force-mode-line-update))

(defun nomadnet-browser--on-event (event data)
  "Update browser status from backend EVENT with DATA."
  (when (string= event "browser_status")
    (let ((buffer (get-buffer nomadnet-browser-buffer-name)))
      (when (and buffer (buffer-live-p buffer))
        (with-current-buffer buffer
          (when nomadnet-browser--loading
            (nomadnet-browser--set-status
             (pcase (plist-get data :state)
               ("path_requested" "Path requested, waiting for path...")
               ("establishing_link" "Establishing link...")
               ("link_established" "Link established")
               ("requesting" "Sending request...")
               ("request_sent" "Request sent, awaiting response...")
               ("receiving"
                (let ((progress (or (plist-get data :progress) 0)))
                  (format "Receiving response %d%%" (round (* 100 progress)))))
               (state (format "%s" state))))))))))

;;;; URL handling

(defun nomadnet-browser-parse-url (url)
  "Split URL into (DESTINATION PATH REQUEST-DATA).
DESTINATION may be nil for URLs relative to the current node."
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
        (1 (unless (nomadnet-hash-p (car components))
             (user-error "Malformed URL: %s" url))
           (list (downcase (car components)) nomadnet-browser-default-path (nreverse request-data)))
        (2 (let ((dest (car components)) (path (cadr components)))
             (cond ((nomadnet-hash-p dest)
                    (list (downcase dest)
                          (if (string-empty-p path) nomadnet-browser-default-path path)
                          (nreverse request-data)))
                   ((string-empty-p dest)
                    (list nil (if (string-empty-p path) nomadnet-browser-default-path path)
                          (nreverse request-data)))
                   (t (user-error "Malformed URL: %s" url)))))
        (_ (user-error "Malformed URL: %s" url))))))

(defun nomadnet-browser--normalize-url-input (input)
  "Normalise INPUT typed by the user into a URL, as nomadnet does."
  (let ((url (string-trim input)))
    (when (and (not (string-search "`" url)) (string-search ":" url))
      (let ((pos (string-search "|" url)))
        (when (and pos (> pos 0))
          (setq url (concat (substring url 0 pos) "`" (substring url (1+ pos)))))))
    url))

;;;; Loading

(defun nomadnet-browser--show-message (text)
  "Replace the page with TEXT."
  (let ((inhibit-read-only t))
    (nomadnet-browser--clear-page-colors)
    (erase-buffer)
    (insert "\n\n" (propertize text 'face 'shadow) "\n")))

(defun nomadnet-browser--write-history ()
  "Record the current page in the history."
  (let ((entry (list nomadnet-browser--destination nomadnet-browser--path
                     nomadnet-browser--request-data)))
    (setq nomadnet-browser--history
          (append (seq-take nomadnet-browser--history nomadnet-browser--history-ptr)
                  (list entry)))
    (setq nomadnet-browser--history-ptr (length nomadnet-browser--history))))

(defun nomadnet-browser-load (url &optional request-data)
  "Load URL with optional REQUEST-DATA alist into the browser buffer."
  (nomadnet-ensure-ready)
  (let ((buffer (nomadnet-browser--buffer)))
    (with-current-buffer buffer
      (when nomadnet-browser--loading
        (user-error "Browser is busy loading %s" nomadnet-browser--url))
      (pcase-let ((`(,dest ,path ,url-data) (nomadnet-browser-parse-url url)))
        (unless (or dest nomadnet-browser--destination)
          (user-error "No node connected; enter a full URL"))
        (let* ((dest (or dest nomadnet-browser--destination))
               (data (append url-data request-data))
               (reload nomadnet-browser--reloading)
               (display-url (concat dest ":" path)))
          (setq nomadnet-browser--loading t)
          (nomadnet-browser--cancel-timers)
          (nomadnet-browser--set-status (format "Retrieving %s" display-url))
          (when (or (null nomadnet-browser--markup) (string-empty-p (buffer-string)))
            (nomadnet-browser--show-message (format "Retrieving\n[%s]" display-url)))
          (nomadnet-request "browser.get"
                            (list :url (concat dest ":" path)
                                  :request_data (if data (nomadnet--alist-to-plist data) nil)
                                  :use_cache (if reload nil t)
                                  :current nomadnet-browser--destination
                                  :timeout nomadnet-browser-timeout)
                            (lambda (result err)
                              (when (buffer-live-p buffer)
                                (with-current-buffer buffer
                                  (setq nomadnet-browser--loading nil)
                                  (if err
                                      (nomadnet-browser--load-failed dest path err)
                                    (nomadnet-browser--load-finished result data)))))))))
    (nomadnet-show-buffer buffer)))

(defun nomadnet--alist-to-plist (alist)
  "Convert ALIST with string keys to a plist with keyword keys."
  (let (out)
    (dolist (pair alist)
      (push (intern (concat ":" (car pair))) out)
      (push (cdr pair) out))
    (nreverse out)))

(defun nomadnet-browser--keep-page-on-error-p (err)
  "Return non-nil when failure ERR should leave the current page in place.
A submission that does not fit in one packet fails before anything is
sent, so the page and its field values stay valid and the user can
shorten the values and submit again."
  (and (stringp err)
       (string-prefix-p nomadnet-request-too-large-prefix err)))

(defun nomadnet-browser--load-failed (dest path err)
  "Show failure ERR for DEST and PATH."
  (setq nomadnet-browser--reloading nil
        nomadnet-browser--history-nav nil)
  (nomadnet-browser--set-status (format "Failed: %s" err))
  (if (and nomadnet-browser--markup (nomadnet-browser--keep-page-on-error-p err))
      (message "Nomad Network browser: %s" err)
    (nomadnet-browser--show-error-page dest path err)))

(defun nomadnet-browser--show-error-page (dest path err)
  "Replace the page with the failure ERR for DEST and PATH."
  (let ((inhibit-read-only t))
    (nomadnet-browser--clear-page-colors)
    (erase-buffer)
    (insert "\n\n  " (propertize "!" 'face 'error) "\n\n")
    (insert (format "  Could not load %s:%s\n\n  %s\n\n" dest path err))
    (insert "  Press " (propertize "l" 'face 'help-key-binding) " to go back, "
            (propertize "g" 'face 'help-key-binding) " to retry or "
            (propertize "u" 'face 'help-key-binding) " to enter a URL.\n"))
  (setq nomadnet-browser--url (concat dest ":" path)
        nomadnet-browser--destination dest
        nomadnet-browser--path path
        nomadnet-browser--markup nil)
  (message "Nomad Network browser: %s" err))

(defun nomadnet-browser--load-finished (result data)
  "Display RESULT of a page request made with request DATA."
  (setq nomadnet-browser--reloading nil)
  (if (plist-get result :file)
      (progn
        (setq nomadnet-browser--history-nav nil)
        (nomadnet-browser--set-status
         (format "Saved %s (%s)" (file-name-nondirectory (plist-get result :file))
                 (nomadnet-format-size (plist-get result :size))))
        (message "Saved %s" (plist-get result :file)))
    (setq nomadnet-browser--destination (plist-get result :destination)
          nomadnet-browser--path (plist-get result :path)
          nomadnet-browser--request-data data
          nomadnet-browser--url (plist-get result :url)
          nomadnet-browser--markup (plist-get result :markup)
          nomadnet-browser--stats result)
    (nomadnet-browser--render)
    (if nomadnet-browser--history-nav
        (setq nomadnet-browser--history-nav nil)
      (nomadnet-browser--write-history))
    (nomadnet-browser--set-status
     (cond ((plist-get result :cached) "Done (cached)")
           ((plist-get result :loopback) "Done (local)")
           (t (format "Done  %s  ↓%s in %.2fs"
                      (nomadnet-format-size (plist-get result :size))
                      (nomadnet-format-size (plist-get result :transfer_size))
                      (or (plist-get result :response_time) 0)))))
    (let ((anchor (cdr (assoc "var_anchor" data))))
      (when anchor (nomadnet-micron-jump-to-anchor anchor)))
    (nomadnet-browser--start-partials)))

(defvar-local nomadnet-browser--color-cookies nil
  "Face remapping cookies applying the page colours to the whole buffer.")

(defun nomadnet-browser--clear-page-colors ()
  "Remove page colours applied to the buffer background and text."
  (dolist (cookie nomadnet-browser--color-cookies)
    (face-remap-remove-relative cookie))
  (setq nomadnet-browser--color-cookies nil))

(defun nomadnet-browser--apply-page-colors (fg bg)
  "Apply page colour specs FG and BG to the whole buffer.
Micron pages declare them with #!fg= and #!bg= headers; nomadnet paints
the entire page area with them, not just the text, so remap the default
face of the buffer accordingly.  A nil spec leaves that colour alone."
  (nomadnet-browser--clear-page-colors)
  (let ((fg (nomadnet-micron-color fg))
        (bg (nomadnet-micron-color bg)))
    (when fg
      (push (face-remap-add-relative 'default :foreground fg) nomadnet-browser--color-cookies))
    (when bg
      (push (face-remap-add-relative 'default :background bg) nomadnet-browser--color-cookies)
      ;; Fringes and the header line would otherwise keep the theme colours
      ;; and frame the page.
      (push (face-remap-add-relative 'fringe :background bg) nomadnet-browser--color-cookies)
      (push (face-remap-add-relative 'header-line :background bg) nomadnet-browser--color-cookies))))

(defun nomadnet-browser--render ()
  "Render the current markup into the buffer."
  (let ((inhibit-read-only t)
        (colors (nomadnet-micron-page-colors nomadnet-browser--markup)))
    (setq nomadnet-browser--page-fg (car colors)
          nomadnet-browser--page-bg (cdr colors))
    (nomadnet-browser--apply-page-colors nomadnet-browser--page-fg nomadnet-browser--page-bg)
    (erase-buffer)
    (let ((rendered (nomadnet-micron-render nomadnet-browser--markup
                                            nomadnet-browser--page-fg
                                            nomadnet-browser--page-bg t)))
      (setq nomadnet-browser--partials (plist-get rendered :partials)))
    (goto-char (point-min))))

;;;; Links

(defun nomadnet-browser--request-data-from-fields (fields)
  "Build a request data alist from link FIELDS."
  (when fields
    (let ((all (member "*" fields)) (names nil) (data nil))
      (dolist (item fields)
        (if (string-search "=" item)
            (let ((kv (split-string item "=")))
              (when (= (length kv) 2)
                (push (cons (concat "var_" (car kv)) (cadr kv)) data)))
          (push item names)))
      (append (nreverse data) (nomadnet-micron-collect-fields names all)))))

(defun nomadnet-browser-handle-link (url fields)
  "Follow link URL with FIELDS from the current page."
  (let ((request-data (nomadnet-browser--request-data-from-fields fields)))
    (cond
     ((string-prefix-p "rrc://" url)
      (message "RRC channel links are not supported by nomadnet.el yet"))
     ((string-prefix-p "p:" url)
      (nomadnet-browser--refresh-partials (cdr (split-string url ":"))))
     ((string-search "@" url)
      (pcase-let ((`(,type ,target) (split-string url "@")))
        (pcase type
          ((or "lxmf" "lxmf.delivery") (nomadnet-browser--open-conversation target))
          ((or "nnn" "nomadnetwork.node") (nomadnet-browser-load target request-data))
          ((or "rrc" "rrc.hub.session") (message "RRC channel links are not supported yet"))
          (_ (message "No handler for destination type %s" type)))))
     (t (nomadnet-browser-load url request-data)))))

(declare-function nomadnet-conversation-open "nomadnet-conversations" (hash &optional display-name))

(defun nomadnet-browser--open-conversation (hash)
  "Open a conversation with HASH."
  (unless (nomadnet-hash-p hash)
    (user-error "Invalid LXMF address in link: %s" hash))
  (nomadnet-conversation-open (downcase hash)))

;;;; Partials

(defun nomadnet-browser--cancel-timers ()
  "Cancel partial refresh timers."
  (dolist (timer nomadnet-browser--timers)
    (cancel-timer timer))
  (setq nomadnet-browser--timers nil))

(defun nomadnet-browser--start-partials ()
  "Load every partial on the current page."
  (dolist (overlay nomadnet-browser--partials)
    (nomadnet-browser--load-partial overlay)))

(defun nomadnet-browser--refresh-partials (ids)
  "Reload partials whose id is in IDS."
  (dolist (overlay nomadnet-browser--partials)
    (let ((id (plist-get (overlay-get overlay 'nomadnet-partial) :id)))
      (when (and id (member id ids))
        (nomadnet-browser--load-partial overlay)))))

(defun nomadnet-browser--load-partial (overlay)
  "Fetch the partial described by OVERLAY and render it in place."
  (when (and (overlay-buffer overlay) (nomadnet-ready-p))
    (let* ((buffer (current-buffer))
           (plist (overlay-get overlay 'nomadnet-partial))
           (url (plist-get plist :url))
           (data (nomadnet-browser--request-data-from-fields (plist-get plist :fields))))
      (if (null (ignore-errors (nomadnet-browser-parse-url url)))
          (nomadnet-browser--replace-partial
           overlay (format "Could not load partial %s: malformed URL" url))
        (nomadnet-request "browser.get"
                          (list :url url
                                :request_data (if data (nomadnet--alist-to-plist data) nil)
                                :use_cache nil
                                :current nomadnet-browser--destination
                                :timeout nomadnet-browser-timeout)
                          (lambda (result err)
                            (when (and (buffer-live-p buffer) (overlay-buffer overlay))
                              (with-current-buffer buffer
                                (nomadnet-browser--partial-loaded overlay result err)))))))))

(defun nomadnet-browser--partial-loaded (overlay result err)
  "Render RESULT or ERR into partial OVERLAY and schedule its refresh."
  (let* ((plist (overlay-get overlay 'nomadnet-partial))
         (url (plist-get plist :url))
         (refresh (plist-get plist :refresh))
         (buffer (current-buffer)))
    (if err
        (nomadnet-browser--replace-partial
         overlay (format "Could not load partial %s: %s" url err))
      (nomadnet-browser--replace-partial overlay (plist-get result :markup) t)
      (when (and refresh nomadnet-browser-partial-refresh)
        (push (run-at-time refresh nil
                           (lambda ()
                             (when (buffer-live-p buffer)
                               (with-current-buffer buffer
                                 (nomadnet-browser--load-partial overlay)))))
              nomadnet-browser--timers)))))

(defun nomadnet-browser--replace-partial (overlay content &optional render)
  "Replace the text of partial OVERLAY with CONTENT, rendering micron if RENDER."
  (let ((inhibit-read-only t)
        (start (overlay-start overlay))
        (end (overlay-end overlay)))
    (save-excursion
      (goto-char start)
      (if render
          (nomadnet-micron-render (string-trim-right content)
                                  nomadnet-browser--page-fg nomadnet-browser--page-bg)
        (insert (propertize content 'face 'shadow) "\n"))
      (let ((new-end (point)))
        ;; Remove the trailing newline of the rendered block so that the
        ;; placeholder's own newline remains, then delete the placeholder.
        (when (and (> new-end start) (eq (char-before new-end) ?\n))
          (delete-region (1- new-end) new-end)
          (setq new-end (1- new-end)))
        (delete-region new-end (+ end (- new-end start)))
        (move-overlay overlay start new-end)))))

;;;; Commands

;;;###autoload
(defun nomadnet-browse (url)
  "Open URL in the Nomad Network browser."
  (interactive
   (list (nomadnet-browser--normalize-url-input
          (read-string "Node URL: "
                       (with-current-buffer (nomadnet-browser--buffer)
                         nomadnet-browser--url)))))
  (nomadnet-browser-load (nomadnet-browser--normalize-url-input url)))

(defun nomadnet-browser-open-url (url)
  "Prompt for URL and load it."
  (interactive
   (list (read-string "URL: " nomadnet-browser--url)))
  (nomadnet-browser-load (nomadnet-browser--normalize-url-input url)))

(defun nomadnet-browser--go-history (ptr)
  "Load history entry number PTR."
  (let ((entry (nth (1- ptr) nomadnet-browser--history)))
    (when entry
      (setq nomadnet-browser--history-ptr ptr
            nomadnet-browser--history-nav t)
      (nomadnet-browser-load (concat (nth 0 entry) ":" (nth 1 entry)) (nth 2 entry)))))

(defun nomadnet-browser-back ()
  "Go back in the browsing history."
  (interactive)
  (if (> nomadnet-browser--history-ptr 1)
      (nomadnet-browser--go-history (1- nomadnet-browser--history-ptr))
    (message "No previous page")))

(defun nomadnet-browser-forward ()
  "Go forward in the browsing history."
  (interactive)
  (if (< nomadnet-browser--history-ptr (length nomadnet-browser--history))
      (nomadnet-browser--go-history (1+ nomadnet-browser--history-ptr))
    (message "No next page")))

(defun nomadnet-browser-reload ()
  "Reload the current page, bypassing the cache."
  (interactive)
  (unless nomadnet-browser--destination
    (user-error "Nothing to reload"))
  (setq nomadnet-browser--reloading t
        nomadnet-browser--history-nav t)
  (nomadnet-browser-load (concat nomadnet-browser--destination ":" nomadnet-browser--path)
                         nomadnet-browser--request-data))

(defun nomadnet-browser-disconnect ()
  "Close the link to the current node and clear the page."
  (interactive)
  (nomadnet-browser--cancel-timers)
  (when (nomadnet-ready-p)
    (nomadnet-request "browser.disconnect" nil #'ignore))
  (setq nomadnet-browser--destination nil
        nomadnet-browser--path nil
        nomadnet-browser--url nil
        nomadnet-browser--markup nil
        nomadnet-browser--history nil
        nomadnet-browser--history-ptr 0
        nomadnet-browser--request-data nil)
  (nomadnet-browser--show-message "Disconnected")
  (nomadnet-browser--set-status "Disconnected"))

(defun nomadnet-browser-save-node ()
  "Save the connected node to the list of known nodes."
  (interactive)
  (unless nomadnet-browser--destination
    (user-error "Not connected to a node"))
  (let ((hash nomadnet-browser--destination))
    (when (y-or-n-p (format "Save node <%s> to known nodes? " hash))
      (nomadnet-with-result "directory.remember" (list :hash hash :hosts_node t)
        (message "Saved node %s" (or (plist-get result :display_name) hash))))))

(defun nomadnet-browser-copy-url ()
  "Copy the current URL to the kill ring."
  (interactive)
  (if nomadnet-browser--url
      (progn (kill-new nomadnet-browser--url)
             (message "Copied %s" nomadnet-browser--url))
    (message "No URL to copy")))

(defun nomadnet-browser-message-operator ()
  "Start a conversation with the operator of the connected node."
  (interactive)
  (unless nomadnet-browser--destination
    (user-error "Not connected to a node"))
  (let ((info (nomadnet-call "peer.info" (list :hash nomadnet-browser--destination))))
    (if (plist-get info :lxmf_address)
        (nomadnet-browser--open-conversation (plist-get info :lxmf_address))
      (user-error "Identity of node is not known yet"))))

(declare-function nomadnet-peer-info "nomadnet-network" (hash))

(defun nomadnet-browser-node-info ()
  "Show information about the connected node."
  (interactive)
  (unless nomadnet-browser--destination
    (user-error "Not connected to a node"))
  (nomadnet-peer-info nomadnet-browser--destination))

(defun nomadnet-browser-view-source ()
  "Show the micron source of the current page."
  (interactive)
  (unless nomadnet-browser--markup
    (user-error "No page loaded"))
  (let ((buffer (get-buffer-create "*NomadNet Page Source*"))
        (markup nomadnet-browser--markup)
        (url nomadnet-browser--url))
    (with-current-buffer buffer
      (let ((inhibit-read-only t))
        (erase-buffer)
        (insert markup)
        (goto-char (point-min)))
      (setq buffer-read-only t
            header-line-format (concat " " url)))
    (nomadnet-show-buffer buffer)))

(provide 'nomadnet-browser)

;;; nomadnet-browser.el ends here
