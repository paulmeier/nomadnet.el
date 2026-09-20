;;; nomadnet-conversations.el --- LXMF conversations  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;;; Commentary:

;; Conversation list, conversation view and message composition for LXMF
;; messages, mirroring the Conversations section of Nomad Network.
;;
;; Conversation list keys:
;;   RET open   n new conversation   D delete   S sync from propagation node
;;   g refresh  t toggle trust       i peer info
;;
;; Conversation view keys:
;;   c / r compose    g refresh   A save attachments of message at point
;;   P purge failed   C clear history   D delete conversation   t toggle trust
;;
;; Compose buffer: C-c C-c sends, C-c C-k cancels.

;;; Code:

(require 'nomadnet-core)
(require 'nomadnet-micron)
(require 'tabulated-list)

(defgroup nomadnet-conversations nil
  "LXMF conversations."
  :group 'nomadnet)

(defcustom nomadnet-compose-renderer 'markdown
  "Renderer hint attached to composed messages.
Nomad Network composes in markdown by default.  Use `micron' to tag
messages as micron, or `plain' to attach no renderer field."
  :type '(choice (const markdown) (const micron) (const plain)))

(defface nomadnet-message-outgoing-face '((t :inherit font-lock-function-name-face))
  "Face for the header of messages sent by this peer.")
(defface nomadnet-message-incoming-face '((t :inherit font-lock-keyword-face))
  "Face for the header of received messages.")
(defface nomadnet-message-title-face '((t :inherit bold))
  "Face for message titles.")
(defface nomadnet-message-meta-face '((t :inherit shadow))
  "Face for message metadata.")
(defface nomadnet-message-failed-face '((t :inherit error))
  "Face for failed messages.")

(defconst nomadnet-conversations-buffer-name "*NomadNet Conversations*")

;;;; Conversation list

(defvar nomadnet-conversations-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    (define-key map (kbd "RET") #'nomadnet-conversations-open)
    (define-key map [mouse-1] #'nomadnet-conversations-mouse-open)
    (define-key map [mouse-2] #'nomadnet-conversations-mouse-open)
    (define-key map (kbd "n") #'nomadnet-conversation-new)
    (define-key map (kbd "D") #'nomadnet-conversations-delete)
    (define-key map (kbd "S") #'nomadnet-sync-messages)
    (define-key map (kbd "g") #'nomadnet-conversations-refresh)
    (define-key map (kbd "t") #'nomadnet-conversations-toggle-trust)
    (define-key map (kbd "i") #'nomadnet-conversations-peer-info)
    map)
  "Keymap for `nomadnet-conversations-mode'.")

(nomadnet-evil-integrate 'nomadnet-conversations-mode nomadnet-conversations-mode-map
 '(("RET" . nomadnet-conversations-open) ("n" . nomadnet-conversation-new) ("D" . nomadnet-conversations-delete)
   ("S" . nomadnet-sync-messages) ("g" . nomadnet-conversations-refresh) ("t" . nomadnet-conversations-toggle-trust)
   ("i" . nomadnet-conversations-peer-info) ("q" . quit-window)
   ("<mouse-1>" . nomadnet-conversations-mouse-open) ("<mouse-2>" . nomadnet-conversations-mouse-open)))

(define-derived-mode nomadnet-conversations-mode tabulated-list-mode "NomadNet-Conversations"
  "Major mode listing LXMF conversations."
  (setq tabulated-list-format [("Name" 28 t) ("New" 4 t :right-align t)
                               ("Trust" 10 t) ("Last activity" 17 t) ("Address" 32 t)]
        tabulated-list-sort-key nil
        tabulated-list-padding 1)
  (tabulated-list-init-header)
  (add-hook 'nomadnet-event-hook #'nomadnet-conversations--on-event))

(defun nomadnet-conversations--entry (conversation)
  "Return a tabulated list entry for CONVERSATION plist."
  (let* ((hash (plist-get conversation :hash))
         (name (or (plist-get conversation :display_name) (format "<%s>" hash)))
         (unread (or (plist-get conversation :unread) 0))
         (failed (or (plist-get conversation :failed) 0))
         (trust (plist-get conversation :trust_level)))
    (list hash
          (vector (propertize name 'face (if (> unread 0) 'nomadnet-unread-face 'default))
                  (cond ((> unread 0) (number-to-string unread))
                        ((> failed 0) (propertize "!" 'face 'nomadnet-message-failed-face))
                        (t ""))
                  (propertize (nomadnet-trust-name trust) 'face (nomadnet-trust-face trust))
                  (nomadnet-format-time (plist-get conversation :last_activity))
                  (propertize hash 'face 'nomadnet-hash-face)))))

(defun nomadnet-conversations-refresh ()
  "Refresh the conversation list."
  (interactive)
  (let ((buffer (get-buffer nomadnet-conversations-buffer-name)))
    (when (and buffer (nomadnet-ready-p))
      (nomadnet-request "conversations.list" nil
                        (lambda (result err)
                          (when (buffer-live-p buffer)
                            (with-current-buffer buffer
                              (if err
                                  (message "Nomad Network: %s" err)
                                (setq tabulated-list-entries
                                      (mapcar #'nomadnet-conversations--entry result))
                                (tabulated-list-print t)))))))))

(defvar nomadnet-conversations--refresh-timer nil)

(defun nomadnet-conversations--on-event (event _data)
  "Refresh lists when EVENT signals a change."
  (when (member event '("conversations_changed" "message_received" "ready"))
    (unless nomadnet-conversations--refresh-timer
      (setq nomadnet-conversations--refresh-timer
            (run-at-time 0.5 nil
                         (lambda ()
                           (setq nomadnet-conversations--refresh-timer nil)
                           (nomadnet-conversations-refresh)
                           (nomadnet-conversation--refresh-visible)))))))

;;;###autoload
(defun nomadnet-conversations ()
  "List LXMF conversations."
  (interactive)
  (nomadnet-ensure-ready)
  (let ((buffer (get-buffer-create nomadnet-conversations-buffer-name)))
    (with-current-buffer buffer
      (unless (derived-mode-p 'nomadnet-conversations-mode)
        (nomadnet-conversations-mode)))
    (nomadnet-show-buffer buffer)
    (nomadnet-conversations-refresh)))

(defun nomadnet-conversations--hash-at-point ()
  "Return the conversation hash at point or signal an error."
  (or (tabulated-list-get-id) (user-error "No conversation at point")))

(defun nomadnet-conversations-open ()
  "Open the conversation at point."
  (interactive)
  (nomadnet-conversation-open (nomadnet-conversations--hash-at-point)))

(defun nomadnet-conversations-mouse-open (event)
  "Open the conversation clicked in EVENT."
  (interactive "e")
  (mouse-set-point event)
  (nomadnet-conversations-open))

(defun nomadnet-conversations-delete ()
  "Delete the conversation at point."
  (interactive)
  (let ((hash (nomadnet-conversations--hash-at-point)))
    (when (yes-or-no-p (format "Delete conversation with %s and all its messages? " hash))
      (nomadnet-with-result "conversation.delete" (list :hash hash)
        (message "Conversation deleted")
        (let ((buffer (get-buffer (nomadnet-conversation--buffer-name hash))))
          (when buffer (kill-buffer buffer)))
        (nomadnet-conversations-refresh)))))

(defun nomadnet-conversations-toggle-trust ()
  "Toggle trust of the peer at point."
  (interactive)
  (nomadnet-toggle-trust (nomadnet-conversations--hash-at-point)
                         #'nomadnet-conversations-refresh))

(declare-function nomadnet-peer-info "nomadnet-network" (hash))

(defun nomadnet-conversations-peer-info ()
  "Show information about the peer at point."
  (interactive)
  (nomadnet-peer-info (nomadnet-conversations--hash-at-point)))

(defun nomadnet-toggle-trust (hash &optional callback)
  "Toggle whether HASH is trusted, then call CALLBACK."
  (let* ((entry (nomadnet-call "directory.entry" (list :hash hash)))
         (trusted (and entry (= (or (plist-get entry :trust_level) 2) 255)))
         (new-level (if trusted 2 255)))
    (nomadnet-with-result "directory.remember" (list :hash hash :trust_level new-level)
      (message "%s is now %s" (or (plist-get result :display_name) hash)
               (nomadnet-trust-name new-level))
      (when callback (funcall callback)))))

;;;###autoload
(defun nomadnet-conversation-new (hash)
  "Start a conversation with the peer whose LXMF address is HASH."
  (interactive (list (nomadnet-read-hash "LXMF address: ")))
  (nomadnet-ensure-ready)
  (nomadnet-with-result "conversation.new" (list :hash hash)
    (nomadnet-conversations-refresh)
    (nomadnet-conversation-open hash (plist-get result :display_name))))

;;;; Conversation view

(defvar-local nomadnet-conversation--hash nil)
(defvar-local nomadnet-conversation--name nil)
(defvar-local nomadnet-conversation--messages nil)

(defvar nomadnet-conversation-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map (kbd "c") #'nomadnet-conversation-compose)
    (define-key map (kbd "r") #'nomadnet-conversation-compose)
    (define-key map (kbd "g") #'nomadnet-conversation-refresh)
    (define-key map (kbd "A") #'nomadnet-conversation-save-attachments)
    (define-key map (kbd "P") #'nomadnet-conversation-purge-failed)
    (define-key map (kbd "C") #'nomadnet-conversation-clear-history)
    (define-key map (kbd "D") #'nomadnet-conversation-delete)
    (define-key map (kbd "t") #'nomadnet-conversation-toggle-trust)
    (define-key map (kbd "i") #'nomadnet-conversation-peer-info)
    (define-key map (kbd "TAB") #'forward-button)
    (define-key map (kbd "<backtab>") #'backward-button)
    (define-key map (kbd "n") #'nomadnet-conversation-next-message)
    (define-key map (kbd "p") #'nomadnet-conversation-previous-message)
    map)
  "Keymap for `nomadnet-conversation-mode'.")

(nomadnet-evil-integrate 'nomadnet-conversation-mode nomadnet-conversation-mode-map
 '(("c" . nomadnet-conversation-compose) ("r" . nomadnet-conversation-compose) ("g" . nomadnet-conversation-refresh)
   ("A" . nomadnet-conversation-save-attachments) ("P" . nomadnet-conversation-purge-failed) ("C" . nomadnet-conversation-clear-history)
   ("D" . nomadnet-conversation-delete) ("t" . nomadnet-conversation-toggle-trust) ("i" . nomadnet-conversation-peer-info)
   ("TAB" . forward-button) ("<backtab>" . backward-button) ("n" . nomadnet-conversation-next-message)
   ("p" . nomadnet-conversation-previous-message) ("q" . quit-window)))

(define-derived-mode nomadnet-conversation-mode special-mode "NomadNet-Conversation"
  "Major mode showing the messages of one LXMF conversation.
Long messages are wrapped at word boundaries with `visual-line-mode'.
\\<nomadnet-conversation-mode-map>\\[nomadnet-conversation-next-message] and \
\\[nomadnet-conversation-previous-message] move between messages."
  (setq buffer-read-only t
        truncate-lines nil)
  (visual-line-mode 1)
  (setq-local nomadnet-micron-link-function #'nomadnet-conversation--handle-link))

(declare-function nomadnet-browser-load "nomadnet-browser" (url &optional request-data))

(defun nomadnet-conversation--handle-link (url fields)
  "Open link URL with FIELDS found in a micron message."
  (ignore fields)
  (if (string-prefix-p "lxmf@" url)
      (nomadnet-conversation-open (substring url 5))
    (nomadnet-browser-load (replace-regexp-in-string "\\`\\(nnn\\|nomadnetwork\\.node\\)@" "" url))))

(defun nomadnet-conversation--buffer-name (hash)
  "Return the conversation buffer name for HASH."
  (format "*NomadNet Conversation %s*" (substring hash 0 8)))

;;;###autoload
(defun nomadnet-conversation-open (hash &optional display-name)
  "Open the conversation with HASH, labelled DISPLAY-NAME."
  (interactive (list (nomadnet-read-hash "LXMF address: ")))
  (nomadnet-ensure-ready)
  (let ((buffer (get-buffer-create (nomadnet-conversation--buffer-name hash))))
    (with-current-buffer buffer
      (unless (derived-mode-p 'nomadnet-conversation-mode)
        (nomadnet-conversation-mode))
      (setq nomadnet-conversation--hash hash
            nomadnet-conversation--name (or display-name nomadnet-conversation--name hash)))
    (nomadnet-show-buffer buffer)
    (nomadnet-conversation-refresh)))

(defun nomadnet-conversation--refresh-visible ()
  "Refresh conversation buffers that are displayed in a window."
  (dolist (buffer (buffer-list))
    (with-current-buffer buffer
      (when (and (derived-mode-p 'nomadnet-conversation-mode)
                 (get-buffer-window buffer t))
        (nomadnet-conversation-refresh)))))

(defun nomadnet-conversation-refresh ()
  "Reload the messages of the current conversation."
  (interactive)
  (let ((buffer (current-buffer))
        (hash nomadnet-conversation--hash))
    (when (and hash (nomadnet-ready-p))
      (nomadnet-request "conversation.messages" (list :hash hash)
                        (lambda (result err)
                          (when (buffer-live-p buffer)
                            (with-current-buffer buffer
                              (if err
                                  (message "Nomad Network: %s" err)
                                (setq nomadnet-conversation--name (plist-get result :display_name)
                                      nomadnet-conversation--messages (plist-get result :messages))
                                (nomadnet-conversation--render result)
                                (nomadnet-request "conversation.mark_read" (list :hash hash) #'ignore)))))))))

(defun nomadnet-conversation--state-label (message)
  "Return a short state label for MESSAGE."
  (let ((state (plist-get message :state)))
    (pcase state
      ("delivered" "✓ delivered")
      ("sent" "sent")
      ("outbound" "queued")
      ("sending" "sending")
      ("generating" "generating")
      ("failed" (propertize "✗ failed" 'face 'nomadnet-message-failed-face))
      ("rejected" (propertize "rejected" 'face 'nomadnet-message-failed-face))
      ("cancelled" "cancelled")
      (_ (or state "")))))

(defun nomadnet-conversation--insert-message (message)
  "Insert MESSAGE plist at point."
  (let* ((outgoing (plist-get message :outgoing))
         (start (point))
         (title (plist-get message :title))
         (content (or (plist-get message :content) ""))
         (renderer (plist-get message :renderer)))
    (insert (propertize (format "%s  %s"
                                (nomadnet-format-time (plist-get message :timestamp) "%Y-%m-%d %H:%M:%S")
                                (if outgoing "You" nomadnet-conversation--name))
                        'face (if outgoing 'nomadnet-message-outgoing-face
                                'nomadnet-message-incoming-face)))
    (insert "  ")
    (insert (propertize
             (string-join
              (delq nil (list (if outgoing (nomadnet-conversation--state-label message)
                                (plist-get message :signature))
                              (plist-get message :method)
                              (when (plist-get message :attachments)
                                (format "%d attachment(s)" (length (plist-get message :attachments))))))
              " · ")
             'face 'nomadnet-message-meta-face))
    (insert "\n")
    (when (and title (not (string-empty-p title)))
      (insert (propertize title 'face 'nomadnet-message-title-face) "\n"))
    (if (equal renderer "micron")
        (nomadnet-micron-render content)
      (insert content)
      (unless (string-suffix-p "\n" content) (insert "\n")))
    (dolist (attachment (plist-get message :attachments))
      (insert (propertize (format "  ⎘ %s (%s)\n" (plist-get attachment :name)
                                  (nomadnet-format-size (plist-get attachment :size)))
                          'face 'nomadnet-message-meta-face)))
    (insert "\n")
    (put-text-property start (point) 'nomadnet-message message)))

(defun nomadnet-conversation--render (result)
  "Render conversation RESULT into the current buffer."
  (let ((inhibit-read-only t)
        (pos (point))
        (at-end (eobp)))
    (erase-buffer)
    (setq header-line-format
          (format " %s <%s>  %s"
                  (plist-get result :display_name) nomadnet-conversation--hash
                  (propertize (nomadnet-trust-name (plist-get result :trust_level))
                              'face (nomadnet-trust-face (plist-get result :trust_level)))))
    (unless (plist-get result :known)
      (insert (propertize "The identity of this peer is not yet known; messages cannot be sent until an announce is received.\n\n"
                          'face 'warning)))
    (if (null (plist-get result :messages))
        (insert (propertize "No messages yet.  Press c to compose.\n" 'face 'shadow))
      (dolist (message (plist-get result :messages))
        (nomadnet-conversation--insert-message message)))
    (if at-end (goto-char (point-max)) (goto-char (min pos (point-max))))))

(defun nomadnet-conversation--message-at-point ()
  "Return the message plist at point."
  (or (get-text-property (point) 'nomadnet-message)
      (user-error "No message at point")))

(defun nomadnet-conversation--message-starts ()
  "Return the positions where messages start in the buffer, in order."
  (let ((starts nil) (pos (point-min)))
    (while pos
      (when (get-text-property pos 'nomadnet-message)
        (push pos starts))
      (setq pos (next-single-property-change pos 'nomadnet-message)))
    (nreverse starts)))

(defun nomadnet-conversation-next-message ()
  "Move to the start of the next message."
  (interactive)
  (let ((next (cl-find-if (lambda (start) (> start (point)))
                          (nomadnet-conversation--message-starts))))
    (if next
        (goto-char next)
      (message "No next message"))))

(defun nomadnet-conversation-previous-message ()
  "Move to the start of the previous message.
From inside a message, move to the start of that message first."
  (interactive)
  (let ((previous (cl-find-if (lambda (start) (< start (point)))
                              (reverse (nomadnet-conversation--message-starts)))))
    (if previous
        (goto-char previous)
      (message "No previous message"))))

(defun nomadnet-conversation-save-attachments ()
  "Save attachments of the message at point to the downloads directory."
  (interactive)
  (let ((message (nomadnet-conversation--message-at-point)))
    (unless (plist-get message :attachments)
      (user-error "Message has no attachments"))
    (nomadnet-with-result "conversation.save_attachments"
        (list :hash nomadnet-conversation--hash :message (plist-get message :hash))
      (message "Saved: %s" (string-join (plist-get result :saved) ", ")))))

(defun nomadnet-conversation-purge-failed ()
  "Remove failed messages from the conversation."
  (interactive)
  (when (y-or-n-p "Remove all failed messages from this conversation? ")
    (nomadnet-with-result "conversation.purge_failed" (list :hash nomadnet-conversation--hash)
      (nomadnet-conversation-refresh))))

(defun nomadnet-conversation-clear-history ()
  "Delete every message in the conversation."
  (interactive)
  (when (yes-or-no-p "Delete all messages in this conversation? ")
    (nomadnet-with-result "conversation.clear_history" (list :hash nomadnet-conversation--hash)
      (nomadnet-conversation-refresh))))

(defun nomadnet-conversation-delete ()
  "Delete the whole conversation."
  (interactive)
  (let ((hash nomadnet-conversation--hash)
        (buffer (current-buffer)))
    (when (yes-or-no-p "Delete this conversation and all its messages? ")
      (nomadnet-with-result "conversation.delete" (list :hash hash)
        (kill-buffer buffer)
        (nomadnet-conversations-refresh)))))

(defun nomadnet-conversation-toggle-trust ()
  "Toggle trust of this conversation's peer."
  (interactive)
  (nomadnet-toggle-trust nomadnet-conversation--hash #'nomadnet-conversation-refresh))

(defun nomadnet-conversation-peer-info ()
  "Show information about this conversation's peer."
  (interactive)
  (nomadnet-peer-info nomadnet-conversation--hash))

;;;; Composing

(defvar-local nomadnet-compose--hash nil)
(defvar-local nomadnet-compose--name nil)

(defvar nomadnet-compose-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "C-c C-c") #'nomadnet-compose-send)
    (define-key map (kbd "C-c C-k") #'nomadnet-compose-cancel)
    map)
  "Keymap for `nomadnet-compose-mode'.")

(nomadnet-evil-integrate 'nomadnet-compose-mode nomadnet-compose-mode-map
 '(("C-c C-c" . nomadnet-compose-send) ("C-c C-k" . nomadnet-compose-cancel)))

(define-derived-mode nomadnet-compose-mode text-mode "NomadNet-Compose"
  "Major mode for composing an LXMF message.
Type a title on the first line after \"Title:\" and the message body after
the separator.  \\[nomadnet-compose-send] sends, \\[nomadnet-compose-cancel] discards."
  (setq-local fill-column 72))

(defconst nomadnet-compose-separator "--text follows this line--")

(defun nomadnet-conversation-compose ()
  "Compose a message in the current conversation."
  (interactive)
  (nomadnet-compose nomadnet-conversation--hash nomadnet-conversation--name))

(defun nomadnet-compose (hash &optional name)
  "Open a compose buffer for HASH labelled NAME."
  (let ((buffer (get-buffer-create (format "*NomadNet Compose %s*" (substring hash 0 8)))))
    (with-current-buffer buffer
      (unless (derived-mode-p 'nomadnet-compose-mode)
        (nomadnet-compose-mode)
        (insert (format "To: %s <%s>\nTitle: \n%s\n" (or name hash) hash nomadnet-compose-separator))
        (put-text-property (point-min) (line-beginning-position 0) 'read-only t)
        (goto-char (point-min))
        (forward-line 1)
        (end-of-line))
      (setq nomadnet-compose--hash hash
            nomadnet-compose--name name))
    (nomadnet-show-buffer buffer)))

(defun nomadnet-compose--parse ()
  "Return (TITLE . BODY) from the compose buffer."
  (save-excursion
    (goto-char (point-min))
    (let ((title "") (body ""))
      (when (re-search-forward "^Title: ?\\(.*\\)$" nil t)
        (setq title (string-trim (match-string 1))))
      (goto-char (point-min))
      (if (search-forward nomadnet-compose-separator nil t)
          (setq body (string-trim (buffer-substring-no-properties (line-beginning-position 2) (point-max))))
        (setq body (string-trim (buffer-substring-no-properties (point-min) (point-max)))))
      (cons title body))))

(defun nomadnet-compose-send ()
  "Send the composed message."
  (interactive)
  (pcase-let ((`(,title . ,body) (nomadnet-compose--parse))
              (hash nomadnet-compose--hash)
              (buffer (current-buffer)))
    (when (and (string-empty-p title) (string-empty-p body))
      (user-error "Message is empty"))
    (nomadnet-with-result "conversation.send"
        (list :hash hash :title title :content body
              :renderer (unless (eq nomadnet-compose-renderer 'plain)
                          (symbol-name nomadnet-compose-renderer)))
      (message "Message queued for delivery")
      (when (buffer-live-p buffer)
        (kill-buffer buffer))
      (nomadnet-conversation-open hash))))

(defun nomadnet-compose-cancel ()
  "Discard the composed message."
  (interactive)
  (when (or (not (buffer-modified-p)) (y-or-n-p "Discard message? "))
    (kill-buffer (current-buffer))))

(provide 'nomadnet-conversations)

;;; nomadnet-conversations.el ends here
