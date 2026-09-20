;;; nomadnet-network.el --- Announce stream and known nodes  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;;; Commentary:

;; The Network section of Nomad Network: the announce stream, the list of
;; known nodes, and information about peers and this node.
;;
;; Announce stream keys:
;;   RET act on entry (browse node, message peer, select propagation node)
;;   b browse   m message   s save to directory   P use as propagation node
;;   d remove from stream   i info   f cycle kind filter   / search by name
;;   g refresh
;;
;; Known nodes keys:
;;   RET / b browse   m message operator   d forget   t toggle trust
;;   I toggle identify on connect   r set sort rank   e edit notes
;;   P use as propagation node   i info   g refresh

;;; Code:

(require 'nomadnet-core)
(require 'tabulated-list)

(declare-function nomadnet-browser-load "nomadnet-browser" (url &optional request-data))
(declare-function nomadnet-conversation-open "nomadnet-conversations" (hash &optional display-name))
(declare-function nomadnet-toggle-trust "nomadnet-conversations" (hash &optional callback))

;;;; Announce stream

(defconst nomadnet-announces-buffer-name "*NomadNet Announces*")

(defvar-local nomadnet-announces--filter nil "Kind filter: nil, \"node\", \"peer\" or \"pn\".")
(defvar-local nomadnet-announces--search nil
  "Search text restricting the announce stream, or nil.
Like the search box of nomadnet's announce stream, it matches
case-insensitively against the announced name and the address.")

(defvar nomadnet-announces-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    (define-key map (kbd "RET") #'nomadnet-announces-info)
    (define-key map [mouse-1] #'nomadnet-announces-mouse-info)
    (define-key map [mouse-2] #'nomadnet-announces-mouse-info)
    (define-key map (kbd "b") #'nomadnet-announces-browse)
    (define-key map (kbd "c") #'nomadnet-announces-act)
    (define-key map (kbd "m") #'nomadnet-announces-message)
    (define-key map (kbd "s") #'nomadnet-announces-save)
    (define-key map (kbd "P") #'nomadnet-announces-use-propagation-node)
    (define-key map (kbd "d") #'nomadnet-announces-remove)
    (define-key map (kbd "i") #'nomadnet-announces-peer-info)
    (define-key map (kbd "f") #'nomadnet-announces-cycle-filter)
    (define-key map (kbd "/") #'nomadnet-announces-search)
    (define-key map (kbd "g") #'nomadnet-announces-refresh)
    map)
  "Keymap for `nomadnet-announces-mode'.")

(nomadnet-evil-integrate 'nomadnet-announces-mode nomadnet-announces-mode-map
 '(("RET" . nomadnet-announces-info) ("b" . nomadnet-announces-browse) ("c" . nomadnet-announces-act)
   ("m" . nomadnet-announces-message) ("s" . nomadnet-announces-save) ("P" . nomadnet-announces-use-propagation-node)
   ("d" . nomadnet-announces-remove) ("i" . nomadnet-announces-peer-info) ("f" . nomadnet-announces-cycle-filter)
   ("/" . nomadnet-announces-search) ("g" . nomadnet-announces-refresh) ("q" . quit-window)
   ("<mouse-1>" . nomadnet-announces-mouse-info) ("<mouse-2>" . nomadnet-announces-mouse-info)))

(define-derived-mode nomadnet-announces-mode tabulated-list-mode "NomadNet-Announces"
  "Major mode listing announces received from the network."
  (setq tabulated-list-format [("Age" 5 nil :right-align t) ("Kind" 5 t) ("Name" 30 t)
                               ("Trust" 9 t) ("Hops" 4 nil :right-align t) ("Address" 32 t)]
        tabulated-list-padding 1
        mode-line-process '(:eval (nomadnet-announces--mode-line)))
  (tabulated-list-init-header)
  (add-hook 'nomadnet-event-hook #'nomadnet-announces--on-event))

(defun nomadnet-announces--mode-line ()
  "Return the mode line suffix describing the active filter and search."
  (concat (when nomadnet-announces--filter (format " [%s]" nomadnet-announces--filter))
          (when nomadnet-announces--search (format " /%s" nomadnet-announces--search))))

(defun nomadnet-announces--match-p (announce search)
  "Return non-nil when ANNOUNCE plist matches SEARCH text.
SEARCH is matched case-insensitively as a substring of the announced
name or of the destination hash; an empty or nil SEARCH matches all."
  (or (null search) (string-empty-p search)
      (let ((case-fold-search t)
            (needle (regexp-quote search)))
        (or (string-match-p needle (or (plist-get announce :name) ""))
            (string-match-p needle (or (plist-get announce :hash) ""))))))

(defun nomadnet-announces-search (search)
  "Show only announces whose name or address contains SEARCH.
An empty SEARCH shows the whole stream again."
  (interactive
   (list (read-string "Search announces (empty to clear): " nomadnet-announces--search)))
  (setq nomadnet-announces--search (let ((text (string-trim search)))
                                     (unless (string-empty-p text) text)))
  (message "%s" (if nomadnet-announces--search
                    (format "Showing announces matching %S" nomadnet-announces--search)
                  "Showing all announces"))
  (nomadnet-announces-refresh))

(defun nomadnet-announces--entry (announce)
  "Return a tabulated list entry for ANNOUNCE plist."
  (let* ((hash (plist-get announce :hash))
         (kind (plist-get announce :kind))
         (name (or (plist-get announce :name)
                   (if (equal kind "pn") "Propagation node" (format "<%s>" hash))))
         (trust (plist-get announce :trust_level))
         (hops (plist-get announce :hops)))
    (list (list hash (plist-get announce :time) kind announce)
          (vector (nomadnet-format-age (plist-get announce :time))
                  (pcase kind ("node" "node") ("peer" "peer") ("pn" "pn") (_ kind))
                  (propertize name 'face (if (plist-get announce :known) 'bold 'default))
                  (propertize (nomadnet-trust-name trust) 'face (nomadnet-trust-face trust))
                  (if hops (number-to-string hops) "?")
                  (propertize hash 'face 'nomadnet-hash-face)))))

(defun nomadnet-announces-refresh ()
  "Refresh the announce stream."
  (interactive)
  (let ((buffer (get-buffer nomadnet-announces-buffer-name)))
    (when (and buffer (nomadnet-ready-p))
      (with-current-buffer buffer
        (nomadnet-request "announces.list"
                          (when nomadnet-announces--filter (list :kind nomadnet-announces--filter))
                          (lambda (result err)
                            (when (buffer-live-p buffer)
                              (with-current-buffer buffer
                                (if err
                                    (message "Nomad Network: %s" err)
                                  (setq tabulated-list-entries
                                        (mapcar #'nomadnet-announces--entry
                                                (cl-remove-if-not
                                                 (lambda (a) (nomadnet-announces--match-p a nomadnet-announces--search))
                                                 result)))
                                  (tabulated-list-print t))))))))))

(defvar nomadnet-announces--refresh-timer nil)

(defun nomadnet-announces--on-event (event _data)
  "Refresh the announce stream when EVENT is an announce."
  (when (member event '("announce" "ready"))
    (unless nomadnet-announces--refresh-timer
      (setq nomadnet-announces--refresh-timer
            (run-at-time 1 nil
                         (lambda ()
                           (setq nomadnet-announces--refresh-timer nil)
                           (nomadnet-announces-refresh)
                           (nomadnet-known-nodes-refresh)))))))

;;;###autoload
(defun nomadnet-announces ()
  "Show the announce stream."
  (interactive)
  (nomadnet-ensure-ready)
  (let ((buffer (get-buffer-create nomadnet-announces-buffer-name)))
    (with-current-buffer buffer
      (unless (derived-mode-p 'nomadnet-announces-mode)
        (nomadnet-announces-mode)))
    (nomadnet-show-buffer buffer)
    (nomadnet-announces-refresh)))

(defun nomadnet-announces--at-point ()
  "Return (HASH TIME KIND ANNOUNCE) for the announce at point."
  (or (tabulated-list-get-id) (user-error "No announce at point")))

(defun nomadnet-announces-info ()
  "Show the announce info panel for the announce at point."
  (interactive)
  (nomadnet-announce-info (nth 3 (nomadnet-announces--at-point))))

(defun nomadnet-announces-mouse-info (event)
  "Show the info panel for the announce clicked in EVENT."
  (interactive "e")
  (mouse-set-point event)
  (nomadnet-announces-info))

(defun nomadnet-announces-act ()
  "Act on the announce at point depending on its kind."
  (interactive)
  (pcase-let ((`(,hash ,_time ,kind ,_announce) (nomadnet-announces--at-point)))
    (pcase kind
      ("node" (nomadnet-browser-load hash))
      ("peer" (nomadnet-conversation-open hash))
      ("pn" (nomadnet-announces-use-propagation-node))
      (_ (nomadnet-peer-info hash)))))

(defun nomadnet-announces-browse ()
  "Browse the node announced at point."
  (interactive)
  (pcase-let ((`(,hash ,_time ,kind ,_announce) (nomadnet-announces--at-point)))
    (if (equal kind "node")
        (nomadnet-browser-load hash)
      (let ((info (nomadnet-call "peer.info" (list :hash hash))))
        (if (plist-get info :node_address)
            (nomadnet-browser-load (plist-get info :node_address))
          (user-error "Identity not known; cannot derive node address"))))))

(defun nomadnet-announces-message ()
  "Message the peer announced at point."
  (interactive)
  (pcase-let ((`(,hash ,_time ,kind ,_announce) (nomadnet-announces--at-point)))
    (if (equal kind "peer")
        (nomadnet-conversation-open hash)
      (let ((info (nomadnet-call "peer.info" (list :hash hash))))
        (if (plist-get info :lxmf_address)
            (nomadnet-conversation-open (plist-get info :lxmf_address))
          (user-error "Identity not known; cannot derive LXMF address"))))))

(defun nomadnet-announces-save ()
  "Save the announced node or peer to the directory."
  (interactive)
  (pcase-let ((`(,hash ,_time ,kind ,_announce) (nomadnet-announces--at-point)))
    (if (equal kind "pn")
        (let ((info (nomadnet-call "peer.info" (list :hash hash))))
          (if (plist-get info :node_address)
              (nomadnet-with-result "directory.remember"
                  (list :hash (plist-get info :node_address) :hosts_node t)
                (message "Saved node %s" (or (plist-get result :display_name) hash))
                (nomadnet-known-nodes-refresh))
            (user-error "Identity not known")))
      (nomadnet-with-result "directory.remember"
          (list :hash hash :hosts_node (if (equal kind "node") t :false))
        (message "Saved %s" (or (plist-get result :display_name) hash))
        (nomadnet-announces-refresh)
        (nomadnet-known-nodes-refresh)))))

(defun nomadnet-announces-use-propagation-node ()
  "Use the announced propagation node for LXMF propagation."
  (interactive)
  (pcase-let ((`(,hash ,_time ,kind ,_announce) (nomadnet-announces--at-point)))
    (let ((pn (if (equal kind "pn")
                  hash
                (user-error "Select a propagation node announce"))))
      (nomadnet-with-result "pn.set" (list :hash pn)
        (message "Propagation node set to %s" (plist-get result :active))
        (run-hooks 'nomadnet-status-changed-hook)))))

(defun nomadnet-announces-remove ()
  "Remove the announce at point from the stream."
  (interactive)
  (pcase-let ((`(,_hash ,time ,_kind ,_announce) (nomadnet-announces--at-point)))
    (nomadnet-with-result "announces.remove" (list :time time)
      (nomadnet-announces-refresh))))

(defun nomadnet-announces-peer-info ()
  "Show raw peer information for the announced destination at point."
  (interactive)
  (nomadnet-peer-info (car (nomadnet-announces--at-point))))

(defun nomadnet-announces-cycle-filter ()
  "Cycle the announce kind filter."
  (interactive)
  (setq nomadnet-announces--filter
        (pcase nomadnet-announces--filter
          ('nil "node") ("node" "peer") ("peer" "pn") (_ nil)))
  (message "Showing %s announces" (or nomadnet-announces--filter "all"))
  (nomadnet-announces-refresh))

;;;; Announce info panel

(defvar-local nomadnet-announce-info--announce nil "Announce plist shown in this buffer.")
(defvar-local nomadnet-announce-info--peer nil "Peer info plist for the announce.")

(defvar nomadnet-announce-info-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map (kbd "l") #'nomadnet-announce-info-back)
    (define-key map (kbd "q") #'nomadnet-announce-info-back)
    (define-key map (kbd "c") #'nomadnet-announce-info-connect)
    (define-key map (kbd "RET") #'push-button)
    (define-key map (kbd "m") #'nomadnet-announce-info-message)
    (define-key map (kbd "s") #'nomadnet-announce-info-save)
    (define-key map (kbd "P") #'nomadnet-announce-info-use-propagation-node)
    (define-key map (kbd "g") #'nomadnet-announce-info-refresh)
    (define-key map (kbd "TAB") #'forward-button)
    (define-key map (kbd "<backtab>") #'backward-button)
    map)
  "Keymap for `nomadnet-announce-info-mode'.")

(nomadnet-evil-integrate 'nomadnet-announce-info-mode nomadnet-announce-info-mode-map
 '(("l" . nomadnet-announce-info-back) ("q" . nomadnet-announce-info-back)
   ("c" . nomadnet-announce-info-connect) ("RET" . push-button)
   ("m" . nomadnet-announce-info-message) ("s" . nomadnet-announce-info-save)
   ("P" . nomadnet-announce-info-use-propagation-node) ("g" . nomadnet-announce-info-refresh)
   ("TAB" . forward-button) ("<backtab>" . backward-button)))

(define-derived-mode nomadnet-announce-info-mode special-mode "NomadNet-Announce"
  "Major mode showing details and actions for one announce."
  (setq buffer-read-only t
        truncate-lines t))

(defun nomadnet-announce-info--kind-label (kind)
  "Return the description of announce KIND."
  (pcase kind
    ("node" "Nomad Network Node")
    ("peer" "LXMF Peer")
    ("pn" "LXMF Propagation Node")
    (_ kind)))

(defun nomadnet-announce-info--button (label action &optional key)
  "Insert an action button LABEL running ACTION, hinting KEY."
  (insert-text-button (format "< %s >" label)
                      'action (lambda (_button) (funcall action))
                      'follow-link t
                      'face 'custom-button
                      'help-echo (if key (format "%s (%s)" label key) label))
  (insert "  "))

(defun nomadnet-announce-info--render ()
  "Render the announce info buffer."
  (let* ((inhibit-read-only t)
         (announce nomadnet-announce-info--announce)
         (peer nomadnet-announce-info--peer)
         (kind (plist-get announce :kind))
         (hash (plist-get announce :hash))
         (trust (plist-get announce :trust_level))
         (name (or (plist-get announce :name)
                   (and peer (plist-get peer :display_name))
                   (format "<%s>" hash))))
    (erase-buffer)
    (insert (propertize "Announce Info\n" 'face '(:height 1.2 :weight bold)) "\n")
    (insert (format "Time   : %s\n" (nomadnet-format-time (plist-get announce :time) "%Y-%m-%d %H:%M:%S")))
    (insert (format "Addr   : %s\n" (propertize hash 'face 'nomadnet-hash-face)))
    (insert (format "Type   : %s\n" (nomadnet-announce-info--kind-label kind)))
    (insert (format "Name   : %s\n" name))
    (when (and peer (plist-get peer :lxmf_address) (not (equal kind "peer")))
      (insert (format "Oprtr  : %s\n" (propertize (plist-get peer :lxmf_address) 'face 'nomadnet-hash-face))))
    (when (and peer (plist-get peer :node_address) (not (equal kind "node")))
      (insert (format "Node   : %s\n" (propertize (plist-get peer :node_address) 'face 'nomadnet-hash-face))))
    (insert (format "Hops   : %s\n" (or (plist-get announce :hops) "unknown")))
    (insert (format "Trust  : %s\n" (propertize (nomadnet-trust-name trust) 'face (nomadnet-trust-face trust))))
    (when (plist-get announce :stamp_cost)
      (insert (format "Stamp  : cost %s\n" (plist-get announce :stamp_cost))))
    (when (and peer (not (plist-get peer :known_identity)))
      (insert (propertize "\nIdentity not yet known; a path request has been sent.\n" 'face 'warning)))
    (insert "\n" (propertize "Announce Data:" 'face 'bold) "\n")
    (insert (or (plist-get announce :name) "(none)") "\n\n")
    (nomadnet-announce-info--button "Back" #'nomadnet-announce-info-back "l")
    (pcase kind
      ("node"
       (nomadnet-announce-info--button "Connect" #'nomadnet-announce-info-connect "c")
       (nomadnet-announce-info--button "Msg Op" #'nomadnet-announce-info-message "m")
       (nomadnet-announce-info--button "Save" #'nomadnet-announce-info-save "s"))
      ("peer"
       (nomadnet-announce-info--button "Converse" #'nomadnet-announce-info-message "m")
       (nomadnet-announce-info--button "Node" #'nomadnet-announce-info-connect "c")
       (nomadnet-announce-info--button "Save" #'nomadnet-announce-info-save "s"))
      ("pn"
       (nomadnet-announce-info--button "Use as PN" #'nomadnet-announce-info-use-propagation-node "P")
       (nomadnet-announce-info--button "Node" #'nomadnet-announce-info-connect "c")
       (nomadnet-announce-info--button "Save" #'nomadnet-announce-info-save "s")))
    (insert "\n\n")
    (insert (propertize "l back  c connect  m message  s save  TAB next button" 'face 'shadow) "\n")
    (goto-char (point-min))
    (forward-button 1 nil t)))

;;;###autoload
(defun nomadnet-announce-info (announce)
  "Show the info panel for ANNOUNCE plist with Back, Connect, Message and Save."
  (nomadnet-ensure-ready)
  (let ((buffer (get-buffer-create "*NomadNet Announce*"))
        (peer (ignore-errors (nomadnet-call "peer.info" (list :hash (plist-get announce :hash)) 10))))
    (with-current-buffer buffer
      (unless (derived-mode-p 'nomadnet-announce-info-mode)
        (nomadnet-announce-info-mode))
      (setq nomadnet-announce-info--announce announce
            nomadnet-announce-info--peer peer)
      (when (and peer (not (plist-get peer :known_identity)))
        (nomadnet-request "peer.request_path" (list :hash (plist-get announce :hash)) #'ignore))
      (nomadnet-announce-info--render))
    (nomadnet-show-buffer buffer)))

(defun nomadnet-announce-info-refresh ()
  "Refresh the announce info panel."
  (interactive)
  (nomadnet-announce-info nomadnet-announce-info--announce))

(defun nomadnet-announce-info-back ()
  "Return to the announce stream."
  (interactive)
  (nomadnet-announces))

(defun nomadnet-announce-info--node-hash ()
  "Return the node address associated with the shown announce."
  (let ((announce nomadnet-announce-info--announce)
        (peer nomadnet-announce-info--peer))
    (cond ((equal (plist-get announce :kind) "node") (plist-get announce :hash))
          ((and peer (plist-get peer :node_address)))
          (t (user-error "Identity not known yet; cannot derive the node address")))))

(defun nomadnet-announce-info-connect ()
  "Connect to the announced node and show its index page."
  (interactive)
  (nomadnet-browser-load (nomadnet-announce-info--node-hash)))

(defun nomadnet-announce-info-message ()
  "Start a conversation with the announced peer or node operator."
  (interactive)
  (let ((announce nomadnet-announce-info--announce)
        (peer nomadnet-announce-info--peer))
    (cond ((equal (plist-get announce :kind) "peer")
           (nomadnet-conversation-open (plist-get announce :hash) (plist-get announce :name)))
          ((and peer (plist-get peer :lxmf_address))
           (nomadnet-conversation-open (plist-get peer :lxmf_address)))
          (t (user-error "Identity not known yet; cannot derive the LXMF address")))))

(defun nomadnet-announce-info-save ()
  "Save the announced node or peer to the directory."
  (interactive)
  (let* ((announce nomadnet-announce-info--announce)
         (kind (plist-get announce :kind))
         (hash (if (equal kind "pn") (nomadnet-announce-info--node-hash) (plist-get announce :hash))))
    (nomadnet-with-result "directory.remember"
        (list :hash hash :hosts_node (if (equal kind "peer") :false t)
              :display_name (plist-get announce :name))
      (message "Saved %s" (or (plist-get result :display_name) hash))
      (nomadnet-known-nodes-refresh)
      (nomadnet-announce-info-refresh))))

(defun nomadnet-announce-info-use-propagation-node ()
  "Use the announced propagation node for LXMF."
  (interactive)
  (let ((announce nomadnet-announce-info--announce))
    (unless (equal (plist-get announce :kind) "pn")
      (user-error "This announce is not from a propagation node"))
    (nomadnet-with-result "pn.set" (list :hash (plist-get announce :hash))
      (message "Propagation node set to %s" (plist-get result :active))
      (run-hooks 'nomadnet-status-changed-hook))))

;;;; Known nodes

(defconst nomadnet-known-nodes-buffer-name "*NomadNet Known Nodes*")

(defvar nomadnet-known-nodes-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    (define-key map (kbd "RET") #'nomadnet-known-nodes-browse)
    (define-key map [mouse-1] #'nomadnet-known-nodes-mouse-browse)
    (define-key map [mouse-2] #'nomadnet-known-nodes-mouse-browse)
    (define-key map (kbd "b") #'nomadnet-known-nodes-browse)
    (define-key map (kbd "m") #'nomadnet-known-nodes-message)
    (define-key map (kbd "d") #'nomadnet-known-nodes-forget)
    (define-key map (kbd "t") #'nomadnet-known-nodes-toggle-trust)
    (define-key map (kbd "I") #'nomadnet-known-nodes-toggle-identify)
    (define-key map (kbd "r") #'nomadnet-known-nodes-set-rank)
    (define-key map (kbd "e") #'nomadnet-known-nodes-edit-notes)
    (define-key map (kbd "P") #'nomadnet-known-nodes-use-propagation-node)
    (define-key map (kbd "i") #'nomadnet-known-nodes-info)
    (define-key map (kbd "g") #'nomadnet-known-nodes-refresh)
    map)
  "Keymap for `nomadnet-known-nodes-mode'.")

(nomadnet-evil-integrate 'nomadnet-known-nodes-mode nomadnet-known-nodes-mode-map
 '(("RET" . nomadnet-known-nodes-browse) ("b" . nomadnet-known-nodes-browse) ("m" . nomadnet-known-nodes-message)
   ("d" . nomadnet-known-nodes-forget) ("t" . nomadnet-known-nodes-toggle-trust) ("I" . nomadnet-known-nodes-toggle-identify)
   ("r" . nomadnet-known-nodes-set-rank) ("e" . nomadnet-known-nodes-edit-notes)
   ("P" . nomadnet-known-nodes-use-propagation-node) ("i" . nomadnet-known-nodes-info)
   ("g" . nomadnet-known-nodes-refresh) ("q" . quit-window)
   ("<mouse-1>" . nomadnet-known-nodes-mouse-browse) ("<mouse-2>" . nomadnet-known-nodes-mouse-browse)))

(define-derived-mode nomadnet-known-nodes-mode tabulated-list-mode "NomadNet-Nodes"
  "Major mode listing known Nomad Network nodes."
  (setq tabulated-list-format [("Name" 30 t) ("Trust" 9 t) ("Hops" 4 nil :right-align t)
                               ("Rank" 4 nil :right-align t) ("Ident" 5 nil) ("Address" 32 t)
                               ("Notes" 30 nil)]
        tabulated-list-padding 1)
  (tabulated-list-init-header))

(defun nomadnet-known-nodes--entry (node)
  "Return a tabulated list entry for NODE plist."
  (let ((hash (plist-get node :hash))
        (trust (plist-get node :trust_level))
        (hops (plist-get node :hops)))
    (list hash
          (vector (or (plist-get node :display_name) (format "<%s>" hash))
                  (propertize (nomadnet-trust-name trust) 'face (nomadnet-trust-face trust))
                  (if hops (number-to-string hops) "?")
                  (if (plist-get node :sort_rank) (number-to-string (plist-get node :sort_rank)) "")
                  (if (plist-get node :identify) "yes" "")
                  (propertize hash 'face 'nomadnet-hash-face)
                  (propertize (replace-regexp-in-string "\n" " " (or (plist-get node :notes) ""))
                              'face 'shadow)))))

(defun nomadnet-known-nodes-refresh ()
  "Refresh the known nodes list."
  (interactive)
  (let ((buffer (get-buffer nomadnet-known-nodes-buffer-name)))
    (when (and buffer (nomadnet-ready-p))
      (nomadnet-request "directory.known_nodes" nil
                        (lambda (result err)
                          (when (buffer-live-p buffer)
                            (with-current-buffer buffer
                              (if err
                                  (message "Nomad Network: %s" err)
                                (setq tabulated-list-entries
                                      (mapcar #'nomadnet-known-nodes--entry result))
                                (tabulated-list-print t)))))))))

;;;###autoload
(defun nomadnet-known-nodes ()
  "List known Nomad Network nodes."
  (interactive)
  (nomadnet-ensure-ready)
  (let ((buffer (get-buffer-create nomadnet-known-nodes-buffer-name)))
    (with-current-buffer buffer
      (unless (derived-mode-p 'nomadnet-known-nodes-mode)
        (nomadnet-known-nodes-mode)))
    (nomadnet-show-buffer buffer)
    (nomadnet-known-nodes-refresh)))

(defun nomadnet-known-nodes--hash-at-point ()
  "Return the node hash at point."
  (or (tabulated-list-get-id) (user-error "No node at point")))

(defun nomadnet-known-nodes-browse ()
  "Browse the node at point."
  (interactive)
  (nomadnet-browser-load (nomadnet-known-nodes--hash-at-point)))

(defun nomadnet-known-nodes-mouse-browse (event)
  "Browse the node clicked in EVENT."
  (interactive "e")
  (mouse-set-point event)
  (nomadnet-known-nodes-browse))

(defun nomadnet-known-nodes-message ()
  "Message the operator of the node at point."
  (interactive)
  (let ((info (nomadnet-call "peer.info" (list :hash (nomadnet-known-nodes--hash-at-point)))))
    (if (plist-get info :lxmf_address)
        (nomadnet-conversation-open (plist-get info :lxmf_address))
      (user-error "Identity of node not known"))))

(defun nomadnet-known-nodes-forget ()
  "Remove the node at point from the directory."
  (interactive)
  (let ((hash (nomadnet-known-nodes--hash-at-point)))
    (when (y-or-n-p (format "Forget node %s? " hash))
      (nomadnet-with-result "directory.forget" (list :hash hash)
        (nomadnet-known-nodes-refresh)))))

(defun nomadnet-known-nodes-toggle-trust ()
  "Toggle trust of the node at point."
  (interactive)
  (nomadnet-toggle-trust (nomadnet-known-nodes--hash-at-point) #'nomadnet-known-nodes-refresh))

(defun nomadnet-known-nodes-toggle-identify ()
  "Toggle whether to identify to the node at point when connecting."
  (interactive)
  (let* ((hash (nomadnet-known-nodes--hash-at-point))
         (entry (nomadnet-call "directory.entry" (list :hash hash)))
         (identify (not (plist-get entry :identify))))
    (nomadnet-with-result "directory.remember" (list :hash hash :identify (if identify t :false))
      (message "Identify on connect: %s" (if identify "yes" "no"))
      (nomadnet-known-nodes-refresh))))

(defun nomadnet-known-nodes-set-rank (rank)
  "Set the sort RANK of the node at point."
  (interactive
   (list (read-string "Sort rank (empty to clear): ")))
  (let ((hash (nomadnet-known-nodes--hash-at-point)))
    (nomadnet-with-result "directory.remember"
        (list :hash hash :sort_rank (if (string-empty-p rank) nil (string-to-number rank)))
      (nomadnet-known-nodes-refresh))))

(defun nomadnet-known-nodes-edit-notes (notes)
  "Set the NOTES stored with the node at point.
Notes are saved in nomadnet's directory, so the nomadnet program shows
them too.  Newlines are entered with \\<minibuffer-local-map>\\[newline]; \
an empty string clears the notes."
  (interactive
   (let* ((hash (nomadnet-known-nodes--hash-at-point))
          (entry (nomadnet-call "directory.entry" (list :hash hash))))
     (list (read-string "Notes (empty to clear): " (or (plist-get entry :notes) "")))))
  (let ((hash (nomadnet-known-nodes--hash-at-point)))
    (nomadnet-with-result "directory.remember" (list :hash hash :notes notes)
      (message "%s" (if (string-empty-p notes)
                        (format "Cleared notes of %s" (or (plist-get result :display_name) hash))
                      (format "Saved notes of %s" (or (plist-get result :display_name) hash))))
      (nomadnet-known-nodes-refresh))))

(defun nomadnet-known-nodes-use-propagation-node ()
  "Use the node at point as LXMF propagation node."
  (interactive)
  (let* ((hash (nomadnet-known-nodes--hash-at-point))
         (info (nomadnet-call "peer.info" (list :hash hash)))
         (identity (plist-get info :identity)))
    (unless identity
      (user-error "Identity of node not known"))
    ;; The propagation destination shares the node's identity.
    (nomadnet-with-result "pn.set" (list :hash hash)
      (message "Propagation node set to %s" (plist-get result :active))
      (run-hooks 'nomadnet-status-changed-hook))))

(defun nomadnet-known-nodes-info ()
  "Show information about the node at point."
  (interactive)
  (nomadnet-peer-info (nomadnet-known-nodes--hash-at-point)))

;;;; Peer information

;;;###autoload
(defun nomadnet-peer-info (hash)
  "Display what is known about destination HASH."
  (interactive (list (nomadnet-read-hash "Destination hash: ")))
  (nomadnet-ensure-ready)
  (let ((info (nomadnet-call "peer.info" (list :hash hash))))
    (with-help-window "*NomadNet Peer*"
      (with-current-buffer standard-output
        (insert (format "Destination : %s\n" hash))
        (insert (format "Name        : %s\n" (plist-get info :display_name)))
        (insert (format "Trust       : %s\n" (nomadnet-trust-name (plist-get info :trust_level))))
        (insert (format "Hops        : %s\n" (or (plist-get info :hops) "unknown")))
        (insert (format "Path known  : %s\n" (if (plist-get info :has_path) "yes" "no")))
        (if (plist-get info :known_identity)
            (progn
              (insert (format "Identity    : %s\n" (plist-get info :identity)))
              (insert (format "LXMF addr   : %s\n" (plist-get info :lxmf_address)))
              (insert (format "Node addr   : %s\n" (plist-get info :node_address))))
          (insert "Identity    : not yet known (waiting for an announce)\n"))
        (let ((entry (plist-get info :entry)))
          (when entry
            (insert "\nDirectory entry\n")
            (insert (format "  Hosts node        : %s\n" (if (plist-get entry :hosts_node) "yes" "no")))
            (insert (format "  Identify on link  : %s\n" (if (plist-get entry :identify) "yes" "no")))
            (insert (format "  Preferred delivery: %s\n"
                            (pcase (plist-get entry :preferred_delivery) (2 "propagated") (_ "direct"))))
            (insert (format "  Sort rank         : %s\n" (or (plist-get entry :sort_rank) "")))
            (unless (string-empty-p (or (plist-get entry :notes) ""))
              (insert (format "  Notes             : %s\n" (plist-get entry :notes))))))))))

(provide 'nomadnet-network)

;;; nomadnet-network.el ends here
