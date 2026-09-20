;;; nomadnet.el --- Nomad Network client for Emacs  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; Author: Paul Meier
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1") (reticulum "0.1.0"))
;; Keywords: comm, network, mesh, reticulum, lxmf
;; URL: https://github.com/paulmeier/nomadnet.el

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; nomadnet.el brings Nomad Network <https://github.com/markqvist/NomadNet>
;; to Emacs: encrypted LXMF messaging, an announce stream and directory of
;; known nodes, and a browser for micron pages hosted on Nomad Network nodes.
;;
;; Everything runs in Emacs Lisp: the Reticulum network stack comes from the
;; reticulum.el library, the client application core is nomadnet-native.el,
;; and the user interface, including the micron markup renderer, is in the
;; other nomadnet-*.el files.  The only external tool is the bzip2 command
;; line utility, used to decompress resources.
;;
;; Entry points:
;;   M-x nomadnet                 dashboard with status and shortcuts
;;   M-x nomadnet-conversations   LXMF conversations
;;   M-x nomadnet-announces       announce stream
;;   M-x nomadnet-known-nodes     saved nodes
;;   M-x nomadnet-browse          open a node URL in the micron browser
;;   M-x nomadnet-guide           the built in Nomad Network guide
;;
;; Modules:
;;   nomadnet-core.el           backend lifecycle, request API, helpers
;;   nomadnet-native.el         client application core on the reticulum library
;;   nomadnet-micron.el         micron markup renderer
;;   nomadnet-browser.el        node browser
;;   nomadnet-conversations.el  LXMF conversations and composing
;;   nomadnet-network.el        announce stream, known nodes, peer info
;;   nomadnet-guide.el          built in guide

;;; Code:

(require 'nomadnet-core)
(require 'nomadnet-micron)
(require 'nomadnet-browser)
(require 'nomadnet-conversations)
(require 'nomadnet-network)
(require 'nomadnet-guide)

;;;; Dashboard

(defvar nomadnet-dashboard-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "c") #'nomadnet-conversations)
    (define-key map (kbd "a") #'nomadnet-announces)
    (define-key map (kbd "n") #'nomadnet-known-nodes)
    (define-key map (kbd "b") #'nomadnet-browse)
    (define-key map (kbd "G") #'nomadnet-guide)
    (define-key map (kbd "L") #'nomadnet-log)
    (define-key map (kbd "A") #'nomadnet-announce-now)
    (define-key map (kbd "N") #'nomadnet-set-display-name)
    (define-key map (kbd "S") #'nomadnet-sync-messages)
    (define-key map (kbd "P") #'nomadnet-select-propagation-node)
    (define-key map (kbd "g") #'nomadnet-dashboard-refresh)
    (define-key map (kbd "R") #'nomadnet-restart)
    (define-key map (kbd "Q") #'nomadnet-stop)
    (define-key map (kbd "q") #'quit-window)
    map)
  "Keymap for `nomadnet-dashboard-mode'.")

(nomadnet-evil-integrate 'nomadnet-dashboard-mode nomadnet-dashboard-mode-map
 '(("c" . nomadnet-conversations) ("a" . nomadnet-announces) ("n" . nomadnet-known-nodes)
   ("b" . nomadnet-browse) ("G" . nomadnet-guide) ("L" . nomadnet-log)
   ("A" . nomadnet-announce-now) ("N" . nomadnet-set-display-name) ("S" . nomadnet-sync-messages)
   ("P" . nomadnet-select-propagation-node) ("g" . nomadnet-dashboard-refresh) ("R" . nomadnet-restart)
   ("Q" . nomadnet-stop) ("q" . quit-window)))

(define-derived-mode nomadnet-dashboard-mode special-mode "NomadNet"
  "Major mode for the Nomad Network dashboard."
  (setq buffer-read-only t
        truncate-lines t))

(defun nomadnet--dashboard-line (key description)
  "Insert a dashboard line for KEY and DESCRIPTION."
  (insert (format "  %-4s %s\n" (propertize key 'face 'help-key-binding) description)))

(defface nomadnet-interface-online-face '((t :inherit success))
  "Face for interfaces that are connected.")
(defface nomadnet-interface-offline-face '((t :inherit error))
  "Face for interfaces that are not connected.")

(defun nomadnet--dashboard-interface-line (interface)
  "Return the dashboard line describing INTERFACE plist.
INTERFACE has :name, :online, :rx and :tx packet counts and, when the
backend reports them, :rxbytes and :txbytes."
  (let ((online (plist-get interface :online))
        (rxbytes (plist-get interface :rxbytes))
        (txbytes (plist-get interface :txbytes)))
    (format "    %-24s %s  ↓%s ↑%s\n"
            (plist-get interface :name)
            (if online
                (propertize "online " 'face 'nomadnet-interface-online-face)
              (propertize "offline" 'face 'nomadnet-interface-offline-face))
            (if (numberp rxbytes)
                (nomadnet-format-size rxbytes)
              (format "%d pkts" (or (plist-get interface :rx) 0)))
            (if (numberp txbytes)
                (nomadnet-format-size txbytes)
              (format "%d pkts" (or (plist-get interface :tx) 0))))))

(defun nomadnet--dashboard-insert-interfaces (interfaces)
  "Insert the Interfaces section for the INTERFACES list, like nomadnet's."
  (insert "\n")
  (if (null interfaces)
      (insert "  Interfaces     : none configured\n")
    (insert (format "  Interfaces     : %d online of %d\n"
                    (cl-count-if (lambda (i) (plist-get i :online)) interfaces)
                    (length interfaces)))
    (dolist (interface interfaces)
      (insert (nomadnet--dashboard-interface-line interface)))))

(defun nomadnet-dashboard-refresh ()
  "Refresh the dashboard buffer."
  (interactive)
  (with-current-buffer (get-buffer-create "*NomadNet*")
    (let ((inhibit-read-only t)
          (pos (point))
          (status (and (nomadnet-ready-p) (ignore-errors (nomadnet-status))))
          (node (and (nomadnet-ready-p) (ignore-errors (nomadnet-call "node.info" nil 5))))
          (sync (and (nomadnet-ready-p) (ignore-errors (nomadnet-call "lxmf.sync_status" nil 5)))))
      (erase-buffer)
      (insert (propertize "Nomad Network\n" 'face '(:height 1.4 :weight bold)))
      (insert "\n")
      (cond
       ((not (nomadnet-running-p))
        (insert "  Not running.  Press " (propertize "R" 'face 'help-key-binding)
                " to start.\n"))
       ((not status)
        (insert "  Starting...\n"))
       (t
        (insert (format "  Display name   : %s\n" (plist-get status :display_name)))
        (insert (format "  LXMF address   : %s\n"
                        (propertize (plist-get status :lxmf_address) 'face 'nomadnet-hash-face)))
        (insert (format "  Identity       : %s\n"
                        (propertize (plist-get status :identity) 'face 'nomadnet-hash-face)))
        (insert (format "  Propagation PN : %s\n" (or (plist-get status :propagation_node) "none selected")))
        (when sync
          (insert (format "  LXMF sync      : %s\n" (plist-get sync :status))))
        (if (plist-get status :node_enabled)
            (insert (format "  Node           : %s <%s>  connects %s, pages %s, files %s\n"
                            (plist-get status :node_name)
                            (propertize (plist-get status :node_address) 'face 'nomadnet-hash-face)
                            (or (plist-get node :connects) 0)
                            (or (plist-get node :served_page_requests) 0)
                            (or (plist-get node :served_file_requests) 0)))
          (insert "  Node           : disabled (enable_node = no in nomadnet config)\n"))
        (insert (format "  Versions       : nomadnet %s, RNS %s, LXMF %s\n"
                        (plist-get status :version) (plist-get status :rns_version)
                        (plist-get status :lxmf_version)))
        (insert (format "  Config         : %s\n" (plist-get status :configdir)))
        (nomadnet--dashboard-insert-interfaces (plist-get status :interfaces))))
      (insert "\n")
      (nomadnet--dashboard-line "c" "Conversations")
      (nomadnet--dashboard-line "a" "Announce stream")
      (nomadnet--dashboard-line "n" "Known nodes")
      (nomadnet--dashboard-line "b" "Browse a node URL")
      (nomadnet--dashboard-line "G" "Guide")
      (nomadnet--dashboard-line "L" "Log file")
      (insert "\n")
      (nomadnet--dashboard-line "A" "Announce now")
      (nomadnet--dashboard-line "N" "Set display name")
      (nomadnet--dashboard-line "S" "Sync messages from propagation node")
      (nomadnet--dashboard-line "P" "Select propagation node")
      (insert "\n")
      (nomadnet--dashboard-line "g" "Refresh")
      (nomadnet--dashboard-line "R" "Restart")
      (nomadnet--dashboard-line "Q" "Stop")
      (nomadnet--dashboard-line "q" "Quit window")
      (goto-char (min pos (point-max))))))

(defcustom nomadnet-dashboard-refresh-interval 10
  "Seconds between automatic refreshes of the dashboard while it is displayed.
The interface status and transfer counters update at this rate.  Set to
nil to refresh only on demand with \\<nomadnet-dashboard-mode-map>\\[nomadnet-dashboard-refresh]."
  :type '(choice (const :tag "Manual only" nil) integer)
  :group 'nomadnet)

(defvar nomadnet--dashboard-timer nil "Timer refreshing the displayed dashboard.")

(defun nomadnet--dashboard-tick ()
  "Refresh the dashboard when it is displayed; stop the timer when it is gone."
  (let ((buffer (get-buffer "*NomadNet*")))
    (cond ((not (buffer-live-p buffer))
           (when nomadnet--dashboard-timer
             (cancel-timer nomadnet--dashboard-timer)
             (setq nomadnet--dashboard-timer nil)))
          ((and (get-buffer-window buffer t) (nomadnet-ready-p))
           (nomadnet-dashboard-refresh)))))

(defun nomadnet--dashboard-start-timer ()
  "Start the dashboard refresh timer if enabled and not running."
  (when (and nomadnet-dashboard-refresh-interval (null nomadnet--dashboard-timer))
    (setq nomadnet--dashboard-timer
          (run-at-time nomadnet-dashboard-refresh-interval nomadnet-dashboard-refresh-interval
                       #'nomadnet--dashboard-tick))))

;;;###autoload
(defun nomadnet ()
  "Open the Nomad Network dashboard, starting Nomad Network if needed."
  (interactive)
  (nomadnet-start)
  (with-current-buffer (get-buffer-create "*NomadNet*")
    (unless (derived-mode-p 'nomadnet-dashboard-mode)
      (nomadnet-dashboard-mode))
    (nomadnet-dashboard-refresh))
  (nomadnet--dashboard-start-timer)
  (nomadnet-show-buffer "*NomadNet*"))

(defun nomadnet--dashboard-on-change ()
  "Refresh the dashboard when the backend state changes."
  (when (get-buffer "*NomadNet*")
    (nomadnet-dashboard-refresh)))

(add-hook 'nomadnet-start-hook #'nomadnet--dashboard-on-change)
(add-hook 'nomadnet-status-changed-hook #'nomadnet--dashboard-on-change)

(provide 'nomadnet)

;;; nomadnet.el ends here
