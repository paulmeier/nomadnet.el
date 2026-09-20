;;; nomadnet-core.el --- Backend lifecycle, requests and helpers for nomadnet.el  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; Author: Paul Meier
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
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

;; Backend lifecycle, the request API used by the user interface modules,
;; and shared helpers.  See nomadnet.el for an overview.

;;; Code:

(require 'cl-lib)
(require 'subr-x)

(defgroup nomadnet nil
  "Nomad Network client for Emacs."
  :group 'comm
  :prefix "nomadnet-")

(defcustom nomadnet-request-timeout 30
  "Seconds to wait for a synchronous request to complete."
  :type 'integer)

(defcustom nomadnet-notify-on-new-message t
  "When non-nil, announce incoming LXMF messages in the echo area."
  :type 'boolean)

(defcustom nomadnet-start-hook nil
  "Hook run after Nomad Network has started."
  :type 'hook)

(defcustom nomadnet-status-changed-hook nil
  "Hook run after the display name or propagation node changes."
  :type 'hook)

(defcustom nomadnet-event-hook nil
  "Hook run with (EVENT DATA) for every event from the backend.
EVENT is a string such as \"announce\" or \"message_received\" and DATA
is a plist with keyword keys."
  :type 'hook)

(defconst nomadnet-directory
  (file-name-directory (or load-file-name buffer-file-name
                           (locate-library "nomadnet-core")))
  "Directory containing the nomadnet.el sources.")

;; When run from a checkout, the reticulum library lives in a sibling
;; directory; make it loadable without further configuration.
(let ((sibling (expand-file-name "../reticulum" nomadnet-directory)))
  (when (and (file-directory-p sibling) (not (locate-library "reticulum")))
    (add-to-list 'load-path (directory-file-name sibling))))

(defconst nomadnet-hash-length 32
  "Length in hex characters of a Reticulum destination hash.")

;;;; Backend lifecycle

(defvar nomadnet--next-id 0)
(defvar nomadnet--status nil "Plist with the last status reported by the backend.")
(defvar nomadnet--ready nil "Non-nil once the backend has reported readiness.")

(declare-function nomadnet-native-start "nomadnet-native" (event-function))
(declare-function nomadnet-native-stop "nomadnet-native" ())
(declare-function nomadnet-native-handle "nomadnet-native" (method params callback))
(defvar nomadnet-native--running)

(defun nomadnet-running-p ()
  "Return non-nil when the backend is running."
  (and (featurep 'nomadnet-native) nomadnet-native--running))

(defun nomadnet-ready-p ()
  "Return non-nil when the backend is running and Nomad Network has started."
  (and (nomadnet-running-p) nomadnet--ready))

;;;###autoload
(defun nomadnet-start ()
  "Start Nomad Network if it is not already running."
  (interactive)
  (require 'nomadnet-native)
  (if (nomadnet-running-p)
      (when (called-interactively-p 'interactive)
        (message "Nomad Network already running"))
    (setq nomadnet--ready nil nomadnet--status nil)
    (nomadnet-native-start #'nomadnet--handle-event)
    (message "Starting Nomad Network..."))
  t)

(defun nomadnet-stop ()
  "Stop Nomad Network."
  (interactive)
  (when (nomadnet-running-p)
    (nomadnet-native-stop)
    (setq nomadnet--ready nil)
    (message "Stopped Nomad Network")))

(defun nomadnet-restart ()
  "Restart Nomad Network."
  (interactive)
  (nomadnet-stop)
  (nomadnet-start))

(defun nomadnet--handle-event (event data)
  "Handle EVENT with DATA emitted by the backend."
  (pcase event
    ("ready"
     (setq nomadnet--status data
           nomadnet--ready t)
     (message "Nomad Network ready: %s <%s>"
              (plist-get data :display_name) (plist-get data :lxmf_address))
     (run-hooks 'nomadnet-start-hook))
    ("fatal"
     (message "Nomad Network failed to start: %s" (plist-get data :message)))
    ("message_received"
     (when nomadnet-notify-on-new-message
       (let ((title (plist-get data :title)))
         (message "Nomad Network: message from %s%s"
                  (plist-get data :source_name)
                  (if (and title (not (string-empty-p title)))
                      (format ": %s" title)
                    ""))))))
  (run-hook-with-args 'nomadnet-event-hook event data))

;;;; Requests

(defun nomadnet-request (method params callback)
  "Ask the backend to perform METHOD with PARAMS plist.
CALLBACK receives (RESULT ERROR).  Returns a request id."
  (unless (nomadnet-running-p)
    (nomadnet-start))
  (let ((id (cl-incf nomadnet--next-id)))
    (nomadnet-native-handle method params callback)
    id))

(defun nomadnet-call (method &optional params timeout)
  "Call METHOD with PARAMS synchronously and return the result.
Signals an error if the backend reports one or TIMEOUT seconds pass."
  (let ((done nil) (result nil) (err nil)
        (deadline (+ (float-time) (or timeout nomadnet-request-timeout))))
    (nomadnet-request method params
                      (lambda (r e) (setq result r err e done t)))
    (while (and (not done) (< (float-time) deadline) (nomadnet-running-p))
      (accept-process-output nil 0.1))
    (cond
     (err (error "Nomad Network: %s" err))
     ((not done) (error "Nomad Network: %s timed out" method))
     (t result))))

(defun nomadnet-ensure-ready (&optional timeout)
  "Start Nomad Network if needed and wait up to TIMEOUT seconds for readiness."
  (nomadnet-start)
  (let ((deadline (+ (float-time) (or timeout 90))))
    (while (and (not nomadnet--ready) (nomadnet-running-p) (< (float-time) deadline))
      (accept-process-output nil 0.2)))
  (unless (nomadnet-ready-p)
    (error "Nomad Network is not ready (see the %s buffer)" "*reticulum-log*"))
  t)

(defmacro nomadnet-with-result (call args &rest body)
  "Run CALL with ARGS asynchronously, binding `result' in BODY on success.
CALL is a backend method name.  Errors are shown with `message'."
  (declare (indent 2))
  `(nomadnet-request ,call ,args
                     (lambda (result err)
                       (if err
                           (message "Nomad Network: %s" err)
                         (ignore result)
                         ,@body))))

;;;; Buffer display and keybinding integration

(defcustom nomadnet-display-buffer-action '(display-buffer-same-window)
  "Action passed to `pop-to-buffer' when showing nomadnet buffers.
The default shows them in the selected window, like a regular Emacs
application, rather than in a side or popup window.  Frameworks whose
`display-buffer-alist' rules match *NomadNet* buffers (for example Doom's
popup system) take precedence; exempt the buffers there as well."
  :type 'sexp)

(defun nomadnet-show-buffer (buffer)
  "Display BUFFER according to `nomadnet-display-buffer-action' and select it."
  (pop-to-buffer buffer nomadnet-display-buffer-action))

(declare-function evil-set-initial-state "evil-core" (mode state))
(declare-function evil-define-key* "evil-core" (state keymap key def &rest bindings))

(defun nomadnet-evil-integrate (mode map bindings)
  "Make BINDINGS of MAP win over evil's normal state in MODE buffers.
BINDINGS is an alist of (KEY-STRING . COMMAND).  A binding on \"g\" is
also available as \"gr\" so that evil's g prefix keeps working.  Does
nothing unless evil is (or gets) loaded."
  (with-eval-after-load 'evil
    (evil-set-initial-state mode 'normal)
    (dolist (binding bindings)
      (let ((key (car binding)) (command (cdr binding)))
        (if (equal key "g")
            (evil-define-key* 'normal map (kbd "gr") command)
          (evil-define-key* 'normal map (kbd key) command))))))

;;;; Helpers shared by the UI modules

(defun nomadnet-hash-p (string)
  "Return non-nil if STRING looks like a destination hash."
  (and (stringp string)
       (= (length string) nomadnet-hash-length)
       (string-match-p "\\`[0-9a-fA-F]+\\'" string)))

(defun nomadnet-read-hash (prompt &optional default)
  "Read a destination hash with PROMPT, offering DEFAULT."
  (let ((value (string-trim (read-string prompt nil nil default))))
    (setq value (replace-regexp-in-string "[<> ]" "" value))
    (unless (nomadnet-hash-p value)
      (user-error "Not a valid destination hash: %s" value))
    (downcase value)))

(defun nomadnet-format-time (time &optional format)
  "Format TIME (seconds since epoch) with FORMAT."
  (if (and time (numberp time) (> time 0))
      (format-time-string (or format "%Y-%m-%d %H:%M") (seconds-to-time time))
    ""))

(defun nomadnet-format-age (time)
  "Return a compact age string for TIME."
  (if (and time (numberp time) (> time 0))
      (let ((delta (- (float-time) time)))
        (cond ((< delta 60) "now")
              ((< delta 3600) (format "%dm" (/ delta 60)))
              ((< delta 86400) (format "%dh" (/ delta 3600)))
              (t (format "%dd" (/ delta 86400)))))
    ""))

(defun nomadnet-format-size (bytes &optional bits)
  "Return BYTES as a human readable string.  With BITS use bit units."
  (if (not (numberp bytes))
      ""
    (let ((num (if bits (* bytes 8) bytes))
          (units '("" "K" "M" "G" "T"))
          (suffix (if bits "b" "B")))
      (while (and (cdr units) (>= (abs num) 1000.0))
        (setq num (/ num 1000.0)
              units (cdr units)))
      (if (string-empty-p (car units))
          (format "%.0f%s" num suffix)
        (format "%.2f%s%s" num (car units) suffix)))))

(defconst nomadnet-trust-levels
  '((0 . "warning") (1 . "untrusted") (2 . "unknown") (255 . "trusted"))
  "Mapping of nomadnet trust level numbers to names.")

(defun nomadnet-trust-name (level)
  "Return the name of trust LEVEL."
  (or (cdr (assq level nomadnet-trust-levels)) "unknown"))

(defun nomadnet-trust-face (level)
  "Return a face for trust LEVEL."
  (pcase level
    (255 'nomadnet-trusted-face)
    (0 'nomadnet-warning-face)
    (1 'nomadnet-untrusted-face)
    (_ 'default)))

(defface nomadnet-trusted-face '((t :inherit success))
  "Face for trusted peers and nodes.")
(defface nomadnet-untrusted-face '((t :inherit shadow))
  "Face for untrusted peers and nodes.")
(defface nomadnet-warning-face '((t :inherit warning))
  "Face for peers whose name collides with a trusted peer.")
(defface nomadnet-hash-face '((t :inherit font-lock-comment-face))
  "Face for destination hashes.")
(defface nomadnet-unread-face '((t :inherit bold))
  "Face for conversations with unread messages.")

(defun nomadnet-status ()
  "Return the last status plist reported by the backend, refreshing it."
  (when (nomadnet-ready-p)
    (setq nomadnet--status (nomadnet-call "status")))
  nomadnet--status)

(defun nomadnet-display-name (hash)
  "Return the best known display string for HASH (synchronous)."
  (condition-case nil
      (plist-get (nomadnet-call "peer.info" (list :hash hash) 5) :display_name)
    (error (format "<%s>" hash))))

;;;; Peer commands

;;;###autoload
(defun nomadnet-announce-now ()
  "Announce this peer's LXMF address on the network."
  (interactive)
  (nomadnet-ensure-ready)
  (nomadnet-with-result "announce" nil
    (message "Nomad Network: announced LXMF address")))

;;;###autoload
(defun nomadnet-set-display-name (name)
  "Set the display NAME announced with this peer."
  (interactive
   (progn
     (nomadnet-ensure-ready)
     (list (read-string "Display name: " (plist-get (nomadnet-status) :display_name)))))
  (nomadnet-with-result "set_display_name" (list :name name)
    (setq nomadnet--status (plist-put nomadnet--status :display_name (plist-get result :display_name)))
    (message "Display name set to %s" (plist-get result :display_name))
    (run-hooks 'nomadnet-status-changed-hook)))

;;;###autoload
(defun nomadnet-sync-messages (&optional limit)
  "Request messages from the selected propagation node.
With prefix LIMIT, download at most that many messages."
  (interactive "P")
  (nomadnet-ensure-ready)
  (nomadnet-with-result "lxmf.sync" (when limit (list :limit (prefix-numeric-value limit)))
    (message "LXMF sync: %s" (plist-get result :status))
    (nomadnet--poll-sync-status)))

(defun nomadnet--poll-sync-status ()
  "Report LXMF sync progress until it settles."
  (run-at-time 2 nil
               (lambda ()
                 (when (nomadnet-ready-p)
                   (nomadnet-with-result "lxmf.sync_status" nil
                     (let ((status (plist-get result :status)))
                       (if (plist-get result :show_percent)
                           (progn
                             (message "LXMF sync: %s %d%%" status
                                      (round (* 100 (or (plist-get result :progress) 0))))
                             (nomadnet--poll-sync-status))
                         (message "LXMF sync: %s" status))))))))

;;;###autoload
(defun nomadnet-select-propagation-node (hash)
  "Use the node with HASH as the LXMF propagation node.
An empty HASH restores automatic selection."
  (interactive
   (progn
     (nomadnet-ensure-ready)
     (list (string-trim
            (read-string "Propagation node hash (empty for automatic): "
                         (plist-get (nomadnet-call "pn.get") :selected))))))
  (when (and (not (string-empty-p hash)) (not (nomadnet-hash-p hash)))
    (user-error "Not a valid destination hash"))
  (nomadnet-with-result "pn.set" (list :hash (if (string-empty-p hash) nil hash))
    (message "Propagation node: %s" (or (plist-get result :active) "none available"))
    (run-hooks 'nomadnet-status-changed-hook)))

;;;###autoload
(defun nomadnet-log ()
  "Open the nomadnet log file."
  (interactive)
  (nomadnet-ensure-ready)
  (let ((path (plist-get (nomadnet-call "log.path") :path)))
    (find-file-read-only path)
    (goto-char (point-max))
    (auto-revert-tail-mode 1)))

(defun nomadnet-reticulum-log ()
  "Show the Reticulum log buffer."
  (interactive)
  (pop-to-buffer (get-buffer-create "*reticulum-log*")))

(provide 'nomadnet-core)

;;; nomadnet-core.el ends here
