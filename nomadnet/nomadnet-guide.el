;;; nomadnet-guide.el --- The Nomad Network guide in Emacs  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;;; Commentary:

;; Renders the guide topics shipped with nomadnet (written in micron) using
;; the Emacs micron renderer.

;;; Code:

(require 'nomadnet-core)
(require 'nomadnet-micron)

(declare-function nomadnet-browser-handle-link "nomadnet-browser" (url fields))

(defvar nomadnet-guide-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map special-mode-map)
    (define-key map (kbd "TAB") #'forward-button)
    (define-key map (kbd "<backtab>") #'backward-button)
    (define-key map (kbd "n") #'forward-button)
    (define-key map (kbd "p") #'backward-button)
    (define-key map (kbd "t") #'nomadnet-guide)
    map)
  "Keymap for `nomadnet-guide-mode'.")

(nomadnet-evil-integrate 'nomadnet-guide-mode nomadnet-guide-mode-map
 '(("TAB" . forward-button) ("<backtab>" . backward-button) ("n" . forward-button)
   ("p" . backward-button) ("t" . nomadnet-guide) ("q" . quit-window)))

(define-derived-mode nomadnet-guide-mode special-mode "NomadNet-Guide"
  "Major mode for reading the Nomad Network guide."
  (setq buffer-read-only t
        truncate-lines nil
        word-wrap t)
  (setq-local nomadnet-micron-link-function #'nomadnet-browser-handle-link))

(defvar nomadnet-guide--topics nil "Cached list of guide topic names.")

(defun nomadnet-guide-topics ()
  "Return the list of guide topic names."
  (or nomadnet-guide--topics
      (setq nomadnet-guide--topics (nomadnet-call "guide.topics"))))

;;;###autoload
(defun nomadnet-guide (topic)
  "Show guide TOPIC."
  (interactive
   (progn
     (nomadnet-ensure-ready)
     (list (completing-read "Guide topic: " (nomadnet-guide-topics) nil t))))
  (nomadnet-ensure-ready)
  (let ((buffer (get-buffer-create (format "*NomadNet Guide: %s*" topic))))
    (nomadnet-with-result "guide.get" (list :topic topic)
      (when (buffer-live-p buffer)
        (with-current-buffer buffer
          (unless (derived-mode-p 'nomadnet-guide-mode)
            (nomadnet-guide-mode))
          (let ((inhibit-read-only t)
                (markup (plist-get result :markup)))
            (erase-buffer)
            (pcase-let ((`(,fg . ,bg) (nomadnet-micron-page-colors markup)))
              (nomadnet-micron-render markup fg bg t))
            (goto-char (point-min))))
        (nomadnet-show-buffer buffer)))))

(provide 'nomadnet-guide)

;;; nomadnet-guide.el ends here
