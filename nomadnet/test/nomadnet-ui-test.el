;;; nomadnet-ui-test.el --- Tests for the nomadnet.el user interface  -*- lexical-binding: t; coding: utf-8; -*-

;;; Commentary:

;; Tests of the UI modules that do not need a running backend: dashboard
;; formatting, announce stream search, conversation navigation, browser
;; page colours and error handling.  Run with: make test

;;; Code:

(require 'ert)
(require 'nomadnet)
(require 'nomadnet-native)

;;;; Dashboard

(ert-deftest nomadnet-ui-dashboard-interface-line-bytes ()
  (let ((line (substring-no-properties
               (nomadnet--dashboard-interface-line
                '(:name "TCP to hub" :online t :rx 10 :tx 4 :rxbytes 1500 :txbytes 200)))))
    (should (string-search "TCP to hub" line))
    (should (string-search "online" line))
    (should (string-search "↓1.50KB" line))
    (should (string-search "↑200B" line))))

(ert-deftest nomadnet-ui-dashboard-interface-line-offline-packets ()
  (let ((line (substring-no-properties
               (nomadnet--dashboard-interface-line '(:name "Down" :online nil :rx 3 :tx 0)))))
    (should (string-search "offline" line))
    (should (string-search "↓3 pkts" line))
    (should (string-search "↑0 pkts" line))))

(ert-deftest nomadnet-ui-dashboard-interfaces-section ()
  (with-temp-buffer
    (nomadnet--dashboard-insert-interfaces
     '((:name "A" :online t :rx 0 :tx 0) (:name "B" :online nil :rx 0 :tx 0)))
    (should (string-search "Interfaces     : 1 online of 2" (buffer-string)))
    (should (string-search "A" (buffer-string)))
    (should (string-search "B" (buffer-string))))
  (with-temp-buffer
    (nomadnet--dashboard-insert-interfaces nil)
    (should (string-search "none configured" (buffer-string)))))

(ert-deftest nomadnet-ui-dashboard-status-shows-interfaces ()
  "The dashboard renders the :interfaces of the status like nomadnet's section."
  (cl-letf (((symbol-function 'nomadnet-running-p) (lambda () t))
            ((symbol-function 'nomadnet-ready-p) (lambda () t))
            ((symbol-function 'nomadnet-status)
             (lambda () '(:display_name "Me" :lxmf_address "aa" :identity "bb"
                          :propagation_node nil :node_enabled nil
                          :version "v" :rns_version "r" :lxmf_version "l" :configdir "/c"
                          :interfaces ((:name "Hub" :online t :rx 1 :tx 2 :rxbytes 10 :txbytes 20)))))
            ((symbol-function 'nomadnet-call) (lambda (&rest _) nil)))
    (unwind-protect
        (progn
          (with-current-buffer (get-buffer-create "*NomadNet*")
            (nomadnet-dashboard-mode))
          (nomadnet-dashboard-refresh)
          (with-current-buffer "*NomadNet*"
            (should (string-search "Interfaces     : 1 online of 1" (buffer-string)))
            (should (string-search "Hub" (buffer-string)))))
      (kill-buffer "*NomadNet*"))))

;;;; Announce stream search

(ert-deftest nomadnet-ui-announces-match ()
  (let ((announce '(:name "Hub Node" :hash "abb3ebcd03cb2388a838e70c001291f9" :kind "node")))
    (should (nomadnet-announces--match-p announce nil))
    (should (nomadnet-announces--match-p announce ""))
    (should (nomadnet-announces--match-p announce "hub"))
    (should (nomadnet-announces--match-p announce "NODE"))
    (should (nomadnet-announces--match-p announce "abb3eb"))
    (should-not (nomadnet-announces--match-p announce "other"))
    ;; Regexp characters in the search are literal.
    (should-not (nomadnet-announces--match-p announce "h.b"))))

(ert-deftest nomadnet-ui-announces-match-without-name ()
  (let ((announce '(:name nil :hash "abb3ebcd03cb2388a838e70c001291f9" :kind "pn")))
    (should (nomadnet-announces--match-p announce "abb3"))
    (should-not (nomadnet-announces--match-p announce "hub"))))

(ert-deftest nomadnet-ui-announces-search-filters-list ()
  (cl-letf (((symbol-function 'nomadnet-ready-p) (lambda () t))
            ((symbol-function 'nomadnet-request)
             (lambda (_method _params callback)
               (funcall callback
                        '((:time 1 :hash "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" :kind "node" :name "Alpha")
                          (:time 2 :hash "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" :kind "peer" :name "Beta"))
                        nil))))
    (with-current-buffer (get-buffer-create nomadnet-announces-buffer-name)
      (unwind-protect
          (progn
            (nomadnet-announces-mode)
            (nomadnet-announces-search "beta")
            (should (= (length tabulated-list-entries) 1))
            (should (string-search "Beta" (buffer-string)))
            (should-not (string-search "Alpha" (buffer-string)))
            (should (string-search "/beta" (nomadnet-announces--mode-line)))
            (nomadnet-announces-search "  ")
            (should (null nomadnet-announces--search))
            (should (= (length tabulated-list-entries) 2)))
        (kill-buffer (current-buffer))))))

;;;; Conversation navigation

(defun nomadnet-ui-test--conversation-buffer ()
  "Return a conversation buffer with three rendered messages."
  (let ((buffer (generate-new-buffer "*test conversation*")))
    (with-current-buffer buffer
      (nomadnet-conversation-mode)
      (setq nomadnet-conversation--hash "cccccccccccccccccccccccccccccccc"
            nomadnet-conversation--name "Peer")
      (nomadnet-conversation--render
       (list :display_name "Peer" :trust_level 2 :known t
             :messages (list (list :timestamp 1 :outgoing nil :content "first message")
                             (list :timestamp 2 :outgoing t :state "delivered" :content "second\nspans lines")
                             (list :timestamp 3 :outgoing nil :content "third")))))
    buffer))

(ert-deftest nomadnet-ui-conversation-wraps-with-visual-line-mode ()
  (with-current-buffer (nomadnet-ui-test--conversation-buffer)
    (unwind-protect
        (progn (should visual-line-mode)
               (should word-wrap))
      (kill-buffer (current-buffer)))))

(ert-deftest nomadnet-ui-conversation-next-previous-message ()
  (with-current-buffer (nomadnet-ui-test--conversation-buffer)
    (unwind-protect
        (let ((starts (nomadnet-conversation--message-starts)))
          (should (= (length starts) 3))
          (goto-char (point-min))
          (should (= (point) (nth 0 starts)))
          (nomadnet-conversation-next-message)
          (should (= (point) (nth 1 starts)))
          (nomadnet-conversation-next-message)
          (should (= (point) (nth 2 starts)))
          ;; At the last message: stay put.
          (nomadnet-conversation-next-message)
          (should (= (point) (nth 2 starts)))
          ;; From inside a message, previous goes to its start first.
          (goto-char (+ (nth 1 starts) 5))
          (nomadnet-conversation-previous-message)
          (should (= (point) (nth 1 starts)))
          (nomadnet-conversation-previous-message)
          (should (= (point) (nth 0 starts)))
          (nomadnet-conversation-previous-message)
          (should (= (point) (nth 0 starts))))
      (kill-buffer (current-buffer)))))

(ert-deftest nomadnet-ui-conversation-evil-bindings-include-navigation ()
  "The evil integration binds n and p to message navigation."
  (with-temp-buffer
    (insert-file-contents (locate-library "nomadnet-conversations.el"))
    (goto-char (point-min))
    (should (search-forward "(\"n\" . nomadnet-conversation-next-message)" nil t))
    (goto-char (point-min))
    (should (search-forward "(\"p\" . nomadnet-conversation-previous-message)" nil t))))

;;;; Browser

(defun nomadnet-ui-test--browser-buffer ()
  "Return a fresh browser buffer."
  (let ((buffer (generate-new-buffer "*test browser*")))
    (with-current-buffer buffer (nomadnet-browser-mode))
    buffer))

(defun nomadnet-ui-test--remapped (face attribute)
  "Return the value ATTRIBUTE is remapped to for FACE in the current buffer."
  (let ((entry (assq face face-remapping-alist)) (value nil))
    (dolist (spec (cdr entry))
      (when (and (listp spec) (plist-member spec attribute))
        (setq value (plist-get spec attribute))))
    value))

(ert-deftest nomadnet-ui-browser-page-colors-cover-buffer ()
  (with-current-buffer (nomadnet-ui-test--browser-buffer)
    (unwind-protect
        (progn
          (setq nomadnet-browser--markup "#!bg=222\n#!fg=ddd\nHello")
          (nomadnet-browser--render)
          (should (equal (nomadnet-ui-test--remapped 'default :background) "#222222"))
          (should (equal (nomadnet-ui-test--remapped 'default :foreground) "#dddddd"))
          (should (equal (nomadnet-ui-test--remapped 'fringe :background) "#222222"))
          ;; A page without colours restores the theme.
          (setq nomadnet-browser--markup "Plain")
          (nomadnet-browser--render)
          (should (null nomadnet-browser--color-cookies))
          (should (null (nomadnet-ui-test--remapped 'default :background)))
          ;; A page with only a background leaves the foreground alone.
          (setq nomadnet-browser--markup "#!bg=000\nDark")
          (nomadnet-browser--render)
          (should (equal (nomadnet-ui-test--remapped 'default :background) "#000000"))
          (should (null (nomadnet-ui-test--remapped 'default :foreground)))
          (nomadnet-browser--show-message "Disconnected")
          (should (null nomadnet-browser--color-cookies)))
      (kill-buffer (current-buffer)))))

(ert-deftest nomadnet-ui-browser-request-too-large-message ()
  (let ((text (nomadnet-native-request-too-large-message 900 431)))
    (should (string-prefix-p nomadnet-request-too-large-prefix text))
    (should (string-search "900 bytes" text))
    (should (string-search "431" text))
    (should (string-search "#5" text))
    (should (nomadnet-browser--keep-page-on-error-p text))
    (should-not (nomadnet-browser--keep-page-on-error-p "Request failed"))
    (should-not (nomadnet-browser--keep-page-on-error-p nil))))

(ert-deftest nomadnet-ui-browser-too-large-keeps-page ()
  "An oversized submission leaves the page and its fields in place."
  (with-current-buffer (nomadnet-ui-test--browser-buffer)
    (unwind-protect
        (progn
          (setq nomadnet-browser--markup "Form `<name`old value>"
                nomadnet-browser--destination "abb3ebcd03cb2388a838e70c001291f9"
                nomadnet-browser--path "/page/form.mu")
          (nomadnet-browser--render)
          (let ((before (buffer-string)))
            (nomadnet-browser--load-failed "abb3ebcd03cb2388a838e70c001291f9" "/page/form.mu"
                                           (nomadnet-native-request-too-large-message 900 431))
            (should (equal (buffer-string) before))
            (should (equal (cdr (assoc "field_name" (nomadnet-micron-collect-fields nil t))) "old value"))
            (should (string-prefix-p "Failed: Request too large" nomadnet-browser--status))
            ;; Other failures replace the page with the error view.
            (nomadnet-browser--load-failed "abb3ebcd03cb2388a838e70c001291f9" "/page/form.mu" "Request failed")
            (should (string-search "Could not load" (buffer-string)))
            (should (null nomadnet-browser--markup))))
      (kill-buffer (current-buffer)))))

(ert-deftest nomadnet-ui-link-request-signals-too-large ()
  "The library signals a dedicated error for requests beyond the link MDU."
  (let ((link (reticulum-link--make :status 'active :mtu 500 :rtt 0.1)))
    (reticulum-link--update-mdu link)
    (should (> (reticulum-link-mdu link) 0))
    (let ((data (make-hash-table :test #'equal)))
      (puthash (reticulum-msgpack-str "field_text") (reticulum-msgpack-str (make-string 2000 ?x)) data)
      (should-error (reticulum-link-request link "/page/x.mu" data)
                    :type 'reticulum-request-too-large))))

;;;; Known nodes

(ert-deftest nomadnet-ui-known-nodes-entry-shows-notes ()
  (let ((entry (nomadnet-known-nodes--entry
                '(:hash "abb3ebcd03cb2388a838e70c001291f9" :display_name "Hub" :trust_level 255
                  :hops 1 :sort_rank nil :identify nil :notes "line one\nline two"))))
    (should (equal (substring-no-properties (aref (cadr entry) 6)) "line one line two"))))

(ert-deftest nomadnet-ui-known-nodes-edit-notes-saves ()
  (let ((sent nil))
    (cl-letf (((symbol-function 'nomadnet-known-nodes--hash-at-point)
               (lambda () "abb3ebcd03cb2388a838e70c001291f9"))
              ((symbol-function 'nomadnet-request)
               (lambda (method params callback)
                 (setq sent (cons method params))
                 (funcall callback '(:display_name "Hub") nil)))
              ((symbol-function 'nomadnet-known-nodes-refresh) #'ignore))
      (nomadnet-known-nodes-edit-notes "remember this")
      (should (equal (car sent) "directory.remember"))
      (should (equal (plist-get (cdr sent) :notes) "remember this"))
      (should (equal (plist-get (cdr sent) :hash) "abb3ebcd03cb2388a838e70c001291f9")))))

(provide 'nomadnet-ui-test)

;;; nomadnet-ui-test.el ends here
