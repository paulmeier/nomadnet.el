;;; nomadnet-micron-test.el --- Tests for the micron renderer  -*- lexical-binding: t; coding: utf-8; -*-

;;; Commentary:

;; Run with: make test

;;; Code:

(require 'ert)
(require 'nomadnet-micron)

(defun nomadnet-test--render (markup &optional width)
  "Render MARKUP at WIDTH and return the plain text."
  (substring-no-properties (nomadnet-micron-to-string markup (or width 40))))

(defun nomadnet-test--face-at (markup text)
  "Render MARKUP and return the face property of the first occurrence of TEXT."
  (let* ((rendered (nomadnet-micron-to-string markup 40))
         (pos (string-search text rendered)))
    (should pos)
    (get-text-property pos 'face rendered)))

(ert-deftest nomadnet-micron-plain-text ()
  (should (equal (nomadnet-test--render "Hello world") "Hello world\n")))

(ert-deftest nomadnet-micron-blank-lines-preserved ()
  (should (equal (nomadnet-test--render "a\n\nb") "a\n\nb\n")))

(ert-deftest nomadnet-micron-comments-are-hidden ()
  (should (equal (nomadnet-test--render "# hidden\nshown") "shown\n")))

(ert-deftest nomadnet-micron-tag-only-lines-emit-nothing ()
  (should (equal (nomadnet-test--render "`Faaa\ntext\n``") "text\n")))

(ert-deftest nomadnet-micron-bold-underline-italic ()
  (let ((face (nomadnet-test--face-at "We `!bold`! and `_under`_ and `*it`*" "bold")))
    (should (equal (plist-get face :weight) 'bold)))
  (let ((face (nomadnet-test--face-at "We `!bold`! and `_under`_ and `*it`*" "under")))
    (should (eq (plist-get face :underline) t)))
  (let ((face (nomadnet-test--face-at "We `!bold`! and `_under`_ and `*it`*" "it")))
    (should (equal (plist-get face :slant) 'italic)))
  (should (null (nomadnet-test--face-at "`!bold`! plain" "plain"))))

(ert-deftest nomadnet-micron-colors ()
  (should (equal (plist-get (nomadnet-test--face-at "`Ff00red`f none" "red") :foreground) "#ff0000"))
  (should (equal (plist-get (nomadnet-test--face-at "`B33fblue`b none" "blue") :background) "#3333ff"))
  (should (equal (plist-get (nomadnet-test--face-at "`FT1a2b3cx`f" "x") :foreground) "#1a2b3c"))
  (should (equal (plist-get (nomadnet-test--face-at "`Fg50gray`f" "gray") :foreground) "gray50"))
  (should (null (nomadnet-test--face-at "`Ff00red`f none" "none"))))

(ert-deftest nomadnet-micron-reset-tag ()
  (should (null (nomadnet-test--face-at "`!`Ff00x`` plain" "plain"))))

(ert-deftest nomadnet-micron-escapes ()
  (should (equal (nomadnet-test--render "a \\`! b") "a `! b\n"))
  (should (equal (nomadnet-test--render "\\>not a heading") ">not a heading\n"))
  (should (equal (nomadnet-test--render "back\\\\slash") "back\\slash\n")))

(ert-deftest nomadnet-micron-headings-and-sections ()
  (let ((out (nomadnet-test--render ">Title\ntext\n>>Sub\nmore\n<top" 20)))
    (should (string-prefix-p "Title" out))
    (should (string-search "\ntext\n" out))
    (should (string-search "\n  Sub" out))
    (should (string-search "\n  more\n" out))
    (should (string-search "\ntop\n" out)))
  (should (eq (plist-get (nomadnet-test--face-at ">Title" "Title") :inherit) 'nomadnet-micron-heading-1))
  (should (eq (plist-get (nomadnet-test--face-at ">>Title" "Title") :inherit) 'nomadnet-micron-heading-2))
  (should (eq (plist-get (nomadnet-test--face-at ">>>>Title" "Title") :inherit) 'nomadnet-micron-heading-3)))

(ert-deftest nomadnet-micron-heading-without-text-indents ()
  (should (equal (nomadnet-test--render ">>\nindented" 20) "  indented\n")))

(ert-deftest nomadnet-micron-alignment ()
  (should (equal (nomadnet-test--render "`cab" 10) "    ab\n"))
  (should (equal (nomadnet-test--render "`rab" 10) "        ab\n"))
  (should (equal (nomadnet-test--render "`rab\n`ac" 10) "        ab\nc\n")))

(ert-deftest nomadnet-micron-dividers ()
  (should (equal (nomadnet-test--render "-" 5) "─────\n"))
  (should (equal (nomadnet-test--render "-=" 5) "=====\n"))
  (should (equal (nomadnet-test--render ">>\n-" 6) "  ──\n")))

(ert-deftest nomadnet-micron-literal-blocks ()
  (should (equal (nomadnet-test--render "`=\n`!not bold`!\n\\`=\n`=\nafter")
                 "`!not bold`!\n`=\nafter\n")))

(ert-deftest nomadnet-micron-links ()
  (let* ((rendered (nomadnet-micron-to-string "see `[the page`abcdef0123456789abcdef0123456789:/page/x.mu`a|b=1] now" 60))
         (pos (string-search "the page" rendered))
         (link (get-text-property pos 'nomadnet-link rendered)))
    (should (equal (substring-no-properties rendered) "see the page now\n"))
    (should (equal (plist-get link :url) "abcdef0123456789abcdef0123456789:/page/x.mu"))
    (should (equal (plist-get link :fields) '("a" "b=1")))
    (should (get-text-property pos 'button rendered)))
  (should (equal (nomadnet-test--render "`[1234:/page/x.mu]" 60) "1234:/page/x.mu\n")))

(ert-deftest nomadnet-micron-fields ()
  (with-temp-buffer
    (let ((nomadnet-micron-width 80))
      (nomadnet-micron-render "Name: `<8|user`bob>\nPw: `<!|pw`secret>\n`<?|opt|1|*`>` Yes\n`<^|color|red`> Red\n`<^|color|blue|*`> Blue" nil nil t))
    (should (equal (substring-no-properties (buffer-string))
                   "Name: bob     \nPw: ******                  \n[X] Yes\n( )  Red\n(X)  Blue\n"))
    (should (equal (nomadnet-micron-collect-fields nil t)
                   '(("field_user" . "bob") ("field_pw" . "secret")
                     ("field_opt" . "1") ("field_color" . "blue"))))
    (should (equal (nomadnet-micron-collect-fields '("user") nil)
                   '(("field_user" . "bob"))))))

(ert-deftest nomadnet-micron-field-toggle ()
  (with-temp-buffer
    (let ((nomadnet-micron-width 80))
      (nomadnet-micron-render "`<^|c|a`> A `<^|c|b|*`> B\n`<?|k|1`> K" nil nil t))
    (goto-char (point-min))
    (push-button)
    (should (equal (nomadnet-micron-collect-fields nil t) '(("field_c" . "a"))))
    (forward-button 2)
    (push-button)
    (should (equal (nomadnet-micron-collect-fields nil t) '(("field_c" . "a") ("field_k" . "1"))))))

(ert-deftest nomadnet-micron-anchors ()
  (with-temp-buffer
    (let ((nomadnet-micron-width 80))
      (nomadnet-micron-render "intro\n>Hello World\ntext\n`:mark\nmarked line\n>>Second" nil nil t))
    (should (assoc "hello-world" nomadnet-micron--anchors))
    (should (assoc "mark" nomadnet-micron--anchors))
    (should (assoc "second" nomadnet-micron--anchors))
    (goto-char (cdr (assoc "mark" nomadnet-micron--anchors)))
    (should (looking-at "marked line"))
    (should (= (length nomadnet-micron--headers) 2))))

(ert-deftest nomadnet-micron-tables ()
  (let ((out (nomadnet-test--render "`t\n| Name | Qty |\n| ---- | --: |\n| Apple | 5 |\n| Kiwi | 12 |\n`t" 60)))
    (should (equal out
                   (concat "┌───────┬─────┐\n"
                           "│ Name  │ Qty │\n"
                           "├───────┼─────┤\n"
                           "│ Apple │   5 │\n"
                           "│ Kiwi  │  12 │\n"
                           "└───────┴─────┘\n")))))

(ert-deftest nomadnet-micron-table-with-markup ()
  (let ((out (nomadnet-test--render "`t\n| A | B |\n| - | - |\n| `F3a3x`f | `!y`! |\n`t" 60)))
    (should (string-search "│ x   │ y   │" out))))

(ert-deftest nomadnet-micron-partials ()
  (with-temp-buffer
    (let ((nomadnet-micron-width 80)
          result)
      (setq result (nomadnet-micron-render "`{abcdef0123456789abcdef0123456789:/page/p.mu`10`pid=7|name}" nil nil t))
      (should (equal (substring-no-properties (buffer-string)) "⧖\n"))
      (let ((partial (overlay-get (car (plist-get result :partials)) 'nomadnet-partial)))
        (should (equal (plist-get partial :url) "abcdef0123456789abcdef0123456789:/page/p.mu"))
        (should (equal (plist-get partial :refresh) 10))
        (should (equal (plist-get partial :id) "7"))
        (should (equal (plist-get partial :fields) '("pid=7" "name")))))))

(ert-deftest nomadnet-micron-page-colors ()
  (should (equal (nomadnet-micron-page-colors "#!c=0\n#!bg=222\n#!fg=ddd\ntext") '("ddd" . "222")))
  (should (equal (nomadnet-micron-page-colors "text") '(nil . nil))))

(ert-deftest nomadnet-micron-slugify ()
  (should (equal (nomadnet-micron-slugify "Hello World") "hello-world"))
  (should (equal (nomadnet-micron-slugify "Introduction & Setup") "introduction-setup"))
  (should (equal (nomadnet-micron-slugify "`!Bold`! Title") "bold-title")))

(ert-deftest nomadnet-micron-heading-with-field-loses-heading ()
  (should (equal (nomadnet-test--render ">`<4|f`ab>" 40) "ab  \n")))

(provide 'nomadnet-micron-test)

;;; nomadnet-micron-test.el ends here
