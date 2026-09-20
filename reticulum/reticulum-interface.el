;;; reticulum-interface.el --- Network interfaces for Reticulum  -*- lexical-binding: t; coding: utf-8; -*-

;; Copyright (C) 2026 Paul Meier

;; This file is part of reticulum.el and is released under the Reticulum
;; License (an MIT-style license with two use conditions).  See the LICENSE
;; file distributed with reticulum.el for the full terms.  In short: you may
;; use, copy, modify and distribute this software freely, provided it is not
;; used in systems built to harm human beings, nor for training artificial
;; intelligence, machine learning or language models.

;;; Commentary:

;; TCP client interfaces with HDLC framing, as used by RNS's
;; TCPClientInterface and by the local shared instance interface of a
;; running rnsd (TCP port 37428).  Received frames are handed to
;; `reticulum-interface-receive-function'.

;;; Code:

(require 'cl-lib)
(require 'reticulum-bytes)

(defconst reticulum-hdlc-flag #x7e)
(defconst reticulum-hdlc-esc #x7d)
(defconst reticulum-hdlc-esc-mask #x20)

(defvar reticulum-interface-receive-function nil
  "Function called with (RAW INTERFACE) for every frame received.")

(defvar reticulum-interfaces nil "List of active interfaces.")

(cl-defstruct (reticulum-interface (:constructor reticulum-interface--make)
                                   (:copier nil))
  name host port process
  (buffer "")
  (online nil)
  (kind 'tcp)
  (hw-mtu 1064)
  (bitrate 10000000)
  reconnect-timer (failures 0)
  (rx 0) (tx 0) (rxbytes 0) (txbytes 0)
  connected-at)

(defun reticulum-hdlc-escape (data)
  "Escape DATA for HDLC framing."
  (let ((out nil))
    (cl-loop for b across data do
             (cond ((= b reticulum-hdlc-esc)
                    (push reticulum-hdlc-esc out) (push (logxor b reticulum-hdlc-esc-mask) out))
                   ((= b reticulum-hdlc-flag)
                    (push reticulum-hdlc-esc out) (push (logxor b reticulum-hdlc-esc-mask) out))
                   (t (push b out))))
    (apply #'unibyte-string (nreverse out))))

(defun reticulum-hdlc-unescape (frame)
  "Remove HDLC escaping from FRAME."
  (let ((out nil) (escape nil))
    (cl-loop for b across frame do
             (cond (escape (push (logxor b reticulum-hdlc-esc-mask) out) (setq escape nil))
                   ((= b reticulum-hdlc-esc) (setq escape t))
                   (t (push b out))))
    (apply #'unibyte-string (nreverse out))))

(defun reticulum-hdlc-frame (data)
  "Wrap DATA in an HDLC frame."
  (concat (unibyte-string reticulum-hdlc-flag)
          (reticulum-hdlc-escape data)
          (unibyte-string reticulum-hdlc-flag)))

(defun reticulum-interface--filter (interface string)
  "Accumulate STRING received on INTERFACE and dispatch complete frames."
  (setf (reticulum-interface-buffer interface)
        (concat (reticulum-interface-buffer interface) (string-to-unibyte string)))
  (let ((buffer (reticulum-interface-buffer interface))
        (flag (unibyte-string reticulum-hdlc-flag))
        (continue t))
    (while continue
      (let ((start (string-search flag buffer)))
        (if (null start)
            (setq buffer "" continue nil)
          (let ((end (string-search flag buffer (1+ start))))
            (if (null end)
                (progn
                  (when (> (length buffer) (* 2 (reticulum-interface-hw-mtu interface)))
                    (setq buffer ""))
                  (setq buffer (substring buffer start))
                  (setq continue nil))
              (let ((frame (reticulum-hdlc-unescape (substring buffer (1+ start) end))))
                (setq buffer (substring buffer end))
                (when (and (> (length frame) 18)
                           (<= (length frame) (reticulum-interface-hw-mtu interface)))
                  (cl-incf (reticulum-interface-rx interface))
                  (cl-incf (reticulum-interface-rxbytes interface) (length frame))
                  (when reticulum-interface-receive-function
                    (condition-case err
                        (funcall reticulum-interface-receive-function frame interface)
                      (error (reticulum-log 1 "error handling frame on %s: %s"
                                            (reticulum-interface-name interface)
                                            (error-message-string err))))))))))))
    (setf (reticulum-interface-buffer interface) buffer)))

(defun reticulum-interface-send (interface raw)
  "Transmit RAW bytes on INTERFACE."
  (let ((process (reticulum-interface-process interface)))
    (when (and process (process-live-p process))
      (process-send-string process (reticulum-hdlc-frame raw))
      (cl-incf (reticulum-interface-tx interface))
      (cl-incf (reticulum-interface-txbytes interface) (length raw))
      t)))

(defun reticulum-interface--reconnect-delay (interface)
  "Return seconds to wait before reconnecting INTERFACE, with backoff."
  (min 300 (* 10 (expt 2 (min 5 (reticulum-interface-failures interface))))))

(defun reticulum-interface--sentinel (interface process event)
  "Handle connection state EVENT of PROCESS for INTERFACE."
  (cond
   ((string-prefix-p "open" event)
    (setf (reticulum-interface-online interface) t
          (reticulum-interface-failures interface) 0
          (reticulum-interface-connected-at interface) (float-time))
    (reticulum-log 4 "%s connected" (reticulum-interface-name interface)))
   ((not (process-live-p process))
    (let ((was-online (reticulum-interface-online interface)))
      (setf (reticulum-interface-online interface) nil)
      (when (memq interface reticulum-interfaces)
        (let ((delay (reticulum-interface--reconnect-delay interface)))
          (cl-incf (reticulum-interface-failures interface))
          (reticulum-log (if was-online 3 5) "%s %s (%s), retrying in %ds"
                         (reticulum-interface-name interface)
                         (if was-online "disconnected" "unreachable")
                         (string-trim event) delay)
          (setf (reticulum-interface-reconnect-timer interface)
                (run-at-time delay nil #'reticulum-interface-connect interface))))))))

(defun reticulum-interface-connect (interface)
  "Open the TCP connection of INTERFACE."
  (when (reticulum-interface-reconnect-timer interface)
    (cancel-timer (reticulum-interface-reconnect-timer interface))
    (setf (reticulum-interface-reconnect-timer interface) nil))
  (condition-case err
      (let ((process (make-network-process
                      :name (format "reticulum-%s" (reticulum-interface-name interface))
                      :buffer nil
                      :host (reticulum-interface-host interface)
                      :service (reticulum-interface-port interface)
                      :coding 'binary
                      :nowait t
                      :noquery t
                      :filter (lambda (_proc string) (reticulum-interface--filter interface string))
                      :sentinel (lambda (proc event) (reticulum-interface--sentinel interface proc event)))))
        (set-process-query-on-exit-flag process nil)
        (setf (reticulum-interface-process interface) process
              (reticulum-interface-buffer interface) "")
        process)
    (error
     (let ((delay (reticulum-interface--reconnect-delay interface)))
       (cl-incf (reticulum-interface-failures interface))
       (reticulum-log 5 "could not connect %s: %s, retrying in %ds" (reticulum-interface-name interface)
                      (error-message-string err) delay)
       (setf (reticulum-interface-reconnect-timer interface)
             (run-at-time delay nil #'reticulum-interface-connect interface)))
     nil)))

(defun reticulum-interface-add-tcp (name host port)
  "Create, register and connect a TCP client interface NAME to HOST:PORT."
  (let ((interface (reticulum-interface--make :name name :host host :port port :kind 'tcp)))
    (push interface reticulum-interfaces)
    (reticulum-interface-connect interface)
    interface))

(defun reticulum-interface-add-local (&optional port)
  "Connect to the shared instance of a running rnsd on PORT (default 37428)."
  (let ((interface (reticulum-interface--make :name "local-instance" :host "127.0.0.1"
                                              :port (or port 37428) :kind 'local
                                              :hw-mtu 262144 :bitrate 1000000000)))
    (push interface reticulum-interfaces)
    (reticulum-interface-connect interface)
    interface))

(defun reticulum-interface-remove (interface)
  "Disconnect and forget INTERFACE."
  (setq reticulum-interfaces (delq interface reticulum-interfaces))
  (when (reticulum-interface-reconnect-timer interface)
    (cancel-timer (reticulum-interface-reconnect-timer interface)))
  (let ((process (reticulum-interface-process interface)))
    (when (and process (process-live-p process))
      (delete-process process)))
  (setf (reticulum-interface-online interface) nil))

(defun reticulum-interface-remove-all ()
  "Disconnect every interface."
  (dolist (interface (copy-sequence reticulum-interfaces))
    (reticulum-interface-remove interface)))

(provide 'reticulum-interface)

;;; reticulum-interface.el ends here
