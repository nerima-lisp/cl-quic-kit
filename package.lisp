(defpackage #:cl-quic-kit
  (:use #:cl)
  (:shadow #:stream)
  (:export
   #:*quic-version-1*
   #:connection-id-p
   #:validate-connection-id
   #:crypto-available-p
   #:require-crypto
   #:invalid-connection-id
   #:crypto-unavailable
   #:quic-error
   #:quic-encoding-error
   #:quic-crypto-error
   #:encode-varint
   #:decode-varint
   #:varint-length
   #:varint-p
   #:octets-copy
   #:ensure-octets
   #:packet-header
   #:make-packet-header
   #:packet-header-p #:packet-header-type #:packet-header-version
   #:packet-header-destination-connection-id #:packet-header-source-connection-id
   #:packet-header-token #:packet-header-packet-number #:packet-header-packet-number-length
   #:packet-header-payload #:packet-header-payload-length #:packet-header-long-p
   #:packet-header-key-phase #:packet-header-reserved-bits #:packet-header-retry-integrity-tag
   #:encode-packet-header
   #:decode-packet-header
   #:retry-integrity-tag
   #:verify-retry-integrity
   #:encode-version-negotiation #:decode-version-negotiation
   #:encode-transport-parameters #:decode-transport-parameters
   #:frame #:make-frame #:frame-type #:frame-fields #:frame-field
   #:encode-frame #:decode-frame #:encode-frames #:decode-frames
   #:flow-control-state #:make-flow-control-state
   #:flow-control-connection-max-data #:flow-control-connection-sent
   #:flow-control-connection-received #:flow-control-connection-receive-limit
   #:flow-control-max-streams-bidi #:flow-control-max-streams-uni
   #:flow-control-stream-count
   #:flow-control-open-stream #:flow-control-close-stream
   #:flow-control-can-send-p #:flow-control-reserve-send
   #:flow-control-note-received #:flow-control-update-max-data
   #:flow-control-update-max-receive-data
   #:flow-control-update-max-streams #:flow-control-data-blocked-p
   #:flow-control-streams-blocked-p #:flow-control-error
   #:flow-control-limit-error #:stream-id-error
   #:flow-control-error-limit #:flow-control-error-attempted
   #:flow-control-mark-data-blocked #:flow-control-mark-streams-blocked
   #:stream #:make-stream #:stream-id #:stream-direction #:stream-initiator
   #:stream-local-p #:stream-write #:stream-finish #:stream-read
   #:stream-receive-data #:stream-reset-send #:stream-stop-sending
   #:stream-reset-receive #:stream-stop-sending-receive
   #:stream-send-offset #:stream-receive-offset #:stream-read-offset
   #:stream-readable-bytes #:stream-set-max-send-offset
   #:stream-set-max-receive-offset
   #:stream-finished-p #:stream-reset-p #:stream-stopped-p
   #:stream-pending-events #:stream-next-event
   #:quic-connection #:make-quic-connection #:connection-touch
   #:connection-state
   #:connection-id-known-p #:connection-add-connection-id
   #:connection-retire-connection-id #:connection-idle-expired-p
   #:connection-close #:connection-check-idle-timeout #:connection-set-state
   #:connection-tls-feed #:connection-tls-poll #:connection-closed
   #:connection-close-error-code #:connection-close-reason
   #:connection-active-connection-id-limit
   #:connection-local-connection-ids #:connection-remote-connection-ids
   #:connection-active-local-id #:connection-close-frame
   #:connection-close-kind #:connection-draining-deadline
   #:connection-handle-new-connection-id #:connection-handle-retire-connection-id
   #:connection-receive-frame #:connection-receive-packet
   #:connection-read #:connection-write #:connection-poll
   #:udp-socket #:make-udp-socket #:udp-socket-local-port
   #:udp-send #:udp-receive #:udp-close
   #:quic-client #:make-quic-client #:client-open-stream
   #:client-write-stream #:client-read-stream #:client-close-stream
   #:client-flush #:client-receive-frame #:client-receive-datagram
   #:make-client-tls-boundary #:client-tls-feed #:client-poll #:client-close
   #:quic-client-connection #:quic-client-udp-socket
   #:quic-client-tls-boundary #:quic-client-tls-secrets
   #:quic-client-peer-transport-parameters))

(in-package #:cl-quic-kit)

(defparameter *quic-version-1* #x00000001
  "The version number assigned to QUIC v1 by RFC 9000.")

(define-condition invalid-connection-id (error)
  ((value :initarg :value :reader invalid-connection-id-value))
  (:report (lambda (condition stream)
            (format stream "Not a valid QUIC connection ID: ~S"
                    (invalid-connection-id-value condition)))))

(define-condition crypto-unavailable (error)
  ((operation :initarg :operation :reader crypto-unavailable-operation))
  (:report (lambda (condition stream)
            (format stream "QUIC crypto operation ~A is unavailable; load cl-crypto-kit"
                    (crypto-unavailable-operation condition)))))

(defun connection-id-p (value)
  "Return true when VALUE is a QUIC connection ID octet vector.

RFC 9000 permits connection IDs from zero through twenty octets."
  (and (typep value '(simple-array (unsigned-byte 8) (*)))
       (<= 0 (length value) 20)))

(defun validate-connection-id (value)
  "Return VALUE, or signal INVALID-CONNECTION-ID when VALUE is malformed."
  (unless (connection-id-p value)
    (error 'invalid-connection-id :value value))
  value)

(defun crypto-available-p ()
  "Report whether the cl-crypto-kit implementation package is loaded."
  (not (null (find-package "CRYPTO-KIT"))))

(defun require-crypto (operation)
  "Return the requested cl-crypto-kit function or signal a boundary error."
  (unless (crypto-available-p)
    (error 'crypto-unavailable :operation operation))
  (let* ((name (etypecase operation
                 (symbol (symbol-name operation))
                 (string operation)))
         (symbol (find-symbol name "CRYPTO-KIT")))
    (if (and symbol (fboundp symbol))
        (symbol-function symbol)
        (error 'crypto-unavailable :operation operation))))
