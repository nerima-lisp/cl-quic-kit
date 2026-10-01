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
   #:encode-packet-header
   #:decode-packet-header
   #:retry-integrity-tag
   #:verify-retry-integrity
   #:frame #:make-frame #:frame-type #:frame-fields #:frame-field
   #:encode-frame #:decode-frame #:encode-frames #:decode-frames
   #:flow-control-state #:make-flow-control-state
   #:flow-control-open-stream #:flow-control-close-stream
   #:flow-control-can-send-p #:flow-control-reserve-send
   #:flow-control-note-received #:flow-control-update-max-data
   #:flow-control-update-max-streams #:flow-control-data-blocked-p
   #:flow-control-streams-blocked-p #:flow-control-error
   #:flow-control-limit-error #:stream-id-error
   #:stream #:make-stream #:stream-id #:stream-direction #:stream-initiator
   #:stream-local-p #:stream-write #:stream-finish #:stream-read
   #:stream-receive-data #:stream-reset-send #:stream-stop-sending
   #:stream-finished-p #:stream-reset-p #:stream-stopped-p
   #:stream-pending-events #:stream-next-event
   #:quic-connection #:make-quic-connection #:connection-touch
   #:connection-id-known-p #:connection-add-connection-id
   #:connection-retire-connection-id #:connection-idle-expired-p
   #:connection-close #:connection-check-idle-timeout #:connection-set-state
   #:connection-tls-feed #:connection-tls-poll #:connection-closed
   #:connection-close-error-code #:connection-close-reason))

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
  "Report whether the optional crypto implementation package is loaded."
  (not (null (find-package "CL-CRYPTO-KIT"))))

(defun require-crypto (operation)
  "Signal a clear boundary error until the crypto backend implements OPERATION."
  (unless (crypto-available-p)
    (error 'crypto-unavailable :operation operation))
  (error 'crypto-unavailable :operation operation))
