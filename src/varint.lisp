(defpackage #:cl-quic-kit
  (:use #:cl)
  (:export
   #:quic-error #:quic-encoding-error #:quic-crypto-error
   #:encode-varint #:decode-varint #:varint-length #:varint-p
   #:octets-copy #:ensure-octets
   #:make-packet-header #:packet-header-p #:packet-header-type
   #:packet-header-version #:packet-header-destination-connection-id
   #:packet-header-source-connection-id #:packet-header-token
   #:packet-header-packet-number #:packet-header-payload
   #:encode-packet-header #:decode-packet-header
   #:retry-integrity-tag #:verify-retry-integrity #:*retry-integrity-tag-function*
   #:make-frame #:frame-p #:frame-type #:frame-fields #:frame-field
   #:encode-frame #:decode-frame #:encode-frames #:decode-frames))

(in-package #:cl-quic-kit)

(define-condition quic-error (error) ())
(define-condition quic-encoding-error (quic-error)
  ((message :initarg :message :reader quic-error-message))
  (:report (lambda (c s) (write-string (quic-error-message c) s))))
(define-condition quic-crypto-error (quic-error)
  ((message :initarg :message :reader quic-crypto-error-message))
  (:report (lambda (c s) (write-string (quic-crypto-error-message c) s))))

(defun ensure-octets (value)
  (unless (and (arrayp value) (= (array-rank value) 1)
               (every (lambda (x) (and (integerp x) (<= 0 x 255))) value))
    (error 'quic-encoding-error :message "Expected a one-dimensional octet vector"))
  value)

(defun octets-copy (value)
  (let ((value (ensure-octets value)))
    (replace (make-array (length value) :element-type '(unsigned-byte 8)) value)))

(defun varint-p (value) (and (integerp value) (<= 0 value) (< value (ash 1 62))))

(defun varint-length (value)
  (cond ((not (varint-p value))
         (error 'quic-encoding-error :message "QUIC varint must be in [0, 2^62)"))
        ((< value (ash 1 6)) 1)
        ((< value (ash 1 14)) 2)
        ((< value (ash 1 30)) 4)
        (t 8)))

(defun encode-varint (value)
  (let* ((size (varint-length value))
         (out (make-array size :element-type '(unsigned-byte 8)))
         (prefix (ecase size (1 0) (2 #x40) (4 #x80) (8 #xc0)))
         (n value))
    (dotimes (i size out)
      (setf (aref out (- size i 1)) (logand #xff n))
      (setf n (ash n -8)))
    (setf (aref out 0) (logior (aref out 0) prefix))
    out))

(defun decode-varint (bytes &optional (start 0))
  (let* ((bytes (ensure-octets bytes))
         (remaining (- (length bytes) start)))
    (when (or (< start 0) (< remaining 1))
      (error 'quic-encoding-error :message "Truncated QUIC varint"))
    (let* ((first (aref bytes start))
           (size (ash 1 (ldb (byte 2 6) first))))
      (when (< remaining size)
        (error 'quic-encoding-error :message "Truncated QUIC varint"))
      (values (loop with result = (logand #x3f first)
                    for i from 1 below size
                    do (setf result (logior (ash result 8) (aref bytes (+ start i))))
                    finally (return result))
              size))))
