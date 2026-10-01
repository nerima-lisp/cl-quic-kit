(in-package #:cl-quic-kit)

(defconstant +quic-v1+ #x00000001)
(defconstant +quic-v2+ #x6b3343cf)

(defstruct (packet-header (:constructor %make-packet-header))
  (long-p nil) (type :short) (version 0) (destination-connection-id #())
  (source-connection-id #()) (token #()) (packet-number 0) (packet-number-length 1)
  (payload-length nil) (payload #()) (reserved-bits 0) (key-phase nil))

(defun make-packet-header (&key (type :short) version destination-connection-id
                                source-connection-id token packet-number
                                (packet-number-length 1) payload-length payload)
  (let ((long-p (not (eq type :short))))
    (%make-packet-header :long-p long-p :type type :version (or version 0)
                         :destination-connection-id (or destination-connection-id #())
                         :source-connection-id (or source-connection-id #())
                         :token (or token #()) :packet-number (or packet-number 0)
                         :packet-number-length packet-number-length
                         :payload-length payload-length :payload (or payload #()))))

(defun %octets (a &rest more)
  (let ((out (make-array (+ (length a) (reduce #'+ more :key #'length :initial-value 0))
                         :element-type '(unsigned-byte 8))) (at 0))
    (dolist (x (cons a more) out) (replace out (ensure-octets x) :start1 at) (incf at (length x)))))

(defun %u32 (n)
  (let ((o (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 o) (setf (aref o (- 3 i)) (logand #xff (ash n (* -8 i)))))))

(defun %read-u32 (b at)
  (when (> (+ at 4) (length b))
    (error 'quic-encoding-error :message "Truncated packet version"))
  (values (+ (ash (aref b at) 24) (ash (aref b (+ at 1)) 16)
             (ash (aref b (+ at 2)) 8) (aref b (+ at 3))) (+ at 4)))

(defun %packet-slice (b at length)
  (when (or (< at 0) (< length 0) (> (+ at length) (length b)))
    (error 'quic-encoding-error :message "Truncated packet"))
  (values (subseq b at (+ at length)) (+ at length)))

(defun encode-packet-header (header &key (include-payload t))
  (let* ((dcid (ensure-octets (packet-header-destination-connection-id header)))
         (scid (ensure-octets (packet-header-source-connection-id header)))
         (pn-len (packet-header-packet-number-length header))
         (pn-bytes (make-array pn-len :element-type '(unsigned-byte 8)))
         (payload (ensure-octets (packet-header-payload header)))
         (type (packet-header-type header)))
    (unless (member pn-len '(1 2 3 4)) (error 'quic-encoding-error :message "Packet number length must be 1, 2, 3, or 4"))
    (dotimes (i pn-len) (setf (aref pn-bytes (- pn-len i 1)) (logand #xff (ash (packet-header-packet-number header) (* -8 i)))))
    (if (packet-header-long-p header)
        (let ((first (logior #xC0 (ecase type (:initial 0) (:0-rtt #x10) (:handshake #x20) (:retry #x30))
                             (1- pn-len))))
          (if (eq type :retry)
              (%octets (vector first) (%u32 (packet-header-version header)) (vector (length dcid)) dcid
                       (vector (length scid)) scid (ensure-octets (packet-header-token header)))
              (let ((body (%octets pn-bytes payload)))
                (%octets (vector first) (%u32 (packet-header-version header)) (vector (length dcid)) dcid
                         (vector (length scid)) scid (if (eq type :initial) (encode-varint (length (packet-header-token header))) #())
                         (if (eq type :initial) (packet-header-token header) #())
                         (encode-varint (length body)) body))))
        (let ((first (logior #x40 (if (packet-header-key-phase header) 4 0) (1- pn-len))))
          (%octets (vector first) dcid pn-bytes (if include-payload payload #()))))))

(defun decode-packet-header (bytes &key (start 0) (short-header-dcid-length 0))
  (let* ((b (ensure-octets bytes)) (at start))
    (when (< (- (length b) at) 1) (error 'quic-encoding-error :message "Truncated packet header"))
    (let* ((first (aref b at)) (long-p (>= first 128)) (pn-len (1+ (logand first 3))))
      (incf at)
      (if long-p
          (multiple-value-bind (version next) (%read-u32 b at)
            (setf at next)
            (let ((type (ecase (ldb (byte 2 4) first) (0 :initial) (1 :0-rtt) (2 :handshake) (3 :retry))))
              (when (> (+ at 2) (length b)) (error 'quic-encoding-error :message "Truncated connection IDs"))
              (let ((dlen (aref b at))) (incf at)
                (multiple-value-bind (dcid next-d) (%packet-slice b at dlen) (setf at next-d)
                  (let ((slen (aref b at))) (incf at)
                    (multiple-value-bind (scid next-s) (%packet-slice b at slen) (setf at next-s)
                      (if (eq type :retry)
                          (values (make-packet-header :type type :version version :destination-connection-id dcid :source-connection-id scid :token (subseq b at)) (length b))
                          (let ((token #()))
                            (when (eq type :initial)
                              (multiple-value-bind (n size) (decode-varint b at)
                                (incf at size)
                                (multiple-value-bind (token-bytes token-end) (%packet-slice b at n)
                                  (setf token token-bytes at token-end))))
                            (multiple-value-bind (length-value size) (decode-varint b at)
                              (incf at size)
                              (when (< length-value pn-len) (error 'quic-encoding-error :message "Invalid packet length"))
                              (multiple-value-bind (pn-bytes next-pn) (%packet-slice b at pn-len) (setf at next-pn)
                                (let ((end (+ (- at start) length-value (- pn-len))))
                                  (declare (ignore end))
                                  (values (make-packet-header :type type :version version :destination-connection-id dcid :source-connection-id scid :token token :packet-number (reduce (lambda (a x) (+ (ash a 8) x)) pn-bytes :initial-value 0) :packet-number-length pn-len :payload-length length-value :payload (subseq b at (min (length b) (+ at (- length-value pn-len))))) (+ at (- length-value pn-len)))))))))))))))
          (progn
            (multiple-value-bind (dcid next) (%packet-slice b at short-header-dcid-length) (setf at next)
              (multiple-value-bind (pn-bytes next-pn) (%packet-slice b at pn-len) (setf at next-pn)
                (values (make-packet-header :type :short :destination-connection-id dcid :packet-number-length pn-len :packet-number (reduce (lambda (a x) (+ (ash a 8) x)) pn-bytes :initial-value 0)) at)))))))

(defparameter *retry-integrity-tag-function* nil)
(defun retry-integrity-tag (pseudo-packet &key original-destination-connection-id)
  (unless *retry-integrity-tag-function*
    (error 'quic-crypto-error :message "Retry integrity crypto provider is not installed"))
  (funcall *retry-integrity-tag-function* pseudo-packet original-destination-connection-id))

(defun verify-retry-integrity (pseudo-packet tag &key original-destination-connection-id)
  (let ((expected (retry-integrity-tag pseudo-packet :original-destination-connection-id original-destination-connection-id)))
    (and (= (length expected) (length tag)) (every #'= expected tag))))

(defun encode-version-negotiation (destination-connection-id source-connection-id versions)
  "Encode a QUIC Version Negotiation packet body and invariant header."
  (let ((dcid (validate-connection-id (ensure-octets destination-connection-id)))
        (scid (validate-connection-id (ensure-octets source-connection-id))))
    (unless (and (plusp (length versions)) (every #'varint-p versions))
      (error 'quic-encoding-error :message "Version Negotiation needs versions"))
    (%octets (vector #x80) (%u32 0) (vector (length dcid)) dcid
             (vector (length scid)) scid
             (apply #'%octets (mapcar #'%u32 versions)))))

(defun decode-version-negotiation (bytes &optional (start 0))
  "Decode a Version Negotiation packet, returning a property list."
  (let ((b (ensure-octets bytes)) (at start))
    (when (> (+ at 7) (length b))
      (error 'quic-encoding-error :message "Truncated Version Negotiation packet"))
    (let ((first (aref b at)))
      (unless (and (logbitp 7 first) (zerop (logand first #x40)))
        (error 'quic-encoding-error :message "Not a Version Negotiation packet")))
    (multiple-value-bind (version next) (%read-u32 b (1+ at))
      (declare (ignore version))
      (setf at next)
      (let ((dl (aref b at))) (incf at)
        (multiple-value-bind (dcid next-d) (%packet-slice b at dl) (setf at next-d)
          (when (>= at (length b)) (error 'quic-encoding-error :message "Missing source connection ID"))
          (let ((sl (aref b at))) (incf at)
            (multiple-value-bind (scid next-s) (%packet-slice b at sl) (setf at next-s)
              (unless (zerop (mod (- (length b) at) 4))
                (error 'quic-encoding-error :message "Invalid version list"))
              (let ((versions nil))
                (loop while (< at (length b)) do
                  (multiple-value-bind (v next-v) (%read-u32 b at)
                    (push v versions) (setf at next-v)))
                (list :version 0 :destination-connection-id dcid
                      :source-connection-id scid :versions (nreverse versions))))))))))

(defun encode-transport-parameters (parameters)
  "Encode transport parameters as an ID/length/value sequence.
PARAMETERS is an alist; values are integers or octet vectors."
  (let ((seen (make-hash-table :test #'eql)) (out #()))
    (dolist (parameter parameters out)
      (let ((id (car parameter)) (value (cdr parameter)))
        (unless (and (varint-p id) (not (gethash id seen)))
          (error 'quic-encoding-error :message "Duplicate or invalid transport parameter"))
        (setf (gethash id seen) t)
        (let ((encoded (if (integerp value) (encode-varint value) (ensure-octets value))))
          (setf out (%octets out (encode-varint id) (encode-varint (length encoded)) encoded)))))))

(defun decode-transport-parameters (bytes)
  "Decode transport parameters into an alist of integer or octet values."
  (let ((b (ensure-octets bytes)) (at 0) (seen (make-hash-table :test #'eql)) (out nil))
    (loop while (< at (length b)) do
      (multiple-value-bind (id next-id) (decode-varint b at) (setf at (+ at next-id))
        (when (gethash id seen) (error 'quic-encoding-error :message "Duplicate transport parameter"))
        (setf (gethash id seen) t)
        (multiple-value-bind (size next-size) (decode-varint b at) (setf at (+ at next-size))
          (multiple-value-bind (value next) (%packet-slice b at size) (setf at next)
            (push (cons id value) out)))))
    (nreverse out)))
