(in-package #:cl-quic-kit)

(defconstant +quic-v1+ #x00000001)
(defconstant +quic-v2+ #x6b3343cf)
(defun %packet-error (message) (error 'quic-encoding-error :message message))
(defun %empty-packet-octets () (make-array 0 :element-type '(unsigned-byte 8)))

(defstruct (packet-header (:constructor %make-packet-header))
  (long-p nil) (type :short) (version 0) (destination-connection-id #())
  (source-connection-id #()) (token #()) (packet-number 0) (packet-number-length 1)
  (payload-length nil) (payload #()) (reserved-bits 0) (key-phase nil)
  (retry-integrity-tag #()))

(defun %octet-vector (value)
  (if (typep value '(simple-array (unsigned-byte 8) (*)))
      value
      (make-array (length value) :element-type '(unsigned-byte 8)
                  :initial-contents value)))

(defun make-packet-header (&key (type :short) version destination-connection-id
                                source-connection-id token packet-number
                                (packet-number-length 1) payload-length payload
                                retry-integrity-tag (reserved-bits 0) key-phase)
  (let ((long-p (not (eq type :short))))
    (%make-packet-header :long-p long-p :type type :version (or version 0)
                         :destination-connection-id
                         (%octet-vector (or destination-connection-id #()))
                         :source-connection-id
                         (%octet-vector (or source-connection-id #()))
                         :token (%octet-vector (or token #()))
                         :packet-number (or packet-number 0)
                         :packet-number-length packet-number-length
                         :payload-length payload-length
                         :payload (%octet-vector (or payload #()))
                         :retry-integrity-tag
                         (%octet-vector (or retry-integrity-tag #()))
                         :reserved-bits reserved-bits :key-phase key-phase)))

(defun %octets (a &rest more)
  (let ((out (make-array (+ (length a) (reduce #'+ more :key #'length :initial-value 0))
                         :element-type '(unsigned-byte 8))) (at 0))
    (dolist (x (cons a more) out)
      (let ((octets (if (typep x '(simple-array (unsigned-byte 8) (*)))
                        x
                        (make-array (length x) :element-type '(unsigned-byte 8)
                                    :initial-contents x))))
        (replace out octets :start1 at)
        (incf at (length octets))))))

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
         (payload (ensure-octets (packet-header-payload header)))
         (type (packet-header-type header))
         (number (packet-header-packet-number header)))
    (validate-connection-id dcid)
    (validate-connection-id scid)
    (unless (member pn-len '(1 2 3 4)) (%packet-error "Packet number length must be 1, 2, 3, or 4"))
    (let ((pn-bytes (make-array pn-len :element-type '(unsigned-byte 8))))
      (unless (and (<= 0 (packet-header-reserved-bits header))
                 (< (packet-header-reserved-bits header) 4))
        (%packet-error "Reserved bits must fit two bits"))
    (unless (and (integerp number) (<= 0 number) (< number (ash 1 (* 8 pn-len))))
      (%packet-error "Packet number does not fit its length"))
    (dotimes (i pn-len) (setf (aref pn-bytes (- pn-len i 1)) (logand #xff (ash (packet-header-packet-number header) (* -8 i)))))
      (if (packet-header-long-p header)
        (let ((first (logior #xC0 (ash (packet-header-reserved-bits header) 2)
                             (ecase type (:initial 0) (:0-rtt #x10) (:handshake #x20) (:retry #x30))
                             (1- pn-len))))
          (if (eq type :retry)
              (let ((tag (ensure-octets (packet-header-retry-integrity-tag header))))
                (unless (= (length tag) 16)
                  (error 'quic-encoding-error :message "Retry integrity tag must be 16 octets"))
                (%octets (vector first) (%u32 (packet-header-version header)) (vector (length dcid)) dcid
                         (vector (length scid)) scid (ensure-octets (packet-header-token header)) tag))
              (let ((body (%octets pn-bytes payload)))
                (%octets (vector first) (%u32 (packet-header-version header)) (vector (length dcid)) dcid
                         (vector (length scid)) scid (if (eq type :initial) (encode-varint (length (packet-header-token header))) (%empty-packet-octets))
                         (if (eq type :initial) (packet-header-token header) (%empty-packet-octets))
                         (encode-varint (length body)) body))))
        (let ((first (logior #x40 (ash (packet-header-reserved-bits header) 4)
                             (if (packet-header-key-phase header) 4 0) (1- pn-len))))
          (%octets (vector first) dcid pn-bytes (if include-payload payload #())))))))

(defun decode-packet-header (bytes &key (start 0) (short-header-dcid-length 0))
  (let* ((b (ensure-octets bytes)) (at start))
    (when (or (< at 0) (>= at (length b))) (%packet-error "Truncated packet header"))
    (let* ((first (aref b at)) (long-p (logbitp 7 first)) (pn-len (1+ (logand first 3))))
      (unless long-p
        (unless (logbitp 6 first) (%packet-error "QUIC fixed bit is not set")))
      (incf at)
      (if long-p
          (multiple-value-bind (version next) (%read-u32 b at)
            (setf at next)
            (when (and (not (zerop version)) (not (logbitp 6 first)))
              (%packet-error "QUIC fixed bit is not set"))
            (let ((type (ecase (ldb (byte 2 4) first) (0 :initial) (1 :0-rtt) (2 :handshake) (3 :retry))))
              (when (> (+ at 2) (length b)) (error 'quic-encoding-error :message "Truncated connection IDs"))
              (let ((dlen (aref b at))) (incf at)
                (multiple-value-bind (dcid next-d) (%packet-slice b at dlen) (setf at next-d)
                  (let ((slen (aref b at))) (incf at)
                    (multiple-value-bind (scid next-s) (%packet-slice b at slen) (setf at next-s)
                      (if (eq type :retry)
                          (progn
                            (when (< (- (length b) at) 16)
                              (error 'quic-encoding-error :message "Truncated Retry integrity tag"))
                            (values (make-packet-header :type type :version version :destination-connection-id dcid
                                                        :source-connection-id scid :reserved-bits (ldb (byte 2 2) first)
                                                        :token (subseq b at (- (length b) 16))
                                                        :retry-integrity-tag (subseq b (- (length b) 16)))
                                    (length b)))
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
                                (let ((payload-size (- length-value pn-len))
                                      (end (+ at (- length-value pn-len))))
                                  (when (> end (length b))
                                    (error 'quic-encoding-error :message "Truncated packet payload"))
                                  (values (make-packet-header :type type :version version
                                                              :destination-connection-id dcid :source-connection-id scid
                                                              :token token
                                                              :packet-number (reduce (lambda (a x) (+ (ash a 8) x)) pn-bytes :initial-value 0)
                                                              :packet-number-length pn-len :payload-length length-value
                                                              :payload (subseq b at (+ at payload-size))) end))))))))))))
          (progn
            (multiple-value-bind (dcid next) (%packet-slice b at short-header-dcid-length) (setf at next)
              (multiple-value-bind (pn-bytes next-pn) (%packet-slice b at pn-len) (setf at next-pn)
                (values (make-packet-header :type :short :destination-connection-id dcid
                                            :packet-number-length pn-len
                                            :packet-number (reduce (lambda (a x) (+ (ash a 8) x)) pn-bytes :initial-value 0)
                                            :reserved-bits (ldb (byte 2 4) first)
                                            :key-phase (logbitp 2 first)
                                            :payload (subseq b at)) (length b)))))))))

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
  (let ((dcid (validate-connection-id (%octet-vector destination-connection-id)))
        (scid (validate-connection-id (%octet-vector source-connection-id))))
    (unless (and (plusp (length versions))
                 (every (lambda (version) (and (integerp version) (<= 0 version) (< version (ash 1 32)))) versions))
      (error 'quic-encoding-error :message "Version Negotiation needs versions"))
    (%octets (vector #x80) (%u32 0) (vector (length dcid)) dcid
             (vector (length scid)) scid
             (apply #'%octets (mapcar #'%u32 versions)))))

(defun decode-version-negotiation (bytes &optional (start 0))
  "Decode a Version Negotiation packet, returning a property list."
  (let ((b (ensure-octets bytes)) (at start))
    (when (or (< at 0) (> (+ at 7) (length b))) (%packet-error "Truncated Version Negotiation packet"))
    (let ((first (aref b at)))
      (unless (and (logbitp 7 first) (zerop (logand first #x40)))
        (error 'quic-encoding-error :message "Not a Version Negotiation packet")))
    (multiple-value-bind (version next) (%read-u32 b (1+ at))
      (declare (ignore version))
      (setf at next)
      (let ((dl (aref b at))) (incf at)
        (multiple-value-bind (dcid next-d) (%packet-slice b at dl) (setf at next-d)
          (when (> at (length b)) (error 'quic-encoding-error :message "Missing source connection ID"))
          (let ((sl (aref b at))) (incf at)
            (multiple-value-bind (scid next-s) (%packet-slice b at sl) (setf at next-s)
              (when (or (zerop (- (length b) at)) (not (zerop (mod (- (length b) at) 4))))
                (%packet-error "Invalid version list"))
              (let ((versions nil))
                (loop while (< at (length b)) do
                  (multiple-value-bind (v next-v) (%read-u32 b at)
                    (push v versions) (setf at next-v)))
                (list :version 0 :destination-connection-id dcid
                      :source-connection-id scid :versions (nreverse versions))))))))))

(defparameter *transport-parameter-integer-ids*
  '(1 3 4 5 6 7 8 9 10 11 14 16 17))
(defparameter *transport-parameter-fixed-octet-sizes*
  '((2 . 16)))

(defun %transport-integer-p (id) (member id *transport-parameter-integer-ids*))
(defun %transport-octets (value) (%octet-vector value))
(defun %transport-parameter-value (id value)
  (cond
    ((%transport-integer-p id)
     (unless (and (integerp value) (varint-p value)) (%packet-error "Invalid transport parameter integer"))
     (when (and (= id 3) (< value 1200)) (%packet-error "max_udp_payload_size is below 1200"))
     (when (and (= id 10) (> value 20)) (%packet-error "ack_delay_exponent exceeds 20"))
     (when (and (= id 11) (> value (1- (ash 1 14)))) (%packet-error "max_ack_delay exceeds 2^14-1"))
     (when (and (= id 14) (< value 2)) (%packet-error "active_connection_id_limit is below 2"))
     (encode-varint value))
    ((= id 0) (let ((octets (%transport-octets value))) (validate-connection-id octets) octets))
    ((= id 2) (let ((octets (%transport-octets value)))
                 (unless (= (length octets) 16) (%packet-error "stateless_reset_token must be 16 octets")) octets))
    ((= id 12) (unless (zerop (length (%transport-octets value))) (%packet-error "disable_active_migration must be empty")) #())
    ((= id 13) (let ((octets (%transport-octets value)))
                  (when (or (< (length octets) 41) (> (length octets) 61))
                    (%packet-error "Invalid preferred_address")) octets))
    ((member id '(15 0)) (let ((octets (%transport-octets value))) (validate-connection-id octets) octets))
    (t (%transport-octets value))))

(defun encode-transport-parameters (parameters)
  "Encode transport parameters as an ID/length/value sequence."
  (let ((seen (make-hash-table :test #'eql)) (out #()))
    (dolist (parameter parameters out)
      (let ((id (car parameter)))
        (unless (and (varint-p id) (not (gethash id seen))) (%packet-error "Duplicate or invalid transport parameter"))
        (setf (gethash id seen) t)
        (let ((encoded (%transport-parameter-value id (cdr parameter))))
          (setf out (%octets out (encode-varint id) (encode-varint (length encoded)) encoded)))))))

(defun decode-transport-parameters (bytes)
  "Decode transport parameters into an alist of integer or octet values."
  (let ((b (ensure-octets bytes)) (at 0) (seen (make-hash-table :test #'eql)) (out nil))
    (loop while (< at (length b)) do
      (multiple-value-bind (id next-id) (decode-varint b at) (setf at (+ at next-id))
        (when (gethash id seen) (%packet-error "Duplicate transport parameter"))
        (setf (gethash id seen) t)
        (multiple-value-bind (size next-size) (decode-varint b at) (setf at (+ at next-size))
          (multiple-value-bind (value next) (%packet-slice b at size) (setf at next)
            (if (%transport-integer-p id)
                (multiple-value-bind (number used) (decode-varint value)
                  (unless (= used (length value)) (%packet-error "Invalid transport parameter integer"))
                  (%transport-parameter-value id number)
                  (push (cons id number) out))
                (push (cons id (%transport-parameter-value id value)) out))))))
    (nreverse out)))
