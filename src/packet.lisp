(in-package #:cl-quic-kit)

(defconstant +quic-v1+ #x00000001)
(defconstant +quic-v2+ #x6b3343cf)
(defconstant +max-quic-packet-size+ 65527)

(defun %packet-error (message)
  (error 'quic-encoding-error :message message))

(defun %empty-packet-octets ()
  (make-array 0 :element-type '(unsigned-byte 8)))

(defun %byte (value)
  (unless (and (integerp value) (<= 0 value 255))
    (%packet-error "Value is not an octet"))
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element value))

(defstruct (packet-header (:constructor %make-packet-header))
  (long-p nil)
  (type :short)
  (version 0)
  (destination-connection-id #())
  (source-connection-id #())
  (token #())
  (packet-number 0)
  (packet-number-length 1)
  payload-length
  (payload #())
  (reserved-bits 0)
  (key-phase nil)
  (retry-integrity-tag #()))

(defun %octet-vector (value)
  (cond
    ((typep value '(simple-array (unsigned-byte 8) (*))) value)
    ((or (vectorp value) (listp value))
     (let ((out (make-array (length value) :element-type '(unsigned-byte 8))))
       (loop for octet across (coerce value 'vector)
             for index from 0
             do (unless (and (integerp octet) (<= 0 octet 255))
                  (%packet-error "Expected octets in packet field"))
                (setf (aref out index) octet))
       out))
    (t (%packet-error "Expected a one-dimensional octet vector"))))

(defun %packet-type-p (type)
  (member type '(:short :initial :0-rtt :handshake :retry) :test #'eq))

(defun make-packet-header (&key (type :short) version destination-connection-id
                                source-connection-id token packet-number
                                (packet-number-length 1) payload-length payload
                                retry-integrity-tag (reserved-bits 0) key-phase)
  (unless (%packet-type-p type)
    (%packet-error "Unknown QUIC packet type"))
  (let ((long-p (not (eq type :short))))
    (%make-packet-header
     :long-p long-p
     :type type
     :version (or version 0)
     :destination-connection-id
     (%octet-vector (or destination-connection-id #()))
     :source-connection-id
     (%octet-vector (or source-connection-id #()))
     :token (%octet-vector (or token #()))
     :packet-number (or packet-number 0)
     :packet-number-length packet-number-length
     :payload-length payload-length
     :payload (%octet-vector (or payload #()))
     :retry-integrity-tag (%octet-vector (or retry-integrity-tag #()))
     :reserved-bits reserved-bits
     :key-phase key-phase)))

(defun %octets (a &rest more)
  (let ((parts (mapcar #'%octet-vector (cons a more))))
    (let ((out (make-array (reduce #'+ parts :key #'length :initial-value 0)
                           :element-type '(unsigned-byte 8)))
          (at 0))
      (dolist (part parts out)
        (replace out part :start1 at)
        (incf at (length part))))))

(defun %u32 (number)
  (unless (and (integerp number) (<= 0 number) (< number (ash 1 32)))
    (%packet-error "Value is not an unsigned 32-bit integer"))
  (let ((out (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 out)
      (setf (aref out (- 3 i)) (logand #xff (ash number (* -8 i)))))))

(defun %read-u32 (bytes at)
  (when (or (< at 0) (> (+ at 4) (length bytes)))
    (%packet-error "Truncated packet version"))
  (values (+ (ash (aref bytes at) 24)
             (ash (aref bytes (+ at 1)) 16)
             (ash (aref bytes (+ at 2)) 8)
             (aref bytes (+ at 3)))
          (+ at 4)))

(defun %packet-slice (bytes at size)
  (when (or (not (integerp at)) (not (integerp size))
            (< at 0) (< size 0) (> at (length bytes))
            (> size (- (length bytes) at)))
    (%packet-error "Truncated packet"))
  (values (subseq bytes at (+ at size)) (+ at size)))

(defun %packet-number-octets (number length)
  (unless (and (member length '(1 2 3 4))
               (integerp number) (<= 0 number)
               (< number (ash 1 (* 8 length))))
    (%packet-error "Packet number does not fit its length"))
  (let ((out (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length out)
      (setf (aref out (- length i 1))
            (logand #xff (ash number (* -8 i)))))))

(defun %packet-number-from-octets (bytes)
  (reduce (lambda (result octet) (+ (ash result 8) octet))
          bytes :initial-value 0))

(defun %packet-reserved-bits (header)
  (let ((reserved (packet-header-reserved-bits header)))
    (unless (and (integerp reserved) (<= 0 reserved 3))
      (%packet-error "Reserved bits must fit two bits"))
    reserved))

(defun encode-packet-header (header &key (include-payload t))
  (let* ((type (packet-header-type header))
         (long-p (packet-header-long-p header))
         (version (packet-header-version header))
         (dcid (%octet-vector (packet-header-destination-connection-id header)))
         (scid (%octet-vector (packet-header-source-connection-id header)))
         (token (%octet-vector (packet-header-token header)))
         (payload (%octet-vector (packet-header-payload header)))
         (reserved (%packet-reserved-bits header)))
    (unless (%packet-type-p type)
      (%packet-error "Unknown QUIC packet type"))
    (validate-connection-id dcid)
    (validate-connection-id scid)
    (when long-p
      (unless (and (integerp version) (plusp version) (< version (ash 1 32)))
        (%packet-error "Long-header packets require a nonzero version")))
    (if long-p
        (case type
          (:retry
           (when (plusp reserved)
             (%packet-error "Retry reserved bits must be zero"))
           (let ((tag (%octet-vector (packet-header-retry-integrity-tag header))))
             (unless (= (length tag) 16)
               (%packet-error "Retry integrity tag must be 16 octets"))
             (%octets
              (%byte #xf0)
              (%u32 version)
              (%byte (length dcid)) dcid
              (%byte (length scid)) scid
              token tag)))
          ((:initial :0-rtt :handshake)
           (when (and (not (eq type :initial)) (plusp (length token)))
             (%packet-error "Only Initial packets carry a token"))
           (let* ((pn-length (packet-header-packet-number-length header))
                  (pn (%packet-number-octets
                       (packet-header-packet-number header) pn-length))
                  (body (%octets pn (if include-payload payload #())))
                  (type-bits (ecase type
                               (:initial 0)
                               (:0-rtt #x10)
                               (:handshake #x20)))
                  (first (logior #xc0 (ash reserved 2) type-bits
                                 (1- pn-length))))
             (%octets
              (%byte first) (%u32 version)
              (%byte (length dcid)) dcid
              (%byte (length scid)) scid
              (if (eq type :initial)
                  (encode-varint (length token))
                  (%empty-packet-octets))
              (if (eq type :initial) token (%empty-packet-octets))
              (encode-varint (length body)) body))))
        (let* ((pn-length (packet-header-packet-number-length header))
               (pn (%packet-number-octets
                    (packet-header-packet-number header) pn-length))
               (first (logior #x40 (ash reserved 4)
                              (if (packet-header-key-phase header) 4 0)
                              (1- pn-length))))
          (%octets (%byte first) dcid pn (if include-payload payload #()))))))

(defun decode-packet-header (bytes &key (start 0) (short-header-dcid-length 0))
  (let* ((b (%octet-vector bytes))
         (at start))
    (when (> (length b) +max-quic-packet-size+)
      (%packet-error "QUIC packet exceeds the maximum UDP payload size"))
    (when (or (< at 0) (>= at (length b)))
      (%packet-error "Truncated packet header"))
    (let* ((first (aref b at))
           (long-p (logbitp 7 first)))
      (incf at)
      (if long-p
          (multiple-value-bind (version next) (%read-u32 b at)
            (setf at next)
            (when (zerop version)
              (%packet-error "Version Negotiation packets use decode-version-negotiation"))
            (unless (logbitp 6 first)
              (%packet-error "QUIC fixed bit is not set"))
            (let ((type (case (ldb (byte 2 4) first)
                          (0 :initial) (1 :0-rtt) (2 :handshake) (3 :retry))))
              (when (> at (1- (length b)))
                (%packet-error "Missing destination connection ID length"))
              (let ((dlen (aref b at)))
                (incf at)
                (multiple-value-bind (dcid next-dcid) (%packet-slice b at dlen)
                  (setf at next-dcid)
                  (when (>= at (length b))
                    (%packet-error "Missing source connection ID length"))
                  (let ((slen (aref b at)))
                    (incf at)
                    (multiple-value-bind (scid next-scid) (%packet-slice b at slen)
                      (setf at next-scid)
                      (validate-connection-id dcid)
                      (validate-connection-id scid)
                      (if (eq type :retry)
                          (progn
                            (when (not (zerop (logand first #x0f)))
                              (%packet-error "Retry reserved bits must be zero"))
                            (when (< (- (length b) at) 16)
                              (%packet-error "Truncated Retry integrity tag"))
                            (values
                             (make-packet-header
                              :type :retry :version version
                              :destination-connection-id dcid
                              :source-connection-id scid
                              :token (subseq b at (- (length b) 16))
                              :packet-number-length 0
                              :retry-integrity-tag (subseq b (- (length b) 16)))
                             (length b)))
                          (let ((token #()))
                            (when (eq type :initial)
                              (multiple-value-bind (token-length token-size)
                                  (decode-varint b at)
                                (incf at token-size)
                                (multiple-value-bind (token-bytes token-end)
                                    (%packet-slice b at token-length)
                                  (setf token token-bytes
                                        at token-end))))
                            (multiple-value-bind (length-value length-size)
                                (decode-varint b at)
                              (incf at length-size)
                              (when (> length-value +max-quic-packet-size+)
                                (%packet-error "QUIC packet length exceeds the maximum UDP payload size"))
                              (let ((pn-length (1+ (logand first 3))))
                                (when (< length-value pn-length)
                                  (%packet-error "Invalid long-header packet length"))
                                (multiple-value-bind (pn-bytes next-pn)
                                    (%packet-slice b at pn-length)
                                  (setf at next-pn)
                                  (let ((payload-size (- length-value pn-length)))
                                    (multiple-value-bind (payload end)
                                        (%packet-slice b at payload-size)
                                      (values
                                       (make-packet-header
                                        :type type :version version
                                        :destination-connection-id dcid
                                        :source-connection-id scid :token token
                                        :packet-number
                                        (%packet-number-from-octets pn-bytes)
                                        :packet-number-length pn-length
                                        :payload-length length-value
                                        :payload payload
                                        :reserved-bits (ldb (byte 2 2) first))
                                       end))))))))))))))
          (progn
            (unless (logbitp 6 first)
              (%packet-error "QUIC fixed bit is not set"))
            (unless (and (integerp short-header-dcid-length)
                         (<= 0 short-header-dcid-length 20))
              (%packet-error "Invalid short-header destination connection ID length"))
            (multiple-value-bind (dcid next-dcid)
                (%packet-slice b at short-header-dcid-length)
              (setf at next-dcid)
              (let ((pn-length (1+ (logand first 3))))
                (multiple-value-bind (pn-bytes next-pn)
                    (%packet-slice b at pn-length)
                  (setf at next-pn)
                  (values
                   (make-packet-header
                    :type :short :destination-connection-id dcid
                    :packet-number-length pn-length
                    :packet-number (%packet-number-from-octets pn-bytes)
                    :reserved-bits (ldb (byte 2 4) first)
                    :key-phase (logbitp 2 first)
                    :payload (subseq b at))
                   (length b))))))))))

(defparameter *retry-integrity-tag-function* nil)

(defun retry-integrity-tag (pseudo-packet &key original-destination-connection-id)
  (unless *retry-integrity-tag-function*
    (error 'quic-crypto-error
           :message "Retry integrity crypto provider is not installed"))
  (let ((tag (funcall *retry-integrity-tag-function*
                      (%octet-vector pseudo-packet)
                      (%octet-vector original-destination-connection-id))))
    (unless (and (typep tag '(simple-array (unsigned-byte 8) (*)))
                 (= (length tag) 16))
      (%packet-error "Retry integrity provider must return 16 octets"))
    tag))

(defun %constant-time-octets-equal-p (left right)
  (let ((difference (logxor (length left) (length right))))
    (dotimes (index (max (length left) (length right))
             (zerop difference))
      (setf difference
            (logior difference
                    (logxor (if (< index (length left)) (aref left index) 0)
                            (if (< index (length right)) (aref right index) 0)))))))

(defun verify-retry-integrity (pseudo-packet tag &key original-destination-connection-id)
  (let ((actual (%octet-vector tag)))
    (and (= (length actual) 16)
         (%constant-time-octets-equal-p
          (retry-integrity-tag
           pseudo-packet
           :original-destination-connection-id original-destination-connection-id)
          actual))))

(defun encode-version-negotiation (destination-connection-id source-connection-id versions)
  "Encode a QUIC Version Negotiation packet with a version-zero header."
  (let ((dcid (validate-connection-id (%octet-vector destination-connection-id)))
        (scid (validate-connection-id (%octet-vector source-connection-id)))
        (versions (and (typep versions 'sequence) (coerce versions 'list))))
    (unless (and versions
                 (every (lambda (version)
                          (and (integerp version) (plusp version)
                               (< version (ash 1 32))))
                        versions))
      (%packet-error "Version Negotiation needs nonzero versions"))
    (%octets
     (%byte #x80) (%u32 0)
     (%byte (length dcid)) dcid
     (%byte (length scid)) scid
     (apply #'%octets (mapcar #'%u32 versions)))))

(defun decode-version-negotiation (bytes &optional (start 0))
  "Decode a Version Negotiation packet into a property list."
  (let* ((b (%octet-vector bytes))
         (at start))
    (when (> (length b) +max-quic-packet-size+)
      (%packet-error "Version Negotiation packet exceeds the maximum UDP payload size"))
    (when (or (< at 0) (> (+ at 7) (length b)))
      (%packet-error "Truncated Version Negotiation packet"))
    (let ((first (aref b at)))
      (unless (and (logbitp 7 first) (not (logbitp 6 first)))
        (%packet-error "Not a Version Negotiation packet")))
    (multiple-value-bind (version next) (%read-u32 b (1+ at))
      (unless (zerop version)
        (%packet-error "Version Negotiation version must be zero"))
      (setf at next)
      (let ((destination-length (aref b at)))
        (incf at)
        (multiple-value-bind (dcid next-dcid)
            (%packet-slice b at destination-length)
          (setf at next-dcid)
          (validate-connection-id dcid)
          (when (>= at (length b))
            (%packet-error "Missing Version Negotiation source connection ID length"))
          (let ((source-length (aref b at)))
            (incf at)
            (multiple-value-bind (scid next-scid)
                (%packet-slice b at source-length)
              (setf at next-scid)
              (validate-connection-id scid)
              (let ((remaining (- (length b) at)))
                (when (or (zerop remaining) (not (zerop (mod remaining 4))))
                  (%packet-error "Invalid Version Negotiation version list"))
                (let ((versions nil))
                  (loop while (< at (length b)) do
                    (multiple-value-bind (supported next-version)
                        (%read-u32 b at)
                      (when (zerop supported)
                        (%packet-error "Version Negotiation cannot advertise version zero"))
                      (push supported versions)
                      (setf at next-version)))
                  (list :version 0
                        :destination-connection-id dcid
                        :source-connection-id scid
                        :versions (nreverse versions)))))))))))

(defparameter *transport-parameter-integer-ids*
  '(1 3 4 5 6 7 8 9 10 11 14 17))

(defun %transport-octets (value)
  (%octet-vector value))

(defun %preferred-address-p (value)
  (and (<= 42 (length value) 61)
       (let ((connection-id-length (aref value 24)))
         (and (<= 1 connection-id-length 20)
              (= (length value) (+ 41 connection-id-length))))))

(defun %transport-integer-p (id)
  (member id *transport-parameter-integer-ids*))

(defun %transport-parameter-value (id value)
  (cond
    ((%transport-integer-p id)
     (unless (varint-p value)
       (%packet-error "Invalid transport parameter integer"))
     (when (and (= id 3) (< value 1200))
       (%packet-error "max_udp_payload_size is below 1200"))
     (when (and (= id 10) (> value 20))
       (%packet-error "ack_delay_exponent exceeds 20"))
     (when (and (= id 11) (> value (1- (ash 1 14))))
       (%packet-error "max_ack_delay exceeds 2^14-1"))
     (when (and (= id 14) (< value 2))
       (%packet-error "active_connection_id_limit is below 2"))
     (encode-varint value))
    ((member id '(0 15 16))
     (let ((octets (%transport-octets value)))
       (validate-connection-id octets)
       octets))
    ((= id 2)
     (let ((octets (%transport-octets value)))
       (unless (= (length octets) 16)
         (%packet-error "stateless_reset_token must be 16 octets"))
       octets))
    ((= id 12)
     (unless (zerop (length (%transport-octets value)))
       (%packet-error "disable_active_migration must be empty"))
     #())
    ((= id 13)
     (let ((octets (%transport-octets value)))
       (unless (%preferred-address-p octets)
         (%packet-error "Invalid preferred_address"))
       octets))
    (t (%transport-octets value))))

(defun encode-transport-parameters (parameters)
  "Encode transport parameters as an ID/length/value sequence."
  (let ((seen (make-hash-table :test #'eql))
        (out #()))
    (dolist (parameter parameters out)
      (unless (and (consp parameter) (varint-p (car parameter)))
        (%packet-error "Invalid transport parameter"))
      (let ((id (car parameter)))
        (when (gethash id seen)
          (%packet-error "Duplicate transport parameter"))
        (setf (gethash id seen) t)
        (let ((encoded (%transport-parameter-value id (cdr parameter))))
          (setf out (%octets out (encode-varint id)
                             (encode-varint (length encoded)) encoded)))))))

(defun decode-transport-parameters (bytes)
  "Decode transport parameters into an alist of integer or octet values."
  (let ((b (%octet-vector bytes))
        (at 0)
        (seen (make-hash-table :test #'eql))
        (out nil))
    (loop while (< at (length b)) do
      (multiple-value-bind (id id-size) (decode-varint b at)
        (incf at id-size)
        (when (gethash id seen)
          (%packet-error "Duplicate transport parameter"))
        (setf (gethash id seen) t)
        (multiple-value-bind (size size-size) (decode-varint b at)
          (incf at size-size)
          (multiple-value-bind (value next) (%packet-slice b at size)
            (setf at next)
            (if (%transport-integer-p id)
                (multiple-value-bind (number used) (decode-varint value)
                  (unless (= used (length value))
                    (%packet-error "Invalid transport parameter integer"))
                  (%transport-parameter-value id number)
                  (push (cons id number) out))
                (push (cons id (%transport-parameter-value id value)) out))))))
    (nreverse out)))
