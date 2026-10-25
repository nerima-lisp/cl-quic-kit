(in-package #:cl-user)

(defun packet-reserved-zero-control ()
  (let* ((header (cl-quic-kit:make-packet-header
                  :type :short :destination-connection-id #(#xaa #xbb)
                  :packet-number #x12 :payload #(#xde #xad)))
         (wire #(#x40 #xaa #xbb #x12 #xde #xad)))
    (check (equalp (cl-quic-kit:encode-packet-header header) wire)
           "zero reserved bits match the short-header wire control")
    (check (equalp (cl-quic-kit:encode-packet-header header :include-payload nil)
                   #(#x40 #xaa #xbb #x12))
           "zero reserved bits preserve header-only encoding")
    (multiple-value-bind (decoded end)
        (cl-quic-kit:decode-packet-header wire :short-header-dcid-length 2)
      (check (= end 6) "zero control consumes the packet")
      (check (eq (cl-quic-kit:packet-header-type decoded) :short)
             "zero control has short-header type")
      (check (zerop (cl-quic-kit:packet-header-reserved-bits decoded))
             "zero control has no reserved bits")
      (check (null (cl-quic-kit:packet-header-key-phase decoded))
             "zero control has no key phase")
      (check (= (cl-quic-kit:packet-header-packet-number-length decoded) 1)
             "zero control has a one-byte packet number")
      (check (= (cl-quic-kit:packet-header-packet-number decoded) #x12)
             "zero control preserves the packet number")
      (check (equalp (cl-quic-kit:packet-header-destination-connection-id decoded)
                     #(#xaa #xbb))
             "zero control preserves the destination ID")
      (check (equalp (cl-quic-kit:packet-header-payload decoded) #(#xde #xad))
             "zero control preserves the payload"))))

(defun packet-reserved-short-encode-wire ()
  ;; RFC 9000 section 17.3.1 assigns reserved bits mask #x18, not spin bit #x20.
  (loop for reserved from 0
        for first-byte in '(#x40 #x48 #x50 #x58) do
    (dolist (key-phase '(nil t))
      (loop for pn-length from 1
            for (pn pn-bytes) in '((#x12 (#x12))
                                   (#x1234 (#x12 #x34))
                                   (#x123456 (#x12 #x34 #x56))
                                   (#x12345678 (#x12 #x34 #x56 #x78))) do
        (let* ((first (+ first-byte (if key-phase 4 0) (1- pn-length)))
               (expected (coerce (append (list first #xaa #xbb) pn-bytes
                                         '(#xde #xad)) 'vector))
               (header (cl-quic-kit:make-packet-header
                        :type :short :destination-connection-id #(#xaa #xbb)
                        :reserved-bits reserved :key-phase key-phase
                        :packet-number pn :packet-number-length pn-length
                        :payload #(#xde #xad))))
          (check (equalp (cl-quic-kit:encode-packet-header header) expected)
                 "short-header encoding matches independent reserved/key-phase/PN bytes")
          (check (equalp (cl-quic-kit:encode-packet-header header :include-payload nil)
                         (subseq expected 0 (+ 3 pn-length)))
                 "header-only encoding preserves reserved/key-phase/PN bytes"))))))

(defun packet-reserved-short-decode-wire ()
  (loop for reserved from 0
        for first-byte in '(#x40 #x48 #x50 #x58) do
    (dolist (spin '(0 #x20))
      (dolist (key-phase '(nil t))
        (loop for pn-length from 1
              for (pn pn-bytes) in '((#x12 (#x12))
                                     (#x1234 (#x12 #x34))
                                     (#x123456 (#x12 #x34 #x56))
                                     (#x12345678 (#x12 #x34 #x56 #x78))) do
          (let ((wire (coerce
                       (append (list (+ first-byte spin (if key-phase 4 0)
                                        (1- pn-length)) #xaa #xbb)
                               pn-bytes '(#xde #xad)) 'vector)))
            (multiple-value-bind (decoded end)
                (cl-quic-kit:decode-packet-header wire :short-header-dcid-length 2)
              (check (= (cl-quic-kit:packet-header-reserved-bits decoded) reserved)
                     "short decoding reads mask #x18 independently of spin")
              (check (eq (cl-quic-kit:packet-header-key-phase decoded) key-phase)
                     "short decoding keeps the key-phase bit independent")
              (check (= (cl-quic-kit:packet-header-packet-number-length decoded) pn-length)
                     "short decoding keeps the packet-number length independent")
              (check (= (cl-quic-kit:packet-header-packet-number decoded) pn)
                     "short decoding preserves the packet number")
              (check (equalp (cl-quic-kit:packet-header-destination-connection-id decoded)
                             #(#xaa #xbb))
                     "short decoding preserves the destination ID")
              (check (equalp (cl-quic-kit:packet-header-payload decoded) #(#xde #xad))
                     "short decoding preserves payload bytes")
              (check (= end (length wire)) "short decoding consumes the wire packet")
              (check (eq (cl-quic-kit:packet-header-type decoded) :short)
                     "short decoding preserves packet type"))))))))

(defun packet-reserved-long-wire-control ()
  (loop for type in '(:initial :0-rtt :handshake)
        for first-bytes in '((#xc0 #xc4 #xc8 #xcc)
                             (#xd0 #xd4 #xd8 #xdc)
                             (#xe0 #xe4 #xe8 #xec)) do
    (loop for reserved from 0
          for first-byte in first-bytes do
      (let* ((header (cl-quic-kit:make-packet-header
                      :type type :version 1 :destination-connection-id #(1)
                      :source-connection-id #(2) :reserved-bits reserved
                      :packet-number 3 :payload #(4 5)))
             (wire (cl-quic-kit:encode-packet-header header)))
        (check (= (aref wire 0) first-byte)
               "long-header reserved mask and packet type remain unchanged")
        (multiple-value-bind (decoded end) (cl-quic-kit:decode-packet-header wire)
          (check (= (cl-quic-kit:packet-header-reserved-bits decoded) reserved)
                 "long decoding keeps its distinct reserved-bit position")
          (check (eq (cl-quic-kit:packet-header-type decoded) type)
                 "long decoding keeps packet-type bits independent")
          (check (and (= end (length wire))
                      (equalp (cl-quic-kit:encode-packet-header decoded) wire))
                 "long-header control preserves the complete wire packet"))))))

(packet-reserved-zero-control)
(packet-reserved-short-encode-wire)
(packet-reserved-short-decode-wire)
(packet-reserved-long-wire-control)
(progn
  (defun packet-reserved-authenticated-wire (client type destination-id source-id)
    (let* ((level (if (eq type :short) :1-rtt :initial))
           (key (cl-quic-kit::%client-key client level :read))
           (plaintext (make-array 4 :element-type (quote (unsigned-byte 8))
                                  :initial-contents (list #x01 #x00 #x00 #x00)))
           (payload (make-array (+ (length plaintext) 16)
                                :element-type (quote (unsigned-byte 8))
                                :initial-element 0))
           (header (cl-quic-kit:make-packet-header
                    :type type :version cl-quic-kit:*quic-version-1*
                    :destination-connection-id destination-id
                    :source-connection-id source-id
                    :reserved-bits 1 :packet-number 0 :packet-number-length 1
                    :payload payload))
           (wire (cl-quic-kit:encode-packet-header header))
           (layout (cl-quic-kit::%client-layout
                    wire :short-header-dcid-length 8))
           (pn-offset (getf layout :pn-offset))
           (associated (subseq wire 0 (1+ pn-offset)))
           (ciphertext (cl-quic-kit.protection:protect-payload
                        key 0 plaintext associated))
           (packet (concatenate (quote (vector (unsigned-byte 8)))
                                associated ciphertext))
           (sample (subseq packet (+ pn-offset 4) (+ pn-offset 20))))
      (cl-quic-kit.protection:apply-header-protection
       key packet sample pn-offset 1 (not (eq type :short)))))

  (defun packet-reserved-authenticated-validation (type)
    (let* ((writes nil)
           (local-id (make-array 8 :element-type (quote (unsigned-byte 8))
                                 :initial-contents (list 1 2 3 4 5 6 7 8)))
           (peer-id (make-array 8 :element-type (quote (unsigned-byte 8))
                                :initial-contents (list 8 7 6 5 4 3 2 1)))
           (secret (make-array 32 :element-type (quote (unsigned-byte 8))
                               :initial-element 17))
           (key (cl-quic-kit.protection:make-key-set secret))
           (client
             (cl-quic-kit:make-quic-client
              :local-connection-id local-id
              :destination-connection-id peer-id
              :disable-hostname-verification-p t
              :io-write (lambda (ignored bytes)
                          (declare (ignore ignored))
                          (push bytes writes))))
           (level (if (eq type :short) :1-rtt :initial)))
      (dolist (key-level (if (eq type :short)
                             (list :initial :1-rtt)
                             (list :initial)))
        (cl-quic-kit::%client-set-key client key-level :read key)
        (cl-quic-kit::%client-set-key client key-level :write key))
      (let* ((wire (packet-reserved-authenticated-wire
                    client type local-id peer-id))
             (layout (cl-quic-kit::%client-layout
                      wire :short-header-dcid-length 8))
             (damaged (copy-seq wire))
             (ciphertext-offset (+ (getf layout :pn-offset) 1)))
        (setf (aref damaged ciphertext-offset)
              (logxor 1 (aref damaged ciphertext-offset)))
        (check (null (cl-quic-kit:client-receive-datagram
                      client damaged :short-header-dcid-length 8))
               "unauthenticated reserved-bit packet is discarded")
        (check (and (not (cl-quic-kit:quic-client-closed-p client))
                    (= (cl-quic-kit::quic-client-authentication-failures client) 1)
                    (null writes))
               "unauthenticated corruption does not close or send")
        (check (null (cl-quic-kit:client-receive-datagram
                      client wire :short-header-dcid-length 8))
               "authenticated non-zero reserved bits are rejected")
        (check (and (cl-quic-kit:quic-client-closed-p client)
                    (eq (cl-quic-kit:connection-state
                         (cl-quic-kit::quic-client-connection client))
                        :closing)
                    writes)
               "authenticated reserved-bit violation emits a close")
        (let* ((response (first writes))
               (response-layout
                 (cl-quic-kit::%client-layout
                  response :short-header-dcid-length 8))
               (peer
                 (cl-quic-kit:make-quic-client
                  :local-connection-id peer-id
                  :destination-connection-id local-id
                  :disable-hostname-verification-p t)))
          (cl-quic-kit::%client-set-key peer level :read key)
          (multiple-value-bind (ignored-level ignored-number close-header)
              (cl-quic-kit::%client-unprotect-packet
               peer response response-layout)
            (declare (ignore ignored-level ignored-number))
            (let ((frame
                    (first (cl-quic-kit:decode-frames
                            (cl-quic-kit:packet-header-payload close-header)))))
              (check (and (eq (cl-quic-kit:frame-type frame) :connection-close)
                          (= (cl-quic-kit:frame-field frame :error-code) #xa))
                     "authenticated reserved-bit violation sends PROTOCOL_VIOLATION")))))))

  (dolist (type (list :initial :short))
    (packet-reserved-authenticated-validation type)))
