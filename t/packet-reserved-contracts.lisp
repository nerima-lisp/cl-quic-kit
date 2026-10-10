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
