(load (merge-pathnames "../package.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/varint.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/packet.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/frame.lisp"
                       (or *load-truename* *default-pathname-defaults*)))

(in-package #:cl-user)

(defparameter *codec-tests-run* 0)

(defun codec-check (condition description)
  (incf *codec-tests-run*)
  (unless condition
    (error "Codec test failed: ~A" description)))

(defun codec-rejects-p (thunk)
  (handler-case
      (progn (funcall thunk) nil)
    (cl-quic-kit:quic-encoding-error () t)))

(defun codec-octets (&rest parts)
  (let ((values (apply #'append (mapcar (lambda (part) (coerce part 'list)) parts))))
    (make-array (length values) :element-type '(unsigned-byte 8)
                :initial-contents values)))

(defun codec-copy (octets)
  (replace (make-array (length octets) :element-type '(unsigned-byte 8)) octets))

(defun codec-frame-round-trip (frame description)
  (let* ((encoded (cl-quic-kit:encode-frame frame))
         (decoded (cl-quic-kit:decode-frame encoded)))
    (codec-check (eq (cl-quic-kit:frame-type decoded)
                     (cl-quic-kit:frame-type frame))
                 (concatenate 'string description " keeps its type"))
    (codec-check (equalp encoded
                         (cl-quic-kit:encode-frame (first (multiple-value-list decoded))))
                 (concatenate 'string description " preserves its wire form"))))

(let* ((dcid #(1 2 3 4))
       (scid #(5 6 7))
       (token #(8 9))
       (payload #(10 11 12))
       (header (cl-quic-kit:make-packet-header
                :type :initial :version cl-quic-kit:*quic-version-1*
                :destination-connection-id dcid :source-connection-id scid
                :token token :packet-number #x1234 :packet-number-length 2
                :reserved-bits 2 :payload payload))
       (encoded (cl-quic-kit:encode-packet-header header)))
  (multiple-value-bind (decoded end)
      (cl-quic-kit:decode-packet-header encoded)
    (codec-check (= end (length encoded)) "Initial header consumes its declared packet")
    (codec-check (and (eq (cl-quic-kit:packet-header-type decoded) :initial)
                      (= (cl-quic-kit:packet-header-version decoded) 1)
                      (= (cl-quic-kit:packet-header-packet-number decoded) #x1234)
                      (= (cl-quic-kit:packet-header-payload-length decoded)
                         (+ 2 (length payload)))
                      (= (cl-quic-kit:packet-header-reserved-bits decoded) 2)
                      (equalp (cl-quic-kit:packet-header-token decoded) token)
                      (equalp (cl-quic-kit:packet-header-payload decoded) payload))
                 "Initial header round trips all fields")))

(dolist (type '(:0-rtt :handshake))
  (let* ((header (cl-quic-kit:make-packet-header
                  :type type :version 1 :destination-connection-id #(1)
                  :source-connection-id #(2) :packet-number 3
                  :packet-number-length 1 :payload #(4 5)))
         (encoded (cl-quic-kit:encode-packet-header header)))
    (multiple-value-bind (decoded end)
        (cl-quic-kit:decode-packet-header encoded)
      (codec-check (and (= end (length encoded))
                        (eq (cl-quic-kit:packet-header-type decoded) type)
                        (equalp (cl-quic-kit:packet-header-payload decoded) #(4 5)))
                   (format nil "~A header round trip" type)))))

(let* ((header (cl-quic-kit:make-packet-header
                :type :short :destination-connection-id #(1 2)
                :packet-number #x7f :packet-number-length 1
                :reserved-bits 3 :key-phase t :payload #(3 4)))
       (encoded (cl-quic-kit:encode-packet-header header)))
  (multiple-value-bind (decoded end)
      (cl-quic-kit:decode-packet-header encoded :short-header-dcid-length 2)
    (codec-check (and (= end (length encoded))
                      (= (cl-quic-kit:packet-header-reserved-bits decoded) 3)
                      (cl-quic-kit:packet-header-key-phase decoded)
                      (equalp (cl-quic-kit:packet-header-payload decoded) #(3 4)))
                 "short header round trips reserved bits and key phase")))

(let* ((tag (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xaa))
       (header (cl-quic-kit:make-packet-header
                :type :retry :version 1 :destination-connection-id #(1 2)
                :source-connection-id #(3) :token #(4 5)
                :retry-integrity-tag tag))
       (encoded (cl-quic-kit:encode-packet-header header)))
  (codec-check (= (aref encoded 0) #xf0) "Retry has no packet-number bits")
  (multiple-value-bind (decoded end)
      (cl-quic-kit:decode-packet-header encoded)
    (codec-check (and (= end (length encoded))
                      (equalp (cl-quic-kit:packet-header-token decoded) #(4 5))
                      (equalp (cl-quic-kit:packet-header-retry-integrity-tag decoded) tag)
                      (= (cl-quic-kit:packet-header-packet-number-length decoded) 0)
                      (equalp encoded (cl-quic-kit:encode-packet-header decoded)))
                 "Retry preserves token, tag, and header representation")))

(codec-check (codec-rejects-p
              (lambda ()
                (cl-quic-kit:encode-packet-header
                 (cl-quic-kit:make-packet-header
                  :type :0-rtt :version 1 :destination-connection-id #()
                  :token #(1) :packet-number 0))))
             "0-RTT rejects a token")
(codec-check (codec-rejects-p
              (lambda ()
                (let ((bytes (codec-copy
                              (cl-quic-kit:encode-packet-header
                               (cl-quic-kit:make-packet-header
                                :type :short :destination-connection-id #(1)
                                :packet-number 0)))))
                  (setf (aref bytes 0) (logand (aref bytes 0) #xbf))
                  (cl-quic-kit:decode-packet-header bytes
                                                    :short-header-dcid-length 1))))
             "short headers require the fixed bit")
(codec-check (codec-rejects-p
              (lambda ()
                (let ((bytes (codec-copy
                              (cl-quic-kit:encode-packet-header
                               (cl-quic-kit:make-packet-header
                                :type :retry :version 1
                                :destination-connection-id #(1)
                                :source-connection-id #(2)
                                :token #() :retry-integrity-tag
                                (make-array 16 :element-type '(unsigned-byte 8)))))))
                  (setf (aref bytes 0) (logior (aref bytes 0) 1))
                  (cl-quic-kit:decode-packet-header bytes))))
             "Retry rejects nonzero unused bits")

(let* ((encoded (cl-quic-kit:encode-version-negotiation
                 #(1 2) #(3) '(1 #x6b3343cf)))
       (decoded (cl-quic-kit:decode-version-negotiation encoded)))
  (codec-check (and (= (getf decoded :version) 0)
                    (equalp (getf decoded :destination-connection-id) #(1 2))
                    (equalp (getf decoded :source-connection-id) #(3))
                    (equal (getf decoded :versions) '(1 #x6b3343cf)))
               "Version Negotiation round trips")
  (codec-check (codec-rejects-p
                (lambda ()
                  (cl-quic-kit:decode-packet-header encoded)))
               "generic packet decoding does not misclassify Version Negotiation"))
(codec-check (codec-rejects-p
              (lambda () (cl-quic-kit:encode-version-negotiation #() #() nil)))
             "Version Negotiation requires a nonempty version list")
(codec-check (codec-rejects-p
              (lambda () (cl-quic-kit:encode-version-negotiation #() #() '(0))))
             "Version Negotiation does not advertise version zero")
(codec-check (codec-rejects-p
              (lambda ()
                (let ((bytes (codec-copy
                              (cl-quic-kit:encode-version-negotiation
                               #(1) #(2) '(1)))))
                  (setf (aref bytes 4) 1)
                  (cl-quic-kit:decode-version-negotiation bytes))))
             "Version Negotiation validates its version field")

(let ((preferred (make-array 42 :element-type '(unsigned-byte 8)
                             :initial-element 0)))
  (setf (aref preferred 24) 1
        (aref preferred 25) #xaa
        (aref preferred 41) #xbb)
  (let* ((parameters
           (list (cons 0 #(1 2)) (cons 1 30) (cons 2 (make-array 16
                                                                   :element-type '(unsigned-byte 8)
                                                                   :initial-element #x10))
                 (cons 3 1200) (cons 4 100) (cons 5 101) (cons 6 102)
                 (cons 7 103) (cons 8 4) (cons 9 5) (cons 10 20)
                 (cons 11 #x3fff) (cons 12 #()) (cons 13 preferred)
                 (cons 14 2) (cons 15 #(3)) (cons 16 #(4 5))
                 (cons 17 1400) (cons 100 #(6 7))))
         (decoded (cl-quic-kit:decode-transport-parameters
                   (cl-quic-kit:encode-transport-parameters parameters))))
    (codec-check (equalp decoded parameters)
                 "all supported transport parameters round trip")))
(codec-check (codec-rejects-p
              (lambda ()
                (cl-quic-kit:encode-transport-parameters '((1 . 1) (1 . 2)))))
             "transport parameter encoding rejects duplicates")
(codec-check (codec-rejects-p
              (lambda ()
                (cl-quic-kit:decode-transport-parameters
                 (codec-octets (cl-quic-kit:encode-varint 1)
                               (cl-quic-kit:encode-varint 0)))))
             "transport parameter decoding rejects an empty integer")
(codec-check (codec-rejects-p
              (lambda ()
                (cl-quic-kit:encode-transport-parameters '((3 . 1199)))))
             "transport parameters enforce the UDP payload minimum")
(codec-check (codec-rejects-p
              (lambda ()
                (cl-quic-kit:encode-transport-parameters
                 (list (cons 13 (make-array 41 :element-type '(unsigned-byte 8)))))))
             "preferred_address requires a nonempty connection ID")

(dolist (case
          (list
           (list (cl-quic-kit:make-frame :padding :count 3) "PADDING")
           (list (cl-quic-kit:make-frame :ping) "PING")
           (list (cl-quic-kit:make-frame :ack :largest-acknowledged 10
                                         :ack-delay 2
                                         :ranges (list (cons 10 2)
                                                       (list :gap 1 :range-length 1)))
                 "ACK")
           (list (cl-quic-kit:make-frame :ack-ecn :largest-acknowledged 10
                                         :ack-delay 2
                                         :ranges (list (cons 10 2)
                                                       (list :gap 1 :range-length 1))
                                         :ect0 3 :ect1 4 :ecn-ce 5)
                 "ACK ECN")
           (list (cl-quic-kit:make-frame :reset-stream :stream-id 1
                                         :application-protocol-error-code 2
                                         :final-size 3)
                 "RESET_STREAM")
           (list (cl-quic-kit:make-frame :stop-sending :stream-id 1
                                         :application-protocol-error-code 2)
                 "STOP_SENDING")
           (list (cl-quic-kit:make-frame :crypto :offset 4 :data #(1 2)) "CRYPTO")
           (list (cl-quic-kit:make-frame :new-token :token #(1 2)) "NEW_TOKEN")
           (list (cl-quic-kit:make-frame :stream :stream-id 1 :offset 4
                                         :data #(1 2) :fin t)
                 "STREAM")
           (list (cl-quic-kit:make-frame :max-data :maximum 10) "MAX_DATA")
           (list (cl-quic-kit:make-frame :max-stream-data :stream-id 2
                                         :maximum 11)
                 "MAX_STREAM_DATA")
           (list (cl-quic-kit:make-frame :max-streams-bidi :maximum 12)
                 "MAX_STREAMS_BIDI")
           (list (cl-quic-kit:make-frame :max-streams-uni :maximum 13)
                 "MAX_STREAMS_UNI")
           (list (cl-quic-kit:make-frame :data-blocked :maximum 14) "DATA_BLOCKED")
           (list (cl-quic-kit:make-frame :stream-data-blocked :stream-id 2
                                         :maximum 15)
                 "STREAM_DATA_BLOCKED")
           (list (cl-quic-kit:make-frame :streams-blocked-bidi :maximum 16)
                 "STREAMS_BLOCKED_BIDI")
           (list (cl-quic-kit:make-frame :streams-blocked-uni :maximum 17)
                 "STREAMS_BLOCKED_UNI")
           (list (cl-quic-kit:make-frame :new-connection-id :sequence 1
                                         :retire-prior-to 0
                                         :connection-id #(1)
                                         :stateless-reset-token
                                         (make-array 16 :element-type '(unsigned-byte 8)
                                                     :initial-element #x20))
                 "NEW_CONNECTION_ID")
           (list (cl-quic-kit:make-frame :retire-connection-id :sequence 1)
                 "RETIRE_CONNECTION_ID")
           (list (cl-quic-kit:make-frame :path-challenge :data #(1 2 3 4 5 6 7 8))
                 "PATH_CHALLENGE")
           (list (cl-quic-kit:make-frame :path-response :data #(8 7 6 5 4 3 2 1))
                 "PATH_RESPONSE")
           (list (cl-quic-kit:make-frame :connection-close :error-code 1
                                         :frame-type 6 :reason #(111 107))
                 "CONNECTION_CLOSE")
           (list (cl-quic-kit:make-frame :application-close :error-code 2
                                         :reason #(98 121 101))
                 "APPLICATION_CLOSE")
           (list (cl-quic-kit:make-frame :handshake-done) "HANDSHAKE_DONE")
           (list (cl-quic-kit:make-frame :datagram :data #(9 8 7)) "DATAGRAM")))
  (codec-frame-round-trip (first case) (second case)))

(let* ((stream (cl-quic-kit:make-frame :stream :stream-id 1 :data #(1 2)))
       (encoded (cl-quic-kit:encode-frame stream))
       (decoded (first (multiple-value-list
                       (cl-quic-kit:decode-frame encoded)))))
  (codec-check (equalp encoded (cl-quic-kit:encode-frame decoded))
               "STREAM without OFFSET preserves its flag bits"))
(codec-check
 (codec-rejects-p
  (lambda ()
    (cl-quic-kit:decode-frame (codec-octets (cl-quic-kit:encode-varint #x11)
                                           (cl-quic-kit:encode-varint 1)))))
 "MAX_STREAM_DATA requires both stream ID and limit")
(codec-check (codec-rejects-p
              (lambda ()
                (cl-quic-kit:encode-frame
                 (cl-quic-kit:make-frame :new-connection-id
                  :sequence 1 :retire-prior-to 0 :connection-id #()
                  :stateless-reset-token
                  (make-array 16 :element-type '(unsigned-byte 8))))))
             "NEW_CONNECTION_ID rejects an empty connection ID")
(codec-check (codec-rejects-p
              (lambda ()
                (cl-quic-kit:encode-frame
                 (cl-quic-kit:make-frame :application-close :error-code 1
                                         :reason #(255)))))
             "CONNECTION_CLOSE rejects invalid UTF-8")
(codec-check (codec-rejects-p
              (lambda ()
                (cl-quic-kit:encode-frames
                 (list (cl-quic-kit:make-frame :datagram :data #(1)
                                               :len-present nil)
                       (cl-quic-kit:make-frame :ping)))))
             "implicit-length frames must be last")

(format t "~D codec tests passed.~%" *codec-tests-run*)
