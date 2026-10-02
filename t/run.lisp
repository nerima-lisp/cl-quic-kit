(require :asdf)
(when (find-package :asdf)
  (asdf:load-system "cl-crypto-kit")
  (asdf:load-system "cl-tls-kit"))

(load (merge-pathnames "../package.lisp"
                       (or *load-truename* *default-pathname-defaults*)))

(dolist (file '("src/varint.lisp" "src/packet.lisp" "src/frame.lisp"
                "src/flow-control.lisp" "src/stream.lisp" "src/state.lisp"
                "src/udp.lisp" "src/protection.lisp" "src/recovery.lisp"
                "src/client.lisp"))
  (load (merge-pathnames (concatenate 'string "../" file)
                         (or *load-truename* *default-pathname-defaults*))))

(when (and (find-package "CRYPTO-KIT")
           (find-package "CL-QUIC-KIT.PROTECTION"))
  (let ((p (find-package "CL-QUIC-KIT.PROTECTION"))
        (crypto (lambda (name) (symbol-function (find-symbol name "CRYPTO-KIT")))))
    (funcall (find-symbol "CONFIGURE-CRYPTO-BACKEND" p)
             :hkdf-extract (funcall crypto "HKDF-EXTRACT")
             :hkdf-expand (funcall crypto "HKDF-EXPAND")
             :aead-seal (funcall crypto "AEAD-SEAL")
             :aead-open (funcall crypto "AEAD-OPEN")
             :aes-ecb (funcall crypto "AES-ENCRYPT-BLOCK")
             :chacha20 (funcall crypto "CHACHA20-KEYSTREAM")
             :constant-time-equal (funcall crypto "CONSTANT-TIME-EQUAL"))))

(in-package #:cl-user)

(defparameter *tests-run* 0)

(defun check (condition description)
  (incf *tests-run*)
  (unless condition
    (error "Test failed: ~A" description)))

;; Keep the RFC 9001 packet-protection vectors in the flake check, including
;; the deterministic Retry integrity vector from Appendix A.
(load (merge-pathnames "protection.lisp"
                       (or *load-truename* *default-pathname-defaults*)))

(check (= cl-quic-kit:*quic-version-1* #x00000001)
       "QUIC v1 has the RFC 9000 version number")
(check (cl-quic-kit:connection-id-p (make-array 0 :element-type '(unsigned-byte 8)))
       "an empty connection ID is valid")
(check (cl-quic-kit:connection-id-p (make-array 20 :element-type '(unsigned-byte 8)))
       "a twenty-octet connection ID is valid")
(check (not (cl-quic-kit:connection-id-p (make-array 21 :element-type '(unsigned-byte 8))))
       "a twenty-one-octet connection ID is invalid")
(let ((rejected nil))
  (handler-case
      (cl-quic-kit:validate-connection-id "not-octets")
    (cl-quic-kit:invalid-connection-id () (setf rejected t)))
  (check rejected "malformed connection IDs are rejected"))
(let ((encoded (cl-quic-kit:encode-varint 494)))
  (multiple-value-bind (value size) (cl-quic-kit:decode-varint encoded)
    (check (and (= value 494) (= size 2)) "varint round trip")))
(let* ((frame (cl-quic-kit:make-frame :ping))
       (decoded (cl-quic-kit:decode-frame (cl-quic-kit:encode-frame frame))))
  (check (eq (cl-quic-kit:frame-type decoded) :ping) "PING frame round trip"))
(let* ((dcid (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4)))
       (scid (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(5 6 7)))
       (token (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(8 9)))
       (payload (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(10 11 12)))
       (header (cl-quic-kit:make-packet-header
                :type :initial :version cl-quic-kit:*quic-version-1*
                :destination-connection-id dcid :source-connection-id scid
                :token token :packet-number #x1234 :packet-number-length 2 :payload payload))
       (encoded (cl-quic-kit:encode-packet-header header)))
  (multiple-value-bind (decoded end) (cl-quic-kit:decode-packet-header encoded)
    (check (and (= end (length encoded)) (= (cl-quic-kit:packet-header-version decoded) 1)
                (= (cl-quic-kit:packet-header-packet-number decoded) #x1234)
                (equalp (cl-quic-kit:packet-header-payload decoded) payload))
           "long header packet round trip")))
(let* ((dcid (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(1 2)))
       (payload (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(3 4)))
       (header (cl-quic-kit:make-packet-header
                :type :short :destination-connection-id dcid :packet-number #x7f
                :reserved-bits 3 :key-phase t :payload payload))
       (encoded (cl-quic-kit:encode-packet-header header)))
  (multiple-value-bind (decoded end)
      (cl-quic-kit:decode-packet-header encoded :short-header-dcid-length 2)
    (check (and (= end (length encoded)) (= (cl-quic-kit:packet-header-reserved-bits decoded) 3)
                (cl-quic-kit:packet-header-key-phase decoded)
                (equalp (cl-quic-kit:packet-header-payload decoded) payload))
           "short header packet round trip")))
(let* ((tag (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xaa))
       (header (cl-quic-kit:make-packet-header
                :type :retry :version 1 :destination-connection-id #() :source-connection-id #(1)
                :token #(2 3) :retry-integrity-tag tag))
       (decoded (multiple-value-list
                 (cl-quic-kit:decode-packet-header
                  (cl-quic-kit:encode-packet-header header)))))
  (check (and (equalp (cl-quic-kit:packet-header-token (first decoded)) #(2 3))
              (equalp (cl-quic-kit:packet-header-retry-integrity-tag (first decoded)) tag))
         "Retry packet preserves token and integrity tag"))
(let* ((encoded (cl-quic-kit:encode-version-negotiation #(1 2) #(3) '(1 #x6b3343cf)))
       (decoded (cl-quic-kit:decode-version-negotiation encoded)))
  (check (equal (getf decoded :versions) '(1 #x6b3343cf))
         "Version Negotiation round trip"))
(let* ((parameters '((1 . 30) (4 . 1200) (0 . #(1 2)) (12 . #())))
       (decoded (cl-quic-kit:decode-transport-parameters
                 (cl-quic-kit:encode-transport-parameters parameters))))
  (check (equalp decoded parameters) "transport parameter integer and opaque values round trip"))
(let* ((frame (cl-quic-kit:make-frame :ack-ecn :largest-acknowledged 10 :ack-delay 2
                                      :ranges (list (cons 10 2) (list :gap 1 :range-length 1))
                                      :ect0 3 :ect1 4 :ecn-ce 5))
       (decoded (cl-quic-kit:decode-frame (cl-quic-kit:encode-frame frame))))
  (check (and (eq (cl-quic-kit:frame-type decoded) :ack-ecn)
              (= (cl-quic-kit:frame-field decoded :ect0) 3)
              (= (length (cl-quic-kit:frame-field decoded :ranges)) 2))
         "ACK ECN ranges round trip"))
(let* ((encoded (cl-quic-kit:encode-frames
                 (list (cl-quic-kit:make-frame :padding :count 3)
                       (cl-quic-kit:make-frame :application-close :error-code 7 :reason #(1 2)))))
       (decoded (cl-quic-kit:decode-frames encoded)))
  (check (and (= (cl-quic-kit:frame-field (first decoded) :count) 3)
              (eq (cl-quic-kit:frame-type (second decoded)) :application-close))
         "PADDING and application close frames round trip"))
(let* ((stream (cl-quic-kit:make-stream 0 :local-initiator :client))
       (payload (make-array 3 :element-type '(unsigned-byte 8)
                            :initial-contents '(1 2 3))))
  (cl-quic-kit:stream-receive-data stream 0 payload :fin t)
  (multiple-value-bind (data fin) (cl-quic-kit:stream-read stream)
    (check (and fin (equalp data payload)) "ordered stream data and FIN")))
(let ((clock 0) (connection nil))
  (setf connection (cl-quic-kit:make-quic-connection
                    :now-fn (lambda () clock) :idle-timeout 10))
  (cl-quic-kit:connection-set-state connection :established)
  (setf clock 10)
  (check (cl-quic-kit:connection-check-idle-timeout connection clock)
         "idle timeout closes established connection"))
(let ((clock 0) (writes nil)
      (cid (make-array 8 :element-type '(unsigned-byte 8) :initial-element 1)))
  (let ((connection (cl-quic-kit:make-quic-connection
                    :local-connection-id cid :now-fn (lambda () clock)
                    :active-connection-id-limit 2
                    :io-write (lambda (connection bytes)
                                (declare (ignore connection))
                                (push bytes writes)))))
    (check (= (length (cl-quic-kit:connection-local-connection-ids connection)) 1)
           "the original connection ID is active")
    (cl-quic-kit:connection-handle-new-connection-id
     connection 1 (make-array 8 :element-type '(unsigned-byte 8) :initial-element 2))
    (check (= (length (cl-quic-kit:connection-remote-connection-ids connection)) 1)
           "NEW_CONNECTION_ID is tracked")
    (cl-quic-kit:connection-handle-new-connection-id
     connection 2 (make-array 8 :element-type '(unsigned-byte 8) :initial-element 3))
    (cl-quic-kit:connection-handle-new-connection-id
     connection 3 (make-array 8 :element-type '(unsigned-byte 8) :initial-element 4))
    (check (eq (cl-quic-kit:connection-state connection) :closing)
           "active connection ID limit starts a transport close")
    (check (= (length writes) 1) "transport close is written through injected I/O")))
(let ((writes nil)
      (cid (make-array 8 :element-type '(unsigned-byte 8) :initial-element 1)))
  (let ((connection (cl-quic-kit:make-quic-connection
                    :local-connection-id cid
                    :io-write (lambda (connection bytes)
                                (declare (ignore connection))
                                (push bytes writes)))))
    (cl-quic-kit:connection-handle-new-connection-id
     connection 1 (make-array 8 :element-type '(unsigned-byte 8) :initial-element 2)
     :retire-prior-to 2)
    (check (null (cl-quic-kit:connection-remote-connection-ids connection))
           "NEW_CONNECTION_ID retires IDs below Retire Prior To before adding")
    (check (= (length writes) 1)
           "a NEW_CONNECTION_ID below Retire Prior To is retired on receipt")
    (cl-quic-kit:connection-handle-new-connection-id
     connection 1 (make-array 8 :element-type '(unsigned-byte 8) :initial-element 3)
     :retire-prior-to 2)
    (check (eq (cl-quic-kit:connection-state connection) :closing)
           "reusing a connection ID sequence with a different ID closes the connection")))
(let ((clock 0) (writes nil))
  (let ((connection (cl-quic-kit:make-quic-connection
                    :now-fn (lambda () clock) :idle-timeout 10
                    :io-write (lambda (connection bytes)
                                (declare (ignore connection))
                                (push bytes writes)))))
    (cl-quic-kit:connection-set-state connection :established)
    (cl-quic-kit:connection-close connection 42 "transport failure")
    (check (eq (cl-quic-kit:connection-state connection) :closing)
           "CONNECTION_CLOSE enters closing")
    (check (= (length writes) 1) "CONNECTION_CLOSE uses injected output")
    (cl-quic-kit:connection-receive-frame
     connection (cl-quic-kit:make-frame :application-close :error-code 7 :reason #()))
    (check (eq (cl-quic-kit:connection-state connection) :draining)
           "peer application close enters draining")
    (setf clock 30)
    (check (cl-quic-kit:connection-poll connection clock)
           "draining deadline closes the connection")))
(let ((connection (cl-quic-kit:make-quic-connection :now-fn (lambda () 0)))
      (bad-packet (make-array 1 :element-type '(unsigned-byte 8) :initial-element 255)))
  (check (null (cl-quic-kit:connection-receive-packet connection bad-packet))
         "malformed packet is rejected")
  (check (eq (cl-quic-kit:connection-state connection) :closing)
         "malformed packet schedules CONNECTION_CLOSE"))
(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (cl-quic-kit.recovery:on-packet-received state :initial 1)
  (check (cl-quic-kit.recovery:ack-needed-p state :initial :now 0)
         "ack eliciting packet schedules ACK"))
(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0)
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame state :application 1 '((1 1))
                                         :received-at 1/10)
    (check (and (= (length acked) 1) (null lost))
           "ACK acknowledges the largest sent packet")
    (check (and (= (cl-quic-kit.recovery:recovery-state-latest-rtt state) 1/10)
                (= (cl-quic-kit.recovery:recovery-state-smoothed-rtt state) 1/10)
                (= (cl-quic-kit.recovery:recovery-state-rtt-variance state) 1/20)
                (= (cl-quic-kit.recovery:recovery-state-min-rtt state) 1/10))
           "first ACK initializes RTT sample state")))
(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (dotimes (number 4)
    (cl-quic-kit.recovery:record-sent-packet state :application (1+ number) 1200
                                             :sent-at 0))
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame state :application 4 '((4 4))
                                         :received-at 0)
    (check (= (length acked) 1) "packet threshold ACK keeps the largest packet")
    (check (= (length lost) 1) "packet threshold marks packet three numbers behind lost")))
(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 1))))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0)
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200
                                           :ack-eliciting-p nil :in-flight-p nil
                                           :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 2 '((2 2))
                                     :received-at 0)
  (check (= (cl-quic-kit.recovery:loss-timeout state :application)
            (* 9/8 333/1000))
         "loss timeout exposes the earliest time-threshold deadline"))
(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0
                                           :ack-eliciting-p nil :in-flight-p nil)
  (check (null (cl-quic-kit.recovery:pto-deadline state :application))
         "non-ack-eliciting packets do not arm PTO")
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200 :sent-at 0)
  (check (= (cl-quic-kit.recovery:pto-deadline state :application) (* 2 333/1000))
         "initial PTO uses twice the initial RTT")
  (let ((probe (cl-quic-kit.recovery:on-pto-expired state)))
    (check (and (= (getf probe :probe-count) 2)
                (= (getf probe :pto-count) 1))
           "PTO expiry requests two probe packets"))
  (check (= (cl-quic-kit.recovery:pto-deadline state :application)
            (+ (* 2 333/1000) (* 2 333/1000)))
         "PTO deadline doubles after an expiry"))
(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 4))))
  (cl-quic-kit.recovery:record-sent-packet state :application 0 1200 :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 0 '((0 0))
                                     :received-at 1/10)
  (dotimes (number 3)
    (cl-quic-kit.recovery:record-sent-packet state :application (1+ number) 1200
                                             :sent-at number))
  (cl-quic-kit.recovery:record-sent-packet state :application 4 1200
                                           :ack-eliciting-p nil :in-flight-p nil
                                           :sent-at 3)
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame state :application 4 '((4 4))
                                         :received-at 4)
    (declare (ignore acked))
    (check (= (length lost) 3) "time-threshold loss reports all overdue packets")
    (check (cl-quic-kit.recovery:recovery-state-persistent-congestion-p state)
           "a loss span of three PTOs enters persistent congestion")
    (check (= (cl-quic-kit.recovery:recovery-state-cwnd state) 2400)
           "persistent congestion reduces cwnd to the minimum window")))
(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0)
                                                        :initial-cwnd 12000)))
  (check (= (progn (cl-quic-kit.recovery:newreno-on-ack state 1200) 13200)
            (cl-quic-kit.recovery:recovery-state-cwnd state))
         "NewReno slow start increases cwnd by acknowledged bytes")
  (cl-quic-kit.recovery:newreno-on-loss state :at 1)
  (check (and (= (cl-quic-kit.recovery:recovery-state-cwnd state) 6600)
              (= (cl-quic-kit.recovery:recovery-state-ssthresh state) 6600))
         "NewReno loss enters congestion avoidance at half cwnd")
  (cl-quic-kit.recovery:newreno-on-ack state 1200 :sent-at 1)
  (check (= (cl-quic-kit.recovery:recovery-state-cwnd state) 6600)
         "ACKs for pre-recovery packets do not grow cwnd")
  (cl-quic-kit.recovery:newreno-on-ack state 1200 :sent-at 2)
  (check (= (cl-quic-kit.recovery:recovery-state-cwnd state) 6818)
         "NewReno congestion avoidance grows cwnd by MSS squared over cwnd"))
(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (cl-quic-kit.recovery:record-sent-packet state :application 0 1200 :sent-at 0)
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0)
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200 :sent-at 0)
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame state :application 2 '((2 2))
                                         :received-at 1/10)
    (check (and (= (length acked) 1) (null lost))
           "ACK leaves below-threshold packets for time loss detection"))
  (multiple-value-bind (lost deadline)
      (cl-quic-kit.recovery:on-loss-timeout state :application :now 1)
    (check (and deadline (= (length lost) 2))
           "time-threshold loss removes and returns expired packets")))
(load (merge-pathnames "protection.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(let ((socket (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                            :local-port 0)))
  (unwind-protect
       (multiple-value-bind (data length address)
           (cl-quic-kit:udp-receive socket)
         (check (and (null data) (null length) (null address))
                "non-blocking UDP receive reports no datagram cleanly"))
    (cl-quic-kit:udp-close socket)))
(load (merge-pathnames "client.lisp"
                       (or *load-truename* *default-pathname-defaults*)))

(let* ((client (cl-quic-kit:make-quic-client))
       (control (cl-quic-kit:client-open-stream client nil :stream-type :control)))
  (check (= (cl-quic-kit::stream-send-offset control) 1)
         "HTTP/3 unidirectional stream reserves its type byte"))

(let ((client (cl-quic-kit:make-quic-client)))
  (setf (cl-quic-kit::quic-client-received-packets client)
        (list (cons :1-rtt '(6 5 3 2))))
  (let ((frame (cl-quic-kit::%client-ack-frame client :1-rtt)))
    (check (equal (cl-quic-kit:frame-field frame :ranges)
                  '((6 . 1) (:gap 0 :range-length 1)))
           "ACK encodes the gap between disjoint packet ranges")))

(check (eq (cl-quic-kit::%client-crypto-signature-scheme
            :ecdsa-secp256r1-sha256)
           :ecdsa-p256-sha256)
       "TLS ECDSA scheme is normalized at the client provider boundary")

(defun %client-test-octets (values)
  (make-array (length values) :element-type '(unsigned-byte 8)
              :initial-contents values))

(let* ((destination (%client-test-octets '(16 17 18 19 20 21 22 23)))
       (sender-id (%client-test-octets '(32 33 34 35 36 37 38 39)))
       (receiver-id (%client-test-octets '(48 49 50 51 52 53 54 55)))
       (wire nil)
       (ack-wire nil)
       (sender (cl-quic-kit:make-quic-client
                :local-connection-id sender-id
                :destination-connection-id destination
                :hostname "localhost"
                :io-write (lambda (connection bytes)
                            (declare (ignore connection))
                            (setf wire bytes))
                :now-fn (lambda () 0)))
       (receiver (cl-quic-kit:make-quic-client
                  :local-connection-id receiver-id
                  :destination-connection-id destination
                  :io-write (lambda (connection bytes)
                              (declare (ignore connection))
                              (setf ack-wire bytes))
                  :now-fn (lambda () 0))))
  (cl-quic-kit:client-start sender)
  (check (and wire (>= (length wire) 1200))
         "client-start emits a protected Initial packet of at least 1200 octets")
  (cl-quic-kit::%client-set-key
   receiver :initial :read (cl-quic-kit::%client-key sender :initial :write))
  (cl-quic-kit::%client-set-key
   receiver :initial :write (cl-quic-kit::%client-key sender :initial :read))
  (check (cl-quic-kit:client-receive-datagram receiver wire)
         "peer decrypts the protected Initial packet")
  (setf wire nil ack-wire nil)
  (cl-quic-kit:client-poll receiver 0)
  (check ack-wire "peer emits an ACK packet after receiving an ack-eliciting Initial")
  (check (cl-quic-kit:client-receive-datagram sender ack-wire)
         "client decrypts the Initial ACK")
  (setf ack-wire nil)
  (cl-quic-kit:client-poll receiver 0)
  (check (null ack-wire) "an ACK is not retransmitted after being sent")

  (let ((handshake-secret
          (%client-test-octets
           '(96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111
             112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127)))
        (application-secret
          (%client-test-octets
           '(64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79
             80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95))))
    (cl-quic-kit::%client-set-key
     sender :handshake :write
     (cl-quic-kit.protection:make-key-set handshake-secret))
    (cl-quic-kit::%client-set-key
     receiver :handshake :read
     (cl-quic-kit::%client-key sender :handshake :write))
    (setf wire nil)
    (cl-quic-kit::%client-queue-frame sender (cl-quic-kit:make-frame :ping)
                                      :handshake)
    (cl-quic-kit:client-flush sender)
    (check wire "client encrypts a Handshake packet")
    (check (cl-quic-kit:client-receive-datagram receiver wire)
           "peer decrypts the Handshake packet")

    (cl-quic-kit::%client-set-key
     sender :1-rtt :write
     (cl-quic-kit.protection:make-key-set application-secret))
    (cl-quic-kit::%client-set-key
     receiver :1-rtt :read
     (cl-quic-kit::%client-key sender :1-rtt :write))
    (let* ((stream (cl-quic-kit:client-open-stream sender nil))
           (request (%client-test-octets
                     '(71 69 84 32 47 32 72 84 84 80 47 51 10))))
      (cl-quic-kit:client-write-stream sender stream request :fin-p t)
      (setf wire nil)
      (cl-quic-kit:client-flush sender)
      (check wire "client encrypts a 1-RTT STREAM packet")
      (check (cl-quic-kit:client-receive-datagram receiver wire)
             "peer decrypts the 1-RTT STREAM packet")
      (let ((peer-stream (gethash 0 (cl-quic-kit::quic-client-streams receiver))))
        (multiple-value-bind (data fin)
            (cl-quic-kit:client-read-stream receiver peer-stream)
          (check (and (equalp data request) fin)
                 "peer exposes received 1-RTT stream data")))
      (setf wire nil)
      (cl-quic-kit:client-poll sender (* 2 333/1000))
      (check wire "PTO sends a protected 1-RTT probe after the stream packet is dropped")
      (check (cl-quic-kit:client-receive-datagram receiver wire)
             "peer decrypts the 1-RTT PTO probe")))

  (let ((idle-wire nil))
    (let ((idle-client
            (cl-quic-kit:make-quic-client
             :local-connection-id sender-id
             :destination-connection-id destination
             :idle-timeout 5
             :io-write (lambda (connection bytes)
                         (declare (ignore connection))
                         (setf idle-wire bytes))
             :now-fn (lambda () 0))))
      (cl-quic-kit:client-poll idle-client 5)
      (check (and (cl-quic-kit::quic-client-closed-p idle-client) idle-wire)
             "idle timeout emits a protected CONNECTION_CLOSE")))

  (let* ((vn (cl-quic-kit:encode-version-negotiation
              sender-id receiver-id (list cl-quic-kit:*quic-version-1* #x6b3343cf)))
         (bad (make-array 1 :element-type '(unsigned-byte 8) :initial-element #xff)))
    (check (null (cl-quic-kit:client-receive-datagram sender vn))
           "client accepts Version Negotiation advertising QUIC v1")
    (cl-quic-kit:client-receive-datagram receiver bad)
    (check (and (cl-quic-kit::quic-client-closed-p receiver)
                (eq (cl-quic-kit:connection-state
                     (cl-quic-kit::quic-client-connection receiver))
                    :closing)
                ack-wire)
           "malformed packet transitions the client to protocol close"))

  (let* ((retry-token (%client-test-octets '(6 7)))
         (retry-scid (%client-test-octets '(80 81 82 83 84 85 86 87)))
         (zero-tag (make-array 16 :element-type '(unsigned-byte 8)
                               :initial-element 0))
         (without-tag
           (cl-quic-kit:encode-packet-header
            (cl-quic-kit:make-packet-header
             :type :retry :version cl-quic-kit:*quic-version-1*
             :destination-connection-id sender-id
             :source-connection-id retry-scid :token retry-token
             :retry-integrity-tag zero-tag)))
         (pseudo (subseq without-tag 0 (- (length without-tag) 16)))
         (tag (cl-quic-kit:retry-integrity-tag
               pseudo :original-destination-connection-id destination))
         (retry
           (cl-quic-kit:encode-packet-header
            (cl-quic-kit:make-packet-header
             :type :retry :version cl-quic-kit:*quic-version-1*
             :destination-connection-id sender-id
             :source-connection-id retry-scid :token retry-token
             :retry-integrity-tag tag))))
    (setf (cl-quic-kit::quic-client-closed-p sender) nil)
    (check (null (cl-quic-kit:client-receive-datagram sender retry))
           "client processes a valid Retry packet")
    (check (and (equalp (cl-quic-kit::quic-client-retry-token sender) retry-token)
                (equalp (cl-quic-kit::quic-client-remote-connection-id sender)
                        retry-scid))
           "Retry replaces the token and remote connection ID")
    (check (zerop (or (cl-quic-kit::%client-level-value
                       (cl-quic-kit::quic-client-packet-numbers sender) :initial)
                      0))
           "Retry resets the Initial packet number space")
    (setf wire nil)
    (cl-quic-kit:client-flush sender)
    (check (and wire
                (equalp (getf (cl-quic-kit::%client-layout wire) :token)
                        retry-token))
           "Retry retransmits ClientHello with the Retry token")))
(format t "~D tests passed.~%" *tests-run*)
