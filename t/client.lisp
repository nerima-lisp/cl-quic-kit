(in-package #:cl-user)

(let* ((writes nil)
       (connection (cl-quic-kit:make-quic-connection
                    :io-write (lambda (ignored bytes)
                                (declare (ignore ignored))
                                (push bytes writes)))))
  (let* ((client (cl-quic-kit:make-quic-client
                  :connection connection
                  :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                  :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                  :disable-hostname-verification-p t))
         (stream (cl-quic-kit:client-open-stream client nil))
         (payload (make-array 3 :element-type '(unsigned-byte 8)
                              :initial-contents '(7 8 9))))
    (cl-quic-kit:client-write-stream client stream payload)
    (cl-quic-kit:client-poll client)
    (let ((frame (cl-quic-kit:decode-frame (first writes))))
             (check (and (eq (cl-quic-kit:frame-type frame) :stream)
                  (= (cl-quic-kit:frame-field frame :stream-id) 0)
                  (equalp (cl-quic-kit:frame-field frame :data) payload))
             "client stream writes are encoded through the injected connection I/O"))))

(let* ((connection (cl-quic-kit:make-quic-connection))
       (client (cl-quic-kit:make-quic-client
                :connection connection
                :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :disable-hostname-verification-p t))
       (stream (cl-quic-kit:client-open-stream client nil))
       (message nil)
       (report nil))
  (cl-quic-kit:client-close-stream client stream)
  (handler-case
      (cl-quic-kit:client-write-stream
       client stream (make-array 1 :element-type '(unsigned-byte 8)))
    (cl-quic-kit:quic-error (condition)
      (setf message (cl-quic-kit::quic-error-message condition)
            report (princ-to-string condition))))
  (check (and (string= message
                       "Cannot write to a stream that is not registered with the client")
               (string= report message))
          "unregistered stream writes report an explicit QUIC error"))

(let* ((connection (cl-quic-kit:make-quic-connection))
       (client (cl-quic-kit:make-quic-client
                :connection connection
                :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :disable-hostname-verification-p t))
       (stream (cl-quic-kit:client-open-stream client nil))
       (flow (cl-quic-kit::quic-client-flow-control client)))
  (setf (cl-quic-kit::flow-control-state-connection-max-data flow) 0)
  (cl-quic-kit:client-write-stream
   client stream (make-array 1 :element-type '(unsigned-byte 8)))
  (check (cl-quic-kit::quic-client-pending-stream-writes client)
         "flow-limited stream writes remain pending before close")
  (cl-quic-kit:client-close-stream client stream)
  (cl-quic-kit:client-flush client)
  (check (null (cl-quic-kit::quic-client-pending-stream-writes client))
         "closing a stream drops its pending writes before a later flush"))

(let* ((client (cl-quic-kit:make-quic-client
                :connection (cl-quic-kit:make-quic-connection)
                :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :disable-hostname-verification-p t))
       (stream (cl-quic-kit:client-open-stream client nil))
       (replacement (cl-quic-kit:make-stream (cl-quic-kit:stream-id stream)
                                             :local-initiator :client)))
  (cl-quic-kit:client-close-stream client replacement)
  (check (eq (gethash (cl-quic-kit:stream-id stream)
                      (cl-quic-kit::quic-client-streams client))
             stream)
         "closing a different stream object does not remove the registered stream"))

(let* ((writes nil)
       (connection (cl-quic-kit:make-quic-connection
                   :io-write (lambda (ignored bytes)
                               (declare (ignore ignored))
                               (push bytes writes))))
       (client (cl-quic-kit:make-quic-client
                :connection connection
                :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :disable-hostname-verification-p t))
       (stream (cl-quic-kit:client-open-stream client nil))
       (flow (cl-quic-kit::quic-client-flow-control client))
       (size 524288)
       (payload (make-array size :element-type '(unsigned-byte 8))))
  (dotimes (index size)
    (setf (aref payload index) (mod index 251)))
  (setf (cl-quic-kit::flow-control-state-connection-max-data flow) 0)
  (cl-quic-kit:client-write-stream client stream payload :fin-p t)
  (cl-quic-kit:client-flush client)
  (cl-quic-kit:flow-control-update-max-data flow size)
  (cl-quic-kit:client-flush client)
  (let* ((frames (remove-if-not
                  (lambda (frame)
                    (eq (cl-quic-kit:frame-type frame) :stream))
                  (mapcar #'cl-quic-kit:decode-frame (reverse writes))))
         (expected-offset 0)
         (last-frame (car (last frames))))
    (check (and frames
                (every (lambda (frame)
                        (let ((offset (cl-quic-kit:frame-field frame :offset))
                              (data (cl-quic-kit:frame-field frame :data)))
                          (prog1 (= offset expected-offset)
                            (incf expected-offset (length data)))))
                       frames)
                (= expected-offset size)
                (cl-quic-kit:frame-field last-frame :fin)
                (equalp (apply #'concatenate '(vector (unsigned-byte 8))
                               (mapcar (lambda (frame)
                                         (cl-quic-kit:frame-field frame :data))
                                       frames))
                        payload)
                (null (cl-quic-kit::quic-client-pending-stream-writes client)))
           "a 524288-byte pending stream write resumes at its offset and preserves FIN")))

(dolist (size '(65526 65527 65528 1048576 8388608))
  (let* ((writes nil)
         (connection (cl-quic-kit:make-quic-connection
                     :io-write (lambda (ignored bytes)
                                 (declare (ignore ignored))
                                 (push bytes writes))))
         (client (cl-quic-kit:make-quic-client
                  :connection connection
                  :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                  :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                  :disable-hostname-verification-p t))
         (stream (cl-quic-kit:client-open-stream client nil))
         (payload (make-array size :element-type '(unsigned-byte 8))))
    (setf (cl-quic-kit.recovery:recovery-state-cwnd
           (cl-quic-kit::quic-client-recovery client))
          most-positive-fixnum)
    (dotimes (index size)
      (setf (aref payload index) (mod index 251)))
    (cl-quic-kit:client-write-stream client stream payload :fin-p t)
    (cl-quic-kit:client-flush client)
    (let ((frames (mapcar #'cl-quic-kit:decode-frame (reverse writes)))
          (received (make-array size :element-type '(unsigned-byte 8)
                                :initial-element 0))
          (saw-fin nil)
          (fin-count 0)
          (fin-end 0))
      (dolist (frame frames)
        (check (<= (length (cl-quic-kit:encode-frame frame)) 1100)
               "large stream fragments fit the packet payload budget")
        (let ((data (cl-quic-kit:frame-field frame :data))
              (offset (cl-quic-kit:frame-field frame :offset 0)))
          (replace received data :start1 offset)
          (when (cl-quic-kit:frame-field frame :fin nil)
            (setf saw-fin t)
            (incf fin-count)
            (setf fin-end (+ offset (length data))))))
      (check (and saw-fin (= fin-count 1) (= fin-end size)
                   (equalp received payload))
             "large stream data reassembles by stream offset"))))

(let* ((writes nil)
       (connection (cl-quic-kit:make-quic-connection
                   :io-write (lambda (ignored bytes)
                               (declare (ignore ignored))
                               (push bytes writes))))
       (client (cl-quic-kit:make-quic-client
                :connection connection
                :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :disable-hostname-verification-p t))
       (stream (cl-quic-kit:client-open-stream client nil))
       (flow (cl-quic-kit::quic-client-flow-control client))
       (payload (make-array 10 :element-type '(unsigned-byte 8)
                            :initial-contents '(0 1 2 3 4 5 6 7 8 9))))
  (setf (cl-quic-kit::flow-control-state-connection-max-data flow) 4)
  (cl-quic-kit:client-write-stream client stream payload :fin-p t)
  (cl-quic-kit:client-flush client)
  (let ((frames (remove-if-not (lambda (frame)
                                 (eq (cl-quic-kit:frame-type frame) :stream))
                               (mapcar #'cl-quic-kit:decode-frame (reverse writes)))))
    (check (= (length frames) 1) "stream data stops at available connection credit"))
  (cl-quic-kit:flow-control-update-max-data flow 10)
  (cl-quic-kit:client-flush client)
  (let ((frames (remove-if-not (lambda (frame)
                                 (eq (cl-quic-kit:frame-type frame) :stream))
                               (mapcar #'cl-quic-kit:decode-frame (reverse writes)))))
    (check (= (length frames) 2) "pending stream data waits for increased credit")
    (check (and (= (length (cl-quic-kit:frame-field (first frames) :data)) 4)
                (= (length (cl-quic-kit:frame-field (second frames) :data)) 6)
                (cl-quic-kit:frame-field (second frames) :fin))
           "pending stream data resumes with the next offset and FIN")))

(let* ((writes nil)
       (connection (cl-quic-kit:make-quic-connection
                   :io-write (lambda (ignored bytes)
                               (declare (ignore ignored))
                               (push bytes writes))))
       (client (cl-quic-kit:make-quic-client
                :connection connection
                :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :disable-hostname-verification-p t))
       (secret (make-array 32 :element-type '(unsigned-byte 8)
                           :initial-element 7)))
  (cl-quic-kit::%client-set-key
   client :1-rtt :write (cl-quic-kit.protection:make-key-set secret))
  (setf (cl-quic-kit.recovery:recovery-state-cwnd
         (cl-quic-kit::quic-client-recovery client))
        1200)
  (let ((stream (cl-quic-kit:client-open-stream client nil))
        (payload (make-array 4096 :element-type '(unsigned-byte 8))))
    (cl-quic-kit:client-write-stream client stream payload :fin-p t)
    (cl-quic-kit:client-flush client)
    (check (<= (cl-quic-kit.recovery:recovery-state-bytes-in-flight
                (cl-quic-kit::quic-client-recovery client))
               (cl-quic-kit.recovery:recovery-state-cwnd
                (cl-quic-kit::quic-client-recovery client)))
           "client flush does not exceed the congestion window")
    (check (cl-quic-kit::quic-client-pending-frames client)
           "congestion-window blocked stream packets remain queued")
    (let ((writes-before-ack (length writes)))
      (cl-quic-kit::%client-handle-ack
       client :1-rtt
       (cl-quic-kit:make-frame :ack
                               :largest-acknowledged 0
                               :ack-delay 0
                               :ranges (list (cons 0 0))))
      (cl-quic-kit:client-flush client)
      (check (> (length writes) writes-before-ack)
             "ACK frees the congestion window and resumes queued stream data")
      (check (cl-quic-kit::quic-client-pending-frames client)
             "ACK flush preserves packet groups after the blocked stream packet"))))

(let* ((ranges (cons (cons 3000 0)
                    (loop repeat 700 collect (list :gap 0 :range-length 0))))
       (frame (cl-quic-kit:make-frame
               :ack :largest-acknowledged 3000 :ack-delay 0 :ranges ranges))
       (parts (cl-quic-kit::%client-split-frame frame)))
  (check (and (> (length parts) 1)
              (every (lambda (part)
                       (<= (length (cl-quic-kit:encode-frame part)) 1100))
                     parts))
         "large ACK ranges split into packet-sized ACK frames")
  (let ((previous-largest 3001))
    (dolist (part parts)
      (let* ((part-ranges (cl-quic-kit:frame-field part :ranges))
             (largest (cl-quic-kit:frame-field part :largest-acknowledged)))
        (check (and (= largest (caar part-ranges))
                    (< largest previous-largest))
               "split ACK largest acknowledged matches its first range")
        (setf previous-largest largest)))))

(let* ((ranges (cons (cons 3000 0)
                    (loop repeat 700 collect (list :gap 0 :range-length 0))))
       (frame (cl-quic-kit:make-frame
               :ack-ecn :largest-acknowledged 3000 :ack-delay 0 :ranges ranges
               :ect0 7 :ect1 11 :ecn-ce 13))
       (parts (cl-quic-kit::%client-split-frame frame)))
  (check (and (> (length parts) 1)
              (every (lambda (part)
                       (and (eq (cl-quic-kit:frame-type part) :ack-ecn)
                            (<= (length (cl-quic-kit:encode-frame part)) 1100)
                            (= (cl-quic-kit:frame-field part :ect0) 7)
                            (= (cl-quic-kit:frame-field part :ect1) 11)
                            (= (cl-quic-kit:frame-field part :ecn-ce) 13)
                            (= (length (cl-quic-kit:frame-field part :ranges))
                               (length (cl-quic-kit::%client-ack-intervals part)))))
                     parts))
         "split ACK ECN preserves counters, size, and ranges"))

(flet ((test-octets (values)
         (make-array (length values) :element-type '(unsigned-byte 8)
                     :initial-contents values)))
  (let* ((destination (test-octets '(90 91 92 93 94 95 96 97)))
       (old-secret (test-octets
                    '(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
                      16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31)))
       (make-test-client
         (lambda (local)
           (cl-quic-kit:make-quic-client
            :local-connection-id local
            :destination-connection-id destination
            :disable-hostname-verification-p t))))
  (let* ((sender (funcall make-test-client (test-octets '(1 2 3 4 5 6 7 8))))
         (receiver (funcall make-test-client (test-octets '(11 12 13 14 15 16 17 18))))
         (old-key (cl-quic-kit.protection:make-key-set old-secret)))
    (dolist (direction '(:read :write))
      (cl-quic-kit::%client-set-key receiver :1-rtt direction old-key))
    (dolist (direction '(:read :write))
      (cl-quic-kit::%client-set-key sender :1-rtt direction old-key))
    (setf (cl-quic-kit::quic-client-application-read-secret receiver) old-secret
          (cl-quic-kit::quic-client-application-write-secret receiver) old-secret
          (cl-quic-kit::quic-client-application-read-secret sender) old-secret
          (cl-quic-kit::quic-client-application-write-secret sender) old-secret)
    (let ((old-wire (cl-quic-kit::%client-build-packet
                     sender :application (list (cl-quic-kit:make-frame :ping)))))
          (check (cl-quic-kit:client-receive-datagram receiver old-wire)
                 "client path opens the current application key")
      (check (null (cl-quic-kit::%client-rotate-application-write-key sender))
             "client does not update keys before handshake confirmation")
      (setf (cl-quic-kit::quic-client-application-handshake-confirmed-p sender) t)
        (check (cl-quic-kit::%client-rotate-application-write-key sender)
                 "client starts an application key update")
      (let ((delayed-peer-old
              (let ((late (funcall make-test-client
                                   (test-octets '(21 22 23 24 25 26 27 28)))))
                (cl-quic-kit::%client-set-key late :1-rtt :write old-key)
                (setf (cl-quic-kit::quic-client-application-write-secret late)
                      old-secret
                      (cl-quic-kit::quic-client-packet-numbers late)
                      '((:1-rtt . 1)))
                (cl-quic-kit::%client-build-packet
                 late :application (list (cl-quic-kit:make-frame :ping))))))
                (check (cl-quic-kit:client-receive-datagram sender delayed-peer-old)
               "local write update leaves the peer's old read key usable"))
      (cl-quic-kit::%client-prepare-next-application-read-key sender)
      (cl-quic-kit::%client-prepare-next-application-read-key receiver)
      (check (and (cl-quic-kit::quic-client-application-read-next-key sender)
                  (cl-quic-kit::quic-client-application-read-next-key receiver))
             "current and next read keys are prepared before key phase processing")
      (let ((next-wire (cl-quic-kit::%client-build-packet
                        sender :application (list (cl-quic-kit:make-frame :ping)))))
        (check (cl-quic-kit:client-receive-datagram receiver next-wire)
               "client path opens the next application key")
        (let ((peer-wire (cl-quic-kit::%client-build-packet
                          receiver :application
                          (list (cl-quic-kit:make-frame :ping)))))
          (check (cl-quic-kit:client-receive-datagram sender peer-wire)
                 "peer key update succeeds before the local write update is acknowledged")
          (check (not (cl-quic-kit::quic-client-closed-p sender))
                 "peer key update does not depend on local write ACK state"))
        (check (= (cl-quic-kit::quic-client-application-read-key-update-packet-number
                   receiver)
                  1)
               "client records the first packet number of the new read generation")
        (let ((delayed-old (let ((late (funcall make-test-client
                                                (test-octets
                                                 '(1 2 3 4 5 6 7 8)))))
                             (cl-quic-kit::%client-set-key late :1-rtt :write old-key)
                             (setf (cl-quic-kit::quic-client-application-write-secret late)
                                   old-secret)
                             (cl-quic-kit::%client-build-packet
                              late :application
                              (list (cl-quic-kit:make-frame :ping))))))
          (check (cl-quic-kit:client-receive-datagram receiver delayed-old)
                 "client path opens a delayed old-generation packet")
          (check (not (cl-quic-kit::quic-client-closed-p receiver))
                 "delayed old-generation packet does not close the connection")
          (check (null (cl-quic-kit::%client-rotate-application-write-key sender))
                 "client does not start another write update before an ACK")
          (setf (cl-quic-kit::quic-client-application-write-key-phase-first-packet-number
                 sender)
                1)
          (cl-quic-kit::%client-handle-ack
           sender :1-rtt
           (cl-quic-kit:make-frame
            :ack :largest-acknowledged 2 :ack-delay 0
            :ranges (list (cons 2 1))))
          (check (cl-quic-kit::quic-client-application-write-key-phase-acked-p
                  sender)
                 "ACK marks the current write key generation acknowledged")
          (setf (cl-quic-kit::quic-client-application-write-key-phase-acked-p
                 sender)
                nil)
          (cl-quic-kit::%client-handle-ack
           sender :1-rtt
           (cl-quic-kit:make-frame
            :ack :largest-acknowledged 2 :ack-delay 0
            :ranges (list (cons 2 0) (list :gap 0 :range-length 0))))
          (check (not (cl-quic-kit::quic-client-application-write-key-phase-acked-p
                       sender))
                 "ACK outside the update packet range does not authorize a key update")
          (setf (cl-quic-kit::quic-client-application-write-key-phase-acked-p
                 sender)
                t)
          (check (cl-quic-kit::%client-rotate-application-write-key sender)
                 "client starts the next write update after an ACK")
          (setf (cl-quic-kit::quic-client-application-write-key-phase-acked-p
                 receiver)
                t)
          (let ((high-old (let ((late (funcall make-test-client
                                                (test-octets
                                                '(1 2 3 4 5 6 7 8)))))
                            (cl-quic-kit::%client-set-key late :1-rtt :write old-key)
                            (setf (cl-quic-kit::quic-client-application-write-secret late)
                                  old-secret
                                  (cl-quic-kit::quic-client-packet-numbers late)
                                  '((:1-rtt . 2)))
                            (cl-quic-kit::%client-build-packet
                             late :application
                             (list (cl-quic-kit:make-frame :ping))))))
            (check (null (cl-quic-kit:client-receive-datagram receiver high-old))
                   "client rejects an old-key packet at or after the update boundary"))
          (check (cl-quic-kit::quic-client-closed-p receiver)
                 "an invalid key phase closes the connection")))))))

(let ((server (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                           :local-port 0
                                           :non-blocking-p nil))
      (client nil))
  (unwind-protect
       (progn
         (setf client
               (cl-quic-kit:make-udp-socket
                :local-host "127.0.0.1" :local-port 0
                :remote-host "127.0.0.1"
                :remote-port (cl-quic-kit:udp-socket-local-port server)
                :non-blocking-p nil))
         (let ((payload (make-array 4 :element-type '(unsigned-byte 8)
                                     :initial-contents '(1 3 3 7))))
           (check (= (cl-quic-kit:udp-send client payload) 4)
                  "UDP sends one complete datagram")
           (multiple-value-bind (received length peer)
               (cl-quic-kit:udp-receive server :wait-p t)
             (check (and (= length 4) (equalp received payload) peer)
                    "UDP receives the datagram and peer address"))))
    (when client (cl-quic-kit:udp-close client))
    (cl-quic-kit:udp-close server)))
