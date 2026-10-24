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
(let* ((client (cl-quic-kit:make-quic-client
                :connection (cl-quic-kit:make-quic-connection)
                :disable-hostname-verification-p t))
       (flow (cl-quic-kit::quic-client-flow-control client))
       (window-size 4096)
       (window-count 40)
       (payload (make-array window-size :element-type '(unsigned-byte 8)
                            :initial-element 42))
       (conflicting-payload
         (make-array window-size :element-type '(unsigned-byte 8)
                     :initial-element 43))
       (initial-connection-limit
         (cl-quic-kit:flow-control-connection-receive-limit flow))
       (stream nil))
  (dotimes (window window-count)
    (let* ((offset (* window window-size))
           (end (+ offset window-size))
           (last-window (= window (1- window-count))))
      (cl-quic-kit:client-receive-frame
       client (cl-quic-kit:make-frame :stream :stream-id 1 :offset offset
                                      :data payload)
       :level :1-rtt)
      (unless stream
        (setf stream (gethash 1 (cl-quic-kit::quic-client-streams client))))
      (check
       (and (= (loop for segment in (cl-quic-kit::stream-received-segments stream)
                     sum (length (cdr segment)))
               window-size)
            (= (cl-quic-kit:stream-readable-bytes stream) window-size))
       "unread client stream payload remains buffered")
      (multiple-value-bind (data fin)
          (cl-quic-kit:client-read-stream client stream)
        (check (and (equalp data payload) (not fin))
               "client reads return the received stream window"))
      (check (and (null (cl-quic-kit::stream-received-segments stream))
                  (null (cl-quic-kit::stream-segments stream))
                  (zerop (cl-quic-kit:stream-readable-bytes stream)))
             "client reads release consumed payload after credit regrant")
      (let ((received-before
              (cl-quic-kit:flow-control-connection-received flow)))
        (cl-quic-kit:client-receive-frame
         client (cl-quic-kit:make-frame :stream :stream-id 1 :offset offset
                                        :data conflicting-payload
                                        :fin last-window)
         :level :1-rtt)
        (check (= (cl-quic-kit:flow-control-connection-received flow)
                  received-before)
               "consumed duplicate ranges do not consume connection credit again"))
      (check (and (null (cl-quic-kit::stream-received-segments stream))
                  (equal (cl-quic-kit::stream-receive-ranges stream)
                         (list (cons 0 end))))
             "released payload remains accounted by receive ranges")
      (when last-window
        (check (= (cl-quic-kit::stream-receive-final-size stream) end)
               "final size remains valid after consumed payload is released"))))
  (check (= (cl-quic-kit:flow-control-connection-receive-limit flow)
            (+ initial-connection-limit (* window-size window-count)))
         "client reads regrant connection receive credit for returned bytes")
  (check (= (cl-quic-kit::stream-receive-max-offset stream)
            (+ (* window-size window-count) 65536))
         "client reads regrant stream receive credit")
  (check (= (cl-quic-kit:flow-control-connection-received flow)
            (* window-size window-count))
         "conflicting consumed duplicates are counted only once"))

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
  (check (cl-quic-kit:client-stream-write-pending-p client stream)
         "pending stream writes are reported through the public client API")
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
    (check (cl-quic-kit:client-stream-write-pending-p client stream)
           "congestion-window blocked stream frames are reported as pending")
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
             "ACK flush preserves packet groups after the blocked stream packet")
      (setf (cl-quic-kit.recovery:recovery-state-cwnd
             (cl-quic-kit::quic-client-recovery client))
            most-positive-fixnum)
      (cl-quic-kit:client-flush client)
      (check (not (cl-quic-kit:client-stream-write-pending-p client stream))
             "stream write is no longer pending after the queued frame is sent"))))

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

(let ((checks 0))
  (labels ((contract-check (condition description)
             (incf checks)
             (check condition description)))
    (let ((client (cl-quic-kit:make-quic-client
                   :connection (cl-quic-kit:make-quic-connection)
                   :disable-hostname-verification-p t)))
      (contract-check (null (cl-quic-kit:client-accept-peer-stream client))
                      "peer stream accept returns NIL before receipt")
      (cl-quic-kit:client-poll client)
      (contract-check (null (cl-quic-kit:client-accept-peer-stream client))
                      "peer stream accept remains NIL when polling finds no stream"))
    (let* ((writes nil)
           (client (cl-quic-kit:make-quic-client
                    :connection
                    (cl-quic-kit:make-quic-connection
                     :io-write (lambda (connection bytes)
                                 (declare (ignore connection))
                                 (push bytes writes)))
                    :disable-hostname-verification-p t))
           (local-stream (cl-quic-kit:client-open-stream client nil))
           (payload (cl-quic-kit:encode-varint 42))
           (response (cl-quic-kit:encode-varint 43)))
      (let ((initial-frame (cl-quic-kit:make-frame :padding)))
        (contract-check
         (eq (cl-quic-kit:client-receive-frame client initial-frame)
             initial-frame)
         "client-receive-frame preserves its two-argument Initial-space behavior")
        (cl-quic-kit:client-receive-frame
         client (cl-quic-kit:make-frame :stream :stream-id 1 :data payload :fin t)
         :level :1-rtt))
      (cl-quic-kit:client-receive-frame
       client (cl-quic-kit:make-frame :stream :stream-id 5 :data payload :fin t)
       :level :1-rtt)
      (cl-quic-kit:client-poll client)
      (let* ((first (cl-quic-kit:client-accept-peer-stream client))
             (second (cl-quic-kit:client-accept-peer-stream client))
             (ids (and first second
                       (list (cl-quic-kit:stream-id first)
                             (cl-quic-kit:stream-id second))))
             (bidi (find 1 (list first second) :key #'cl-quic-kit:stream-id)))
        (contract-check (and first second (not (eq first second)))
                        "received peer streams remain available after client-poll")
        (contract-check (and ids
                             (member (first ids) (list 1 5))
                             (member (second ids) (list 1 5))
                             (/= (first ids) (second ids)))
                        "peer stream accept returns each received peer ID")
        (contract-check (and first second
                             (not (eq first local-stream))
                             (not (eq second local-stream))
                             (not (cl-quic-kit:stream-local-p first))
                             (not (cl-quic-kit:stream-local-p second)))
                        "peer stream accept never returns a local stream")
        (contract-check (null (cl-quic-kit:client-accept-peer-stream client))
                        "each peer stream is returned exactly once")
        (multiple-value-bind (received fin-p)
            (cl-quic-kit:client-read-stream client bidi)
          (contract-check (and (equalp received payload) fin-p)
                          "peer stream read returns its data and FIN"))
        (cl-quic-kit:client-write-stream client bidi response :fin-p t)
        (cl-quic-kit:client-poll client)
        (let ((frame-wire
                (cl-quic-kit:encode-frame
                 (cl-quic-kit:make-frame :stream
                                         :stream-id (cl-quic-kit:stream-id bidi)
                                         :offset 0 :data response
                                         :fin t :len-present t))))
          (contract-check
           (find frame-wire writes
                 :test (lambda (expected actual) (equalp expected actual)))
           "peer stream write sends its data and FIN"))))
    (let* ((client (cl-quic-kit:make-quic-client
                    :connection (cl-quic-kit:make-quic-connection)
                    :disable-hostname-verification-p t))
           (stream (cl-quic-kit:client-open-stream client nil)))
      (cl-quic-kit:client-receive-frame
       client (cl-quic-kit:make-frame :max-data :maximum 0)
       :level :1-rtt)
      (cl-quic-kit:client-write-stream client stream
                                      (cl-quic-kit:encode-varint 1))
      (contract-check (cl-quic-kit:client-stream-write-pending-p client stream)
                      "flow-controlled writes remain pending through the public API"))
    (let* ((client (cl-quic-kit:make-quic-client
                    :connection (cl-quic-kit:make-quic-connection)
                    :disable-hostname-verification-p t))
           (connection (cl-quic-kit:quic-client-connection client)))
      (contract-check (null (cl-quic-kit:quic-connection-closed-reason connection))
                      "connection close reason is NIL before it is recorded")
      (cl-quic-kit:connection-close connection :no-error "local shutdown")
      (contract-check
       (equalp (cl-quic-kit:quic-connection-closed-reason connection)
               #(108 111 99 97 108 32 115 104 117 116 100 111 119 110))
       "local connection-close reason is recorded as octets"))
    (let* ((client (cl-quic-kit:make-quic-client
                    :connection (cl-quic-kit:make-quic-connection)
                    :disable-hostname-verification-p t)))
      (cl-quic-kit:client-receive-frame
       client (cl-quic-kit:make-frame :stream :stream-id 1
                                      :data (cl-quic-kit:encode-varint 7)
                                      :fin t)
       :level :1-rtt)
      (cl-quic-kit:client-close client :reason "client shutdown")
      (contract-check (null (cl-quic-kit:client-accept-peer-stream client))
                      "closed clients return NIL for queued peer streams"))
    (let* ((distinct-client (cl-quic-kit:make-quic-client
                             :connection (cl-quic-kit:make-quic-connection)
                             :disable-hostname-verification-p t))
           (duplicate-client (cl-quic-kit:make-quic-client
                              :connection (cl-quic-kit:make-quic-connection)
                              :disable-hostname-verification-p t)))
      (cl-quic-kit:client-receive-frames
       distinct-client :initial 17 (list (cl-quic-kit:make-frame :padding)))
      (cl-quic-kit:client-receive-frames
       distinct-client :initial 19 (list (cl-quic-kit:make-frame :padding)))
      (contract-check
       (equal (list 19 17)
              (cdr (assoc :initial
                          (cl-quic-kit::quic-client-received-packets distinct-client))))
       "batch receive records caller-supplied packet numbers")
      (cl-quic-kit:client-receive-frames
       duplicate-client :1-rtt 7
       (list (cl-quic-kit:make-frame
              :stream :stream-id 1 :data (cl-quic-kit:encode-varint 1) :fin t)
             (cl-quic-kit:make-frame
              :stream :stream-id 5 :data (cl-quic-kit:encode-varint 2) :fin t)))
      (cl-quic-kit:client-receive-frames
       duplicate-client :1-rtt 7
       (list (cl-quic-kit:make-frame
              :stream :stream-id 9 :data (cl-quic-kit:encode-varint 3) :fin t)))
      (contract-check
       (and (equal (list 7 7)
                   (cdr (assoc :1-rtt
                               (cl-quic-kit::quic-client-received-packets duplicate-client))))
            (gethash 1 (cl-quic-kit::quic-client-streams duplicate-client))
            (gethash 5 (cl-quic-kit::quic-client-streams duplicate-client))
            (gethash 9 (cl-quic-kit::quic-client-streams duplicate-client)))
       "batch receive reprocesses frames with a repeated packet number")
      (contract-check
       (handler-case
           (progn
             (cl-quic-kit:client-receive-frames
              distinct-client :invalid 23
              (list (cl-quic-kit:make-frame :padding)))
             nil)
         (cl-quic-kit::quic-frame-space-error () t))
       "batch receive retains the frame-space error for an invalid level")
      (format t "client public API contract: ~D checks~%" checks))))
(let* ((secret (make-array 12 :element-type '(unsigned-byte 8)
                            :initial-contents '(83 69 67 82 69 84 45 68 85 77 77 89)))
       (secret-report (format nil "~{~D~^ ~}" (coerce secret 'list)))
       (header (cl-quic-kit:make-packet-header
                :destination-connection-id secret
                :source-connection-id secret
                :token secret
                :payload secret
                :retry-integrity-tag secret))
       (key-set (cl-quic-kit.protection::%make-key-set
                 secret secret secret :aes-128-gcm))
       (connection (cl-quic-kit:make-quic-connection
                    :local-connection-id secret))
       (client (cl-quic-kit::%make-quic-client
                :connection connection
                :retry-token secret
                :application-read-secret secret
                :application-write-secret secret)))
  (setf (cl-quic-kit::quic-connection-stream-engine connection) client)
  (labels ((check-redacted (object description)
             (let ((report (princ-to-string object)))
               (check (and (search "redacted" report)
                           (not (search secret-report report)))
                      description))))
    (check-redacted header "packet header printer redacts octet fields")
    (check-redacted key-set "protection key-set printer redacts key bytes")
    (check-redacted client "QUIC client printer redacts secret state")
    (check-redacted connection "connection printer redacts secret state")
    (check-redacted (list client connection)
                    "client/connection cycle prints without exposing secret state"))
  (let ((condition nil))
    (handler-case
        (cl-quic-kit.protection::%protection-octets (list :secret secret) "secret")
      (type-error (caught) (setf condition caught)))
    (let ((report (and condition (princ-to-string condition))))
      (check (and condition
                  (eq (type-error-datum condition) :invalid-octet-vector)
                  (not (search secret-report report)))
             "type errors retain a safe octet classification datum"))))
(eval-when (:compile-toplevel :load-toplevel :execute) (require :sb-posix))
(progn
  (defun client-close-fd-open-p (descriptor)
    (handler-case
        (progn (sb-posix:fcntl descriptor sb-posix:f-getfd) t)
      (sb-posix:syscall-error (condition)
        (if (= (sb-posix:syscall-errno condition) sb-posix:ebadf)
            nil
            (error condition)))))

  (defun client-close-socket-case (provided-p send-failure-p cleanup-failure-p)
    (let* ((provided (and provided-p
                          (cl-quic-kit:make-udp-socket :local-host "127.0.0.1")))
           (client nil)
           (socket nil)
           (native nil)
           (descriptor nil)
           (destination
             (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-contents '(8 7 6 5 4 3 2 1)))
           (send-condition
             (make-condition 'simple-error :format-control "close send failure"))
           (cleanup-condition
             (make-condition 'simple-error :format-control "close cleanup failure"))
           (writes nil)
           (native-closes 0)
           (original-close (symbol-function 'sb-bsd-sockets:socket-close)))
      (unwind-protect
           (progn
             (setf client
                   (cl-quic-kit:make-quic-client
                    :hostname "localhost"
                    :udp-socket provided
                    :server-host "127.0.0.1" :server-port 9
                    :local-connection-id
                    (make-array 8 :element-type '(unsigned-byte 8)
                                  :initial-contents '(1 2 3 4 5 6 7 8))
                    :destination-connection-id destination
                    :io-write (lambda (connection bytes)
                                (check
                                 (eq connection
                                     (cl-quic-kit::quic-client-connection client))
                                 "close callback receives the client's connection")
                                (push bytes writes)
                                (when send-failure-p (error send-condition)))))
             (setf socket (cl-quic-kit::quic-client-udp-socket client)
                   native (cl-quic-kit::udp-socket-socket socket)
                   descriptor (sb-bsd-sockets:socket-file-descriptor native))
             (check (if provided-p (eq socket provided) (not (eq socket provided)))
                    "client socket ownership matches the constructor input")
             (check (client-close-fd-open-p descriptor)
                    "client owns an open descriptor before close")
             (setf (symbol-function 'sb-bsd-sockets:socket-close)
                   (lambda (raw &rest arguments)
                     (if (eq raw native)
                         (progn
                           (incf native-closes)
                           (apply original-close raw arguments)
                           (when cleanup-failure-p (error cleanup-condition)))
                         (apply original-close raw arguments))))
             (let ((caught nil) (result nil))
               (handler-case
                   (setf result
                         (cl-quic-kit:client-close
                          client :error-code 7 :reason "close"))
                 (error (condition) (setf caught condition)))
               (check (eq caught (cond (send-failure-p send-condition)
                                      (cleanup-failure-p cleanup-condition)))
                      "send errors stay primary; cleanup-only errors propagate")
               (check (null result) "failed close does not return success"))
             (check (not (client-close-fd-open-p descriptor))
                    "close releases the actual UDP descriptor after errors")
             (check (= native-closes 1)
                    "close invokes native descriptor cleanup exactly once")
             (check (cl-quic-kit::udp-socket-closed-p socket)
                    "UDP ownership is closed")
             (check (cl-quic-kit::quic-client-closed-p client)
                    "client is closed after every outcome")
             (check
              (eq :closing
                  (cl-quic-kit:connection-state
                   (cl-quic-kit::quic-client-connection client)))
              "the connection enters closing")
             (check (= 1 (length writes))
                    "close attempts one protected datagram"))
        (setf (symbol-function 'sb-bsd-sockets:socket-close) original-close)
        (when (and socket descriptor (client-close-fd-open-p descriptor))
          (cl-quic-kit:udp-close socket))
        (when (and provided (not socket))
          (cl-quic-kit:udp-close provided))
        (check (eq original-close (symbol-function 'sb-bsd-sockets:socket-close))
               "native socket-close spy is restored exactly"))))

  (defun client-close-provided-send-error ()
    (client-close-socket-case t t nil))

  (defun client-close-internal-send-error ()
    (client-close-socket-case nil t nil))

  (defun client-close-cleanup-error ()
    (client-close-socket-case t nil t))

  (defun client-close-dual-error ()
    (client-close-socket-case t t t))

  (defun client-default-clock-ack-rtt-bounded ()
    (let* ((client
             (cl-quic-kit:make-quic-client
              :disable-hostname-verification-p t))
           (clock (cl-quic-kit::quic-client-clock client))
           (state (cl-quic-kit::quic-client-recovery client))
           (tick (/ 1 internal-time-units-per-second)))
      (dotimes (number 4000)
        (let ((sent-at (- (funcall clock) tick)))
          (cl-quic-kit.recovery:record-sent-packet
           state :application number 1200 :sent-at sent-at)
          (cl-quic-kit::%client-handle-ack
           client :1-rtt
           (cl-quic-kit:make-frame
            :ack :largest-acknowledged number :ack-delay 0
            :ranges (list (cons number 0))))
          (let ((latest (cl-quic-kit.recovery:recovery-state-latest-rtt state))
                (smoothed
                  (cl-quic-kit.recovery:recovery-state-smoothed-rtt state))
                (variance
                  (cl-quic-kit.recovery:recovery-state-rtt-variance state)))
            (check (and (rationalp latest) (plusp latest))
                   "default-clock ACK sampling retains rational RTT values")
            (check (and (<= (denominator smoothed) 1000000000)
                        (<= (denominator variance) 1000000000))
                   "default-clock ACK updates retain bounded RTT precision"))))))

  (client-close-provided-send-error)
  (client-close-internal-send-error)
  (client-close-cleanup-error)
  (client-close-dual-error)
  (client-default-clock-ack-rtt-bounded))
