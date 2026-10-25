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
(let* ((writes nil)
       (connection (cl-quic-kit:make-quic-connection
                    :io-write (lambda (ignored bytes)
                                (declare (ignore ignored))
                                (push bytes writes))))
       (local (make-array 8 :element-type (quote (unsigned-byte 8))))
       (destination (make-array 8 :element-type (quote (unsigned-byte 8))))
       (client (cl-quic-kit:make-quic-client
                :connection connection
                :local-connection-id local
                :destination-connection-id destination
                :disable-hostname-verification-p t)))
  (cl-quic-kit::%client-requeue-record
   client
   (list :level :initial
         :frames (list (cl-quic-kit:make-frame :ping))))
  (cl-quic-kit:client-flush client)
  (check (and (= (length writes) 1)
              (= (cl-quic-kit::%client-pto-probe-budget client :initial) 0))
         "loss-requeued frames send with an unset PTO probe budget"))
(check
 (let* ((writes nil)
        (local (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-element 1))
        (destination (make-array 8 :element-type '(unsigned-byte 8)
                                :initial-element 2))
        (connection
          (cl-quic-kit:make-quic-connection
           :io-write (lambda (ignored bytes)
                       (declare (ignore ignored))
                       (push bytes writes))))
        (client
          (cl-quic-kit:make-quic-client
           :connection connection
           :local-connection-id local
           :destination-connection-id destination
           :disable-hostname-verification-p t))
        (packet
          (cl-quic-kit:encode-packet-header
           (cl-quic-kit:make-packet-header
            :type :initial :version cl-quic-kit:*quic-version-1*
            :destination-connection-id destination
            :source-connection-id local
            :packet-number 0 :packet-number-length 1 :payload #()))))
   (and (null (cl-quic-kit:client-receive-datagram client packet))
        (not (cl-quic-kit:quic-client-closed-p client))
        (zerop (cl-quic-kit::quic-client-authentication-failures client))
        (null writes)))
 "client drops an Initial too short for header protection without closing or writing")
(let* ((layout-symbol (find-symbol "%CLIENT-LAYOUT" "CL-QUIC-KIT"))
       (close-symbol (find-symbol "%CLIENT-PROTOCOL-CLOSE" "CL-QUIC-KIT"))
       (original-layout (symbol-function layout-symbol))
       (original-close (symbol-function close-symbol))
       (captured nil)
       (marker "PEER_CLIENT_DIAGNOSTIC_7F3A")
       (client (cl-quic-kit:make-quic-client :disable-hostname-verification-p t))
       (input (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)))
  (unwind-protect
       (progn
         (setf (symbol-function close-symbol)
               (lambda (ignored code reason)
                 (declare (ignore ignored))
                 (setf captured (list code reason))))
         (setf (symbol-function layout-symbol)
               (lambda (bytes &key short-header-dcid-length)
                 (declare (ignore bytes short-header-dcid-length))
                 (error "~A" marker)))
         (cl-quic-kit:client-receive-datagram client input)
         (check (and (= (first captured) 7)
                     (string= (second captured) "invalid packet")
                     (not (search marker (second captured))))
                "client generic receive errors use a fixed marker-free close reason")
         (setf captured nil)
         (setf (symbol-function layout-symbol)
               (lambda (bytes &key short-header-dcid-length)
                 (declare (ignore bytes short-header-dcid-length))
                 (error (find-symbol "QUIC-FRAME-SPACE-ERROR" "CL-QUIC-KIT")
                        :message marker)))
         (cl-quic-kit:client-receive-datagram client input)
         (check (and (= (first captured) 10)
                     (string= (second captured) "invalid packet")
                     (not (search marker (second captured))))
                "client frame-space errors retain close code 10 and redact their reason"))
    (setf (symbol-function close-symbol) original-close
          (symbol-function layout-symbol) original-layout)))
(progn
  (let* ((writes nil)
         (local (make-array 8 :element-type '(unsigned-byte 8)
                            :initial-contents '(1 2 3 4 5 6 7 8)))
         ;; The packet helper loops protected packets through this client's receive path.
         (destination local)
         (secret (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element 17))
         (key (cl-quic-kit.protection:make-key-set secret))
         (client (cl-quic-kit:make-quic-client
                  :local-connection-id local
                  :destination-connection-id destination
                  :disable-hostname-verification-p t
                  :io-write (lambda (ignored bytes)
                              (declare (ignore ignored))
                              (push bytes writes))))
         (limit (expt 2 52)))
    (dolist (direction '(:read :write))
      (cl-quic-kit::%client-set-key client :1-rtt direction key))
    (labels ((packet ()
               (cl-quic-kit::%client-build-packet
                client :application (list (cl-quic-kit:make-frame :ping))))
             (damaged-packet ()
               (let ((wire (packet)))
                 (setf (aref wire (1- (length wire)))
                       (logxor 1 (aref wire (1- (length wire)))))
                 wire)))
      (check (null (cl-quic-kit:client-receive-datagram client (damaged-packet)))
             "unauthenticated application packet is discarded")
      (check (= (cl-quic-kit::quic-client-authentication-failures client) 1)
             "AEAD authentication failure increments the connection counter")
      (check (not (cl-quic-kit:quic-client-closed-p client))
             "an authentication failure below the limit leaves the client open")
      (check (null writes) "an authentication drop sends neither ACK nor close")
      (check (cl-quic-kit:client-receive-datagram client (packet))
             "a valid packet remains usable after authentication failure")
      (check (= (cl-quic-kit::quic-client-authentication-failures client) 1)
             "successful authentication does not reset the counter")
      (setf (cl-quic-kit::quic-client-authentication-failures client) (- limit 2))
      (check (null (cl-quic-kit:client-receive-datagram client (damaged-packet)))
             "the failure immediately below the AEAD limit is discarded")
      (check (and (= (cl-quic-kit::quic-client-authentication-failures client)
                     (1- limit))
                  (not (cl-quic-kit:quic-client-closed-p client)))
             "the client remains open below the AEAD limit")
      (check (null (cl-quic-kit:client-receive-datagram client (damaged-packet)))
             "the failure at the AEAD limit is discarded")
      (check (and (= (cl-quic-kit::quic-client-authentication-failures client) limit)
                  (not (cl-quic-kit:quic-client-closed-p client)))
             "the client remains open at the AEAD limit")
      (check (null (cl-quic-kit:client-receive-datagram client (damaged-packet)))
             "the first failure over the AEAD limit is discarded")
      (check (and (= (cl-quic-kit::quic-client-authentication-failures client)
                     (1+ limit))
                  (cl-quic-kit:quic-client-closed-p client)
                  (eq :closing
                      (cl-quic-kit:connection-state
                       (cl-quic-kit::quic-client-connection client)))
                  writes)
             "exceeding the AEAD limit closes and emits a CONNECTION_CLOSE")))
  (progn
    (dolist (cipher (quote (:aes-128-gcm :aes-256-gcm :chacha20-poly1305)))
      (let* ((limit (if (eq cipher :chacha20-poly1305) (expt 2 36) (expt 2 52)))
             (initial-key (cl-quic-kit.protection:make-key-set
                           (make-array 32 :element-type (quote (unsigned-byte 8))
                                       :initial-element 19)))
             (client (cl-quic-kit:make-quic-client
                      :disable-hostname-verification-p t
                      :io-write (lambda (ignored bytes)
                                  (declare (ignore ignored bytes))))))
        (cl-quic-kit::%client-set-authentication-cipher client cipher)
        (setf (cl-quic-kit::quic-client-authentication-failures client) (1- limit))
        (cl-quic-kit::%client-authentication-failed client initial-key)
        (check (and (= (cl-quic-kit::quic-client-authentication-failures client) limit)
                    (not (cl-quic-kit:quic-client-closed-p client)))
               "the selected AEAD accepts failures through its limit across keys")
        (cl-quic-kit::%client-authentication-failed client initial-key)
        (check (and (= (cl-quic-kit::quic-client-authentication-failures client)
                       (1+ limit))
                    (cl-quic-kit:quic-client-closed-p client))
               "the selected AEAD closes only after its integrity limit is exceeded")))
    (let* ((limit (expt 2 36))
           (client (cl-quic-kit:make-quic-client
                    :disable-hostname-verification-p t
                    :io-write (lambda (ignored bytes)
                                (declare (ignore ignored bytes))))))
      (setf (cl-quic-kit::quic-client-authentication-failures client) (1+ limit))
      (cl-quic-kit::%client-set-authentication-cipher client :chacha20-poly1305)
      (check (and (cl-quic-kit:quic-client-closed-p client)
                  (eq :closing
                      (cl-quic-kit:connection-state
                       (cl-quic-kit::quic-client-connection client))))
             "selecting ChaCha enforces its limit on failures counted before suite selection"))))
(let* ((client (cl-quic-kit:make-quic-client
                :connection (cl-quic-kit:make-quic-connection)
                :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :disable-hostname-verification-p t))
       (other-client (cl-quic-kit:make-quic-client
                      :connection (cl-quic-kit:make-quic-connection)
                      :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                      :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                      :disable-hostname-verification-p t))
       (stream (cl-quic-kit:client-open-stream client nil))
       (other-stream (cl-quic-kit:client-open-stream other-client nil))
       (payload (make-array 3 :element-type '(unsigned-byte 8)
                            :initial-contents '(9 8 7)))
       (rejected nil)
       (message nil))
  (check (= (cl-quic-kit:stream-id stream)
            (cl-quic-kit:stream-id other-stream))
         "two clients can register distinct streams with the same ID")
  (cl-quic-kit:client-receive-frame
   client (cl-quic-kit:make-frame :stream :stream-id (cl-quic-kit:stream-id stream)
                                  :offset 0 :data payload)
   :level :1-rtt)
  (handler-case (cl-quic-kit:client-read-stream other-client stream)
    (cl-quic-kit:quic-error (condition)
      (setf rejected t
            message (cl-quic-kit::quic-error-message condition))))
  (check (and rejected
              (string= message
                       "Cannot read from a stream that is not registered with the client"))
         "client read rejects a stream owned by another client")
  (check (= (cl-quic-kit:stream-readable-bytes stream) (length payload))
         "a rejected foreign read leaves buffered data untouched")
  (check (equalp (cl-quic-kit:client-read-stream client stream) payload)
         "the owning client can still read the stream after rejection"))
(let* ((client (cl-quic-kit:make-quic-client
                :connection (cl-quic-kit:make-quic-connection)
                :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :disable-hostname-verification-p t))
       (stream (cl-quic-kit:client-open-stream client nil))
       (flow (cl-quic-kit::quic-client-flow-control client))
       (initial (cl-quic-kit:flow-control-connection-receive-limit flow)))
  (flet ((receive-reset (final-size)
           (cl-quic-kit:client-receive-frame
            client (cl-quic-kit:make-frame
                    :reset-stream :stream-id (cl-quic-kit:stream-id stream)
                    :application-protocol-error-code 0 :final-size final-size)
            :level :1-rtt)))
    (receive-reset 8)
    (check (= (cl-quic-kit:flow-control-connection-received flow) 8)
           "RESET_STREAM charges its full final size")
    (check (= (cl-quic-kit:flow-control-connection-receive-limit flow)
              (+ initial 8))
           "RESET_STREAM returns discarded bytes to connection credit")
    (let* ((frames (mapcar (function cdr)
                           (cl-quic-kit::quic-client-pending-frames client)))
           (maximum (find :max-data frames :key (function cl-quic-kit:frame-type))))
      (check (and maximum
                  (= (cl-quic-kit:frame-field maximum :maximum) (+ initial 8)))
             "RESET_STREAM advertises its returned credit with MAX_DATA")
      (check (notany (lambda (frame)
                       (eq (cl-quic-kit:frame-type frame) :max-stream-data))
                     frames)
             "RESET_STREAM does not replenish the reset stream"))
    (receive-reset 8)
    (check (and (= (cl-quic-kit:flow-control-connection-receive-limit flow)
                   (+ initial 8))
                (= (count :max-data
                          (cl-quic-kit::quic-client-pending-frames client)
                          :key (lambda (entry)
                                 (cl-quic-kit:frame-type (cdr entry))))
                   1))
           "duplicate RESET_STREAM does not return credit twice")))

(let* ((client (cl-quic-kit:make-quic-client
                :connection (cl-quic-kit:make-quic-connection)
                :local-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :destination-connection-id (make-array 8 :element-type '(unsigned-byte 8))
                :disable-hostname-verification-p t))
       (stream (cl-quic-kit:client-open-stream client nil))
       (flow (cl-quic-kit::quic-client-flow-control client))
       (initial (cl-quic-kit:flow-control-connection-receive-limit flow)))
  (cl-quic-kit:client-receive-frame
   client (cl-quic-kit:make-frame :stream :stream-id (cl-quic-kit:stream-id stream)
                                  :offset 0 :data (make-array 2
                                                             :element-type '(unsigned-byte 8)
                                                             :initial-contents '(1 2)))
   :level :1-rtt)
  (check (= (length (cl-quic-kit:client-read-stream client stream)) 2)
         "read-before-reset data is delivered")
  (check (= (cl-quic-kit::stream-receive-credit-returned stream) 2)
         "client reads record connection credit already returned")
  (cl-quic-kit:client-receive-frame
   client (cl-quic-kit:make-frame :reset-stream :stream-id (cl-quic-kit:stream-id stream)
                                  :application-protocol-error-code 0 :final-size 10)
   :level :1-rtt)
  (check (= (cl-quic-kit:flow-control-connection-received flow) 10)
         "RESET_STREAM accounts for gaps through the final size")
  (check (= (cl-quic-kit:flow-control-connection-receive-limit flow)
            (+ initial 10))
         "RESET_STREAM returns only credit not returned by earlier reads"))
(let* ((client (cl-quic-kit:make-quic-client
                :connection (cl-quic-kit:make-quic-connection)
                :disable-hostname-verification-p t
                :transport-parameters (list (cons 4 1048576)
                                            (cons 6 32768)
                                            (cons 8 1))))
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
               "client reads return the received stream window")
        (when (zerop window)
          (check (= (cl-quic-kit::stream-receive-max-offset stream) 36864)
                 "client read advances the configured stream receive window")
          (let* ((frames (mapcar (function cdr)
                                 (cl-quic-kit::quic-client-pending-frames client)))
                 (maximum (find :max-stream-data frames
                                :key (function cl-quic-kit:frame-type))))
            (check (and maximum
                        (= (cl-quic-kit:frame-field maximum :maximum) 36864))
                   "client read advertises the configured receive window with MAX_STREAM_DATA"))))
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
            (+ (* window-size window-count) 32768))
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
(progn
  (dolist (case '((:stream-only t nil)
                 (:connection-only nil t)
                 (:both t t)))
    (destructuring-bind (name stream-blocked connection-blocked) case
      (let* ((client (cl-quic-kit:make-quic-client
                      :connection
                      (cl-quic-kit:make-quic-connection)
                      :local-connection-id
                      (make-array 8 :element-type '(unsigned-byte 8))
                      :destination-connection-id
                      (make-array 8 :element-type '(unsigned-byte 8))
                      :disable-hostname-verification-p t))
             (stream (cl-quic-kit:client-open-stream client nil))
             (flow (cl-quic-kit::quic-client-flow-control client))
             (payload (make-array 10 :element-type '(unsigned-byte 8)
                                    :initial-contents '(0 1 2 3 4 5 6 7 8 9))))
        (setf (cl-quic-kit::stream-send-offset stream) 4
              (cl-quic-kit::stream-send-max-offset stream)
              (if stream-blocked 4 14)
              (cl-quic-kit::flow-control-state-connection-sent flow) 4
              (cl-quic-kit::flow-control-state-connection-max-data flow)
              (if connection-blocked 4 14))
        (labels ((assert-blocked-frames (frames copies phase)
                   (let ((stream-frames
                           (remove-if-not
                            (lambda (frame)
                              (eq (cl-quic-kit:frame-type frame)
                                  :stream-data-blocked))
                            frames))
                         (connection-frames
                           (remove-if-not
                            (lambda (frame)
                              (eq (cl-quic-kit:frame-type frame) :data-blocked))
                            frames)))
                     (check (= (length frames)
                               (* copies (+ (if stream-blocked 1 0)
                                            (if connection-blocked 1 0))))
                            (format nil "~A emits frames only for exhausted credits"
                                    phase))
                     (check (= (length stream-frames)
                               (if stream-blocked copies 0))
                            (format nil "~A classifies stream credit separately" phase))
                     (check (every
                             (lambda (frame)
                               (and (= (cl-quic-kit:frame-field frame :maximum) 4)
                                    (= (cl-quic-kit:frame-field frame :stream-id)
                                       (cl-quic-kit:stream-id stream))))
                             stream-frames)
                            (format nil "~A stream frame carries its stream ID and limit"
                                    phase))
                     (check (= (length connection-frames)
                               (if connection-blocked copies 0))
                            (format nil "~A classifies connection credit separately" phase))
                     (check (every
                             (lambda (frame)
                               (= (cl-quic-kit:frame-field frame :maximum) 4))
                             connection-frames)
                            (format nil "~A connection frame carries its limit" phase))
                     (check (= (+ (length stream-frames)
                                  (length connection-frames))
                               (length frames))
                            (format nil "~A has no unrelated queued frame" phase)))))
          (cl-quic-kit:client-write-stream client stream payload :fin-p t)
          (assert-blocked-frames
           (mapcar #'cdr (cl-quic-kit::quic-client-pending-frames client))
           1 (format nil "~A write" name))
          (cl-quic-kit::%client-drain-pending-stream-writes client)
          (assert-blocked-frames
           (mapcar #'cdr (cl-quic-kit::quic-client-pending-frames client))
           2 (format nil "~A pending-write drain" name))
          (let ((pending (cl-quic-kit::quic-client-pending-stream-writes client)))
            (check (and (= (length pending) 1)
                        (eq (first (first pending)) stream)
                        (equalp (second (first pending)) payload)
                        (third (first pending)))
                   (format nil "~A preserves the blocked bytes and FIN" name))))))))

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
        (progn
          (check (<= (length (cl-quic-kit:encode-frame frame)) 1100)
                 "large stream fragments fit the packet payload budget")
          (when (and (= size 65526) (eq frame (first frames)))
            (let* ((small-frame
                     (cl-quic-kit:make-frame
                      :stream :stream-id 0
                      :data (make-array 3 :element-type '(unsigned-byte 8)
                                        :initial-contents '(1 2 3))))
                   (parts (cl-quic-kit::%client-split-frame small-frame)))
              (check (and (= (length parts) 1) (eq (first parts) small-frame))
                     "fitting stream frame is returned unchanged by packet splitting fast path"))))
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
    (progn
      (check (cl-quic-kit::quic-client-pending-frames client)
             "congestion-window blocked stream packets remain queued")
      (let* ((pending (cl-quic-kit::quic-client-pending-frames client))
             (frames (mapcar #'cdr pending)))
        (check (and pending
                    (every (lambda (entry) (eq (car entry) :1-rtt)) pending)
                    (every (lambda (frame)
                             (and (eq (cl-quic-kit:frame-type frame) :stream)
                                  (= (cl-quic-kit:frame-field frame :stream-id)
                                     (cl-quic-kit::stream-id stream))))
                           frames)
                    (loop for left in frames
                          for right in (cdr frames)
                          always
                          (= (+ (cl-quic-kit:frame-field left :offset 0)
                                (length (cl-quic-kit:frame-field left :data)))
                             (cl-quic-kit:frame-field right :offset 0)))
                    (= (+ (cl-quic-kit:frame-field (first frames) :offset 0)
                          (loop for frame in frames
                                sum (length (cl-quic-kit:frame-field frame :data))))
                       (length payload))
                    (cl-quic-kit:frame-field (car (last frames)) :fin nil))
               "blocked stream packet suffix preserves order and encryption level")))
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
         (lambda (local remote)
           (cl-quic-kit:make-quic-client
            :local-connection-id local
            :destination-connection-id remote
            :disable-hostname-verification-p t))))
  (let* ((sender (funcall make-test-client (test-octets '(1 2 3 4 5 6 7 8)) destination))
         (receiver (funcall make-test-client destination (test-octets '(1 2 3 4 5 6 7 8))))
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
                                    (test-octets '(21 22 23 24 25 26 27 28))
                                    (test-octets '(1 2 3 4 5 6 7 8)))))
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
                                                (test-octets '(1 2 3 4 5 6 7 8))
                                                destination)))
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
                                                (test-octets '(1 2 3 4 5 6 7 8))
                                                destination)))
                            (cl-quic-kit::%client-set-key late :1-rtt :write old-key)
                            (setf (cl-quic-kit::quic-client-application-write-secret late)
                                  old-secret
                                  (cl-quic-kit::quic-client-packet-numbers late)
                                  '((:1-rtt . 2)))
                            (cl-quic-kit::%client-build-packet
                             late :application
                             (list (cl-quic-kit:make-frame :ping))))))
            (check (null (cl-quic-kit:client-receive-datagram receiver high-old))
                   "old-key packet rejected by the next key is discarded")
            (check (= (cl-quic-kit::quic-client-authentication-failures receiver) 1)
                   "failed next-key authentication increments the lifetime counter"))
          (check (not (cl-quic-kit::quic-client-closed-p receiver))
                 "invalid key phase below the limit leaves the connection open")))))))

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
(progn
  (eval-when (:compile-toplevel :load-toplevel :execute)
    (require :sb-posix))
  (flet ((octets (&rest values)
           (make-array (length values) :element-type (quote (unsigned-byte 8))
                       :initial-contents values)))
    (labels ((make-client (local destination writes)
               (cl-quic-kit:make-quic-client
                :local-connection-id local
                :destination-connection-id destination
                :disable-hostname-verification-p t
                :io-write (lambda (ignored bytes)
                            (declare (ignore ignored))
                            (push bytes writes))))
             (server-packet (local source level number key frames)
               (let ((server (cl-quic-kit:make-quic-client
                              :local-connection-id source
                              :destination-connection-id local
                              :disable-hostname-verification-p t)))
                 (cl-quic-kit::%client-set-key server level :write key)
                 (setf (cl-quic-kit::quic-client-packet-numbers server)
                       (list (cons level number)))
                 (cl-quic-kit::%client-build-packet server level frames)))
             (retry-packet (local retry-cid original token)
               (let* ((base (cl-quic-kit:make-packet-header
                             :type :retry :version cl-quic-kit:*quic-version-1*
                             :destination-connection-id local
                             :source-connection-id retry-cid
                             :token token
                             :retry-integrity-tag (make-array
                                                   16
                                                   :element-type
                                                   (quote (unsigned-byte 8))
                                                   :initial-element 0)))
                      (pseudo-wire (cl-quic-kit:encode-packet-header base))
                      (tag (cl-quic-kit::retry-integrity-tag
                            (subseq pseudo-wire 0 (- (length pseudo-wire) 16))
                            :original-destination-connection-id original)))
                 (cl-quic-kit:encode-packet-header
                  (cl-quic-kit:make-packet-header
                   :type :retry :version cl-quic-kit:*quic-version-1*
                   :destination-connection-id local
                   :source-connection-id retry-cid
                   :token token :retry-integrity-tag tag)))))
      (let* ((local (octets 1 2 3 4 5 6 7 8))
             (original (octets 9 10 11 12 13 14 15 16))
             (first-server-cid (octets 21 22 23 24 25 26 27 28))
             (other-server-cid (octets 31 32 33 34 35 36 37 38))
             (writes nil)
             (client (make-client local original writes))
             (handshake-secret (make-array
                                32 :element-type (quote (unsigned-byte 8))
                                :initial-element 77))
             (handshake-key (cl-quic-kit.protection:make-key-set handshake-secret))
             (initial-key
               (getf (cl-quic-kit.protection:derive-initial-secrets original) :server)))
        (cl-quic-kit::%client-set-key client :handshake :read handshake-key)
        (let ((handshake-wire
                (server-packet
                 local first-server-cid :handshake 0 handshake-key
                 (list (cl-quic-kit:make-frame :ping)))))
          (check (cl-quic-kit:client-receive-datagram client handshake-wire)
                 "client accepts authenticated Handshake before the first Initial")
          (check (and (not
                       (cl-quic-kit::quic-client-server-initial-source-connection-id-set-p
                        client))
                      (equalp (cl-quic-kit::quic-client-remote-connection-id client)
                              original))
                 "Handshake source CID does not select the server CID"))
        (let ((initial-wire
                (server-packet
                 local first-server-cid :initial 0 initial-key
                 (list (cl-quic-kit:make-frame :ping)))))
          (check (cl-quic-kit:client-receive-datagram client initial-wire)
                 "client pins the server CID from the first decryptable Initial")
          (check (and (cl-quic-kit::quic-client-server-initial-source-connection-id-set-p
                       client)
                      (equalp
                       (cl-quic-kit::quic-client-server-initial-source-connection-id client)
                       first-server-cid)
                      (equalp (cl-quic-kit::quic-client-remote-connection-id client)
                              first-server-cid))
                 "first Initial source CID becomes the remote server CID"))
        (let* ((state-before
                 (cl-quic-kit:connection-state
                  (cl-quic-kit::quic-client-connection client)))
               (received-before
                 (copy-tree (cl-quic-kit::quic-client-received-packets client)))
               (mismatched-handshake
                 (server-packet
                  local other-server-cid :handshake 1 handshake-key
                  (list (cl-quic-kit:make-frame
                         :connection-close :error-code 0 :frame-type 0 :reason #())))))
          (check (null (cl-quic-kit:client-receive-datagram
                        client mismatched-handshake))
                 "client drops authenticated Handshake with a changed server CID")
          (check (and (equalp
                       (cl-quic-kit::quic-client-server-initial-source-connection-id client)
                       first-server-cid)
                      (equalp (cl-quic-kit::quic-client-remote-connection-id client)
                              first-server-cid)
                      (equal (cl-quic-kit::quic-client-received-packets client)
                             received-before)
                      (eql (cl-quic-kit:connection-state
                            (cl-quic-kit::quic-client-connection client))
                           state-before)
                      (not (cl-quic-kit::quic-client-closed-p client))
                      (null writes))
                 "changed Handshake CID leaves CID, packet, connection, and close state unchanged")))
      (let* ((local (octets 41 42 43 44 45 46 47 48))
             (original (octets 49 50 51 52 53 54 55 56))
             (retry-cid (octets 61 62 63 64 65 66 67 68))
             (first-server-cid (octets 71 72 73 74 75 76 77 78))
             (other-server-cid (octets 81 82 83 84 85 86 87 88))
             (token (octets 5 4 3 2))
             (writes nil)
             (client (make-client local original writes))
             (initial-key nil))
        (check (null (cl-quic-kit:client-receive-datagram
                      client (retry-packet local retry-cid original token)))
               "client accepts an authenticated Retry before the first Initial")
        (check (and (cl-quic-kit::quic-client-retry-received-p client)
                    (not
                     (cl-quic-kit::quic-client-server-initial-source-connection-id-set-p
                      client))
                    (equalp (cl-quic-kit::quic-client-remote-connection-id client)
                            retry-cid))
               "Retry source CID does not pin the server CID")
        (setf initial-key
              (getf (cl-quic-kit.protection:derive-initial-secrets retry-cid) :server))
        (let ((initial-wire
                (server-packet
                 local first-server-cid :initial 0 initial-key
                 (list (cl-quic-kit:make-frame :ping)))))
          (check (cl-quic-kit:client-receive-datagram client initial-wire)
                 "client accepts the first authenticated Initial after Retry")
          (check (and (cl-quic-kit::quic-client-server-initial-source-connection-id-set-p
                       client)
                      (equalp
                       (cl-quic-kit::quic-client-server-initial-source-connection-id client)
                       first-server-cid)
                      (equalp (cl-quic-kit::quic-client-remote-connection-id client)
                              first-server-cid))
                 "post-Retry Initial source CID selects the server CID"))
        (let* ((state-before
                (cl-quic-kit:connection-state
                 (cl-quic-kit::quic-client-connection client)))
               (mismatched-initial
                 (server-packet
                  local other-server-cid :initial 1 initial-key
                  (list (cl-quic-kit:make-frame
                         :connection-close :error-code 0 :frame-type 0 :reason #())))))
          (check (null (cl-quic-kit:client-receive-datagram
                        client mismatched-initial))
                 "client drops a changed CID after the first post-Retry Initial")
          (check (and (equalp
                       (cl-quic-kit::quic-client-remote-connection-id client)
                       first-server-cid)
                      (equal (cdr (assoc :initial
                                         (cl-quic-kit::quic-client-received-packets client)))
                             (list 0))
                      (eql (cl-quic-kit:connection-state
                            (cl-quic-kit::quic-client-connection client))
                           state-before)
                      (not (cl-quic-kit::quic-client-closed-p client))
                      (null writes))
                 "changed post-Retry CID does not process frames or close the client"))))))
(progn
  (defun client-close-fd-open-p (descriptor)
    (handler-case
        (progn (sb-posix:fcntl descriptor sb-posix:f-getfd) t)
      (sb-posix:syscall-error (condition)
        (if (= (sb-posix:syscall-errno condition) sb-posix:ebadf)
            nil
            (error condition)))))

  (defun client-close-socket-case (provided-p send-failure-p cleanup-failure-p)
  (labels ((octets (&rest bytes)
             (make-array (length bytes) :element-type '(unsigned-byte 8)
                         :initial-contents bytes))
           (wire-frames (wire destination)
             (let* ((key (getf (cl-quic-kit.protection:derive-initial-secrets destination)
                               :client))
                    (header (cl-quic-kit:decode-packet-header wire))
                    (offset
                      (- (length wire)
                         (cl-quic-kit:packet-header-payload-length header)))
                    (sample (subseq wire (+ offset 4) (+ offset 20)))
                    (first
                      (cl-quic-kit.protection:remove-header-protection
                       key wire sample offset 4 t))
                    (pn-length (1+ (logand (aref first 0) 3)))
                    (plain
                      (cl-quic-kit.protection:remove-header-protection
                       key wire sample offset pn-length t))
                    (decoded (cl-quic-kit:decode-packet-header plain)))
               (check (eq :initial (cl-quic-kit:packet-header-type decoded))
                      "close uses Initial protection")
               (check (equalp destination
                              (cl-quic-kit:packet-header-destination-connection-id decoded))
                      "close addresses the configured peer")
               (cl-quic-kit:decode-frames
                (cl-quic-kit.protection:unprotect-payload
                 key (cl-quic-kit:packet-header-packet-number decoded)
                 (cl-quic-kit:packet-header-payload decoded)
                 (subseq plain 0 (+ offset pn-length)))))))
    (let ((cl-quic-kit.protection::*hkdf-extract* #'crypto-kit:hkdf-extract)
          (cl-quic-kit.protection::*hkdf-expand* #'crypto-kit:hkdf-expand)
          (cl-quic-kit.protection::*aead-seal* #'crypto-kit:aead-seal)
          (cl-quic-kit.protection::*aead-open* #'crypto-kit:aead-open)
          (cl-quic-kit.protection::*aes-ecb* #'crypto-kit:aes-encrypt-block)
          (cl-quic-kit.protection::*chacha20* #'crypto-kit:chacha20-keystream)
          (cl-quic-kit.protection::*constant-time-equal* #'crypto-kit:constant-time-equal))
      (let* ((listener
               (cl-quic-kit:make-udp-socket
                :local-host "127.0.0.1" :non-blocking-p nil))
             (provided nil)
             (client nil)
             (socket nil)
             (native nil)
             (descriptor nil)
             (destination (octets 8 7 6 5 4 3 2 1))
             (send-condition
               (make-condition 'simple-error :format-control "close send failure"))
             (cleanup-condition-type 'sb-bsd-sockets:socket-error)
             (writes nil)
             (native-closes 0)
             (original-close (symbol-function 'sb-bsd-sockets:socket-close)))
        (unwind-protect
             (progn
               (when provided-p
                 (setf provided
                       (cl-quic-kit:make-udp-socket
                        :remote-host "127.0.0.1"
                        :remote-port (cl-quic-kit:udp-socket-local-port listener))))
               (setf client
                     (cl-quic-kit:make-quic-client
                      :hostname "localhost"
                      :udp-socket provided
                      :server-host "127.0.0.1"
                      :server-port (cl-quic-kit:udp-socket-local-port listener)
                      :local-connection-id (octets 1 2 3 4 5 6 7 8)
                      :destination-connection-id destination
                      :io-write (lambda (connection bytes)
                                  (check (eq connection
                                             (cl-quic-kit::quic-client-connection client))
                                         "close callback receives the client's connection")
                                  (push bytes writes)
                                  (when send-failure-p (error send-condition)))))
               (setf socket (cl-quic-kit::quic-client-udp-socket client)
                     native (cl-quic-kit::udp-socket-socket socket)
                     descriptor (sb-bsd-sockets:socket-file-descriptor native))
               (check (if provided-p (eq socket provided) (not (eq socket provided)))
                      "client socket ownership matches the public constructor input")
               (check (client-close-fd-open-p descriptor)
                      "client owns an open descriptor before close")
               (check (= 3 (cl-quic-kit:udp-send socket (octets 7 8 9)))
                      "the real socket can send before close")
               (multiple-value-bind (bytes length peer)
                   (cl-quic-kit:udp-receive listener :wait-p t)
                 (check (equalp bytes #(7 8 9))
                        "loopback receives the actual socket's bytes")
                 (check (= length 3) "loopback reports the actual datagram length")
                 (check (equalp (first peer) #(127 0 0 1))
                        "loopback receives from localhost")
                 (check (plusp (cl-quic-kit:udp-socket-local-port socket))
                        "the client socket has a real bound port"))
               (setf (symbol-function 'sb-bsd-sockets:socket-close)
                     (lambda (raw &rest arguments)
                       (if (eq raw native)
                           (progn
                             (incf native-closes)
                             (apply original-close raw arguments)
                             (when cleanup-failure-p (sb-bsd-sockets:socket-error "close" 5)))
                           (apply original-close raw arguments))))
               (let ((caught nil) (result nil))
                 (handler-case
                     (setf result
                           (cl-quic-kit:client-close
                            client :error-code 7 :reason "close"))
                   (error (condition) (setf caught condition)))
                 (check (cond
                              (send-failure-p (eq caught send-condition))
                              (cleanup-failure-p (typep caught cleanup-condition-type))
                              (t (null caught)))
                        "original send error takes precedence; cleanup-only failure propagates")
                 (check (eq result (not (or send-failure-p cleanup-failure-p)))
                        "only a successful close returns T"))
               (check (not (client-close-fd-open-p descriptor))
                      "first close releases the actual descriptor")
               (check (= native-closes 1)
                      "first close invokes native cleanup exactly once")
               (check (cl-quic-kit::udp-socket-closed-p socket)
                      "UDP ownership is closed")
               (check (cl-quic-kit:quic-client-closed-p client)
                      "client is closed after every outcome")
               (check (eq :closing
                          (cl-quic-kit:connection-state
                           (cl-quic-kit::quic-client-connection client)))
                      "the connection enters closing")
               (check (= 1 (length writes))
                      "close attempts one protected datagram")
               (let* ((frames (wire-frames (first writes) destination))
                      (close (find :connection-close frames
                                   :key #'cl-quic-kit:frame-type)))
                 (check (= 1 (count :connection-close frames
                                    :key #'cl-quic-kit:frame-type))
                        "wire contains exactly one transport close")
                 (check (= 7 (cl-quic-kit:frame-field close :error-code))
                        "wire retains the requested error code")
                 (check (= 0 (cl-quic-kit:frame-field close :frame-type))
                        "wire close has no triggering frame")
                 (check (equalp #(99 108 111 115 101)
                                (cl-quic-kit:frame-field close :reason))
                        "wire retains the close reason"))
               (check (cl-quic-kit:client-close client)
                      "repeated close succeeds without retrying errors")
               (check (= native-closes 1)
                      "repeated close does not repeat native cleanup")
               (check (= 1 (length writes))
                      "repeated close does not repeat the send")
               (check (not (client-close-fd-open-p descriptor))
                      "repeated close keeps the descriptor closed"))
          (setf (symbol-function 'sb-bsd-sockets:socket-close) original-close)
          (when (and native descriptor (client-close-fd-open-p descriptor))
            (funcall original-close native))
          (when (and provided (not socket))
            (cl-quic-kit:udp-close provided))
          (cl-quic-kit:udp-close listener))
        (check (eq original-close
                   (symbol-function 'sb-bsd-sockets:socket-close))
               "native socket-close spy is restored exactly")))))

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
  #+linux (client-close-cleanup-error)
  #+linux (client-close-dual-error)
  (progn
  (defun client-close-provided-control ()
    (client-close-socket-case t nil nil))
  (defun client-close-internal-control ()
    (client-close-socket-case nil nil nil))
  (client-default-clock-ack-rtt-bounded)
  (client-close-provided-control)
  (client-close-internal-control)))
(progn
  (defun auth-drop-octets (&rest bytes)
    (make-array (length bytes) :element-type '(unsigned-byte 8)
                :initial-contents bytes))

  (defun auth-drop-bare-packet ()
    (cl-quic-kit:encode-packet-header
     (cl-quic-kit:make-packet-header
      :type :initial :version 1
      :destination-connection-id (auth-drop-octets 1 2 3 4 5 6 7 8)
      :source-connection-id (auth-drop-octets 8 7 6 5 4 3 2 1)
      :packet-number 0 :packet-number-length 4 :payload (auth-drop-octets))))

  (defun auth-drop-fixture (function)
    (let ((cl-quic-kit.protection::*hkdf-extract* #'crypto-kit:hkdf-extract)
          (cl-quic-kit.protection::*hkdf-expand* #'crypto-kit:hkdf-expand)
          (cl-quic-kit.protection::*aead-seal* #'crypto-kit:aead-seal)
          (cl-quic-kit.protection::*aead-open* #'crypto-kit:aead-open)
          (cl-quic-kit.protection::*aes-ecb* #'crypto-kit:aes-encrypt-block)
          (cl-quic-kit.protection::*chacha20* #'crypto-kit:chacha20-keystream)
          (cl-quic-kit.protection::*constant-time-equal*
            #'crypto-kit:constant-time-equal))
      (let* ((local (auth-drop-octets 1 2 3 4 5 6 7 8))
             (peer (auth-drop-octets 8 7 6 5 4 3 2 1))
             (keys (cl-quic-kit.protection:derive-initial-secrets peer))
             (writes nil)
             (client (cl-quic-kit:make-quic-client
                      :local-connection-id local
                      :destination-connection-id peer
                      :disable-hostname-verification-p t
                      :io-write (lambda (ignored bytes)
                                  (declare (ignore ignored))
                                  (push bytes writes)))))
        (labels ((packet (number &optional (payload (auth-drop-octets 1 0 0 0 0 0 0 0)))
                   (let* ((wire
                            (cl-quic-kit:encode-packet-header
                             (cl-quic-kit:make-packet-header
                              :type :initial :version 1
                              :destination-connection-id local
                              :source-connection-id peer
                              :packet-number number :packet-number-length 4
                              :payload
                              (make-array (+ 16 (length payload))
                                          :element-type '(unsigned-byte 8)))))
                          (offset (- (length wire) (length payload) 20))
                          (key (getf keys :server)))
                     (replace wire
                              (cl-quic-kit.protection:protect-payload
                               key number payload (subseq wire 0 (+ offset 4)))
                              :start1 (+ offset 4))
                     (cl-quic-kit.protection:apply-header-protection
                      key wire (subseq wire (+ offset 4) (+ offset 20)) offset 4 t)))
                 (frames ()
                   (loop for wire in (reverse writes) append
                     (let* ((header (cl-quic-kit:decode-packet-header wire))
                            (offset
                              (- (length wire)
                                 (cl-quic-kit:packet-header-payload-length header)))
                            (key (getf keys :client))
                            (sample (subseq wire (+ offset 4) (+ offset 20)))
                            (first
                              (cl-quic-kit.protection:remove-header-protection
                               key wire sample offset 4 t))
                            (pn-length (1+ (logand (aref first 0) 3)))
                            (plain
                              (cl-quic-kit.protection:remove-header-protection
                               key wire sample offset pn-length t))
                            (decoded (cl-quic-kit:decode-packet-header plain)))
                       (cl-quic-kit:decode-frames
                        (cl-quic-kit.protection:unprotect-payload
                         key (cl-quic-kit:packet-header-packet-number decoded)
                         (cl-quic-kit:packet-header-payload decoded)
                         (subseq plain 0 (+ offset pn-length))))))))
          (unwind-protect
               (funcall function client #'packet #'frames
                        (lambda () (reverse writes)))
            (cl-quic-kit:client-close client)
            (check (cl-quic-kit::quic-client-closed-p client)
                   "fixture cleanup closes the client")
            (check (null (cl-quic-kit::quic-client-udp-socket client))
                   "fixture owns no UDP socket"))))))

  (defun auth-drop-damaged-packet (packet number)
    (let ((bytes (funcall packet number)))
      (setf (aref bytes (1- (length bytes)))
            (logxor 1 (aref bytes (1- (length bytes)))))
      bytes))

  (defun auth-drop-check-ack (frames number)
    (let ((ack (find :ack frames :key #'cl-quic-kit:frame-type)))
      (check ack "authenticated control produces an ACK")
      (check (= number (cl-quic-kit:frame-field ack :largest-acknowledged))
             "only authenticated packet numbers are acknowledged")
      (check (equal (list (cons number 0))
                    (cl-quic-kit:frame-field ack :ranges))
             "discarded packets do not enter ACK ranges")
      (check (not (find :connection-close frames
                        :key #'cl-quic-kit:frame-type))
             "drop does not emit CONNECTION_CLOSE")))

  (defun auth-drop-prefix-and-sample ()
    (auth-drop-fixture
     (lambda (client packet frames writes)
       (dolist (bytes
                (list (auth-drop-octets 255)
                      (auth-drop-octets 192)
                      (auth-drop-octets 0)
                      (auth-drop-bare-packet)))
         (check (null (cl-quic-kit:client-receive-datagram client bytes))
                "unauthenticated truncated input is discarded")
         (check (not (cl-quic-kit::quic-client-closed-p client))
                "drop stays open")
         (check (null (funcall writes)) "drop performs no writes")
         (check (zerop (cl-quic-kit::quic-client-authentication-failures client))
                "header truncation is not an AEAD failure"))
       (check (cl-quic-kit:client-receive-datagram client (funcall packet 4))
              "authenticated control after truncated input is accepted")
       (cl-quic-kit:client-poll client)
       (auth-drop-check-ack (funcall frames) 4))))

  (defun auth-drop-coalesced ()
    (auth-drop-fixture
     (lambda (client packet frames writes)
       (declare (ignore writes))
       (let ((header
               (cl-quic-kit:client-receive-datagram
                client
                (concatenate '(vector (unsigned-byte 8))
                             (auth-drop-damaged-packet packet 0)
                             (funcall packet 1)))))
         (check (and header
                     (= 1 (cl-quic-kit:packet-header-packet-number header)))
                "a later authenticated coalesced packet is processed"))
       (check (= 1 (cl-quic-kit::quic-client-authentication-failures client))
              "coalesced failure counted once")
       (check (not (cl-quic-kit::quic-client-closed-p client))
              "coalesced drop stays open")
       (cl-quic-kit:client-poll client)
       (auth-drop-check-ack (funcall frames) 1)))
    (auth-drop-fixture
     (lambda (client packet frames writes)
       (declare (ignore writes))
       (let ((header
               (cl-quic-kit:client-receive-datagram
                client
                (concatenate '(vector (unsigned-byte 8))
                             (funcall packet 2)
                             (auth-drop-octets 255)))))
         (check (and header
                     (= 2 (cl-quic-kit:packet-header-packet-number header)))
                "truncated tail preserves the authenticated preceding packet"))
       (check (not (cl-quic-kit::quic-client-closed-p client))
              "truncated tail stays open")
       (cl-quic-kit:client-poll client)
       (auth-drop-check-ack (funcall frames) 2))))

  (auth-drop-prefix-and-sample)
  (progn
  (auth-drop-coalesced)
  (let* ((client-id (auth-drop-octets 1 2 3 4 5 6 7 8))
         (server-id (auth-drop-octets 8 7 6 5 4 3 2 1))
         (close-wire nil)
         (key
           (cl-quic-kit.protection:make-key-set
            (make-array 32 :element-type '(unsigned-byte 8)
                        :initial-element #x55)))
         (client
           (cl-quic-kit:make-quic-client
            :local-connection-id client-id
            :destination-connection-id server-id
            :disable-hostname-verification-p t
            :io-write (lambda (connection bytes)
                        (declare (ignore connection))
                        (setf close-wire bytes))))
         (peer
           (cl-quic-kit:make-quic-client
            :connection
            (cl-quic-kit:make-quic-connection
             :role :server :local-connection-id server-id)
            :local-connection-id server-id
            :destination-connection-id client-id
            :disable-hostname-verification-p t)))
    (dolist (direction '(:read :write))
      (cl-quic-kit::%client-set-key client :1-rtt direction key)
      (cl-quic-kit::%client-set-key peer :1-rtt direction key))
    (let ((packet
            (cl-quic-kit::%client-build-packet
             peer :application
             (list (cl-quic-kit:make-frame
                    :stream :stream-id 1 :offset 0 :data #(1) :fin t)
                   (cl-quic-kit:make-frame
                    :stream :stream-id 1 :offset 0 :data #() :fin t)))))
      (check (and packet
                  (null (cl-quic-kit:client-receive-datagram client packet))
                  close-wire)
             "client emits a close for inconsistent stream final size")
      (check
       (and (cl-quic-kit:client-receive-datagram peer close-wire)
            (eq (cl-quic-kit:connection-state
                 (cl-quic-kit:quic-client-connection peer))
                :draining)
            (= (cl-quic-kit::quic-connection-closed-error
                (cl-quic-kit:quic-client-connection peer))
               6))
       "client reports FINAL_SIZE_ERROR to peer for inconsistent stream final size")))))
