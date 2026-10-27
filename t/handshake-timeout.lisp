(progn
  (define-condition server-handshake-timeout-test-close-error (error) () (:report "Injected TLS driver close failure"))
  (defun server-handshake-timeout-test-type-error-p (thunk)
    (handler-case
        (progn (funcall thunk) nil)
      (type-error () t))))

(defun server-handshake-timeout-test-cid (octet)
  (make-array 8 :element-type '(unsigned-byte 8) :initial-element octet))

(defun server-handshake-timeout-test-server
    (&key (max-connections 2) (max-handshakes 1) (handshake-timeout 10))
  (cl-quic-kit::%make-quic-server
   :udp-socket :server-handshake-timeout-test
   :max-connections max-connections
   :max-handshakes max-handshakes
   :handshake-timeout handshake-timeout
   :retry-policy :never
   :retry-tokens (make-hash-table :test #'equalp)
   :retired-retry-cids (make-hash-table :test #'equalp)
   :retired-local-cids (make-hash-table :test #'equalp)
   :paths (make-hash-table :test #'equalp)
   :connections (make-hash-table :test #'equalp)
   :accepted-connections nil
   :shutdown-deadline nil
   :shutdown-error-code :no-error
   :shutdown-reason #()
   :closed-p nil))

(defun server-handshake-timeout-test-connection
    (server local-cid remote-cid original-cid started-at &optional alias-cid)
  (let* ((connection
          (cl-quic-kit:make-quic-connection
           :role :server
           :local-connection-id local-cid
           :idle-timeout 100
           :now-fn (lambda () started-at)))
         (server-connection
          (cl-quic-kit::%make-server-connection
           :server server
           :connection connection
           :address :peer
           :now started-at
           :handshake-deadline
           (+ (cl-quic-kit::%server-exact-real started-at)
              (cl-quic-kit::%server-exact-real
               (cl-quic-kit::quic-server-handshake-timeout server)))
           :original-destination-connection-id original-cid
           :local-connection-id local-cid
           :remote-connection-id remote-cid
           :pending-datagrams (list #(1 2)))))
    (cl-quic-kit:connection-set-state connection :handshaking)
    (setf (gethash local-cid
                   (cl-quic-kit::quic-server-connections server))
          server-connection)
    (when alias-cid
      (setf (gethash alias-cid
                     (cl-quic-kit::quic-server-connections server))
            server-connection))
    server-connection))

(defun server-handshake-timeout-test-packet
    (type destination-cid source-cid)
  (cl-quic-kit:encode-packet-header
   (cl-quic-kit:make-packet-header
    :type type
    :version cl-quic-kit:*quic-version-1*
    :destination-connection-id destination-cid
    :source-connection-id source-cid
    :packet-number 0
    :packet-number-length 1
    :payload #(1))))
(defun server-handshake-timeout-test-with-poll
    (server thunk &optional tls-driver-close-function)
  (let* ((socket (cl-quic-kit::quic-server-udp-socket server))
         (receive-symbol (find-symbol "UDP-RECEIVE" "CL-QUIC-KIT"))
         (client-poll-symbol (find-symbol "CLIENT-POLL" "CL-QUIC-KIT"))
         (tls-driver-close-symbol
           (find-symbol "TLS13-SERVER-DRIVER-CLOSE" "CL-TLS-KIT"))
         (original-receive (symbol-function receive-symbol))
         (original-client-poll (symbol-function client-poll-symbol))
         (original-tls-driver-close
           (symbol-function tls-driver-close-symbol))
         (queue nil))
    (unwind-protect
         (progn
           (setf (symbol-function receive-symbol)
                 (lambda (candidate-socket &rest arguments)
                   (if (eq candidate-socket socket)
                       (if queue
                           (values-list (pop queue))
                           (values nil nil nil))
                       (apply original-receive candidate-socket arguments)))
                 (symbol-function client-poll-symbol)
                 (lambda (&rest arguments)
                   (declare (ignore arguments))
                   nil))
           (when tls-driver-close-function
             (setf (symbol-function tls-driver-close-symbol)
                   tls-driver-close-function))
           (funcall thunk
                    (lambda (bytes byte-count address)
                      (setf queue
                            (nconc queue
                                   (list (list bytes byte-count address)))))))
      (setf (symbol-function receive-symbol) original-receive
            (symbol-function client-poll-symbol) original-client-poll
            (symbol-function tls-driver-close-symbol)
            original-tls-driver-close))))

(defun server-handshake-timeout-test-admit-client (server at)
  (let* ((local-cid (server-handshake-timeout-test-cid 61))
         (original-cid (server-handshake-timeout-test-cid 71))
         (remote-cid (server-handshake-timeout-test-cid 81))
         (header
          (cl-quic-kit:make-packet-header
           :type :initial
           :version cl-quic-kit:*quic-version-1*
           :destination-connection-id original-cid
           :source-connection-id remote-cid
           :packet-number 0
           :packet-number-length 1
           :payload #()))
         (create-symbol (find-symbol "%SERVER-CREATE-CONNECTION" "CL-QUIC-KIT"))
         (original-create (symbol-function create-symbol))
         (process-symbol (find-symbol "%SERVER-PROCESS-PROTECTED-DATAGRAM" "CL-QUIC-KIT"))
         (original-process (symbol-function process-symbol))
         (created nil))
    (unwind-protect
         (progn
           (setf (symbol-function create-symbol)
                 (lambda (candidate-server candidate-header path address record now)
                   (declare (ignore candidate-header record))
                   (let* ((connection
                           (cl-quic-kit:make-quic-connection
                            :role :server
                            :local-connection-id local-cid
                            :idle-timeout 100
                            :now-fn (lambda () now)))
                          (server-connection
                           (cl-quic-kit::%make-server-connection
                            :server candidate-server
                            :connection connection
                            :path path
                            :address address
                            :now now
                            :handshake-deadline
                            (+ (cl-quic-kit::%server-exact-real now)
                               (cl-quic-kit::%server-exact-real
                                (cl-quic-kit::quic-server-handshake-timeout candidate-server)))
                            :original-destination-connection-id original-cid
                            :local-connection-id local-cid
                            :remote-connection-id remote-cid
                            :pending-datagrams nil)))
                     (cl-quic-kit:connection-set-state connection :handshaking)
                     (setf (gethash local-cid
                                    (cl-quic-kit::quic-server-connections
                                     candidate-server))
                           server-connection
                           created server-connection)
                     server-connection))
                 (symbol-function process-symbol)
                 (lambda (&rest arguments)
                   (declare (ignore arguments))
                   nil))
           (cl-quic-kit::%server-start-or-feed-initial
            server header nil :new-peer nil #(1) at)
           (and created
                (eq created
                    (gethash local-cid
                             (cl-quic-kit::quic-server-connections server)))
                (= (cl-quic-kit::%server-connection-count server) 1)
                (= (cl-quic-kit::%server-handshaking-count server) 1)
                (= (cl-quic-kit::server-connection-handshake-deadline created)
                   (+ (cl-quic-kit::%server-exact-real at)
                      (cl-quic-kit::%server-exact-real
                       (cl-quic-kit::quic-server-handshake-timeout server))))))
      (setf (symbol-function create-symbol) original-create
            (symbol-function process-symbol) original-process))))

(progn
  (let ((server
          (cl-quic-kit:make-quic-server
           :local-address "127.0.0.1" :local-port 0 :max-connections 1)))
    (unwind-protect
         (check (= (cl-quic-kit::quic-server-handshake-timeout server) 10)
                "server handshake timeout defaults to ten seconds")
      (cl-quic-kit:quic-server-close server)))

  (dolist (invalid
          (append '(0 -1 "10" nil #c(1 2)
                    #+sbcl sb-ext:single-float-positive-infinity)
                  #+sbcl (list (sb-kernel:make-single-float #x7fc00000))))
    (check
     (server-handshake-timeout-test-type-error-p
      (lambda ()
        (cl-quic-kit:make-quic-server
         :max-connections 1 :handshake-timeout invalid)))
     "server rejects non-positive and non-real handshake timeouts"))

  (let ((server
          (cl-quic-kit:make-quic-server
           :local-address "127.0.0.1" :local-port 0
           :max-connections 1 :handshake-timeout 3/2)))
    (unwind-protect
         (check (= (cl-quic-kit::quic-server-handshake-timeout server) 3/2)
                "server accepts a positive rational handshake timeout")
      (cl-quic-kit:quic-server-close server))))
(let* ((server (server-handshake-timeout-test-server
                :max-connections 1 :max-handshakes 1))
       (server-connection
         (server-handshake-timeout-test-connection
          server
          (server-handshake-timeout-test-cid 1)
          (server-handshake-timeout-test-cid 2)
          (server-handshake-timeout-test-cid 3)
          0))
       (connection
         (cl-quic-kit::server-connection-connection server-connection)))
  (setf (cl-quic-kit::server-connection-handshake-complete-p server-connection) t
        (cl-quic-kit::server-connection-accepted-p server-connection) t
        (cl-quic-kit::quic-server-accepted-connections server) (list connection))
  (cl-quic-kit:connection-set-state connection :established)
  (server-handshake-timeout-test-with-poll
   server
   (lambda (enqueue)
     (declare (ignore enqueue))
     (cl-quic-kit:quic-server-poll server 9)
     (check (and (eq (cl-quic-kit:connection-state connection) :established)
                 (eq (cl-quic-kit:quic-server-accept-connection server)
                     connection))
            "a handshake completed before its deadline remains established and accepted")
     (cl-quic-kit:quic-server-poll server 10)
     (check (and (eq (cl-quic-kit:connection-state connection) :established)
                 (= (cl-quic-kit::%server-connection-count server) 1))
            "a completed handshake is not expired at its deadline"))))

(let* ((server (server-handshake-timeout-test-server :max-connections 2 :max-handshakes 1))
       (local-cid (server-handshake-timeout-test-cid 11))
       (remote-cid (server-handshake-timeout-test-cid 21))
       (original-cid (server-handshake-timeout-test-cid 31))
       (alias-cid (server-handshake-timeout-test-cid 41))
       (server-connection
         (server-handshake-timeout-test-connection
          server local-cid remote-cid original-cid 0 alias-cid))
       (connection
         (cl-quic-kit::server-connection-connection server-connection))
       (packet
         (server-handshake-timeout-test-packet
          :handshake local-cid remote-cid))
       (process-symbol
         (find-symbol "%SERVER-PROCESS-PROTECTED-DATAGRAM" "CL-QUIC-KIT"))
       (original-process (symbol-function process-symbol))
       (processed 0))
  (unwind-protect
       (progn
         (setf (symbol-function process-symbol)
               (lambda (candidate bytes now)
                 (declare (ignore bytes))
                 (when (eq candidate server-connection)
                   (incf processed))
                 (setf (cl-quic-kit::server-connection-now candidate) now)
                 (cl-quic-kit::connection-touch
                  (cl-quic-kit::server-connection-connection candidate) now)))
         (server-handshake-timeout-test-with-poll
          server
          (lambda (enqueue)
            (funcall enqueue packet (length packet) :peer)
            (cl-quic-kit:quic-server-poll server 9)
            (check (and (= processed 1)
                        (= (cl-quic-kit::server-connection-handshake-deadline
                            server-connection)
                           10)
                        (= (cl-quic-kit::%server-connection-count server) 1)
                        (= (cl-quic-kit::%server-handshaking-count server) 1))
                   "traffic just before the deadline does not extend the absolute deadline")
            (cl-quic-kit:quic-server-poll server 8)
            (check (and (= processed 1)
                        (= (cl-quic-kit::%server-connection-count server) 1)
                        (= (cl-quic-kit::%server-handshaking-count server) 1))
                   "a backward clock sample does not expire the handshake early")
            (funcall enqueue packet (length packet) :peer)
            (cl-quic-kit:quic-server-poll server 10)
            (check (and (= processed 1)
                        (eq (cl-quic-kit:connection-state connection) :closed)
                        (null (gethash local-cid
                                       (cl-quic-kit::quic-server-connections server)))
                        (null (gethash alias-cid
                                       (cl-quic-kit::quic-server-connections server)))
                        (zerop (hash-table-count
                                (cl-quic-kit::quic-server-connections server)))
                        (null (cl-quic-kit::server-connection-pending-datagrams
                               server-connection))
                        (not (member connection
                                     (cl-quic-kit::quic-server-accepted-connections server)
                                     :test #'eq))
                        (zerop (cl-quic-kit::%server-connection-count server))
                        (zerop (cl-quic-kit::%server-handshaking-count server))
                        (null (cl-quic-kit:quic-server-accept-connection server)))
                   "the next poll silently expires the handshake before late traffic and releases its routes, queue, and admission slots")
            (check (server-handshake-timeout-test-admit-client server 10)
                   "a new client can reuse the released max-handshakes slot"))))
    (setf (symbol-function process-symbol) original-process)))
(let* ((server (server-handshake-timeout-test-server
                :max-connections 2 :max-handshakes 1))
       (server-connection
        (server-handshake-timeout-test-connection
         server
         (server-handshake-timeout-test-cid 51)
         (server-handshake-timeout-test-cid 52)
         (server-handshake-timeout-test-cid 53)
         0))
       (connection
        (cl-quic-kit::server-connection-connection server-connection))
       (engine (cl-quic-kit::%make-quic-client))
       (key-secret (make-array 32 :element-type (quote (unsigned-byte 8))
                               :initial-element 7))
       (key-set (cl-quic-kit.protection:make-key-set key-secret))
       (key-material
        (list (cl-quic-kit.protection:key-set-key key-set)
              (cl-quic-kit.protection:key-set-iv key-set)
              (cl-quic-kit.protection:key-set-hp key-set)))
       (read-secret (make-array 32 :element-type (quote (unsigned-byte 8))
                                :initial-element 8))
       (write-secret (make-array 32 :element-type (quote (unsigned-byte 8))
                                 :initial-element 9))
       (next-secret (make-array 32 :element-type (quote (unsigned-byte 8))
                                :initial-element 10))
       (client-hello-wire (make-array 8 :element-type (quote (unsigned-byte 8))
                                      :initial-element 11))
       (tls-boundary (cl-tls-kit:make-quic-tls-boundary))
       (boundary-wire (make-array 8 :element-type (quote (unsigned-byte 8))
                                  :initial-element 12))
       (tls-driver-secret (make-array 32 :element-type (quote (unsigned-byte 8))
                                      :initial-element 13))
       (tls-driver (list :tls-driver))
       (error-driver nil)
       (tls-driver-close-count 0))
  (setf (cl-tls-kit:quic-tls-boundary-transcript tls-boundary)
        (list boundary-wire)
        (cl-quic-kit::quic-client-connection engine) connection
        (cl-quic-kit::quic-client-keys engine)
        (list (list :initial :read key-set :write key-set)
              (list :handshake :read key-set :write key-set))
        (cl-quic-kit::quic-client-application-read-old-key engine) key-set
        (cl-quic-kit::quic-client-application-read-next-key engine) key-set
        (cl-quic-kit::quic-client-application-read-next-secret engine) next-secret
        (cl-quic-kit::quic-client-application-read-secret engine) read-secret
        (cl-quic-kit::quic-client-application-write-secret engine) write-secret
        (cl-quic-kit::quic-client-client-hello-wire engine) client-hello-wire
        (cl-quic-kit::quic-client-tls-boundary engine) tls-boundary
        (cl-quic-kit::quic-client-tls-driver engine) tls-driver
        (cl-quic-kit::server-connection-engine server-connection) engine
        (cl-quic-kit::server-connection-tls-boundary server-connection) tls-boundary
        (cl-quic-kit::server-connection-tls-driver server-connection) tls-driver
        (cl-quic-kit::quic-connection-stream-engine connection) engine)
  (server-handshake-timeout-test-with-poll
   server
   (lambda (enqueue)
     (declare (ignore enqueue))
     (cl-quic-kit:quic-server-poll server 10)
     (check (and (null (cl-quic-kit::quic-client-keys engine))
                 (every (lambda (octets) (every (function zerop) octets))
                        key-material))
            "an expired handshake clears retained QUIC packet keys")
     (check (and (every (lambda (secret) (every (function zerop) secret))
                        (list read-secret write-secret next-secret))
                 (every (function zerop) client-hello-wire))
            "an expired handshake erases retained QUIC TLS secrets")
     (check (and (= tls-driver-close-count 1)
                 (every (function zerop) tls-driver-secret)
                 (every (function zerop) boundary-wire))
            "an expired handshake closes the public TLS driver and clears transcript bytes")
     (check (and (null (cl-quic-kit::server-connection-engine server-connection))
                 (null (cl-quic-kit::server-connection-tls-boundary server-connection))
                 (null (cl-quic-kit::server-connection-tls-driver server-connection))
                 (null (cl-quic-kit::quic-connection-stream-engine connection))
                 (null (cl-quic-kit::quic-client-tls-boundary engine))
                 (null (cl-quic-kit::quic-client-tls-driver engine))
                 (cl-quic-kit::quic-client-closed-p engine))
            "an expired handshake releases its engine and TLS driver state")
     (let* ((error-server-connection
             (server-handshake-timeout-test-connection
              server
              (server-handshake-timeout-test-cid 54)
              (server-handshake-timeout-test-cid 55)
              (server-handshake-timeout-test-cid 56)
              0))
            (error-connection
             (cl-quic-kit::server-connection-connection
              error-server-connection)))
       (setf error-driver (list :tls-driver-error)
             (cl-quic-kit::server-connection-tls-driver
              error-server-connection)
             error-driver
             (cl-quic-kit::server-connection-accepted-p
              error-server-connection)
             t
             (cl-quic-kit::quic-server-accepted-connections server)
             (list error-connection))
       (check (handler-case
                  (progn
                    (cl-quic-kit:quic-server-poll server 10)
                    nil)
                (server-handshake-timeout-test-close-error () t))
              "TLS driver close failures are propagated")
       (check (and (= tls-driver-close-count 2)
                   (eq (cl-quic-kit:connection-state error-connection) :closed)
                   (null (cl-quic-kit::server-connection-pending-datagrams
                          error-server-connection))
                   (null (cl-quic-kit::server-connection-tls-driver
                          error-server-connection))
                   (null (cl-quic-kit::quic-server-accepted-connections server))
                   (zerop (cl-quic-kit::%server-connection-count server))
                   (zerop (cl-quic-kit::%server-handshaking-count server)))
              "a TLS close failure still releases routes, accept state, and handshake capacity"))
     (let* ((normal-server
             (server-handshake-timeout-test-server
              :max-connections 1 :max-handshakes 1))
            (normal-server-connection
             (server-handshake-timeout-test-connection
              normal-server
              (server-handshake-timeout-test-cid 31)
              (server-handshake-timeout-test-cid 32)
              (server-handshake-timeout-test-cid 33)
              0))
            (normal-connection
             (cl-quic-kit::server-connection-connection
              normal-server-connection))
            (normal-driver (list :normal-tls-driver))
            (normal-close-count 0))
       (setf (cl-quic-kit::server-connection-tls-driver
              normal-server-connection)
             normal-driver
             (cl-quic-kit::server-connection-pending-datagrams
              normal-server-connection)
             nil
             (cl-quic-kit::server-connection-accepted-p
              normal-server-connection)
             t
             (cl-quic-kit::quic-server-accepted-connections normal-server)
             (list normal-connection))
       (cl-quic-kit:connection-set-state normal-connection :closed)
       (server-handshake-timeout-test-with-poll
        normal-server
        (lambda (normal-enqueue)
          (declare (ignore normal-enqueue))
          (cl-quic-kit::%server-poll-connections normal-server 0)
          (check (and (= normal-close-count 1)
                      (eq (cl-quic-kit:connection-state normal-connection) :closed)
                      (null (cl-quic-kit::server-connection-tls-driver
                             normal-server-connection))
                      (null (cl-quic-kit::quic-server-accepted-connections
                             normal-server))
                      (zerop (cl-quic-kit::%server-connection-count normal-server)))
                 "the normal closed-connection path uses the public TLS driver close"))
        (lambda (candidate-driver)
          (unless (eq candidate-driver normal-driver)
            (error "unexpected normal TLS driver"))
          (incf normal-close-count)
          candidate-driver))
       (check (server-handshake-timeout-test-admit-client normal-server 0)
              "normal close releases the max-handshakes slot"))
     (check (server-handshake-timeout-test-admit-client server 10)
            "a new client can reuse max-handshakes after TLS close failure")
     (let* ((large-server
             (server-handshake-timeout-test-server
              :max-connections 1 :max-handshakes 1
              :handshake-timeout 1.0d0))
            (large-clock 1.0d20)
            (large-connection
             (server-handshake-timeout-test-connection
              large-server
              (server-handshake-timeout-test-cid 57)
              (server-handshake-timeout-test-cid 58)
              (server-handshake-timeout-test-cid 59)
              large-clock))
            (large-quic-connection
             (cl-quic-kit::server-connection-connection large-connection))
            (deadline (cl-quic-kit::server-connection-handshake-deadline
                       large-connection)))
       (check (> deadline (cl-quic-kit::%server-exact-real large-clock))
              "a large finite clock preserves a positive handshake timeout")
       (server-handshake-timeout-test-with-poll
        large-server
        (lambda (large-enqueue)
          (declare (ignore large-enqueue))
          (cl-quic-kit:quic-server-poll large-server large-clock)
          (check (and (= (cl-quic-kit::%server-connection-count large-server) 1)
                      (eq (cl-quic-kit:connection-state
                           large-quic-connection)
                          :handshaking))
                 "a large clock does not expire before the exact deadline")
          (cl-quic-kit:quic-server-poll large-server deadline)
          (check (and (eq (cl-quic-kit:connection-state
                           large-quic-connection)
                          :closed)
                      (zerop (cl-quic-kit::%server-connection-count large-server))
                      (zerop (cl-quic-kit::%server-handshaking-count
                              large-server)))
                 "a large clock expires on its exact rational deadline")))))
   (lambda (candidate-driver)
     (incf tls-driver-close-count)
     (cond ((eq candidate-driver tls-driver)
            (fill tls-driver-secret 0))
           ((eq candidate-driver error-driver)
            (error (quote server-handshake-timeout-test-close-error)))
           (t
            (error "unexpected TLS driver close"))))))
