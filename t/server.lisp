(in-package #:cl-user)

(defun server-test-initial-packet
    (version destination-cid source-cid &optional (token #()) (datagram-size 1200))
  (loop for payload-size from 0 to datagram-size
        for packet =
          (cl-quic-kit:encode-packet-header
           (cl-quic-kit:make-packet-header
            :type :initial :version version
            :destination-connection-id destination-cid
            :source-connection-id source-cid :token token
            :packet-number 0 :packet-number-length 1
            :payload (make-array payload-size
                                 :element-type '(unsigned-byte 8))))
        when (= (length packet) datagram-size)
          return packet
        finally (error "Could not construct a QUIC Initial datagram of the requested size")))

(defun server-test-token-entry (server)
  (loop for token being the hash-keys
          of (cl-quic-kit::quic-server-retry-tokens server)
        using (hash-value record)
        return (values token record)))

(defun server-test-receive (socket &optional return-nil-on-timeout-p)
  (loop repeat 1000
        for bytes = (cl-quic-kit:udp-receive socket)
        when bytes
          return bytes
        do (sleep 0.001)
        finally (if return-nil-on-timeout-p
                    (return nil)
                  (error "Timed out waiting for a UDP datagram"))))

(defun server-test-poll-until (server predicate &optional at (attempts 1000))
  (loop repeat attempts
        do (if at
               (cl-quic-kit:quic-server-poll server at)
             (cl-quic-kit:quic-server-poll server))
        when (funcall predicate)
          return t
        do (sleep 0.001)
        finally (error "Timed out waiting for server activity")))
(defun server-test-poll-until-datagram-received
    (server socket expected-bytes &optional at (attempts 1000))
  (let* ((receive-symbol (find-symbol "UDP-RECEIVE" "CL-QUIC-KIT"))
         (original-receive (symbol-function receive-symbol))
         (ingress-seen-p nil))
    (unwind-protect
         (progn
           (setf (symbol-function receive-symbol)
                 (lambda (candidate-socket &rest arguments)
                   (let ((results
                           (multiple-value-list
                            (apply original-receive
                                   candidate-socket arguments))))
                     (when (and (eq candidate-socket socket)
                                (first results)
                                (or (null expected-bytes)
                                    (equalp (first results)
                                            expected-bytes)))
                       (setf ingress-seen-p t))
                     (values-list results))))
           (server-test-poll-until
            server
            (lambda () ingress-seen-p)
            at attempts))
      (setf (symbol-function receive-symbol) original-receive))))
(defun server-test-client-receive (client)
  (cl-quic-kit:client-receive-datagram
   client
   (server-test-receive
    (cl-quic-kit:quic-client-udp-socket client))))

(defun server-test-type-error-p (function)
  (handler-case
      (progn (funcall function) nil)
    (type-error () t)))

(check (server-test-type-error-p
        (lambda () (cl-quic-kit:make-quic-server)))
       "server requires a positive max-connections value")
(check
 (let* ((destination
          (make-array 8 :element-type '(unsigned-byte 8)
                        :initial-contents '(1 2 3 4 5 6 7 8)))
        (source
          (make-array 8 :element-type '(unsigned-byte 8)
                        :initial-contents '(8 7 6 5 4 3 2 1)))
        (sender
          (cl-quic-kit:make-quic-client
           :local-connection-id source
           :destination-connection-id destination
           :disable-hostname-verification-p t))
        (connection
          (cl-quic-kit:make-quic-connection
           :role :server :local-connection-id destination
           :io-write (lambda (ignored bytes)
                       (declare (ignore ignored bytes)))))
        (engine
          (cl-quic-kit:make-quic-client
           :connection connection
           :local-connection-id destination
           :destination-connection-id source
           :disable-hostname-verification-p t))
        (server-connection
          (cl-quic-kit::%make-server-connection
           :connection connection :engine engine
           :local-connection-id destination))
        (initial
          (cl-quic-kit.protection:derive-initial-secrets destination))
        (limit (expt 2 36)))
   (cl-quic-kit::%client-set-key engine :initial :read
                                 (getf initial :client))
   (cl-quic-kit::%client-set-key engine :initial :write
                                 (getf initial :server))
   (cl-quic-kit::%client-set-authentication-cipher
    engine :chacha20-poly1305)
   (setf (cl-quic-kit::quic-client-authentication-failures engine)
         (1- limit))
   (labels ((packet ()
              (cl-quic-kit::%client-build-packet
               sender :initial
               (list (cl-quic-kit:make-frame :ping))))
            (damaged-packet ()
              (let ((wire (packet)))
                (setf (aref wire (1- (length wire)))
                      (logxor 1 (aref wire (1- (length wire)))))
                wire)))
     (cl-quic-kit::%server-process-protected-datagram
      server-connection
      (concatenate '(vector (unsigned-byte 8))
                   (damaged-packet) (damaged-packet) (packet))
      0)
     (and (= (cl-quic-kit::quic-client-authentication-failures engine)
             (1+ limit))
          (cl-quic-kit:quic-client-closed-p engine)
          (eq :closing (cl-quic-kit:connection-state connection))
          (null
           (cl-quic-kit::%client-level-value
            (cl-quic-kit::quic-client-received-packets engine) :initial)))))
 "server enforces the selected AEAD limit across Initial keys and stops coalesced packets after close")
(progn
  (check
   (let* ((server
            (cl-quic-kit::%make-quic-server
             :retry-tokens (make-hash-table :test #'equalp)
             :paths (make-hash-table :test #'equalp)))
          (first-cid
            (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))
          (second-cid
            (make-array 1 :element-type '(unsigned-byte 8) :initial-element 2)))
     (let ((cl-quic-kit::*quic-server-path-cache-limit* 1))
  (let* ((first-path
           (cl-quic-kit::%server-path server :first first-cid 0 t))
         (second-path
           (cl-quic-kit::%server-path server :second second-cid 0 t)))
    (and first-path second-path
         (null
          (gethash
           (cl-quic-kit::%server-path-key :first first-cid)
           (cl-quic-kit::quic-server-paths server)))
         (eq second-path
             (gethash
              (cl-quic-kit::%server-path-key :second second-cid)
              (cl-quic-kit::quic-server-paths server)))
         (= (hash-table-count (cl-quic-kit::quic-server-paths server))
            1)))))
   "server path cache enforces its configured capacity")
  (check
   (let* ((server
            (cl-quic-kit::%make-quic-server
             :retry-tokens (make-hash-table :test #'equalp)))
          (path (cl-quic-kit::%make-server-amplification-state
                 :received 1200))
          (header
            (cl-quic-kit:make-packet-header
             :type :initial :version cl-quic-kit:*quic-version-1*
             :destination-connection-id
             (make-array 4 :element-type '(unsigned-byte 8) :initial-element 1)
             :source-connection-id
             (make-array 4 :element-type '(unsigned-byte 8) :initial-element 2))))
     (setf (gethash #(9) (cl-quic-kit::quic-server-retry-tokens server))
           :occupied)
     (let ((cl-quic-kit::*quic-server-retry-cache-limit* 1))
       (and (null (cl-quic-kit::%server-send-retry
                   server header path :peer 0))
            (= (hash-table-count
                (cl-quic-kit::quic-server-retry-tokens server))
               1))))
   "server Retry token cache enforces its configured capacity")
  (check
   (let* ((server
            (cl-quic-kit:make-quic-server
             :local-address "127.0.0.1" :local-port 0 :max-connections 1))
          (expired-token #(1))
          (live-token #(2))
          (expired-record
            (cl-quic-kit::%make-server-retry-token :retain-until 1))
          (live-record
            (cl-quic-kit::%make-server-retry-token :retain-until 100))
          (expired-path-key
            (cl-quic-kit::%server-path-key
             :expired-address
             (make-array 1 :element-type '(unsigned-byte 8) :initial-element 3)))
          (live-path-key
            (cl-quic-kit::%server-path-key
             :live-address
             (make-array 1 :element-type '(unsigned-byte 8) :initial-element 4))))
     (unwind-protect
          (progn
            (setf (gethash expired-token
                           (cl-quic-kit::quic-server-retry-tokens server))
                  expired-record
                  (gethash live-token
                           (cl-quic-kit::quic-server-retry-tokens server))
                  live-record
                  (gethash expired-path-key
                           (cl-quic-kit::quic-server-paths server))
                  (cl-quic-kit::%make-server-amplification-state
                   :expires-at 1)
                  (gethash live-path-key
                           (cl-quic-kit::quic-server-paths server))
                  (cl-quic-kit::%make-server-amplification-state
                   :expires-at 100))
            (cl-quic-kit:quic-server-poll server 1)
            (and (null (gethash expired-token
                                (cl-quic-kit::quic-server-retry-tokens server)))
                 (eq live-record
                     (gethash live-token
                              (cl-quic-kit::quic-server-retry-tokens server)))
                 (null (gethash expired-path-key
                                (cl-quic-kit::quic-server-paths server)))
                 (gethash live-path-key
                          (cl-quic-kit::quic-server-paths server))))
       (cl-quic-kit:quic-server-close server)))
   "server poll prunes expired Retry and path cache entries while retaining live entries"))
(check
 (let* ((server
          (cl-quic-kit::%make-quic-server
           :retry-tokens (make-hash-table :test #'equalp)
           :connections (make-hash-table :test #'equalp)))
        (forbidden #(1 2 3 4 5 6 7 8))
        (active-local-cid #(17 18 19 20 21 22 23 24))
        (active-original-cid #(25 26 27 28 29 30 31 32))
        (active-connection
          (cl-quic-kit::%make-server-connection
           :local-connection-id active-local-cid
           :original-destination-connection-id active-original-cid))
        (expected #(9 10 11 12 13 14 15 16))
        (calls 0)
        (original (symbol-function
                   'cl-quic-kit::%server-random-octets)))
   (unwind-protect
        (progn
          (setf (gethash active-local-cid
                         (cl-quic-kit::quic-server-connections server))
                active-connection)
          (setf (symbol-function 'cl-quic-kit::%server-random-octets)
                (lambda (length)
                  (declare (ignore length))
                  (incf calls)
                  (case calls
                    (1 forbidden)
                    (2 active-local-cid)
                    (3 active-original-cid)
                    (t expected))))
          (and (equalp
                (cl-quic-kit::%server-new-retry-source-connection-id
                 server forbidden)
                expected)
               (= calls 4)))
     (setf (symbol-function 'cl-quic-kit::%server-random-octets)
           original)))
 "Retry source CID generation retries Initial destination and active connection ID collisions")
(check
 (let ((server (cl-quic-kit:make-quic-server
                :local-address "127.0.0.1" :local-port 0
                :max-connections 1)))
   (unwind-protect
        (and (plusp (cl-quic-kit:udp-socket-local-port
                     (cl-quic-kit::quic-server-udp-socket server)))
             (= (cl-quic-kit::quic-server-max-connections server) 1))
     (cl-quic-kit:quic-server-close server)))
 "server binds its UDP socket and stores max-connections for CID routing")
(check (server-test-type-error-p
        (lambda () (cl-quic-kit:make-quic-server :max-connections 0)))
       "server rejects zero max-connections")
(check (server-test-type-error-p
        (lambda () (cl-quic-kit:make-quic-server :max-connections -1)))
       "server rejects negative max-connections")
(check (server-test-type-error-p
        (lambda () (cl-quic-kit:make-quic-server
                    :max-connections 1 :retry-policy :sometimes)))
       "server rejects an unknown Retry policy")
(check (server-test-type-error-p
        (lambda () (cl-quic-kit:make-quic-server
                    :udp-socket :not-a-socket :max-connections 1)))
       "server rejects a value that is not a UDP socket")

(let ((socket (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                           :local-port 0)))
  (let ((server (cl-quic-kit:make-quic-server :udp-socket socket
                                               :max-connections 2)))
    (unwind-protect
         (progn
           (check (not (cl-quic-kit:quic-server-poll server))
                  "an open server poll reports that it remains open")
           (check (cl-quic-kit:quic-server-close server)
                  "server close returns true")
           (check (cl-quic-kit::udp-socket-closed-p socket)
                  "server close closes its owned UDP socket")
           (check (cl-quic-kit:quic-server-poll server)
                  "poll after close reports a closed server")
           (check (cl-quic-kit:quic-server-close server)
                  "repeated server close is idempotent"))
      (cl-quic-kit:quic-server-close server))))

(let* ((server
         (cl-quic-kit::%make-quic-server
          :udp-socket nil :max-connections 1 :retry-policy :always
          :retry-tokens (make-hash-table :test #'equalp)
          :paths (make-hash-table :test #'equalp) :closed-p nil))
       (path (cl-quic-kit::%make-server-amplification-state
              :received 10 :sent 20))
       (send-count 0)
       (sender (lambda (socket bytes address)
                 (declare (ignore socket bytes address))
                 (incf send-count))))
  (check (cl-quic-kit::%server-emit server path :peer
                                    (make-array 10 :element-type '(unsigned-byte 8))
                                    sender)
         "server may send up to the exact three-times amplification budget")
  (check (= (cl-quic-kit::server-amplification-state-sent path) 30)
         "server accounts for bytes sent against the amplification budget")
  (check (not (cl-quic-kit::%server-emit
               server path :peer #(0) sender))
         "server sends nothing when the amplification budget is exhausted")
  (check (= send-count 1)
         "an insufficient amplification budget does not call the datagram sender"))

(defun server-test-retry-token-validation ()
  (let* ((directory (server-test-make-temp-directory))
         (socket nil)
         (server nil)
         (client nil))
    (unwind-protect
        (multiple-value-bind (server-tls-options client-tls-options)
            (server-test-tls-settings directory)
          (setf socket
                (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                             :local-port 0))
          (setf server
                (cl-quic-kit:make-quic-server
                 :udp-socket socket
                 :max-connections 2
                 :tls-server-options
                 (append server-tls-options (list :alpn-protocols (list "h3")))))
          (setf client
                (apply (function cl-quic-kit:make-quic-client) :server-host "127.0.0.1"
                       :server-port (cl-quic-kit:udp-socket-local-port socket)
                       :hostname "localhost"
                       :now-fn (lambda () 0)
                       :alpn (list "h3") client-tls-options))
          (progn
            (cl-quic-kit:client-poll client 0)
            (progn
              (server-test-poll-until
               server
               (lambda ()
                 (plusp
                  (hash-table-count
                   (cl-quic-kit::quic-server-retry-tokens server)))))
              (server-test-client-receive client))
            (check (not (cl-quic-kit:quic-client-closed-p client))
                   "client accepts the server Retry integrity tag")
            (multiple-value-bind (token record)
                (server-test-token-entry server)
              (check (and token record
                          (not (equalp
                                (cl-quic-kit::server-retry-token-retry-source-connection-id
                                 record)
                                (cl-quic-kit::server-retry-token-original-destination-connection-id
                                 record))))
                     "server retains a Retry token whose Retry source CID differs from its Initial destination CID")
              (check (eq (cl-quic-kit::%server-token-status
                          server token
                          (cl-quic-kit::server-retry-token-address record)
                          (cl-quic-kit::server-retry-token-retry-source-connection-id record)
                          (cl-quic-kit::server-retry-token-client-source-connection-id record)
                          (1- (cl-quic-kit::server-retry-token-expires-at record)))
                         :valid)
                     "a fresh Retry token validates for its source address and connection IDs")
              (check (eq (cl-quic-kit::%server-token-status
                          server #(0 1 2)
                          (cl-quic-kit::server-retry-token-address record)
                          #(0 1 2)
                          (cl-quic-kit::server-retry-token-client-source-connection-id record)
                          0)
                         :unknown)
                     "an unrecognized token has no cached Retry record")
              (check (eq (cl-quic-kit::%server-token-status
                          server token :different-address
                          (cl-quic-kit::server-retry-token-retry-source-connection-id record)
                          (cl-quic-kit::server-retry-token-client-source-connection-id record)
                          (1- (cl-quic-kit::server-retry-token-expires-at record)))
                         :address-mismatch)
                     "Retry tokens are bound to the source address")
              (check (eq (cl-quic-kit::%server-token-status
                          server token
                          (cl-quic-kit::server-retry-token-address record)
                          #(0 1 2)
                          (cl-quic-kit::server-retry-token-client-source-connection-id record)
                          0)
                         :connection-id-mismatch)
                     "Retry tokens are bound to the Retry source connection ID")
              (cl-quic-kit:client-poll client 0)
              (server-test-poll-until
               server
               (lambda ()
                 (cl-quic-kit::server-retry-token-used-p record)))
              (check (cl-quic-kit::server-retry-token-used-p record)
                     "client API returns the Retry token in its next Initial")
              (check (eq (cl-quic-kit::%server-token-status
                          server token
                          (cl-quic-kit::server-retry-token-address record)
                          (cl-quic-kit::server-retry-token-retry-source-connection-id record)
                          (cl-quic-kit::server-retry-token-client-source-connection-id record)
                          (1- (cl-quic-kit::server-retry-token-expires-at record)))
                         :valid)
                     "a Retry token remains valid when repeated for the same address and connection IDs")
              (check (eq (cl-quic-kit::%server-token-status
                          server token
                          (cl-quic-kit::server-retry-token-address record)
                          (cl-quic-kit::server-retry-token-retry-source-connection-id record)
                          (cl-quic-kit::server-retry-token-client-source-connection-id record)
                          (cl-quic-kit::server-retry-token-expires-at record))
                         :expired)
                     "Retry tokens expire at their finite lifetime"))))
      (when client
        (cl-quic-kit:client-close client))
      (if server
          (cl-quic-kit:quic-server-close server)
        (when socket
          (cl-quic-kit:udp-close socket)))
      (server-test-remove-temp-directory directory))))

(let* ((socket (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                            :local-port 0))
       (server (cl-quic-kit:make-quic-server :udp-socket socket
                                             :max-connections 2))
       (client (cl-quic-kit:make-quic-client
                :server-host "127.0.0.1"
                :server-port (cl-quic-kit:udp-socket-local-port socket)
                :hostname "localhost"
                :now-fn (lambda () 0))))
  (unwind-protect
       (progn
         (cl-quic-kit:client-poll client 0)
         (server-test-poll-until
            server
            (lambda ()
              (plusp
               (hash-table-count
                (cl-quic-kit::quic-server-retry-tokens server)))))
         (progn
           (server-test-client-receive client)
           (cl-quic-kit:client-poll client 0))
         (multiple-value-bind (token record)
             (server-test-token-entry server)
           (declare (ignore token))
           (setf (cl-quic-kit::server-retry-token-expires-at record) 0))
         (server-test-poll-until
            server
            (lambda ()
              (multiple-value-bind (token record)
                  (server-test-token-entry server)
                (declare (ignore token))
                (plusp
                 (cl-quic-kit::server-retry-token-next-packet-number
                  record)))))
         (server-test-client-receive client)
         (check (let ((connection (cl-quic-kit:quic-client-connection client)))
                  (and (eq (cl-quic-kit:connection-state connection) :draining)
                       (eq (cl-quic-kit:connection-close-kind connection) :transport)
                       (= (cl-quic-kit::quic-connection-closed-error connection)
                          #x0b)))
                "recognized expired Retry token receives transport INVALID_TOKEN close"))
    (cl-quic-kit:client-close client)
    (cl-quic-kit:quic-server-close server)))

(let* ((server-socket (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                                   :local-port 0))
       (server (cl-quic-kit:make-quic-server :udp-socket server-socket
                                             :max-connections 2))
       (peer (cl-quic-kit:make-udp-socket
              :remote-host "127.0.0.1"
              :remote-port (cl-quic-kit:udp-socket-local-port server-socket)
              :non-blocking-p t))
       (destination-cid #(1 2 3 4 5 6 7 8))
       (source-cid #(8 7 6 5 4 3 2 1)))
  (unwind-protect
      (progn
        (let* ((packet
                 (cl-quic-kit:encode-packet-header
                  (cl-quic-kit:make-packet-header
                   :type :initial :version cl-quic-kit:*quic-version-1*
                   :destination-connection-id destination-cid
                   :source-connection-id source-cid
                   :packet-number 0 :packet-number-length 1)
                  :include-payload nil))
               (header-length (+ 7 (length destination-cid)
                                 (length source-cid))))
          (let ((malformed-packet
                 (subseq packet 0 header-length)))
            (cl-quic-kit:udp-send peer malformed-packet)
            (server-test-poll-until-datagram-received
             server server-socket malformed-packet)))
        (multiple-value-bind (response length address)
            (cl-quic-kit:udp-receive peer)
          (declare (ignore length address))
          (check (null response)
                 "server drops a malformed Initial without replying"))
        (progn
          (cl-quic-kit:udp-send
           peer (server-test-initial-packet cl-quic-kit:*quic-version-1*
                                            destination-cid source-cid #() 1199))
          (progn
            (server-test-poll-until-datagram-received
             server server-socket
             (server-test-initial-packet
              cl-quic-kit:*quic-version-1*
              destination-cid source-cid #() 1199))
            (check
             (zerop (hash-table-count
                     (cl-quic-kit::quic-server-paths server)))
             "server discards a 1199-byte Initial without retaining path state"))
          (multiple-value-bind (response length address)
              (cl-quic-kit:udp-receive peer)
            (declare (ignore length address))
            (check (null response)
                   "server drops a 1199-byte Initial without replying"))
          (progn
            (cl-quic-kit:udp-send
             peer (server-test-initial-packet
                   #xfaceb00c destination-cid source-cid #() 1199))
            (server-test-poll-until-datagram-received
             server server-socket
             (server-test-initial-packet
              #xfaceb00c destination-cid source-cid #() 1199))
            (multiple-value-bind (response length address)
                (cl-quic-kit:udp-receive peer)
              (declare (ignore length address))
              (check (null response)
                     "server drops an unknown-version 1199-byte Initial without Version Negotiation"))
            (cl-quic-kit:udp-send
             peer (server-test-initial-packet
                   #xfaceb00c destination-cid source-cid))))
        (server-test-poll-until-datagram-received
         server server-socket
         (server-test-initial-packet
          #xfaceb00c destination-cid source-cid))
        (multiple-value-bind (response length address)
            (server-test-receive peer)
          (declare (ignore length address))
          (let ((negotiation (and response
                                  (cl-quic-kit:decode-version-negotiation response))))
            (check (and negotiation
                        (member cl-quic-kit:*quic-version-1*
                                (getf negotiation :versions)))
                   "server negotiates QUIC v1 for an unsupported Initial version")
            (check (and negotiation
                        (equalp (getf negotiation :destination-connection-id)
                                source-cid))
                   "Version Negotiation echoes the Initial source connection ID")
            (progn
              (check (and negotiation
                           (equalp (getf negotiation :source-connection-id)
                                   destination-cid))
                     "Version Negotiation echoes the Initial destination connection ID")
              (check
               (zerop (hash-table-count
                       (cl-quic-kit::quic-server-paths server)))
               "full-size unsupported Initial retains no path state")
              (check
               (and response (<= (length response) (* 3 1200)))
               "Version Negotiation stays within three times its 1200-byte datagram"))
            (let* ((wide-dcid
                     (make-array 20 :element-type (quote (unsigned-byte 8))
                                 :initial-element #xa1))
                   (wide-scid
                     (make-array 20 :element-type (quote (unsigned-byte 8))
                                 :initial-element #xb2))
                   (packet
                     (server-test-initial-packet
                      #xfaceb00c wide-dcid wide-scid #() 1200)))
              (check (= (length packet) 1200)
                     "maximum-length-CID unsupported Initial meets the 1200-byte minimum")
              (cl-quic-kit:udp-send peer packet)
              (server-test-poll-until-datagram-received
               server server-socket packet)
              (multiple-value-bind (response length address)
                  (server-test-receive peer)
                (declare (ignore length address))
                (let ((wide-negotiation
                        (and response
                             (cl-quic-kit:decode-version-negotiation response))))
                  (check (and wide-negotiation
                              (equalp (getf wide-negotiation
                                           :destination-connection-id)
                                      wide-scid)
                              (equalp (getf wide-negotiation
                                           :source-connection-id)
                                      wide-dcid))
                         "Version Negotiation echoes maximum-length Initial connection IDs")
                  (check (and response
                              (<= (length response) (* 3 (length packet))))
                         "maximum-CID Version Negotiation stays within three times its Initial")
                  (check
                   (zerop (hash-table-count
                           (cl-quic-kit::quic-server-paths server)))
                   "full-size unsupported maximum-CID Initial retains no path state")))
              (let ((packet
                      (cl-quic-kit:encode-version-negotiation
                       source-cid destination-cid (list cl-quic-kit:*quic-version-1*))))
                (cl-quic-kit:udp-send peer packet)
                (server-test-poll-until-datagram-received
                 server server-socket packet))
              (let ((packet
                      (server-test-initial-packet
                       #xfaceb00c destination-cid source-cid #() 1199)))
                (cl-quic-kit:udp-send peer packet)
                (server-test-poll-until-datagram-received
                 server server-socket packet))
              (check
               (zerop (hash-table-count
                       (cl-quic-kit::quic-server-paths server)))
               "server retains no path after Version Negotiation and a 1199-byte Initial")
              (multiple-value-bind (response length address)
                  (cl-quic-kit:udp-receive peer)
                (declare (ignore length address))
                (check (null response)
                       "server sends no response to a received Version Negotiation packet"))))))
    (cl-quic-kit:udp-close peer)
    (cl-quic-kit:quic-server-close server)))
(progn
  (defun server-test-issue-retry (server client &optional at)
    (cl-quic-kit:client-poll client 0)
    (server-test-poll-until
     server
     (lambda ()
       (plusp
        (hash-table-count
         (cl-quic-kit::quic-server-retry-tokens server))))
     at)
    (server-test-client-receive client)
    (server-test-token-entry server))

  (defun server-test-invalid-token-response
      (server client socket packet record)
    (cl-quic-kit:udp-send socket packet)
    (server-test-poll-until
     server
     (lambda ()
       (plusp
        (cl-quic-kit::server-retry-token-next-packet-number record))))
    (let ((response (server-test-receive socket)))
      (check (<= (length response) (* 3 (length packet)))
             "the protected Retry-token error response stays within three times its input size")
      (cl-quic-kit:client-receive-datagram client response)))

  (defun server-test-retry-policy-never ()
    (let* ((directory (server-test-make-temp-directory))
           (server-socket
            (cl-quic-kit:make-udp-socket :local-host "127.0.0.1" :local-port 0))
           (server nil)
           (client nil))
      (unwind-protect
          (progn
            (multiple-value-bind (server-tls-options client-tls-options)
                (server-test-tls-settings directory)
              (setf server
                    (cl-quic-kit:make-quic-server
                     :udp-socket server-socket :max-connections 1
                     :retry-policy :never
                     :tls-server-options
                     server-tls-options))
              (setf client
                    (apply (function cl-quic-kit:make-quic-client)
                           :server-host "127.0.0.1"
                           :server-port (cl-quic-kit:udp-socket-local-port server-socket)
                           :hostname "localhost"
                           :now-fn (lambda () 0)
                           client-tls-options)))
            (cl-quic-kit:client-poll client 0)
            (server-test-poll-until
             server
             (lambda ()
               (loop for path being the hash-values
                     of (cl-quic-kit::quic-server-paths server)
                     thereis
                     (>=
                      (cl-quic-kit::server-amplification-state-received path)
                      1200))))
            (check
             (loop for path being the hash-values
                   of (cl-quic-kit::quic-server-paths server)
                   thereis
                   (>=
                    (cl-quic-kit::server-amplification-state-received path)
                    1200))
             "client Initial reaches the listener at the 1200-byte minimum")
            (multiple-value-bind (response length address)
                (cl-quic-kit:udp-receive
                 (cl-quic-kit::quic-client-udp-socket client))
              (declare (ignore length address))
              (check
               (or (null response)
                   (not (eq (cl-quic-kit:packet-header-type
                             (cl-quic-kit:decode-packet-header response))
                            :retry)))
               "retry-policy never does not send Retry for a valid 1200-byte Initial"))
            (check
             (zerop (hash-table-count
                     (cl-quic-kit::quic-server-retry-tokens server)))
             "retry-policy never records no Retry token"))
        (when client
          (cl-quic-kit:client-close client))
        (unwind-protect
            (if server
                (cl-quic-kit:quic-server-close server)
              (cl-quic-kit:udp-close server-socket))
          (server-test-remove-temp-directory directory)))))

  (defun server-test-corrupted-retry-token ()
    (let* ((directory (server-test-make-temp-directory))
           (credentials (multiple-value-list (server-test-tls-settings directory)))
           (server-tls-options (first credentials))
           (client-tls-options (second credentials))
           (server-socket
            (cl-quic-kit:make-udp-socket :local-host "127.0.0.1" :local-port 0))
           (server nil)
           (client nil))
      (unwind-protect
          (progn
            (setf server
                  (cl-quic-kit:make-quic-server
                   :udp-socket server-socket
                   :max-connections 2
                   :tls-server-options
                   (append server-tls-options
                           (list :alpn-protocols
                                 (list "h3")))))
            (setf client
                  (apply (function cl-quic-kit:make-quic-client) :server-host "127.0.0.1"
                         :server-port (cl-quic-kit:udp-socket-local-port server-socket)
                         :hostname "localhost"
                         :now-fn (lambda () 0)
                         :alpn (list "h3") client-tls-options))
            (multiple-value-bind (token record)
                (server-test-issue-retry server client)
              (let ((corrupted-token (copy-seq token)))
                (setf (aref corrupted-token 0)
                      (logxor (aref corrupted-token 0) #xff))
                (let ((header
                       (server-test-invalid-token-response
                        server client (cl-quic-kit::quic-client-udp-socket client)
                        (server-test-initial-packet
                         cl-quic-kit:*quic-version-1*
                         (cl-quic-kit::server-retry-token-retry-source-connection-id
                          record)
                         (cl-quic-kit::server-retry-token-client-source-connection-id
                          record)
                         corrupted-token)
                        record)))
                  (check (and header
                              (eq (cl-quic-kit:packet-header-type header) :initial))
                         "a corrupted token response has an Initial packet header")
                  (check (and (eq (cl-quic-kit:connection-state
                                   (cl-quic-kit:quic-client-connection client))
                                  :draining)
                              (= (cl-quic-kit::quic-connection-closed-error
                                  (cl-quic-kit:quic-client-connection client))
                                 #x0b))
                         "a corrupted token for an issued Retry SCID receives INVALID_TOKEN")
                  (check (= (hash-table-count
                             (cl-quic-kit::quic-server-retry-tokens server))
                            1)
                         "a corrupted token for an issued Retry SCID does not trigger a second Retry")))))
        (when client
          (cl-quic-kit:client-close client))
        (unwind-protect
            (if server
                (cl-quic-kit:quic-server-close server)
              (cl-quic-kit:udp-close server-socket))
          (server-test-remove-temp-directory directory)))))

  (defun server-test-retry-same-tuple-duplicate ()
    (let* ((directory (server-test-make-temp-directory))
           (server-socket
             (cl-quic-kit:make-udp-socket :local-host "127.0.0.1" :local-port 0))
           (server nil)
           (client nil))
      (unwind-protect
           (multiple-value-bind (server-tls-options client-tls-options)
               (server-test-tls-settings directory)
             (setf server
                   (cl-quic-kit:make-quic-server
                    :udp-socket server-socket
                    :max-connections 2
                    :tls-server-options
                    (append server-tls-options
                            (list :alpn-protocols (list "h3")))))
             (setf client
                   (apply (function cl-quic-kit:make-quic-client)
                          :server-host "127.0.0.1"
                          :server-port
                          (cl-quic-kit:udp-socket-local-port server-socket)
                          :hostname "localhost"
                          :now-fn (lambda () 0)
                          :alpn (list "h3")
                          client-tls-options))
             (multiple-value-bind (token record)
                 (server-test-issue-retry server client 0)
               (cl-quic-kit:client-poll client 0)
               (server-test-poll-until
                server
                (lambda ()
                  (cl-quic-kit::server-retry-token-used-p record))
                0)
               (check (server-test-loopback-handshake server client 0)
                      "the token-bearing Initial completes its handshake before the duplicate")
               (cl-quic-kit:client-poll client 0)
               (cl-quic-kit:quic-server-poll server 0)
               (multiple-value-bind (response length address)
                   (cl-quic-kit:udp-receive
                    (cl-quic-kit::quic-client-udp-socket client))
                 (declare (ignore length address))
                 (check (null response)
                        "the completed Retry handshake leaves no server datagram queued before the duplicate"))
               (let* ((path
                        (cl-quic-kit::%server-path
                         server
                         (cl-quic-kit::server-retry-token-address record)
                         (cl-quic-kit::server-retry-token-original-destination-connection-id
                          record)
                         0))
                      (received-before
                        (cl-quic-kit::server-amplification-state-received path))
                      (duplicate
                        (server-test-initial-packet
                         cl-quic-kit:*quic-version-1*
                         (cl-quic-kit::server-retry-token-retry-source-connection-id
                          record)
                         (cl-quic-kit::server-retry-token-client-source-connection-id
                          record)
                         token)))
                 (cl-quic-kit:udp-send
                  (cl-quic-kit::quic-client-udp-socket client) duplicate)
                 (progn
                  (server-test-poll-until-datagram-received
                   server server-socket duplicate 0)
                  (check
                   (= (cl-quic-kit::server-amplification-state-received path)
                      received-before)
                   "a duplicate Initial on a completed connection does not update path receive accounting"))
                 (let ((response
                         (server-test-receive
                          (cl-quic-kit::quic-client-udp-socket client) t)))
                   (when response
                     (let ((header (cl-quic-kit:decode-packet-header response)))
                       (check (and header
                                   (not (eq (cl-quic-kit:packet-header-type header)
                                            :retry)))
                              "a repeated same-tuple Retry token Initial receives no second Retry")
                       (cl-quic-kit:client-receive-datagram client response)))
                   (check (null response)
                          "a repeated same-tuple Retry token Initial receives no close or second Retry")
                   (progn
                    (check (not (cl-quic-kit:quic-client-closed-p client))
                           "a repeated same-tuple Retry token remains acceptable")
                    (let* ((retry-cid
                             (cl-quic-kit::server-retry-token-retry-source-connection-id
                              record))
                           (server-connection
                             (gethash retry-cid
                                      (cl-quic-kit::quic-server-connections
                                       server))))
                      (check server-connection
                             "the completed Retry connection remains routed")
                      (cl-quic-kit:connection-set-state
                       (cl-quic-kit::server-connection-connection
                        server-connection)
                       :closed)
                      (cl-quic-kit:quic-server-poll server 0)
                      (check (null (gethash retry-cid
                                            (cl-quic-kit::quic-server-connections
                                             server)))
                             "terminal cleanup removes the used Retry route"))
                    (cl-quic-kit:udp-send
                     (cl-quic-kit::quic-client-udp-socket client) duplicate)
                    (server-test-poll-until-datagram-received
                     server server-socket duplicate 0)
                    (let ((response
                            (server-test-receive
                             (cl-quic-kit::quic-client-udp-socket client))))
                      (let ((header (cl-quic-kit:decode-packet-header response)))
                        (check (and header
                                    (eq (cl-quic-kit:packet-header-type header)
                                        :initial))
                               "a replayed used Retry token receives a protected Initial close")
                        (cl-quic-kit:client-receive-datagram client response))
                      (check
                       (and (eq (cl-quic-kit:connection-state
                                 (cl-quic-kit:quic-client-connection client))
                                :draining)
                            (= (cl-quic-kit::quic-connection-closed-error
                                (cl-quic-kit:quic-client-connection client))
                               #x0b))
                       "a consumed Retry token is rejected after route removal"))
                    (check
                     (zerop (hash-table-count
                             (cl-quic-kit::quic-server-connections server)))
                     "a replayed used Retry token does not recreate a connection"))))))
        (when client
          (cl-quic-kit:client-close client))
        (unwind-protect
             (if server
                 (cl-quic-kit:quic-server-close server)
               (cl-quic-kit:udp-close server-socket))
          (server-test-remove-temp-directory directory)))))
  (let* ((server-socket
          (cl-quic-kit:make-udp-socket :local-host "127.0.0.1" :local-port 0))
         (server (cl-quic-kit:make-quic-server
                  :udp-socket server-socket :max-connections 2))
         (client (cl-quic-kit:make-quic-client
                  :server-host "127.0.0.1"
                  :server-port (cl-quic-kit:udp-socket-local-port server-socket)
                  :hostname "localhost" :now-fn (lambda () 0))))
    (unwind-protect
        (multiple-value-bind (token record)
            (server-test-issue-retry server client)
          (declare (ignore token record))
          (clrhash (cl-quic-kit::quic-server-retry-tokens server))
          (cl-quic-kit:client-poll client 0)
          (server-test-poll-until-datagram-received server server-socket nil)
          (multiple-value-bind (response length address)
              (server-test-receive
               (cl-quic-kit::quic-client-udp-socket client))
            (declare (ignore length address))
            (let ((header (and response
                               (cl-quic-kit:decode-packet-header response))))
              (check (and header
                          (eq (cl-quic-kit:packet-header-type header) :retry))
                     "an unrecognized token is treated as absent and receives a new Retry")
              (check (= (hash-table-count
                         (cl-quic-kit::quic-server-retry-tokens server))
                        1)
                     "the absent-token retry policy records a replacement token"))))
      (cl-quic-kit:client-close client)
      (cl-quic-kit:quic-server-close server)))

  (let* ((server-socket
          (cl-quic-kit:make-udp-socket :local-host "127.0.0.1" :local-port 0))
         (server (cl-quic-kit:make-quic-server
                  :udp-socket server-socket :max-connections 2))
         (client (cl-quic-kit:make-quic-client
                  :server-host "127.0.0.1"
                  :server-port (cl-quic-kit:udp-socket-local-port server-socket)
                  :hostname "localhost" :now-fn (lambda () 0)))
         (other-peer (cl-quic-kit:make-udp-socket
                      :remote-host "127.0.0.1"
                      :remote-port
                      (cl-quic-kit:udp-socket-local-port server-socket)
                      :non-blocking-p t)))
    (unwind-protect
        (multiple-value-bind (token record)
            (server-test-issue-retry server client)
          (let ((header
                 (server-test-invalid-token-response
                  server client other-peer
                  (server-test-initial-packet
                   cl-quic-kit:*quic-version-1*
                   (cl-quic-kit::server-retry-token-retry-source-connection-id
                    record)
                   (cl-quic-kit::server-retry-token-client-source-connection-id
                    record)
                   token)
                  record)))
            (check (and header
                        (eq (cl-quic-kit:packet-header-type header) :initial))
                   "a Retry token from a different UDP source receives a protected Initial")
            (check (= (cl-quic-kit::quic-connection-closed-error
                       (cl-quic-kit:quic-client-connection client))
                      #x0b)
                   "a Retry token from a different UDP source receives INVALID_TOKEN")))
      (cl-quic-kit:udp-close other-peer)
      (cl-quic-kit:client-close client)
      (cl-quic-kit:quic-server-close server)))

  (let* ((server-socket
          (cl-quic-kit:make-udp-socket :local-host "127.0.0.1" :local-port 0))
         (server (cl-quic-kit:make-quic-server
                  :udp-socket server-socket :max-connections 2))
         (client (cl-quic-kit:make-quic-client
                  :server-host "127.0.0.1"
                  :server-port (cl-quic-kit:udp-socket-local-port server-socket)
                  :hostname "localhost" :now-fn (lambda () 0))))
    (unwind-protect
        (multiple-value-bind (token record)
            (server-test-issue-retry server client)
          (let ((wrong-client-cid
                 (copy-seq
                  (cl-quic-kit::server-retry-token-client-source-connection-id
                   record))))
            (setf (aref wrong-client-cid 0)
                  (logxor (aref wrong-client-cid 0) #xff))
            (let ((header
                   (server-test-invalid-token-response
                    server client (cl-quic-kit::quic-client-udp-socket client)
                    (server-test-initial-packet
                     cl-quic-kit:*quic-version-1*
                     (cl-quic-kit::server-retry-token-retry-source-connection-id
                      record)
                     wrong-client-cid token)
                    record)))
              (check (and header
                          (eq (cl-quic-kit:packet-header-type header) :initial)
                          (equalp
                           (cl-quic-kit:packet-header-destination-connection-id
                            header)
                           wrong-client-cid))
                     "a token with a mismatched client CID receives a close to that CID")
              (check (= (cl-quic-kit::quic-connection-closed-error
                         (cl-quic-kit:quic-client-connection client))
                        #x0b)
                     "a token with a mismatched client CID receives INVALID_TOKEN"))))
      (cl-quic-kit:client-close client)
      (cl-quic-kit:quic-server-close server))))
(defun server-test-run-openssl (&rest arguments)
  (multiple-value-bind (output errors exit-code)
      (uiop:run-program (cons "openssl" arguments)
                        :output :string :error-output :string
                        :ignore-error-status t)
    (declare (ignore output errors))
    (unless (and (integerp exit-code) (zerop exit-code))
      (error "OpenSSL could not create the TLS handshake test credential"))))
(defun server-test-read-octets (path)
  (with-open-file (stream path :direction :input
                          :element-type '(unsigned-byte 8))
    (let ((bytes (make-array (file-length stream)
                             :element-type '(unsigned-byte 8))))
      (unless (= (read-sequence bytes stream) (length bytes))
        (error "OpenSSL returned a truncated TLS test key"))
      bytes)))
(defun server-test-make-temp-directory ()
  (multiple-value-bind (output errors exit-code)
      (uiop:run-program '("mktemp" "-d")
                        :output :string :error-output :string
                        :ignore-error-status t)
    (declare (ignore errors))
    (unless (and (integerp exit-code) (zerop exit-code))
      (error "Could not create a temporary TLS test directory"))
    (pathname
     (format nil "~A/"
             (string-right-trim
              '(#\Newline #\Return #\Space #\Tab) output)))))
(defun server-test-read-certificate-der (path)
  (cl-tls-kit:pem-block-der
   (first
    (cl-tls-kit:pem-decode
     (uiop:read-file-string path)))))
(defun server-test-read-p256-private-key (path)
  (let* ((node
           (cl-tls-kit:der-decode
            (server-test-read-octets path)))
         (children (cl-tls-kit:der-node-children node))
         (scalar-node (second children))
         (scalar (and scalar-node
                      (= (cl-tls-kit:der-node-tag scalar-node) 4)
                      (cl-tls-kit:der-node-value scalar-node))))
    (unless (and (= (cl-tls-kit:der-node-tag node) 16)
                 scalar
                 (= (length scalar) 32))
      (error "OpenSSL returned an invalid P-256 test key"))
    (crypto-kit:make-ec-private-key :p256 scalar)))
(defun server-test-make-credential (directory)
  (let* ((certificate-path
           (namestring (merge-pathnames "server.crt" directory)))
         (key-path
           (namestring (merge-pathnames "server.key" directory)))
         (der-path
           (namestring (merge-pathnames "server.der" directory))))
    (server-test-run-openssl
     "req" "-x509" "-newkey" "ec" "-pkeyopt"
     "ec_paramgen_curve:prime256v1" "-pkeyopt"
     "ec_param_enc:named_curve" "-nodes" "-days" "2"
     "-subj" "/CN=localhost"
     "-addext" "subjectAltName=DNS:localhost"
     "-addext" "basicConstraints=critical,CA:TRUE"
     "-addext" "keyUsage=critical,keyCertSign,digitalSignature"
     "-addext" "extendedKeyUsage=serverAuth"
     "-keyout" key-path "-out" certificate-path)
    (server-test-run-openssl
     "ec" "-in" key-path "-outform" "DER" "-out" der-path)
    (values (server-test-read-certificate-der certificate-path)
            (server-test-read-p256-private-key der-path))))
(defun server-test-tls-settings (directory)
  (multiple-value-bind (generated-certificate generated-private-key)
      (server-test-make-credential directory)
    (values
     (list :certificate-chain (list generated-certificate)
           :private-key generated-private-key)
     (list :tls-trust-anchors
           (list (cl-tls-kit.x509:parse-certificate-der generated-certificate))
           :tls-verify-signature (function crypto-kit:verify-signature)
           ;; The generated P-256 credential uses ecdsa_secp256r1_sha256.
           :tls-signature-algorithms #(#x0403)))))
(progn
(defun server-test-post-handshake-snapshot (server-connection server)
  (let* ((engine (cl-quic-kit::server-connection-engine server-connection))
         (recovery (cl-quic-kit::quic-client-recovery engine))
         (paths (cl-quic-kit::quic-server-paths server)))
    (list
     (copy-tree (cl-quic-kit::quic-client-received-packets engine))
     (cl-quic-kit::quic-connection-last-activity
      (cl-quic-kit::server-connection-connection server-connection))
     (cl-quic-kit::server-connection-now server-connection)
     (list
      (cl-quic-kit.recovery:recovery-state-bytes-in-flight recovery)
      (cl-quic-kit.recovery:recovery-state-pto-count recovery)
      (cl-quic-kit.recovery:recovery-state-cwnd recovery)
      (cl-quic-kit.recovery:recovery-state-smoothed-rtt recovery)
      (cl-quic-kit.recovery:recovery-state-rtt-variance recovery)
      (cl-quic-kit.recovery:recovery-state-latest-rtt recovery)
      (cl-quic-kit.recovery:recovery-state-min-rtt recovery)
      (cl-quic-kit.recovery:recovery-state-ssthresh recovery)
      (cl-quic-kit.recovery:recovery-state-persistent-congestion-p recovery))
     (loop for name in '(:initial :handshake :application)
           for space = (cl-quic-kit.recovery:recovery-space recovery name)
           collect
             (list name
                   (cl-quic-kit.recovery::packet-number-space-largest-received space)
                   (cl-quic-kit.recovery::packet-number-space-largest-acked space)
                   (cl-quic-kit.recovery::packet-number-space-ack-eliciting-count space)
                   (cl-quic-kit.recovery::packet-number-space-ack-pending space)
                   (cl-quic-kit.recovery::packet-number-space-ack-deadline space)
                   (cl-quic-kit.recovery::packet-number-space-loss-time space)
                   (hash-table-count
                    (cl-quic-kit.recovery::packet-number-space-sent space))))
     (hash-table-count paths)
     (loop for key being the hash-keys of paths using (hash-value path)
           collect
             (list (copy-tree key)
                   (cl-quic-kit::server-amplification-state-received path)
                   (cl-quic-kit::server-amplification-state-sent path)
                   (cl-quic-kit::server-amplification-state-expires-at path)
                   (cl-quic-kit::server-amplification-state-validated-p path))))))
(defun server-test-loopback-handshake (server client &optional at)
  (let ((accepted nil))
    (loop repeat 1000
          do (if at
                 (cl-quic-kit:client-poll client at)
               (cl-quic-kit:client-poll client))
          (if at
              (cl-quic-kit:quic-server-poll server at)
            (cl-quic-kit:quic-server-poll server))
          (unless accepted
            (setf accepted
                  (cl-quic-kit:quic-server-accept-connection server)))
          when (and accepted
                    (eq (cl-quic-kit:connection-state
                         (cl-quic-kit:quic-client-connection client))
                        :established))
          return accepted
          do (sleep 0.001)
          finally (error "Loopback TLS handshake did not complete")))))
(defun server-test-invalid-client-transport-parameters (server-tls-options client-tls-options) (let ((preferred-address
         (make-array 42 :element-type '(unsigned-byte 8) :initial-element 0))
        (reset-token
         (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xaa))
        (client-source-cid
         (make-array 4
                     :element-type
                     '(unsigned-byte 8)
                     :initial-contents
                     (list 1 2 3 4))))
    (setf (aref preferred-address 24) 1)
    (labels ((parameter (id value)
               (cl-quic-kit::%octets (cl-quic-kit:encode-varint id)
                                     (cl-quic-kit:encode-varint (length value))
                                     value))
             (integer-parameter (id value)
               (parameter id (cl-quic-kit:encode-varint value)))
             (run-case (description parameter-bytes &optional error-marker)
               (let* ((socket
                       (cl-quic-kit:make-udp-socket :local-host
                                                    "127.0.0.1"
                                                    :local-port
                                                    0))
                      (server
                       (cl-quic-kit:make-quic-server :udp-socket
                                                     socket
                                                     :max-connections
                                                     1
                                                     :retry-policy
                                                     :always
                                                     :transport-parameters
                                                     (list :initial-max-data
                                                           2097152)
                                                     :tls-server-options
                                                     (append server-tls-options (list :alpn-protocols (list "h3")))))
                      (client nil)
                      (server-connection nil)
                      (original-decoder
                       (symbol-function
                        (find-symbol "DECODE-TRANSPORT-PARAMETERS"
                                     "CL-QUIC-KIT"))))
                 (unwind-protect
                     (progn
                       (progn
                         (setf client
                               (apply (function cl-quic-kit:make-quic-client)
                                       :server-host "127.0.0.1"
                                       :server-port (cl-quic-kit:udp-socket-local-port socket)
                                       :hostname "localhost"
                                       :local-connection-id client-source-cid
                                       :disable-hostname-verification-p t
                                       :alpn (list "h3")
                                       client-tls-options))
                         (setf (cl-quic-kit::quic-client-transport-parameters client)
                               parameter-bytes)
                         (when error-marker
                           (setf (symbol-function
                                  (find-symbol "DECODE-TRANSPORT-PARAMETERS"
                                               "CL-QUIC-KIT"))
                                 (lambda (bytes &rest options)
                                   (if (equalp bytes parameter-bytes)
                                       (error
                                        (find-symbol "QUIC-ENCODING-ERROR"
                                                     "CL-QUIC-KIT")
                                        :message error-marker)
                                       (apply original-decoder bytes options))))))
                       (setf server-connection (loop repeat 2000
                                                     do (cl-quic-kit:client-poll
                                                         client) (cl-quic-kit:quic-server-poll
                                                                  server) (setf server-connection (loop for candidate being the hash-values of (cl-quic-kit::quic-server-connections
                                                                                                                                                server)
                                                                                                        return candidate))
                                                     when (and server-connection
                                                               (eql
                                                                (cl-quic-kit::quic-connection-closed-error
                                                                 (cl-quic-kit::server-connection-connection
                                                                  server-connection))
                                                                #x08))
                                                       return server-connection
                                                     do (sleep 0.001)))
                       (check
                        (and server-connection
                             (eq
                              (cl-quic-kit:connection-state
                               (cl-quic-kit::server-connection-connection
                                server-connection))
                              :closing)
                             (eq
                              (cl-quic-kit:connection-close-kind
                               (cl-quic-kit::server-connection-connection
                                server-connection))
                              :transport)
                             (=
                              (cl-quic-kit::quic-connection-closed-error
                               (cl-quic-kit::server-connection-connection
                                server-connection))
                              #x08)
                             (not
                              (cl-quic-kit::server-connection-handshake-complete-p
                               server-connection))
                             (null
                              (cl-quic-kit::quic-server-accepted-connections
                               server)))
                        (format nil
                                "~A produces a server TRANSPORT_PARAMETER_ERROR close"
                                description))
                       (progn
                         (cl-quic-kit:client-poll client)
                         (when error-marker
                           (let ((reason
                                   (cl-quic-kit:quic-connection-closed-reason
                                    (cl-quic-kit:quic-client-connection client))))
                             (check
                              (and
                               (equalp
                                reason
                                (cl-quic-kit::%quic-close-reason
                                 "invalid peer transport parameters"))
                               (not
                                (equalp reason
                                        (cl-quic-kit::%quic-close-reason
                                         error-marker))))
                              "server transport-parameter close reason is fixed and excludes the peer marker"))))
                       (check
                        (and
                         (=
                          (cl-quic-kit::quic-connection-closed-error
                           (cl-quic-kit:quic-client-connection client))
                          #x08)
                         (eq
                          (cl-quic-kit:connection-state
                           (cl-quic-kit:quic-client-connection client))
                          :draining))
                        (format nil
                                "~A delivers error 0x08 to the client"
                                description))
                       (check
                        (null
                         (cl-quic-kit:quic-server-accept-connection server))
                        (format nil
                                "~A is never accepted by the server"
                                description)))
                   (unwind-protect
                       (when client
                         (cl-quic-kit:client-close client))
                     (setf (symbol-function
                            (find-symbol "DECODE-TRANSPORT-PARAMETERS"
                                         "CL-QUIC-KIT"))
                           original-decoder))
                   (cl-quic-kit:quic-server-close server)))))
      (dolist
          (case (list
                 (list "duplicate parameter ID"
                       (cl-quic-kit::%octets (integer-parameter 1 0)
                                             (integer-parameter 1 1)))
                 (list "truncated parameter ID varint" #(#xc0))
                 (list "truncated parameter length varint"
                       (cl-quic-kit::%octets (cl-quic-kit:encode-varint 1)
                                             #(#xc0)))
                 (list "truncated integer value varint" (parameter 1 #(#xc0)))
                 (list "parameter length exceeds the remaining bytes"
                       (cl-quic-kit::%octets (cl-quic-kit:encode-varint 1)
                                             (cl-quic-kit:encode-varint 2)
                                             #(0)))
                 (list "max_udp_payload_size below 1200"
                       (integer-parameter 3 1199))
                 (list "ack_delay_exponent above 20" (integer-parameter 10 21))
                 (list "active_connection_id_limit below 2"
                       (integer-parameter 14 1))
                 (list "initial_max_streams_bidi at 2^60"
                       (integer-parameter 8 (ash 1 60)))
                 (list "initial_max_streams_uni at 2^60"
                       (integer-parameter 9 (ash 1 60)))
                 (list "max_ack_delay at 2^14"
                       (integer-parameter 11 (ash 1 14)))
                 (list "client original_destination_connection_id"
                       (parameter 0 #(1 2 3)))
                 (list "client stateless_reset_token" (parameter 2 reset-token))
                 (list "client preferred_address"
                       (parameter 13 preferred-address))
                 (list "client retry_source_connection_id"
                       (parameter 16 #(9 8 7)))
                 (list "missing initial_source_connection_id"
                       (integer-parameter 1 1))
                 (list "disable_active_migration has a non-empty value"
                       (parameter 12 #(0)))
                 (list "integer parameter value contains trailing bytes"
                       (parameter 1 #(0 0)))
                 (list "mismatched initial_source_connection_id"
                       (parameter 15 #(9 8 7 6)))
                 (list "initial_source_connection_id exceeds 20 bytes"
                       (parameter 15
                                  #(1 2
                                      3
                                      4
                                      5
                                      6
                                      7
                                      8
                                      9
                                      10
                                      11
                                      12
                                      13
                                      14
                                      15
                                      16
                                      17
                                      18
                                      19
                                      20
                                      21)))
                 (list "peer-controlled transport-parameter diagnostic"
                       #(#xc0)
                       "PEER_TP_DIAGNOSTIC_7F3A")))
        (run-case (first case) (second case) (third case))))))
(progn
  (defun server-test-remove-temp-directory (directory)
    (dolist (name (list "server.crt" "server.key" "server.der"))
      (let ((path (merge-pathnames name directory)))
        (when (probe-file path)
          (delete-file path))))
    (multiple-value-bind (output errors exit-code)
        (uiop:run-program (list "rmdir" (namestring directory))
                          :output :string :error-output :string
                          :ignore-error-status t)
      (declare (ignore output errors))
      (unless (and (integerp exit-code) (zerop exit-code))
        (error "Could not remove the temporary TLS test directory"))))

  (defun server-test-evicted-retry-token ()
    (let ((cl-quic-kit::*quic-server-retry-cache-limit* 1))
      (let* ((server-socket
              (cl-quic-kit:make-udp-socket :local-host "127.0.0.1" :local-port 0))
             (server
              (cl-quic-kit:make-quic-server
               :udp-socket server-socket :max-connections 2
               :retry-policy :always))
             (client
              (cl-quic-kit:make-quic-client
               :server-host "127.0.0.1"
               :server-port (cl-quic-kit:udp-socket-local-port server-socket)
               :hostname "localhost" :now-fn (lambda () 0)))
             (other-peer
              (cl-quic-kit:make-udp-socket
               :remote-host "127.0.0.1"
               :remote-port
               (cl-quic-kit:udp-socket-local-port server-socket)
               :non-blocking-p t)))
        (unwind-protect
            (multiple-value-bind (token record)
                (server-test-issue-retry server client)
              (let ((second-initial
                     (server-test-initial-packet
                      cl-quic-kit:*quic-version-1*
                      #(69 69 69 69 69 69 69 69)
                      #(70 70 70 70 70 70 70 70))))
                (cl-quic-kit:udp-send other-peer second-initial)
                (progn
                  (server-test-poll-until
                   server
                   (lambda ()
                     (and
                      (= (hash-table-count
                          (cl-quic-kit::quic-server-retry-tokens server))
                         1)
                      (not (nth-value
                            1
                            (gethash
                             token
                             (cl-quic-kit::quic-server-retry-tokens server)))))))
                  (multiple-value-bind (replacement-token replacement-record)
                      (server-test-token-entry server)
                    (declare (ignore replacement-record))
                    (check (not (equalp token replacement-token))
                           "a second Retry evicts the first token at the configured cache limit"))
                  (let ((retry-response
                         (server-test-receive other-peer)))
                    (check
                     (eq
                      (cl-quic-kit:packet-header-type
                       (cl-quic-kit:decode-packet-header retry-response))
                      :retry)
                     "the second Initial receives a replacement Retry"))
                  (let* ((path
                          (cl-quic-kit::%server-path
                           server
                           (cl-quic-kit::server-retry-token-address record)
                           (cl-quic-kit::server-retry-token-original-destination-connection-id
                            record)
                           0))
                         (received-before
                          (cl-quic-kit::server-amplification-state-received path))
                         (replayed-initial
                          (server-test-initial-packet
                           cl-quic-kit:*quic-version-1*
                           (cl-quic-kit::server-retry-token-retry-source-connection-id
                            record)
                           (cl-quic-kit::server-retry-token-client-source-connection-id
                            record)
                           token)))
                    (cl-quic-kit:udp-send
                     (cl-quic-kit::quic-client-udp-socket client)
                     replayed-initial)
                    (server-test-poll-until
                     server
                     (lambda ()
                       (> (cl-quic-kit::server-amplification-state-received path)
                          received-before)))
                    (let* ((response
                            (server-test-receive
                             (cl-quic-kit::quic-client-udp-socket client)))
                           (header
                            (cl-quic-kit:client-receive-datagram client response))
                           (connection
                            (cl-quic-kit:quic-client-connection client)))
                      (check
                       (and header
                            (eq (cl-quic-kit:packet-header-type header) :initial))
                       "an evicted nonempty Retry token receives CONNECTION_CLOSE instead of Retry")
                      (check
                       (and (eq (cl-quic-kit:connection-state connection) :draining)
                            (= (cl-quic-kit::quic-connection-closed-error connection)
                               #x0b))
                       "an evicted nonempty Retry token receives INVALID_TOKEN")))))
              (cl-quic-kit:udp-close other-peer)
              (cl-quic-kit:client-close client)
              (cl-quic-kit:quic-server-close server)))))

    (progn (server-test-retry-token-validation) (server-test-corrupted-retry-token) (server-test-retry-same-tuple-duplicate))
    (server-test-retry-policy-never)
    (server-test-evicted-retry-token))
    (defun server-test-poll-admits-initial-at-draining-deadline ()
      (let* ((directory (server-test-make-temp-directory))
             (server-tls-options
              (nth-value 0 (server-test-tls-settings directory)))
             (server-socket
              (cl-quic-kit:make-udp-socket
               :local-host "127.0.0.1" :local-port 0))
             (server
              (cl-quic-kit:make-quic-server
               :udp-socket server-socket :max-connections 1
               :retry-policy :never
               :tls-server-options server-tls-options))
             (peer
              (cl-quic-kit:make-udp-socket
               :remote-host "127.0.0.1"
               :remote-port (cl-quic-kit:udp-socket-local-port server-socket)
               :non-blocking-p t))
             (local-cid
              (make-array 8 :element-type '(unsigned-byte 8)
                          :initial-contents '(41 42 43 44 45 46 47 48)))
             (alias-cid
              (make-array 8 :element-type '(unsigned-byte 8)
                          :initial-contents '(51 52 53 54 55 56 57 58)))
             (remote-cid
              (make-array 8 :element-type '(unsigned-byte 8)
                          :initial-contents '(61 62 63 64 65 66 67 68)))
             (connection
              (cl-quic-kit:make-quic-connection
               :role :server :local-connection-id local-cid
               :now-fn (lambda () 0)))
             (engine
              (cl-quic-kit:make-quic-client
               :connection connection :local-connection-id local-cid
               :destination-connection-id remote-cid
               :disable-hostname-verification-p t :now-fn (lambda () 0)))
             (server-connection
              (cl-quic-kit::%make-server-connection
               :server server :connection connection :engine engine
               :original-destination-connection-id
               (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-contents '(11 12 13 14 15 16 17 18))
               :local-connection-id local-cid :remote-connection-id remote-cid
               :pending-datagrams nil))
             (initial-packet
              (server-test-initial-packet
               cl-quic-kit:*quic-version-1*
               #(101 102 103 104 105 106 107 108)
               #(111 112 113 114 115 116 117 118)))
             (receive-symbol (find-symbol "UDP-RECEIVE" "CL-QUIC-KIT"))
             (original-receive (symbol-function receive-symbol))
             (queued-datagram nil))
        (unwind-protect
            (progn
              (cl-quic-kit:connection-set-state connection :draining)
              (setf (cl-quic-kit::quic-connection-draining-deadline connection) 10
                    (gethash local-cid
                             (cl-quic-kit::quic-server-connections server))
                    server-connection
                    (gethash alias-cid
                             (cl-quic-kit::quic-server-connections server))
                    server-connection)
              (cl-quic-kit:udp-send peer initial-packet)
              (loop repeat 1000
                    do (multiple-value-bind (bytes length address)
                           (funcall original-receive server-socket)
                         (when bytes
                           (setf queued-datagram (list bytes length address))))
                    when queued-datagram
                    return queued-datagram
                    do (sleep 0.001)
                    finally (error "Timed out waiting for the queued Initial"))
              (setf (symbol-function receive-symbol)
                    (lambda (candidate-socket &rest arguments)
                      (if (and (eq candidate-socket server-socket)
                               queued-datagram)
                          (multiple-value-prog1
                              (values-list queued-datagram)
                            (setf queued-datagram nil))
                        (apply original-receive candidate-socket arguments))))
              (cl-quic-kit:quic-server-poll server 10)
              (check
               (and (eq (cl-quic-kit:connection-state connection) :closed)
                    (null (gethash local-cid
                                   (cl-quic-kit::quic-server-connections server)))
                    (null (gethash alias-cid
                                   (cl-quic-kit::quic-server-connections server)))
                    (= (hash-table-count
                        (cl-quic-kit::quic-server-connections server))
                       1)
                    (loop for active being the hash-values
                          of (cl-quic-kit::quic-server-connections server)
                          thereis (cl-quic-kit::server-connection-p active)))
               "poll admits a queued Initial after releasing a draining route at its deadline"))
          (setf (symbol-function receive-symbol) original-receive)
          (cl-quic-kit:udp-close peer)
          (cl-quic-kit:quic-server-close server)
          (server-test-remove-temp-directory directory))))

  (defun server-test-retry-full-used-cache-issues-retry ()
    (let* ((cl-quic-kit::*quic-server-retry-cache-limit* 1)
          (directory (server-test-make-temp-directory))
          (server-tls-options (nth-value 0 (server-test-tls-settings directory)))
          (server-socket
           (cl-quic-kit:make-udp-socket
            :local-host "127.0.0.1" :local-port 0))
          (server nil)
          (first-client nil)
          (second-client nil))
      (unwind-protect
          (progn
            (setf server
                  (cl-quic-kit:make-quic-server
                   :udp-socket server-socket :max-connections 1
                   :retry-policy :always
                   :tls-server-options server-tls-options)
                  first-client
                  (cl-quic-kit:make-quic-client
                   :server-host "127.0.0.1"
                   :server-port (cl-quic-kit:udp-socket-local-port server-socket)
                   :disable-hostname-verification-p t
                   :now-fn (lambda () 0)))
            (multiple-value-bind (token record)
                (server-test-issue-retry server first-client 0)
              (cl-quic-kit:client-poll first-client 0)
              (server-test-poll-until
               server
               (lambda ()
                 (and (cl-quic-kit::server-retry-token-used-p record)
                      (= (cl-quic-kit::%server-connection-count server) 1)))
               0)
              (check
               (and (cl-quic-kit::server-retry-token-used-p record)
                    (= (cl-quic-kit::%server-connection-count server) 1))
               "a token-bearing Initial fills connection capacity and uses its Retry token")
              (setf second-client
                    (cl-quic-kit:make-quic-client
                     :server-host "127.0.0.1"
                     :server-port (cl-quic-kit:udp-socket-local-port server-socket)
                     :disable-hostname-verification-p t
                     :now-fn (lambda () 0)))
              (cl-quic-kit:client-poll second-client 0)
              (server-test-poll-until-datagram-received
               server server-socket nil 0)
              (let* ((response
                      (server-test-receive
                       (cl-quic-kit::quic-client-udp-socket second-client) t))
                     (header
                      (and response
                           (cl-quic-kit:decode-packet-header response))))
                (check
                 (and header
                      (eq (cl-quic-kit:packet-header-type header) :retry)
                      (= (hash-table-count
                          (cl-quic-kit::quic-server-retry-tokens server))
                         1)
                      (null (gethash token
                                     (cl-quic-kit::quic-server-retry-tokens server))))
                 "a fresh Initial receives Retry when the bounded cache contains only a used token")
                (check
                 (eq (cl-quic-kit::%server-token-status
                      server token
                      (cl-quic-kit::server-retry-token-address record)
                      (cl-quic-kit::server-retry-token-retry-source-connection-id record)
                      (cl-quic-kit::server-retry-token-client-source-connection-id record)
                      0)
                     :invalid-token)
                 "an evicted used token is rejected through its retired Retry source CID")
                (multiple-value-bind (fresh-token fresh-record)
                    (server-test-token-entry server)
                  (progn
                    (check
                     (and (not (equalp token fresh-token))
                          (eq (cl-quic-kit::%server-token-status
                               server fresh-token
                               (cl-quic-kit::server-retry-token-address fresh-record)
                               (cl-quic-kit::server-retry-token-retry-source-connection-id
                                fresh-record)
                               (cl-quic-kit::server-retry-token-client-source-connection-id
                                fresh-record)
                               0)
                              :valid))
                     "the new Retry token remains valid in the bounded cache")
                    (let* ((server-connection
                            (cl-quic-kit::%server-find-initial-connection
                             server
                             (cl-quic-kit::server-retry-token-retry-source-connection-id record)
                             (cl-quic-kit::server-retry-token-client-source-connection-id record)))
                           (process-symbol
                            (find-symbol "%SERVER-PROCESS-PROTECTED-DATAGRAM" "CL-QUIC-KIT"))
                           (original-process (symbol-function process-symbol))
                           (invalid-symbol
                            (find-symbol "%SERVER-SEND-INVALID-TOKEN" "CL-QUIC-KIT"))
                           (original-invalid (symbol-function invalid-symbol))
                           (processed nil)
                           (invalid-token-p nil)
                           (duplicate
                            (server-test-initial-packet
                             cl-quic-kit:*quic-version-1*
                             (cl-quic-kit::server-retry-token-retry-source-connection-id record)
                             (cl-quic-kit::server-retry-token-client-source-connection-id record)
                             token)))
                      (check
                       (and server-connection
                            (not (cl-quic-kit::server-connection-handshake-complete-p
                                  server-connection)))
                       "the used Retry token belongs to an active handshake route")
                      (unwind-protect
                          (progn
                            (setf (symbol-function process-symbol)
                                  (lambda (candidate bytes at)
                                    (declare (ignore bytes at))
                                    (setf processed candidate)))
                            (setf (symbol-function invalid-symbol)
                                  (lambda (&rest arguments)
                                    (declare (ignore arguments))
                                    (setf invalid-token-p t)))
                            (cl-quic-kit::%server-handle-datagram
                             server duplicate
                             (cl-quic-kit::server-retry-token-address record)
                             (length duplicate) 0)
                            (check
                             (and (eq server-connection processed)
                                  (not invalid-token-p))
                             "a repeated Initial for an active route survives Retry token eviction"))
                        (setf (symbol-function process-symbol) original-process
                              (symbol-function invalid-symbol) original-invalid))))))))
        (when first-client
          (cl-quic-kit:client-close first-client))
        (when second-client
          (cl-quic-kit:client-close second-client))
        (progn
          (if server
              (cl-quic-kit:quic-server-close server)
            (cl-quic-kit:udp-close server-socket))
          (server-test-remove-temp-directory directory)))))
  (defun server-test-retry-admission-evicts-paired-cache-entries ()
    (labels ((indexed-octets (marker index length)
               (let ((octets
                       (make-array length
                                   :element-type '(unsigned-byte 8)
                                   :initial-element marker)))
                 (setf (aref octets 1) (ldb (byte 8 8) index)
                       (aref octets 2) (ldb (byte 8 0) index))
                 octets)))
      (let* ((limit cl-quic-kit::*quic-server-retry-cache-limit*)
             (tokens (make-hash-table :test #'equalp))
             (retired-cids (make-hash-table :test #'equalp))
             (address :peer)
             (destination-cid (indexed-octets #x30 1 8))
             (source-cid (indexed-octets #x31 1 8))
             (oldest-token (indexed-octets #x60 1 32))
             (paired-token (indexed-octets #x60 2 32))
             (oldest-cid (indexed-octets #x40 1 8))
             (oldest-token-cid (indexed-octets #x50 1 8))
             (fresh-token (indexed-octets #x70 (1+ limit) 32))
             (fresh-cid (indexed-octets #x71 (1+ limit) 8))
             (server
               (cl-quic-kit::%make-quic-server
                :max-connections 1 :max-handshakes 1 :retry-policy :always
                :retry-tokens tokens :retired-retry-cids retired-cids
                :retired-local-cids (make-hash-table :test #'equalp)
                :paths (make-hash-table :test #'equalp)
                :connections (make-hash-table :test #'equalp)))
             (path
               (cl-quic-kit::%make-server-amplification-state :received 1200))
             (header
               (cl-quic-kit:make-packet-header
                :type :initial :version cl-quic-kit:*quic-version-1*
                :destination-connection-id destination-cid
                :source-connection-id source-cid :token #()))
             (random-symbol
               (find-symbol "%SERVER-RANDOM-OCTETS" "CL-QUIC-KIT"))
             (original-random (symbol-function random-symbol))
             (retry-packet-symbol
               (find-symbol "%SERVER-RETRY-PACKET" "CL-QUIC-KIT"))
             (original-retry-packet (symbol-function retry-packet-symbol))
             (emit-symbol (find-symbol "%SERVER-EMIT" "CL-QUIC-KIT"))
             (original-emit (symbol-function emit-symbol))
             (emitted-count 0))
        (dotimes (index limit)
          (let* ((number (1+ index))
                 (token (indexed-octets #x60 number 32))
                 (retry-cid
                  (if (= number 2)
                      oldest-cid
                    (indexed-octets #x50 number 8)))
                 (record
                  (cl-quic-kit::%make-server-retry-token
                   :address address
                   :original-destination-connection-id destination-cid
                   :retry-source-connection-id retry-cid
                   :client-source-connection-id source-cid
                   :expires-at 5000 :retain-until (+ 100 number))))
            (setf (gethash token tokens) record
                  (gethash (indexed-octets #x40 number 8) retired-cids)
                  number)))
        (unwind-protect
             (progn
               (setf (symbol-function random-symbol)
                     (lambda (length &optional operation)
                       (declare (ignore operation))
                       (if (= length 32) fresh-token fresh-cid))
                     (symbol-function retry-packet-symbol)
                     (lambda (header retry-source-cid token original-dcid)
                       (declare (ignore header retry-source-cid token original-dcid))
                       #(1))
                     (symbol-function emit-symbol)
                     (lambda (candidate-server candidate-path candidate-address bytes)
                       (declare
                        (ignore candidate-server candidate-path candidate-address bytes))
                       (incf emitted-count)
                       t))
               (check
                (cl-quic-kit::%server-send-retry
                 server header path address 0)
                "Retry admission continues when both caches reach their limit")
               (check
                (and (= emitted-count 1)
                     (<= (hash-table-count tokens) limit)
                     (<= (hash-table-count retired-cids) limit)
                     (gethash fresh-token tokens)
                     (null (gethash oldest-token tokens))
                     (null (gethash paired-token tokens))
                     (gethash oldest-token-cid retired-cids)
                     (null (gethash oldest-cid retired-cids)))
                "full Retry caches evict the matching token and tombstone together"))
          (setf (symbol-function random-symbol) original-random
                (symbol-function retry-packet-symbol) original-retry-packet
                (symbol-function emit-symbol) original-emit))
        (multiple-value-bind (status)
            (cl-quic-kit::%server-token-status
             server oldest-token address oldest-token-cid source-cid 0)
          (check (not (eq status :valid))
                 "an evicted Retry token is rejected while its CID tombstone remains"))
        (multiple-value-bind (status)
            (cl-quic-kit::%server-token-status
             server paired-token address oldest-cid source-cid 0)
          (check (not (eq status :valid))
                 "a token is rejected when its matching CID tombstone is evicted"))
        (multiple-value-bind (status)
            (cl-quic-kit::%server-token-status
             server fresh-token address fresh-cid source-cid 0)
          (check (eq status :valid)
                 "a newly admitted Retry token remains valid"))))))
(progn
  (let* ((directory (server-test-make-temp-directory))
         (socket nil)
         (server nil)
         (client nil))
    (unwind-protect
        (multiple-value-bind (server-tls-options client-tls-options)
            (server-test-tls-settings directory)
          (setf socket
                (cl-quic-kit:make-udp-socket
                 :local-host "127.0.0.1" :local-port 0))
          (setf server
                (cl-quic-kit:make-quic-server
                 :udp-socket socket
                 :max-connections 1
                 :retry-policy :always
                 :transport-parameters (list :initial-max-data 2097152)
                 :tls-server-options
                 (append server-tls-options (list :alpn-protocols (list "h3")))))
          (setf client
                (apply (function cl-quic-kit:make-quic-client)
                       :server-host "127.0.0.1"
                       :server-port (cl-quic-kit:udp-socket-local-port socket)
                       :idle-timeout 60
                       :hostname "localhost"
                       :alpn '("h3") client-tls-options))
          (let ((server-connection
                 (server-test-loopback-handshake server client)))
            (check
             (eq (cl-quic-kit:connection-state server-connection)
                 :established)
             "the server accepts a connection after its TLS handshake")
            (check
             (equal (cl-quic-kit:quic-connection-alpn server-connection)
                    "h3")
             "the server connection records the negotiated ALPN")
            (check
             (eq (cl-quic-kit:connection-state
                  (cl-quic-kit:quic-client-connection client))
                 :established)
             "the client confirms the server handshake")
            (progn
              (check
               (equal
                (cdr
                 (assoc 4
                        (cl-quic-kit:quic-client-peer-transport-parameters client)))
                2097152)
               "the server forwards configured initial max data")
              (check
               (= (cdr
                   (assoc 1
                          (cl-quic-kit:quic-client-peer-transport-parameters client)))
                  30000)
               "the server advertises its idle timeout in milliseconds")
              (check
               (let* ((server-state
                       (loop for entry being the hash-values
                             of (cl-quic-kit::quic-server-connections server)
                             when (eq (cl-quic-kit::server-connection-connection entry)
                                      server-connection)
                             return entry))
                      (parameters
                       (cl-quic-kit:decode-transport-parameters
                        (cl-quic-kit::server-connection-peer-transport-parameters
                         server-state))))
                 (= (cdr (assoc 1 parameters)) 60000))
               "the server observes the client idle timeout in milliseconds")
              (check
               (let ((parameters
                      (cl-quic-kit:decode-transport-parameters
                       (cl-quic-kit::%client-transport-parameters
                        (make-array 8 :element-type '(unsigned-byte 8)
                                    :initial-element 0)
                        cl-quic-kit::*quic-idle-timeout-default*))))
                 (= (cdr (assoc 1 parameters)) 30000))
               "the client advertises its idle timeout in milliseconds")
              (check
               (null (cl-quic-kit:quic-server-accept-connection server))
               "the server returns each completed connection once")
              (check
               (= (cl-quic-kit::quic-connection-idle-timeout server-connection) 30)
               "the server clamps the peer idle timeout to its local limit")
              (server-test-invalid-client-transport-parameters server-tls-options client-tls-options))))
      (unwind-protect
          (when client
            (cl-quic-kit:client-close client))
        (unwind-protect
            (if server
                (cl-quic-kit:quic-server-close server)
              (when socket
                (cl-quic-kit:udp-close socket)))
          (server-test-remove-temp-directory directory))))))
(progn (server-test-poll-admits-initial-at-draining-deadline)
         (server-test-retry-full-used-cache-issues-retry)
         (server-test-retry-admission-evicts-paired-cache-entries))

(progn
  (let* ((directory (server-test-make-temp-directory))
         (socket nil)
         (server nil)
         (client nil))
    (unwind-protect
        (multiple-value-bind (server-tls-options client-tls-options)
            (server-test-tls-settings directory)
          (setf socket
                (cl-quic-kit:make-udp-socket
                 :local-host "127.0.0.1" :local-port 0))
          (setf server
                (cl-quic-kit:make-quic-server
                 :udp-socket socket
                 :max-connections 1
                 :retry-policy :always
                 :tls-server-options
                 (append server-tls-options (list :alpn-protocols (list "h3")))))
          (setf client
                (let ((client-cid
                       (make-array 8 :element-type '(unsigned-byte 8)
                                   :initial-contents '(0 1 2 3 4 5 6 7))))
                  (apply (function cl-quic-kit:make-quic-client)
                         :server-host "127.0.0.1"
                         :server-port (cl-quic-kit:udp-socket-local-port socket)
                         :local-connection-id client-cid
                         :transport-parameters
                         (cl-quic-kit:encode-transport-parameters
                          (list (cons 1 1000) (cons 15 client-cid)))
                         :hostname "localhost"
                         :alpn '("h3") client-tls-options)))
          (let* ((server-connection
                  (server-test-loopback-handshake server client))
                 (server-state
                  (loop for entry being the hash-values
                        of (cl-quic-kit::quic-server-connections server)
                        when (eq (cl-quic-kit::server-connection-connection entry)
                                 server-connection)
                        return entry))
                 (valid-packet
                  (cl-quic-kit::%client-build-packet
                   client :application
                   (list (cl-quic-kit:make-frame :ping))))
                 (ignored-0-rtt-packet
                  (cl-quic-kit:encode-packet-header
                   (cl-quic-kit:make-packet-header
                    :type :0-rtt
                    :version cl-quic-kit:*quic-version-1*
                    :destination-connection-id
                    (cl-quic-kit::quic-client-remote-connection-id client)
                    :source-connection-id
                    (cl-quic-kit::quic-client-local-connection-id client)
                    :packet-number 0 :packet-number-length 1
                    :payload (cl-quic-kit:encode-frame
                              (cl-quic-kit:make-frame
                               :stream :stream-id 0 :offset 0 :data #(1 2 3) :fin t))))))
            (cl-quic-kit:connection-touch server-connection 0)
            (let ((invalid-packet (copy-seq valid-packet)))
              (setf (aref invalid-packet (1- (length invalid-packet)))
                    (logxor (aref invalid-packet
                                  (1- (length invalid-packet)))
                            1))
              (let ((received-before
                     (cl-quic-kit::server-amplification-state-received
                      (cl-quic-kit::server-connection-path server-state))))
                (cl-quic-kit:udp-send
                 (cl-quic-kit:quic-client-udp-socket client)
                 invalid-packet)
                (progn
                  (server-test-poll-until
                   server
                   (lambda ()
                     (> (cl-quic-kit::server-amplification-state-received
                         (cl-quic-kit::server-connection-path server-state))
                        received-before))
                   0.5)
                  (check (not (cl-quic-kit:quic-server-poll server 0.5))
                         "server polling completes for a packet with an invalid authentication tag"))
                (check
                 (> (cl-quic-kit::server-amplification-state-received
                     (cl-quic-kit::server-connection-path server-state))
                    received-before)
                 "the invalid protected packet reached the server over UDP")))
            (check
             (= (cl-quic-kit::quic-connection-last-activity server-connection) 0)
             "unauthenticated packets do not reset server idle timeout")
            (cl-quic-kit:udp-send
             (cl-quic-kit:quic-client-udp-socket client) valid-packet)
            (server-test-poll-until
             server
             (lambda ()
               (= (cl-quic-kit::quic-connection-last-activity
                   server-connection)
                  0.9))
             0.9)
            (check
             (eq (cl-quic-kit:connection-state server-connection) :established)
             "authenticated peer traffic resets server idle timeout")
            (check
             (= (cl-quic-kit::quic-connection-last-activity server-connection)
                0.9)
             "server activity uses the quic-server-poll clock")
            (progn
              (check
               (= (cl-quic-kit::quic-connection-idle-timeout server-connection)
                  1)
               "server applies the peer max idle timeout")
              (cl-quic-kit:quic-server-poll server 1.5)
              (check
               (eq (cl-quic-kit:connection-state server-connection) :established)
               "authenticated traffic keeps the connection alive beyond the original idle deadline"))
            (cl-quic-kit:connection-touch server-connection 0.9)
            (cl-quic-kit:udp-send
             (cl-quic-kit:quic-client-udp-socket client)
             ignored-0-rtt-packet)
            (let* ((path (cl-quic-kit::server-connection-path server-state))
                   (engine (cl-quic-kit::server-connection-engine server-state))
                   (streams (cl-quic-kit::quic-client-streams engine))
                   (received-before
                    (cl-quic-kit::server-amplification-state-received path))
                   (stream-count-before (hash-table-count streams))
                   (stream-data-before
                    (loop for stream being the hash-values of streams
                          sum (cl-quic-kit:stream-readable-bytes stream))))
              (server-test-poll-until
               server
               (lambda ()
                 (> (cl-quic-kit::server-amplification-state-received path)
                    received-before))
               1.5)
              (check
               (> (cl-quic-kit::server-amplification-state-received path)
                  received-before)
               "0-RTT UDP ingress increases the server path's received bytes")
              (check
               (= (hash-table-count streams) stream-count-before)
               "ignored 0-RTT data does not create a stream")
              (check
               (= (loop for stream being the hash-values of streams
                        sum (cl-quic-kit:stream-readable-bytes stream))
                  stream-data-before)
               "ignored 0-RTT data is not delivered to a stream"))
            (progn
              (check
               (= (cl-quic-kit::quic-connection-last-activity
                   server-connection)
                  0.9)
               "ignored 0-RTT preserves the authenticated activity timestamp")
              (cl-quic-kit:quic-server-poll server 2)
              (check
               (and (eq (cl-quic-kit:connection-state server-connection)
                        :closing)
                    (= (cl-quic-kit::quic-connection-last-activity
                        server-connection)
                       0.9))
               "ignored 0-RTT does not reset server idle timeout"))))
      (unwind-protect
          (when client
            (cl-quic-kit:client-close client))
        (unwind-protect
            (if server
                (cl-quic-kit:quic-server-close server)
              (when socket
                (cl-quic-kit:udp-close socket)))
          (server-test-remove-temp-directory directory))))))
(progn
  (let ((cl-quic-kit::*quic-server-path-cache-limit* 1)
       (cl-quic-kit::*quic-server-retry-cache-limit* 1))
    (let* ((server-socket
         (cl-quic-kit:make-udp-socket
          :local-host "127.0.0.1" :local-port 0))
       (server
         (cl-quic-kit:make-quic-server
          :udp-socket server-socket :max-connections 1
          :retry-policy :always))
       (short-peer nil)
       (retry-peer nil)
       (destination-cid #(1 2 3 4 5 6 7 8))
       (source-cid #(8 7 6 5 4 3 2 1)))
  (unwind-protect
       (progn
         (setf short-peer
               (cl-quic-kit:make-udp-socket
                :remote-host "127.0.0.1"
                :remote-port (cl-quic-kit:udp-socket-local-port server-socket)
                :non-blocking-p t))
         (setf retry-peer
               (cl-quic-kit:make-udp-socket
                :remote-host "127.0.0.1"
                :remote-port (cl-quic-kit:udp-socket-local-port server-socket)
                :non-blocking-p t))
         (let* ((short-packet
                  (server-test-initial-packet
                   #xfaceb00c destination-cid source-cid #() 1199))
                (unsupported-packet
                  (server-test-initial-packet
                   #xfaceb00c destination-cid source-cid #() 1200))
                (valid-packet
                  (server-test-initial-packet
                   cl-quic-kit:*quic-version-1*
                   destination-cid source-cid)))
           (cl-quic-kit:udp-send short-peer short-packet)
           (server-test-poll-until-datagram-received
            server server-socket short-packet)
           (multiple-value-bind (response length address)
               (cl-quic-kit:udp-receive short-peer)
             (declare (ignore length address))
             (check
              (null response)
              "unknown-version-cache-capacity: short Initial receives no Version Negotiation"))
           (check
            (zerop (hash-table-count
                    (cl-quic-kit::quic-server-paths server)))
            "unknown-version-cache-capacity: short Initial retains no path state")
           (cl-quic-kit:udp-send short-peer unsupported-packet)
           (server-test-poll-until-datagram-received
            server server-socket unsupported-packet)
           (check
            (and (zerop (hash-table-count
                         (cl-quic-kit::quic-server-paths server)))
                 (zerop (hash-table-count
                         (cl-quic-kit::quic-server-retry-tokens server))))
            "unknown-version-cache-capacity: 1200-byte Initial retains no path or Retry-token state")
           (let* ((response (server-test-receive short-peer))
                  (negotiation
                    (and response
                         (cl-quic-kit:decode-version-negotiation response))))
             (check
              (and negotiation
                   (member cl-quic-kit:*quic-version-1*
                           (getf negotiation :versions)))
              "unknown-version-cache-capacity: large unsupported Initial receives Version Negotiation")
             (check
              (and response
                   (<= (length response) (* 3 (length unsupported-packet))))
              "unknown-version-cache-capacity: Version Negotiation stays within three times its datagram"))
           (cl-quic-kit:udp-send retry-peer valid-packet)
           (server-test-poll-until
            server
            (lambda ()
              (plusp
               (hash-table-count
                (cl-quic-kit::quic-server-retry-tokens server)))))
           (check
            (and (= (hash-table-count
                     (cl-quic-kit::quic-server-paths server))
                    1)
                 (= (hash-table-count
                     (cl-quic-kit::quic-server-retry-tokens server))
                    1))
            "unknown-version-cache-capacity: valid Initial obtains the only cache slot after unsupported Initials")
           (let* ((response (server-test-receive retry-peer))
                  (header (cl-quic-kit:decode-packet-header response))
                  (first-token (cl-quic-kit:packet-header-token header))
                  (token-table
                    (cl-quic-kit::quic-server-retry-tokens server)))
             (check
              (eq (cl-quic-kit:packet-header-type header) :retry)
              "unknown-version-cache-capacity: later valid Initial receives Retry")
             (check
              (<= (length response) (* 3 (length valid-packet)))
              "unknown-version-cache-capacity: Retry stays within three times its datagram")
             (check
              (and (gethash first-token token-table)
                   (= (hash-table-count token-table) 1)
                   (= (cl-quic-kit::server-amplification-state-sent
                       (loop for path being the hash-values
                               of (cl-quic-kit::quic-server-paths server)
                             return path))
                      (length response)))
              "unknown-version-cache-capacity: successful Retry accounts sent bytes and retains its returned token")
             (let* ((second-destination-cid #(11 12 13 14 15 16 17 18))
                    (second-source-cid #(21 22 23 24 25 26 27 28))
                    (second-packet
                      (server-test-initial-packet
                       cl-quic-kit:*quic-version-1*
                       second-destination-cid second-source-cid)))
               (cl-quic-kit:udp-send retry-peer second-packet)
               (server-test-poll-until
                server
                (lambda ()
                  (and (null (gethash first-token token-table))
                       (= (hash-table-count
                           (cl-quic-kit::quic-server-paths server))
                          1)
                       (= (hash-table-count token-table) 1))))
               (let* ((response (server-test-receive retry-peer))
                      (header (cl-quic-kit:decode-packet-header response))
                      (second-token (cl-quic-kit:packet-header-token header)))
                 (check
                  (eq (cl-quic-kit:packet-header-type header) :retry)
                  "unknown-version-cache-capacity: a valid Initial still receives Retry when both caches are full")
                 (check
                  (and second-token
                       (not (equalp first-token second-token))
                       (null (gethash first-token token-table))
                       (gethash second-token token-table)
                       (= (hash-table-count
                           (cl-quic-kit::quic-server-paths server))
                          1)
                       (= (hash-table-count token-table) 1))
                  "unknown-version-cache-capacity: full path cache evicts its unused token and stays capped; client must restart with a fresh Initial")
                 (check
                  (<= (length response) (* 3 (length second-packet)))
                  "unknown-version-cache-capacity: Retry after cache eviction stays within three times its datagram"))))))
    (unwind-protect
         (when short-peer
           (cl-quic-kit:udp-close short-peer))
      (unwind-protect
           (when retry-peer
             (cl-quic-kit:udp-close retry-peer))
        (cl-quic-kit:quic-server-close server))))))
  (let* ((directory (server-test-make-temp-directory))
         (socket nil)
         (server nil)
         (client nil)
         (attacker nil))
    (unwind-protect
         (multiple-value-bind (server-tls-options client-tls-options) (server-test-tls-settings directory) (setf socket
                 (cl-quic-kit:make-udp-socket
                  :local-host "127.0.0.1" :local-port 0))
           (setf server
                 (cl-quic-kit:make-quic-server
                  :udp-socket socket
                  :max-connections 1
                  :retry-policy :never
                  :tls-server-options
                  (append server-tls-options (list :alpn-protocols (list "h3")))))
           (setf client
                 (apply (function cl-quic-kit:make-quic-client) :server-host "127.0.0.1"
                  :server-port (cl-quic-kit:udp-socket-local-port socket)
                  :hostname "localhost"
                  :idle-timeout 60
                  :alpn (list "h3") client-tls-options))
           (setf attacker
                 (cl-quic-kit:make-udp-socket
                  :remote-host "127.0.0.1"
                  :remote-port
                  (cl-quic-kit:udp-socket-local-port socket)
                  :non-blocking-p t))
           (let* ((server-connection
                    (server-test-loopback-handshake server client))
                  (server-state
                    (loop for entry being the hash-values
                            of (cl-quic-kit::quic-server-connections server)
                          when (eq
                                (cl-quic-kit::server-connection-connection
                                 entry)
                                server-connection)
                            return entry))
                  (paths-before
                    (loop for path being the hash-values
                            of (cl-quic-kit::quic-server-paths server)
                          collect path))
                  (initial
                    (cl-quic-kit.protection:derive-initial-secrets
                     (cl-quic-kit::quic-client-initial-destination-connection-id
                      client))))
             (cl-quic-kit::%client-set-key
              client :initial :write (getf initial :client))
             (let* ((packet
                      (cl-quic-kit::%client-build-packet
                       client :initial
                       (list
                        (cl-quic-kit:make-frame
                         :connection-close :error-code #x55
                         :frame-type 0 :reason #()))))
                    (path-count-before (length paths-before))
                    (header (cl-quic-kit:decode-packet-header packet)))
               (check (and (eq (cl-quic-kit:connection-state server-connection) :established) (equalp (cl-quic-kit:packet-header-destination-connection-id header) (cl-quic-kit::server-connection-local-connection-id server-state))) "the forged Initial targets the established connection CID")
               (let ((fixed-now (cl-quic-kit::server-connection-now server-state))
                     (before
                       (server-test-post-handshake-snapshot
                        server-state server)))
                  (cl-quic-kit::%server-process-protected-datagram
                   server-state packet 1)
                  (cl-quic-kit:udp-send attacker packet)
                  (server-test-poll-until-datagram-received
                    server socket packet fixed-now 10)
                  (check
                   (equalp before
                           (server-test-post-handshake-snapshot
                            server-state server))
                   "post-handshake Initial leaves packet history, recovery, activity, and path state unchanged")
                  (check
                   (and (= path-count-before
                           (hash-table-count
                            (cl-quic-kit::quic-server-paths server)))
                        (eq (cl-quic-kit:connection-state server-connection)
                            :established)
                        (null (cl-quic-kit::quic-connection-closed-error
                               server-connection))
                        (null (cl-quic-kit:udp-receive attacker)))
                   "an alternate-source Initial cannot create a path or drain the connection")))))
      (unwind-protect
           (when client
             (cl-quic-kit:client-close client))
        (unwind-protect
             (when attacker
               (cl-quic-kit:udp-close attacker))
          (unwind-protect
               (if server
                   (cl-quic-kit:quic-server-close server)
                   (when socket
                     (cl-quic-kit:udp-close socket)))
            (server-test-remove-temp-directory directory)))))))

(progn
  (let* ((directory (server-test-make-temp-directory))
         (socket nil)
         (server nil)
         (client nil)
         (writes nil))
    (unwind-protect
         (multiple-value-bind (server-tls-options client-tls-options) (server-test-tls-settings directory) (setf socket
                 (cl-quic-kit:make-udp-socket
                  :local-host "127.0.0.1" :local-port 0))
           (setf server
                 (cl-quic-kit:make-quic-server
                  :udp-socket socket
                  :max-connections 1
                  :retry-policy :never
                  :tls-server-options
                  (append server-tls-options (list :alpn-protocols (list "h3")))))
           (setf client
                 (apply (function cl-quic-kit:make-quic-client) :server-host "127.0.0.1" :server-port (cl-quic-kit:udp-socket-local-port socket) :hostname "localhost" :idle-timeout 60 :alpn (list "h3") :io-write (lambda (connection bytes)
                    (declare (ignore connection))
                    (push bytes writes)) client-tls-options))
           (cl-quic-kit:client-poll client)
           (let* ((hello-wire
                    (cl-quic-kit::quic-client-client-hello-wire client))
                  (hello
                    (cl-tls-kit:decode-handshake hello-wire)))
             (setf (cl-tls-kit:tls13-client-hello-extensions hello)
                   (append
                    (cl-tls-kit:tls13-client-hello-extensions hello)
                    (list (cl-tls-kit:make-tls-extension 42 #()))))
             (let* ((crafted-wire (cl-tls-kit:encode-handshake 1 hello))
                    (packet
                      (cl-quic-kit::%client-build-packet
                       client :initial
                       (list (cl-quic-kit:make-frame
                              :crypto :offset 0 :data crafted-wire))))
                    (client-socket
                      (cl-quic-kit::quic-client-udp-socket client))
                    (response nil))
               (check (and writes hello-wire packet)
                      "fatal TLS alert test captures a real ClientHello and builds its protected Initial")
               (check (>= (length packet) 1200)
                      "fatal TLS alert ClientHello Initial meets the QUIC minimum datagram size")
               (cl-quic-kit:udp-send client-socket packet)
               (server-test-poll-until
                server
                (lambda ()
                  (setf response (cl-quic-kit:udp-receive client-socket))
                  response))
               (let* ((header (cl-quic-kit:decode-packet-header response))
                      (server-cid
                        (cl-quic-kit:packet-header-source-connection-id header))
                      (connection (cl-quic-kit:quic-client-connection client))
                      (server-connection
                       (gethash server-cid
                                (cl-quic-kit::quic-server-connections server))))
                 (check (<= (length response) (* 3 (length packet)))
                        "fatal TLS alert CONNECTION_CLOSE respects the three-times amplification limit")
                 (cl-quic-kit:client-receive-datagram client response)
                 (check (and (eq (cl-quic-kit:connection-state connection) :draining)
                             (= (cl-quic-kit::quic-connection-closed-error connection)
                                (+ #x0100 47)))
                        "fatal TLS alert 47 reaches the client as QUIC crypto error 0x012f")
                 (check
                  (and server-connection
                       (= (hash-table-count
                          (cl-quic-kit::quic-server-connections server))
                          1)
                       (eq (gethash server-cid
                                (cl-quic-kit::quic-server-connections server))
                            server-connection)
                       (eq (cl-quic-kit:connection-state
                            (cl-quic-kit::server-connection-connection
                             server-connection))
                           :closing)
                       (null (cl-quic-kit:quic-server-accept-connection
                              server)))
                  "fatal TLS alert retains its server CID route during closing before acceptance")
                 (cl-quic-kit:udp-send client-socket packet)
                 (server-test-poll-until-datagram-received server socket packet)
                 (progn
                  (let ((replay-response (server-test-receive client-socket t)))
                    (when replay-response
                      (cl-quic-kit:client-receive-datagram client replay-response))
                    (check
                     (and replay-response
                          (= (hash-table-count
                             (cl-quic-kit::quic-server-connections server))
                             1)
                          (eq (gethash server-cid
                                   (cl-quic-kit::quic-server-connections server))
                               server-connection)
                          (<= (cl-quic-kit::server-amplification-state-sent
                               (cl-quic-kit::server-connection-path server-connection))
                              (* 3 (cl-quic-kit::server-amplification-state-received
                                    (cl-quic-kit::server-connection-path
                                     server-connection))))
                          (eq (cl-quic-kit:connection-state
                               (cl-quic-kit::server-connection-connection
                                server-connection))
                              :closing)
                          (eq (cl-quic-kit:connection-state connection) :draining)
                          (= (cl-quic-kit::quic-connection-closed-error connection)
                             (+ #x0100 47))
                          (null (cl-quic-kit:quic-server-accept-connection
                                 server)))
                     "replaying the exact Initial elicits a close response on the existing connection"))
                  (progn
                    (let ((sent-before
                           (cl-quic-kit::server-amplification-state-sent
                            (cl-quic-kit::server-connection-path
                             server-connection)))
                          (received-before
                           (cl-quic-kit::server-amplification-state-received
                            (cl-quic-kit::server-connection-path
                             server-connection))))
                      (cl-quic-kit:udp-send client-socket packet)
                      (server-test-poll-until-datagram-received
                       server socket packet)
                      (check
                       (and (cl-quic-kit::server-connection-close-response-attempted-p
                             server-connection)
                            (> (cl-quic-kit::server-amplification-state-received
                                (cl-quic-kit::server-connection-path
                                 server-connection))
                               received-before)
                            (= (cl-quic-kit::server-amplification-state-sent
                                (cl-quic-kit::server-connection-path
                                 server-connection))
                               sent-before)
                            (<= (cl-quic-kit::server-amplification-state-sent
                                 (cl-quic-kit::server-connection-path
                                  server-connection))
                                (* 3 (cl-quic-kit::server-amplification-state-received
                                      (cl-quic-kit::server-connection-path
                                       server-connection))))
                            (null (server-test-receive client-socket t)))
                       "closing connections rate-limit repeated CONNECTION_CLOSE responses"))
                    (cl-quic-kit:quic-server-poll
                     server
                     (cl-quic-kit:connection-draining-deadline
                      (cl-quic-kit::server-connection-connection
                       server-connection))))
                  (check
                   (and (eq (cl-quic-kit:connection-state
                             (cl-quic-kit::server-connection-connection
                              server-connection))
                            :closed)
                        (zerop (hash-table-count
                                (cl-quic-kit::quic-server-connections server)))
                        (null (gethash server-cid
                                       (cl-quic-kit::quic-server-connections server)))
                        (null (cl-quic-kit:quic-server-accept-connection
                               server)))
                   "fatal TLS alert removes the server CID route after draining"))))))
      (unwind-protect
           (when client
             (cl-quic-kit:client-close client))
        (unwind-protect
             (if server
                 (cl-quic-kit:quic-server-close server)
                 (when socket
                   (cl-quic-kit:udp-close socket)))
          (server-test-remove-temp-directory directory))))))

(progn
  (let* ((directory (server-test-make-temp-directory))
         (socket nil)
         (server nil)
         (client nil)
         (local-cid
           (make-array 8 :element-type '(unsigned-byte 8)
                       :initial-contents '(1 2 3 4 5 6 7 8)))
         (client-parameters
           (cl-quic-kit:encode-transport-parameters
            (list (cons 1 5000) (cons 15 local-cid))))
         (key-exchange
           (list
            :generate
            (lambda (group)
              (case group
                (#x001d
                 (let ((private (crypto-kit:random-octets 32)))
                   (values private (crypto-kit:x25519-base private))))
                (#x0017 (crypto-kit:p256-generate-keypair))
                (otherwise (error "Unexpected TLS key exchange group ~D" group))))
            :shared-secret
            (lambda (group private public)
              (case group
                (#x001d
                 (multiple-value-bind (secret all-zero)
                     (crypto-kit:x25519 private public)
                   (when all-zero
                     (error "Unexpected all-zero X25519 test secret"))
                   secret))
                (#x0017 (crypto-kit:p256-ecdh private public))
                (otherwise (error "Unexpected TLS key exchange group ~D" group))))
            :random #'crypto-kit:random-octets))
         (server-state nil))
    (unwind-protect
         (multiple-value-bind (server-tls-options client-tls-options) (server-test-tls-settings directory) (setf socket
                 (cl-quic-kit:make-udp-socket
                  :local-host "127.0.0.1" :local-port 0))
           (setf server
                 (cl-quic-kit:make-quic-server
                  :udp-socket socket
                  :max-connections 1
                  :retry-policy :never
                  :tls-server-options
                  (append server-tls-options (list :supported-groups (quote (#x0017)) :alpn-protocols (list "h3")))))
           (setf client
                 (apply (function cl-quic-kit:make-quic-client) :server-host "127.0.0.1"
                  :server-port (cl-quic-kit:udp-socket-local-port socket)
                  :hostname "localhost"
                  :local-connection-id local-cid
                  :transport-parameters client-parameters
                  :idle-timeout 60
                  :alpn (list "h3")
                  :tls-key-exchange key-exchange client-tls-options))
           (cl-quic-kit:client-poll client)
           (server-test-poll-until
            server
            (lambda ()
              (setf server-state
                    (loop for entry being the hash-values
                            of (cl-quic-kit::quic-server-connections server)
                          return entry))
              (and server-state
                   (eq
                    (cl-tls-kit::tls13-server-driver-state
                     (cl-quic-kit::server-connection-tls-driver server-state))
                    :awaiting-second-client-hello))))
           (check
            (equalp
             (cl-quic-kit::server-connection-peer-transport-parameters server-state)
             client-parameters)
            "HRR loopback captures the first peer transport-parameter event before Finished")
           (check
            (and (not (cl-quic-kit::server-connection-handshake-complete-p
                       server-state))
                 (not (cl-quic-kit::server-connection-accepted-p server-state))
                 (not (eq (cl-quic-kit:connection-state
                           (cl-quic-kit::server-connection-connection server-state))
                          :established))
                 (null (cl-quic-kit:quic-client-peer-transport-parameters
                        (cl-quic-kit::server-connection-engine server-state)))
                 (= (cl-quic-kit::quic-connection-idle-timeout
                     (cl-quic-kit::server-connection-connection server-state))
                    cl-quic-kit::*quic-idle-timeout-default*)
                 (null (cl-quic-kit::quic-server-accepted-connections server)))
            "HRR first peer transport parameters do not establish, accept, or apply idle timeout")
           (setf (cl-quic-kit::server-connection-peer-transport-parameters
                  server-state)
                 #(255))
           (cl-quic-kit:client-poll client)
           (server-test-poll-until
            server
            (lambda ()
              (eq
               (cl-tls-kit::tls13-server-driver-state
                (cl-quic-kit::server-connection-tls-driver server-state))
               :awaiting-client-finished)))
           (check
            (equalp
             (cl-quic-kit::server-connection-peer-transport-parameters server-state)
             client-parameters)
            "HRR second pre-Finished peer transport-parameter event replaces the first value")
           (check
            (and (not (cl-quic-kit::server-connection-handshake-complete-p
                       server-state))
                 (not (cl-quic-kit::server-connection-accepted-p server-state))
                 (not (eq (cl-quic-kit:connection-state
                           (cl-quic-kit::server-connection-connection server-state))
                          :established))
                 (null (cl-quic-kit:quic-client-peer-transport-parameters
                        (cl-quic-kit::server-connection-engine server-state)))
                 (= (cl-quic-kit::quic-connection-idle-timeout
                     (cl-quic-kit::server-connection-connection server-state))
                    cl-quic-kit::*quic-idle-timeout-default*)
                 (null (cl-quic-kit::quic-server-accepted-connections server)))
            "HRR second peer transport parameters remain provisional until Finished")
           (let ((accepted (server-test-loopback-handshake server client)))
             (check
              (and (eq accepted
                       (cl-quic-kit::server-connection-connection server-state))
                   (cl-quic-kit::server-connection-handshake-complete-p server-state)
                   (cl-quic-kit::server-connection-accepted-p server-state)
                   (eq (cl-quic-kit:connection-state accepted) :established))
              "HRR connection becomes established and accepted after Finished")
             (check
              (and (= (cl-quic-kit::quic-connection-idle-timeout accepted) 5)
                   (= (cdr (assoc 1
                                  (cl-quic-kit:quic-client-peer-transport-parameters
                                   (cl-quic-kit::server-connection-engine
                                    server-state))))
                      5000))
              "HRR peer transport parameters apply the idle timeout after Finished")))
      (unwind-protect
           (when client
             (cl-quic-kit:client-close client))
        (unwind-protect
             (if server
                 (cl-quic-kit:quic-server-close server)
                 (when socket
                   (cl-quic-kit:udp-close socket)))
          (server-test-remove-temp-directory directory))))))
(progn
  (defun server-test-make-pending-alert-connection
      (server address connection-id path now)
    (let* ((remote-id (make-array 8 :element-type (quote (unsigned-byte 8))
                                  :initial-contents (quote (21 22 23 24 25 26 27 28))))
           (server-connection
            (cl-quic-kit::%make-server-connection
             :server server :path path :address address :now now
             :original-destination-connection-id connection-id
             :local-connection-id connection-id
             :remote-connection-id remote-id
             :pending-datagrams nil))
           (connection
            (cl-quic-kit:make-quic-connection
             :role :server :local-connection-id connection-id
             :now-fn
             (lambda ()
               (cl-quic-kit::server-connection-now server-connection))
             :idle-timeout 1
             :io-write
             (lambda (ignored bytes)
               (declare (ignore ignored))
               (cl-quic-kit::%server-engine-write server-connection bytes))))
           (engine
            (cl-quic-kit:make-quic-client
             :connection connection :local-connection-id connection-id
             :destination-connection-id remote-id
             :disable-hostname-verification-p t
             :now-fn
             (lambda ()
               (cl-quic-kit::server-connection-now server-connection)))))
      (setf (cl-quic-kit::server-connection-connection server-connection)
            connection
            (cl-quic-kit::server-connection-engine server-connection)
            engine)
      (let ((initial
             (cl-quic-kit.protection:derive-initial-secrets connection-id)))
        (cl-quic-kit::%client-set-key engine :initial :write
                                      (getf initial :server)))
      (setf (gethash connection-id
                     (cl-quic-kit::quic-server-connections server))
            server-connection)
      server-connection))

  (defun server-test-tls-alert-close-waits-for-amplification-budget ()
    (let* ((server-socket
            (cl-quic-kit:make-udp-socket
             :local-host "127.0.0.1" :local-port 0))
           (server
            (cl-quic-kit:make-quic-server
             :udp-socket server-socket :max-connections 1
             :retry-policy :never))
           (peer
            (cl-quic-kit:make-udp-socket
             :remote-host "127.0.0.1"
             :remote-port (cl-quic-kit:udp-socket-local-port server-socket)
             :non-blocking-p t))
           (address nil))
      (unwind-protect
          (progn
            (cl-quic-kit:udp-send
             peer (make-array 1 :element-type (quote (unsigned-byte 8))
                              :initial-element 1))
            (loop repeat 1000
                  do (multiple-value-bind (bytes length source-address)
                         (cl-quic-kit:udp-receive server-socket)
                       (declare (ignore length))
                       (when bytes
                         (setf address source-address)))
                  (when address
                    (return))
                  (sleep 0.001)
                  finally (error "Did not receive the test peer datagram"))
            (let* ((path
                    (cl-quic-kit::%make-server-amplification-state
                     :received 1200 :sent 3600))
                   (connection-id (make-array 8 :element-type (quote (unsigned-byte 8))
                                              :initial-contents (quote (1 2 3 4 5 6 7 8))))
                   (server-connection
                    (server-test-make-pending-alert-connection
                     server address connection-id path 1)))
              (cl-quic-kit::%server-handle-tls-events
               server-connection
               (list (list :type :alert :description 47)))
              (check
               (and (cl-quic-kit::server-connection-pending-datagrams
                     server-connection)
                    (eq (gethash connection-id
                                 (cl-quic-kit::quic-server-connections server))
                        server-connection)
                    (= (hash-table-count
                        (cl-quic-kit::quic-server-connections server))
                       1))
               "TLS alert close remains routed while amplification blocks its output")
              (check
               (and (= (cl-quic-kit::server-amplification-state-sent path)
                       (* 3 (cl-quic-kit::server-amplification-state-received path)))
                    (null (server-test-receive peer t)))
               "TLS alert close emits nothing beyond the three-times amplification limit")
              (let ((pending
                     (first
                      (cl-quic-kit::server-connection-pending-datagrams
                       server-connection))))
                (progn
                  (loop repeat 8
                        do (cl-quic-kit::%server-process-protected-datagram
                            server-connection #(64) 1))
                  (check
                   (and (= (length (cl-quic-kit::server-connection-pending-datagrams
                                    server-connection))
                           1)
                        (not (cl-quic-kit::server-connection-close-response-attempted-p
                              server-connection)))
                   "closing flood does not add responses to an amplification-blocked close queue")
                  (setf (cl-quic-kit::server-amplification-state-received path)
                        (ceiling (+ (cl-quic-kit::server-amplification-state-sent path)
                                    (length pending))
                                 3)))
                (cl-quic-kit:quic-server-poll server 2)
                (let ((response (server-test-receive peer t)))
                  (progn
                    (check
                     (and response
                          (= (length response) (length pending))
                          (= (cl-quic-kit::server-amplification-state-sent path)
                             (+ 3600 (length pending)))
                          (<= (cl-quic-kit::server-amplification-state-sent path)
                              (* 3 (cl-quic-kit::server-amplification-state-received path)))
                          (null
                           (cl-quic-kit::server-connection-pending-datagrams
                            server-connection))
                          (eq (gethash connection-id
                                       (cl-quic-kit::quic-server-connections server))
                              server-connection)
                          (eq (cl-quic-kit:connection-state
                               (cl-quic-kit::server-connection-connection server-connection))
                              :closing))
                     (format nil
                             "TLS alert retry: response=~S pending=~D sent=~D received=~D queued=~D routed=~S state=~S"
                             (and response (length response))
                             (length pending)
                             (cl-quic-kit::server-amplification-state-sent path)
                             (cl-quic-kit::server-amplification-state-received path)
                             (length (cl-quic-kit::server-connection-pending-datagrams server-connection))
                             (eq (gethash connection-id (cl-quic-kit::quic-server-connections server))
                                 server-connection)
                             (cl-quic-kit:connection-state
                              (cl-quic-kit::server-connection-connection server-connection))))
                    (let ((deadline
                           (cl-quic-kit:connection-draining-deadline
                            (cl-quic-kit::server-connection-connection server-connection))))
                      (cl-quic-kit:quic-server-poll server deadline)
                      (check
                       (and (eq (cl-quic-kit:connection-state
                                 (cl-quic-kit::server-connection-connection server-connection))
                                :closed)
                            (null (gethash connection-id
                                           (cl-quic-kit::quic-server-connections server)))
                            (zerop (hash-table-count
                                    (cl-quic-kit::quic-server-connections server))))
                       "TLS alert close removes routes after its draining deadline")))))
              (let* ((expired-id (make-array 8 :element-type (quote (unsigned-byte 8))
                                             :initial-contents (quote (31 32 33 34 35 36 37 38))))
                     (expired-path
                      (cl-quic-kit::%make-server-amplification-state
                       :received 1200 :sent 3600))
                     (expired-connection
                      (server-test-make-pending-alert-connection
                       server address expired-id expired-path 3)))
                (cl-quic-kit::%server-handle-tls-events
                 expired-connection
                 (list (list :type :alert :description 47)))
                (let ((deadline
                       (cl-quic-kit:connection-draining-deadline
                        (cl-quic-kit::server-connection-connection
                         expired-connection))))
                  (cl-quic-kit:quic-server-poll server deadline)
                  (check
                   (and (eq (cl-quic-kit:connection-state
                             (cl-quic-kit::server-connection-connection
                              expired-connection))
                            :closed)
                        (null (gethash expired-id
                                       (cl-quic-kit::quic-server-connections
                                        server)))
                        (zerop (hash-table-count
                                (cl-quic-kit::quic-server-connections server))))
                   "TLS alert pending output is discarded when its close deadline expires"))))
            (cl-quic-kit:udp-close peer)
            (cl-quic-kit:quic-server-close server)))))

  (defun server-test-retry-capacity-rejection-cleans-new-paths ()
    (let ((cl-quic-kit::*quic-server-retry-cache-limit* 1)
          (server-socket
           (cl-quic-kit:make-udp-socket
            :local-host "127.0.0.1" :local-port 0))
          (server nil)
          (first-client nil)
          (second-client nil))
      (unwind-protect
           (progn
             (setf server
                   (cl-quic-kit:make-quic-server
                    :udp-socket server-socket :max-connections 1
                    :retry-policy :always)
                   first-client
                   (cl-quic-kit:make-quic-client
                    :server-host "127.0.0.1"
                    :server-port (cl-quic-kit:udp-socket-local-port server-socket)
                    :disable-hostname-verification-p t
                    :now-fn (lambda () 0)))
             (multiple-value-bind (token record)
                 (server-test-issue-retry server first-client 0)
               (let* ((path-key
                        (cl-quic-kit::%server-path-key
                         (cl-quic-kit::server-retry-token-address record)
                         (cl-quic-kit::server-retry-token-original-destination-connection-id
                          record)))
                      (original-path
                        (gethash path-key
                                 (cl-quic-kit::quic-server-paths server)))
                      (initial-packet
                        (server-test-initial-packet
                         cl-quic-kit:*quic-version-1*
                         (cl-quic-kit::server-retry-token-retry-source-connection-id
                          record)
                         (cl-quic-kit::server-retry-token-client-source-connection-id
                          record)
                         token))
                      (connection-id
                        (make-array 8
                                    :element-type '(unsigned-byte 8)
                                    :initial-contents '(91 92 93 94 95 96 97 98)))
                      (remote-id
                        (make-array 8
                                    :element-type '(unsigned-byte 8)
                                    :initial-contents '(71 72 73 74 75 76 77 78)))
                      (dummy-connection
                        (cl-quic-kit:make-quic-connection
                         :role :server :local-connection-id connection-id
                         :now-fn (lambda () 0)))
                      (dummy-engine
                        (cl-quic-kit:make-quic-client
                         :connection dummy-connection
                         :local-connection-id connection-id
                         :destination-connection-id remote-id
                         :disable-hostname-verification-p t
                         :now-fn (lambda () 0)))
                      (dummy
                        (cl-quic-kit::%make-server-connection
                         :server server :connection dummy-connection
                         :engine dummy-engine
                         :original-destination-connection-id
                         #(81 82 83 84 85 86 87 88)
                         :local-connection-id connection-id
                         :remote-connection-id remote-id
                         :pending-datagrams nil)))
                 (setf (gethash connection-id
                                (cl-quic-kit::quic-server-connections server))
                       dummy)
                 (cl-quic-kit:client-poll first-client 0)
                 (server-test-poll-until-datagram-received
                  server server-socket nil 0)
                 (check
                  (and original-path
                       (eq original-path
                           (gethash path-key
                                    (cl-quic-kit::quic-server-paths server)))
                       (not (cl-quic-kit::server-retry-token-used-p record))
                       (eq record
                           (gethash token
                                    (cl-quic-kit::quic-server-retry-tokens server)))
                       (eq dummy
                           (gethash connection-id
                                    (cl-quic-kit::quic-server-connections server)))
                       (= (hash-table-count
                           (cl-quic-kit::quic-server-connections server))
                          1))
                  "capacity rejection preserves the preexisting Retry path and leaves its token unused")
                 (remhash path-key (cl-quic-kit::quic-server-paths server))
                 (let ((path-count (hash-table-count
                                    (cl-quic-kit::quic-server-paths server))))
                   (loop repeat 3 do
                     (cl-quic-kit::%server-handle-datagram
                      server initial-packet
                      (cl-quic-kit::server-retry-token-address record)
                      (length initial-packet) 0))
                   (check
                    (= (hash-table-count
                        (cl-quic-kit::quic-server-paths server))
                       path-count)
                    "repeated capacity-rejected valid-token Initials leave no new path state"))
                 (check
                  (and (not (cl-quic-kit::server-retry-token-used-p record))
                       (eq record
                           (gethash token
                                    (cl-quic-kit::quic-server-retry-tokens server))))
                  "repeated capacity rejections keep the valid Retry token available")
                 (setf second-client
                       (cl-quic-kit:make-quic-client
                        :server-host "127.0.0.1"
                        :server-port
                        (cl-quic-kit:udp-socket-local-port server-socket)
                        :disable-hostname-verification-p t
                        :now-fn (lambda () 0)))
                 (cl-quic-kit:client-poll second-client 0)
                 (server-test-poll-until-datagram-received
                  server server-socket nil 0)
                 (let* ((response
                          (server-test-receive
                           (cl-quic-kit::quic-client-udp-socket second-client)
                           t))
                        (header
                          (and response
                               (cl-quic-kit:decode-packet-header response))))
                   (check
                    (and header
                         (eq (cl-quic-kit:packet-header-type header) :retry)
                         (null
                          (gethash token
                                   (cl-quic-kit::quic-server-retry-tokens server)))
                         (= (hash-table-count
                             (cl-quic-kit::quic-server-retry-tokens server))
                            1))
                    "a fresh Retry remains admissible after capacity rejections")))))
        (when first-client
          (cl-quic-kit:client-close first-client))
        (when second-client
          (cl-quic-kit:client-close second-client))
        (if server
            (cl-quic-kit:quic-server-close server)
          (cl-quic-kit:udp-close server-socket)))))

  (defun server-test-terminal-connection-releases-capacity ()
    (let* ((directory (server-test-make-temp-directory))
           (server-tls-options
            (append (nth-value 0 (server-test-tls-settings directory))
                    (list :alpn-protocols (list "h3"))))
           (server-socket
            (cl-quic-kit:make-udp-socket
             :local-host "127.0.0.1" :local-port 0))
           (server
            (cl-quic-kit:make-quic-server
             :udp-socket server-socket :max-connections 1
             :retry-policy :never
             :tls-server-options server-tls-options))
           (writes nil)
           (connection-id
            (make-array 8
                        :element-type (quote (unsigned-byte 8))
                        :initial-contents (quote (41 42 43 44 45 46 47 48))))
           (alias-id
            (make-array 8
                        :element-type (quote (unsigned-byte 8))
                        :initial-contents (quote (51 52 53 54 55 56 57 58))))
           (remote-id
            (make-array 8
                        :element-type (quote (unsigned-byte 8))
                        :initial-contents (quote (61 62 63 64 65 66 67 68))))
           (connection
            (cl-quic-kit:make-quic-connection
             :role :server :local-connection-id connection-id
             :now-fn (lambda () 5)
             :io-write
             (lambda (ignored bytes)
               (declare (ignore ignored))
               (push bytes writes))))
           (engine
            (cl-quic-kit:make-quic-client
             :connection connection :local-connection-id connection-id
             :destination-connection-id remote-id
             :disable-hostname-verification-p t :now-fn (lambda () 5)))
           (server-connection
            (cl-quic-kit::%make-server-connection
             :server server :connection connection :engine engine
             :original-destination-connection-id #(11 12 13 14 15 16 17 18)
             :local-connection-id connection-id
             :remote-connection-id remote-id
             :pending-datagrams (list #(1))))
           (secret (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 7)))
      (unwind-protect
          (progn
            (progn (cl-quic-kit:connection-set-state connection :draining) (setf (cl-quic-kit::server-connection-handshake-complete-p server-connection) t (cl-quic-kit::server-connection-accepted-p server-connection) t (cl-quic-kit::quic-server-accepted-connections server) (list connection)))
            (setf (cl-quic-kit::quic-connection-draining-deadline connection) 10
                  (gethash connection-id
                           (cl-quic-kit::quic-server-connections server))
                  server-connection
                  (gethash alias-id
                           (cl-quic-kit::quic-server-connections server))
                  server-connection)
            (cl-quic-kit::%client-set-key
             engine :1-rtt :write
             (cl-quic-kit.protection:make-key-set secret))
            (cl-quic-kit::%client-queue-frame
             engine (cl-quic-kit:make-frame :ping) :1-rtt)
            (check
             (eq (handler-case
                     (cl-quic-kit::%server-process-protected-datagram
                      server-connection #(64) 5)
                   (error () nil))
                 server-connection)
             "draining connections ignore packet input before decryption")
            (progn (cl-quic-kit:quic-server-poll server 5) (check (equal (cl-quic-kit::quic-server-accepted-connections server) (list connection)) "the completed connection remains queued until the application accepts it"))
            (check
             (and (eq (cl-quic-kit:connection-state connection) :draining)
                  (null writes)
                  (null (cl-quic-kit::server-connection-pending-datagrams
                         server-connection))
                  (cl-quic-kit::quic-client-pending-frames engine)
                  (= (hash-table-count
                      (cl-quic-kit::quic-server-connections server))
                     2)
                  (eq (gethash connection-id
                               (cl-quic-kit::quic-server-connections server))
                      server-connection)
                  (eq (gethash alias-id
                               (cl-quic-kit::quic-server-connections server))
                      server-connection))
             "draining polling suppresses output and retains every CID alias")
            (progn (cl-quic-kit:quic-server-poll server 10) (check (null (cl-quic-kit::quic-server-accepted-connections server)) "terminal route cleanup removes an unaccepted connection from the pending accept queue"))
            (check
             (and (eq (cl-quic-kit:connection-state connection) :closed)
                  (zerop (hash-table-count
                          (cl-quic-kit::quic-server-connections server)))
                  (null (gethash connection-id
                                 (cl-quic-kit::quic-server-connections server)))
                  (null (gethash alias-id
                                 (cl-quic-kit::quic-server-connections server))))
             "terminal connection polling removes every CID alias from capacity")
            (let ((packet
                   (server-test-initial-packet
                    cl-quic-kit:*quic-version-1*
                    #(101 102 103 104 105 106 107 108)
                    #(111 112 113 114 115 116 117 118))))
              (cl-quic-kit::%server-handle-datagram
               server packet
               (list (cl-quic-kit::%udp-address "127.0.0.1") 12345)
               1200 11)
              (check
               (and (= (hash-table-count
                        (cl-quic-kit::quic-server-connections server))
                       1)
                    (loop for active being the hash-values
                          of (cl-quic-kit::quic-server-connections server)
                          thereis (cl-quic-kit::server-connection-p active)))
               "a new Initial is admitted after terminal connection cleanup")))
        (unwind-protect (cl-quic-kit:quic-server-close server) (server-test-remove-temp-directory directory)))))

  (server-test-tls-alert-close-waits-for-amplification-budget)
  (server-test-retry-capacity-rejection-cleans-new-paths)
  (progn
    (defun server-test-peer-close-stops-coalesced-packet-processing ()
      (let* ((server-socket
               (cl-quic-kit:make-udp-socket
                :local-host "127.0.0.1" :local-port 0))
             (server
               (cl-quic-kit:make-quic-server
                :udp-socket server-socket :max-connections 1
                :retry-policy :never))
             (writes nil)
             (server-cid
              (make-array 8
                          :element-type (quote (unsigned-byte 8))
                          :initial-contents (quote (31 32 33 34 35 36 37 38))))
             (peer-cid
              (make-array 8
                          :element-type (quote (unsigned-byte 8))
                          :initial-contents (quote (41 42 43 44 45 46 47 48))))
             (server-connection-state
               (cl-quic-kit:make-quic-connection
                :role :server :local-connection-id server-cid
                :now-fn (lambda () 0)
                :io-write
                (lambda (ignored bytes)
                  (declare (ignore ignored))
                  (push bytes writes))))
             (server-engine
               (cl-quic-kit:make-quic-client
                :connection server-connection-state
                :local-connection-id server-cid
                :destination-connection-id peer-cid
                :disable-hostname-verification-p t :now-fn (lambda () 0)))
             (server-connection
               (cl-quic-kit::%make-server-connection
                :server server :connection server-connection-state
                :engine server-engine :local-connection-id server-cid
                :remote-connection-id peer-cid))
             (peer-connection
               (cl-quic-kit:make-quic-connection
                :role :client :local-connection-id peer-cid
                :now-fn (lambda () 0)))
             (peer-engine
               (cl-quic-kit:make-quic-client
                :connection peer-connection
                :local-connection-id peer-cid
                :destination-connection-id server-cid
                :disable-hostname-verification-p t :now-fn (lambda () 0)))
             (secret (make-array 32 :element-type (quote (unsigned-byte 8))
                                 :initial-element 7)))
        (unwind-protect
             (progn
               (cl-quic-kit:connection-set-state
                server-connection-state :established)
               (dolist (level (list :handshake :1-rtt))
                 (cl-quic-kit::%client-set-key
                  server-engine level :read
                  (cl-quic-kit.protection:make-key-set secret))
                 (cl-quic-kit::%client-set-key
                  peer-engine level :write
                  (cl-quic-kit.protection:make-key-set secret)))
               (let* ((close-packet
                        (cl-quic-kit::%client-build-packet
                         peer-engine :handshake
                         (list
                          (cl-quic-kit:make-frame
                           :connection-close :error-code #x55
                           :frame-type 0 :reason #()))))
                      (later-packet
                        (cl-quic-kit::%client-build-packet
                         peer-engine :application
                         (list
                          (cl-quic-kit:make-frame
                           :crypto :offset 0 :data #(1)))))
                      (datagram
                        (and close-packet later-packet
                             (concatenate (quote (vector (unsigned-byte 8)))
                                          close-packet later-packet)))
                      (result
                        (and datagram
                             (handler-case
                                 (cl-quic-kit::%server-process-protected-datagram
                                  server-connection datagram 5)
                               (error () nil)))))
                 (check
                  (and datagram
                       (eq result server-connection)
                       (eq (cl-quic-kit:connection-state
                            server-connection-state)
                           :draining)
                       (= (cl-quic-kit::quic-connection-last-activity
                           server-connection-state)
                          0)
                       (null writes))
                  "server stops processing coalesced packets after peer close")))
          (cl-quic-kit:quic-server-close server))))
    (server-test-peer-close-stops-coalesced-packet-processing)
    (server-test-terminal-connection-releases-capacity)
    (progn
  (defun server-test-stream-public-api ()
    (let* ((directory (server-test-make-temp-directory))
           (socket nil)
           (server nil)
           (client nil))
      (unwind-protect
          (multiple-value-bind (server-tls-options client-tls-options)
              (server-test-tls-settings directory)
            (setf socket
                  (cl-quic-kit:make-udp-socket
                   :local-host "127.0.0.1" :local-port 0))
            (setf server
                  (cl-quic-kit:make-quic-server
                   :udp-socket socket
                   :max-connections 1
                   :retry-policy :always
                   :transport-parameters
                   (list :initial-max-data 4
                         :initial-max-stream-data-bidi-local 65536
                         :initial-max-stream-data-bidi-remote 2
                         :initial-max-stream-data-uni 4
                         :initial-max-streams-bidi 10
                         :initial-max-streams-uni 10)
                   :tls-server-options
                   (append server-tls-options
                           (list :alpn-protocols (list "h3")))))
            (setf client
                  (apply (function cl-quic-kit:make-quic-client)
                         :server-host "127.0.0.1"
                         :server-port (cl-quic-kit:udp-socket-local-port socket)
                         :idle-timeout 60
                         :hostname "localhost"
                         :alpn (list "h3")
                         client-tls-options))
            (let* ((server-connection
                    (server-test-loopback-handshake server client))
                   (client-stream (cl-quic-kit:client-open-stream client nil))
                   (payload
                    (make-array 6 :element-type '(unsigned-byte 8)
                                :initial-contents (list 11 12 13 14 15 16)))
                   (server-stream nil))
              (check
               (eq (cl-quic-kit:connection-state server-connection) :established)
               "stream API uses the accepted server connection")
              (check
               (null (cl-quic-kit:quic-connection-accept-stream server-connection))
               "server stream accept is empty before peer data arrives")
              (check
               (server-test-type-error-p
                (lambda ()
                  (cl-quic-kit:quic-connection-accept-stream
                   server-connection :type :invalid)))
               "server stream accept rejects an invalid direction")
              (cl-quic-kit:client-write-stream client client-stream payload :fin-p t)
              (check
               (cl-quic-kit:client-stream-write-pending-p client client-stream)
               "client write remains queued past the server flow-control limit")
              (cl-quic-kit:client-poll client)
              (cl-quic-kit:quic-server-poll server)
              (check
               (null (cl-quic-kit:quic-connection-accept-stream
                      server-connection :type :unidirectional))
               "server stream accept filters by direction")
              (setf server-stream
                    (cl-quic-kit:quic-connection-accept-stream
                     server-connection :type :bidirectional))
              (check
               (and server-stream
                    (not (cl-quic-kit:stream-local-p server-stream)))
               "server stream accept returns the peer stream")
              (check
               (null (cl-quic-kit:quic-connection-accept-stream server-connection))
               "server stream accept returns each peer stream only once")
              (multiple-value-bind (first-data first-fin)
                  (cl-quic-kit:quic-connection-read-stream
                   server-connection server-stream)
                (check
                 (and (equalp first-data (subseq payload 0 2))
                      (not first-fin))
                 "server stream read respects the initial stream and connection credit"))
              (cl-quic-kit:quic-connection-flush server-connection)
              (cl-quic-kit:quic-server-poll server)
              (cl-quic-kit:client-poll client)
              (progn
                (check
                 (cl-quic-kit:client-stream-write-pending-p client client-stream)
                 "client write remains queued after returning one receive window")
                (cl-quic-kit:quic-server-poll server)
                (multiple-value-bind (next-data next-fin)
                    (cl-quic-kit:quic-connection-read-stream
                     server-connection server-stream)
                  (check
                   (and (equalp next-data (subseq payload 2 4))
                        (not next-fin))
                   "server stream read returns the next receive window"))
                (cl-quic-kit:quic-connection-flush server-connection)
                (cl-quic-kit:quic-server-poll server)
                (cl-quic-kit:client-poll client)
                (check
                 (not (cl-quic-kit:client-stream-write-pending-p client client-stream))
                 "second server read credit releases the remaining client write"))
              (cl-quic-kit:quic-server-poll server)
              (progn
                (multiple-value-bind (remaining-data fin-p)
                    (cl-quic-kit:quic-connection-read-stream
                     server-connection server-stream)
                  (check
                   (and (equalp remaining-data (subseq payload 4))
                        fin-p)
                   "server stream read returns the final octets and FIN"))
                (let* ((uni-stream
                         (cl-quic-kit:quic-connection-open-stream
                          server-connection :type :unidirectional))
                       (application-bytes
                         (make-array 1 :element-type (quote (unsigned-byte 8))
                                     :initial-contents (quote (2)))))
                  (cl-quic-kit:quic-connection-write-stream
                   server-connection uni-stream application-bytes :fin-p t)
                  (cl-quic-kit:quic-connection-flush server-connection)
                  (cl-quic-kit:quic-server-poll server)
                  (cl-quic-kit:client-poll client)
                  (let ((peer-stream
                          (cl-quic-kit:client-accept-peer-stream
                           client :type :unidirectional)))
                    (check peer-stream
                           "client receives a server unidirectional stream")
                    (when peer-stream
                      (multiple-value-bind (received fin-p)
                          (cl-quic-kit:client-read-stream client peer-stream)
                        (check
                         (and (equalp received application-bytes) fin-p)
                         "raw unidirectional stream preserves the nonzero application prefix"))))))
              (let* ((response-stream
                      (cl-quic-kit:quic-connection-open-stream server-connection))
                     (response
                      (make-array 3 :element-type '(unsigned-byte 8)
                                  :initial-contents (list 21 22 23))))
                (cl-quic-kit:quic-connection-write-stream
                 server-connection response-stream response :fin-p t)
                (cl-quic-kit:quic-connection-flush server-connection)
                (cl-quic-kit:quic-server-poll server)
                (cl-quic-kit:client-poll client)
                (let ((peer-stream
                       (cl-quic-kit:client-accept-peer-stream
                        client :type :bidirectional)))
                  (check peer-stream
                         "client receives a stream opened by the server")
                  (multiple-value-bind (received fin-p)
                      (cl-quic-kit:client-read-stream client peer-stream)
                    (progn
                      (check
                       (and (equalp received response) fin-p)
                       "server stream write and flush deliver octets and FIN")
                      (let* ((engine
                              (cl-quic-kit::quic-connection-stream-engine
                               server-connection))
                             (flow (cl-quic-kit::quic-client-flow-control engine))
                             (peer-parameters
                              (cl-quic-kit:quic-client-peer-transport-parameters engine))
                             (peer-limit (cdr (assoc 8 peer-parameters)))
                             (limit (cl-quic-kit:flow-control-max-streams-bidi flow))
                             (limit-condition nil)
                             (local-parameters
                              (cl-quic-kit::%client-local-transport-parameters engine))
                             (local-limit (cdr (assoc 8 local-parameters)))
                             (client-flow (cl-quic-kit::quic-client-flow-control client))
                             (client-peer-limit
                              (cl-quic-kit:flow-control-max-streams-bidi client-flow))
                             (stream-id (* 4 client-peer-limit)))
                        (check
                         (and (integerp peer-limit) (= peer-limit limit))
                         "server stream limit matches negotiated peer bidi limit")
                        (loop while (< (cl-quic-kit:flow-control-stream-count
                                        flow :bidirectional)
                                       limit)
                              do (cl-quic-kit:quic-connection-open-stream server-connection))
                        (check
                         (= (cl-quic-kit:flow-control-stream-count flow :bidirectional) limit)
                         "server API opens streams up to the negotiated peer limit")
                        (handler-case
                            (cl-quic-kit:quic-connection-open-stream server-connection)
                          (cl-quic-kit:flow-control-limit-error (condition)
                                                                (setf limit-condition condition)))
                        (check
                         (and limit-condition
                              (= (cl-quic-kit:flow-control-error-limit limit-condition) limit)
                              (= (cl-quic-kit:flow-control-error-attempted limit-condition)
                                 (1+ limit)))
                         "server API signals the flow-control limit condition at the peer maximum")
                        (check
                         (and (integerp local-limit) (= local-limit client-peer-limit))
                         "client observes the server advertised bidi stream limit")
                        (cl-quic-kit::%client-queue-frame
                         client
                         (cl-quic-kit:make-frame :stream :stream-id stream-id :offset 0
                                                 :data #() :fin nil)
                         :1-rtt)
                        (cl-quic-kit:client-flush client)
                        (cl-quic-kit:quic-server-poll server)
                        (check
                         (and (eq (cl-quic-kit:connection-state server-connection) :closing)
                              (= (cl-quic-kit::quic-connection-closed-error server-connection) 4)
                              (null (gethash stream-id (cl-quic-kit::quic-client-streams engine))))
                         "server frame path rejects a peer stream beyond its advertised limit"))))))))
        (when client
          (cl-quic-kit:client-close client))
        (if server
            (cl-quic-kit:quic-server-close server)
          (when socket
            (cl-quic-kit:udp-close socket))))))
  (server-test-stream-public-api))))
(progn
  (defun server-test-max-handshakes-configuration ()
    (let ((server
           (cl-quic-kit:make-quic-server
            :local-address "127.0.0.1" :local-port 0
            :max-connections 3)))
      (unwind-protect
          (check (= (cl-quic-kit::quic-server-max-handshakes server) 3)
                 "max-handshakes defaults to max-connections")
        (cl-quic-kit:quic-server-close server)))
    (let ((server
           (cl-quic-kit:make-quic-server
            :local-address "127.0.0.1" :local-port 0
            :max-connections 3 :max-handshakes 1)))
      (unwind-protect
          (check (= (cl-quic-kit::quic-server-max-handshakes server) 1)
                 "server stores an explicit max-handshakes value")
        (cl-quic-kit:quic-server-close server)))
    (dolist (limit '(0 -1))
      (check
       (server-test-type-error-p
        (lambda ()
          (cl-quic-kit:make-quic-server
           :max-connections 3 :max-handshakes limit)))
       (format nil "server rejects max-handshakes ~D" limit)))
    (check
     (server-test-type-error-p
      (lambda ()
        (cl-quic-kit:make-quic-server
         :max-connections 2 :max-handshakes 3)))
     "server rejects max-handshakes greater than max-connections"))

  (progn
  (server-test-max-handshakes-configuration)
  (defun server-test-max-handshakes-admission ()
  (let* ((directory (server-test-make-temp-directory))
         (socket nil)
         (server nil)
         (first-client nil)
         (second-client nil)
         (first-connection nil)
         (first-cid
           (make-array 8 :element-type '(unsigned-byte 8)
                       :initial-contents '(21 22 23 24 25 26 27 28)))
         (second-cid
           (make-array 8 :element-type '(unsigned-byte 8)
                       :initial-contents '(31 32 33 34 35 36 37 38))))
    (unwind-protect
         (multiple-value-bind (server-tls-options client-tls-options)
             (server-test-tls-settings directory)
           (setf socket
                 (cl-quic-kit:make-udp-socket
                  :local-host "127.0.0.1" :local-port 0))
           (setf server
                 (cl-quic-kit:make-quic-server
                  :udp-socket socket
                  :max-connections 2
                  :max-handshakes 1
                  :retry-policy :never
                  :tls-server-options
                  (append server-tls-options
                          (list :alpn-protocols (list "h3")))))
           (setf first-client
                 (apply (function cl-quic-kit:make-quic-client)
                        :server-host "127.0.0.1"
                        :server-port
                        (cl-quic-kit:udp-socket-local-port socket)
                        :hostname "localhost"
                        :local-connection-id first-cid
                        :idle-timeout 60
                        :alpn (list "h3")
                        client-tls-options))
           (setf second-client
                 (apply (function cl-quic-kit:make-quic-client)
                        :server-host "127.0.0.1"
                        :server-port
                        (cl-quic-kit:udp-socket-local-port socket)
                        :hostname "localhost"
                        :local-connection-id second-cid
                        :idle-timeout 60
                        :alpn (list "h3")
                        client-tls-options))
           (cl-quic-kit:client-start first-client)
           (server-test-poll-until
            server
            (lambda ()
              (setf first-connection
                    (loop for active in
                          (cl-quic-kit::%server-routed-connections server)
                          when (equalp
                                first-cid
                                (cl-quic-kit::server-connection-remote-connection-id
                                 active))
                          return active))
              (and first-connection
                   (eq
                    (cl-quic-kit:connection-state
                     (cl-quic-kit::server-connection-connection
                      first-connection))
                    :handshaking))))
           (check
            (and first-connection
                 (not
                  (cl-quic-kit::server-connection-handshake-complete-p
                   first-connection))
                 (not (cl-quic-kit::server-connection-accepted-p
                       first-connection))
                 (= (cl-quic-kit::%server-handshaking-count server) 1))
            "the first Initial allocates one incomplete handshaking connection")
           (progn
             (let* ((engine
                      (cl-quic-kit::server-connection-engine first-connection))
                    (connection
                      (cl-quic-kit::server-connection-connection first-connection))
                    (rejected
                      (handler-case
                          (progn
                            (cl-quic-kit::%client-process-received-frame
                             engine :1-rtt
                             (cl-quic-kit:make-frame :handshake-done))
                            nil)
                        (cl-quic-kit::quic-frame-space-error () t))))
               (check
                (and rejected
                     (eq (cl-quic-kit::quic-connection-role connection) :server)
                     (eq (cl-quic-kit:connection-state connection) :handshaking)
                     (not
                      (cl-quic-kit::server-connection-handshake-complete-p
                       first-connection))
                     (= (cl-quic-kit::%server-handshaking-count server) 1))
                "server rejects peer HANDSHAKE_DONE in 1-RTT before TLS completion"))
             (cl-quic-kit:client-start second-client))
           (server-test-poll-until-datagram-received server socket nil)
           (let ((routed
                   (cl-quic-kit::%server-routed-connections server)))
             (check
              (and (= (length routed) 1)
                   (eq (first routed) first-connection)
                   (= (cl-quic-kit::%server-handshaking-count server) 1)
                   (notany
                    (lambda (active)
                      (equalp
                       second-cid
                       (cl-quic-kit::server-connection-remote-connection-id
                        active)))
                    routed))
              "max-handshakes declines a second Initial before allocating a connection"))
           (let ((invalid-packet
                   (cl-quic-kit::%client-build-packet
                    first-client :initial
                    (list (cl-quic-kit:make-frame :handshake-done)))))
             (check invalid-packet
                    "the test builds a protected Initial packet")
             (cl-quic-kit:udp-send
              (cl-quic-kit:quic-client-udp-socket first-client)
              invalid-packet)
             (server-test-poll-until-datagram-received
              server socket invalid-packet)
             (let ((connection
                     (cl-quic-kit::server-connection-connection
                      first-connection)))
               (check
                (and (eq (cl-quic-kit:connection-state connection) :closing)
                     (= (cl-quic-kit::quic-connection-closed-error connection) 10)
                     (not
                      (cl-quic-kit::server-connection-handshake-complete-p
                       first-connection)))
                "server rejects HANDSHAKE_DONE in an Initial packet"))))
      (unwind-protect
           (when second-client
             (cl-quic-kit:client-close second-client))
        (unwind-protect
             (when first-client
               (cl-quic-kit:client-close first-client))
          (unwind-protect
               (if server
                   (cl-quic-kit:quic-server-close server)
                 (when socket
                   (cl-quic-kit:udp-close socket)))
            (server-test-remove-temp-directory directory)))))))
  (server-test-max-handshakes-admission))

  (defun server-test-shutdown-and-connection-close ()
    (let* ((directory (server-test-make-temp-directory))
           (socket nil)
           (server nil)
           (client nil)
           (second-client nil)
           (new-client nil))
      (unwind-protect
          (multiple-value-bind (server-tls-options client-tls-options)
              (server-test-tls-settings directory)
            (setf socket
                  (cl-quic-kit:make-udp-socket
                   :local-host "127.0.0.1" :local-port 0))
            (setf server
                  (cl-quic-kit:make-quic-server
                   :udp-socket socket
                   :max-connections 3
                   :max-handshakes 3
                   :retry-policy :always
                   :tls-server-options
                   (append server-tls-options
                           (list :alpn-protocols (list "h3")))))
            (flet ((make-client ()
                                (apply (function cl-quic-kit:make-quic-client)
                                       :server-host "127.0.0.1"
                                       :server-port
                                       (cl-quic-kit:udp-socket-local-port socket)
                                       :idle-timeout 60
                                       :hostname "localhost"
                                       :alpn (list "h3")
                                       client-tls-options)))
              (setf client (make-client)
                    second-client (make-client))
              (let* ((first-connection
                      (server-test-loopback-handshake server client))
                     (second-connection
                      (server-test-loopback-handshake server second-client))
                     (client-stream nil)
                     (deadline nil))
                (check
                 (and (eq (cl-quic-kit:connection-state first-connection)
                          :established)
                      (eq (cl-quic-kit:connection-state second-connection)
                          :established)
                      (= (hash-table-count
                          (cl-quic-kit::quic-server-connections server))
                         2))
                 "shutdown test starts with two established routed connections")
                (cl-quic-kit:quic-server-shutdown
                 server :grace-period 30
                 :error-code :internal-error :reason "server shutdown")
                (setf deadline
                      (cl-quic-kit::quic-server-shutdown-deadline server))
                (check
                 (and (numberp deadline)
                      (eq (cl-quic-kit:connection-state first-connection)
                          :established)
                      (eq (cl-quic-kit:connection-state second-connection)
                          :established))
                 "shutdown leaves established connections available during grace")
                (cl-quic-kit:quic-server-shutdown
                 server :grace-period 0
                 :error-code :internal-error :reason "server shutdown")
                (check
                 (= deadline
                    (cl-quic-kit::quic-server-shutdown-deadline server))
                 "repeated shutdown does not extend or shorten its deadline")
                (setf new-client (make-client))
                (cl-quic-kit:client-poll new-client)
                (cl-quic-kit:quic-server-poll server)
                (cl-quic-kit:client-poll new-client)
                (check
                 (and (eq (cl-quic-kit:connection-state
                           (cl-quic-kit:quic-client-connection new-client))
                          :handshaking)
                      (equalp (cl-quic-kit::quic-client-retry-token new-client) #())
                      (= (hash-table-count
                          (cl-quic-kit::quic-server-connections server))
                         2)
                      (null (cl-quic-kit:quic-server-accept-connection server)))
                 "shutdown ignores a new Initial while preserving existing routes")
                (let* ((stream
                        (cl-quic-kit:client-open-stream client nil))
                       (payload
                        (make-array 2 :element-type '(unsigned-byte 8)
                                    :initial-contents '(31 32))))
                  (setf client-stream stream)
                  (cl-quic-kit:client-write-stream
                   client stream payload :fin-p t)
                  (cl-quic-kit:client-poll client)
                  (cl-quic-kit:quic-server-poll server)
                  (let ((server-stream
                         (cl-quic-kit:quic-connection-accept-stream
                          first-connection)))
                    (multiple-value-bind (received fin-p)
                        (cl-quic-kit:quic-connection-read-stream
                         first-connection server-stream)
                      (check
                       (and server-stream (equalp received payload) fin-p)
                       "shutdown continues processing streams on an existing connection"))))
                (let* ((first-route
                        (loop for route being the hash-values
                              of (cl-quic-kit::quic-server-connections server)
                              when (eq
                                    (cl-quic-kit::server-connection-connection
                                     route)
                                    first-connection)
                              return route))
                       (engine
                        (and first-route
                             (cl-quic-kit::server-connection-engine first-route)))
                       (packet-numbers nil)
                       (close-packet nil)
                       (close-header nil)
                       (reason-bytes
                        (map '(vector (unsigned-byte 8))
                             #'char-code "connection closing")))
                  (check engine
                         "shutdown test retains the first connection packet engine")
                  (cl-quic-kit:quic-connection-close
                   first-connection
                   :error-code :protocol-violation
                   :reason "connection closing")
                  (setf packet-numbers
                        (copy-tree
                         (cl-quic-kit::quic-client-packet-numbers engine)))
                  (check
                   (and (eq (cl-quic-kit:connection-state first-connection)
                            :closing)
                        (eq (cl-quic-kit:connection-close-kind first-connection)
                            :transport)
                        (= (cl-quic-kit::quic-connection-closed-error
                            first-connection)
                           10)
                        (equalp (cl-quic-kit:quic-connection-closed-reason
                                 first-connection)
                                reason-bytes))
                   "connection close records its transport error and reason")
                  (cl-quic-kit:quic-connection-close
                   first-connection
                   :error-code :internal-error :reason "duplicate close")
                  (check
                   (equalp packet-numbers
                           (cl-quic-kit::quic-client-packet-numbers engine))
                   "repeated connection close does not send another packet")
                  (setf close-packet
                        (server-test-receive
                         (cl-quic-kit:quic-client-udp-socket client)))
                  (setf close-header
                        (cl-quic-kit:client-receive-datagram
                         client close-packet))

                  (check (and close-header
                              (eq (cl-quic-kit:connection-state
                                   (cl-quic-kit:quic-client-connection client))
                                  :draining)
                              (eq (cl-quic-kit:connection-close-kind
                                   (cl-quic-kit:quic-client-connection client))
                                  :transport)
                              (= (cl-quic-kit::quic-connection-closed-error
                                  (cl-quic-kit:quic-client-connection client))
                                 10)
                              (equalp
                               (cl-quic-kit:quic-connection-closed-reason
                                (cl-quic-kit:quic-client-connection client))
                               reason-bytes))
                         "client decrypts the protected CONNECTION_CLOSE and enters draining")
                  (let ((condition nil))
                    (handler-case
                        (cl-quic-kit:quic-connection-open-stream
                         (cl-quic-kit:quic-client-connection client))
                      (cl-quic-kit:connection-closed (closed)
                                                     (setf condition closed)))
                    (check
                     (and condition
                          (= (cl-quic-kit:connection-close-error-code condition) 10)
                          (equalp (cl-quic-kit:connection-close-reason condition) reason-bytes))
                     "opening a stream after peer close signals the close details"))
                  (let ((condition nil))
                    (handler-case
                        (cl-quic-kit:quic-connection-write-stream
                         (cl-quic-kit:quic-client-connection client) client-stream #() :fin-p t)
                      (cl-quic-kit:connection-closed (closed)
                                                     (setf condition closed)))
                    (check
                     (and condition
                          (= (cl-quic-kit:connection-close-error-code condition) 10)
                          (equalp (cl-quic-kit:connection-close-reason condition) reason-bytes))
                     "writing a stream after peer close signals the close details"))
                  (check
                   (eq (cl-quic-kit:connection-state second-connection)
                       :established)
                   "a connection without a direct close remains active until the shutdown deadline")
                  (check
                   (and (cl-quic-kit:quic-server-poll server deadline)
                        (cl-quic-kit::quic-server-closed-p server)
                        (cl-quic-kit::udp-socket-closed-p socket)
                        (zerop (hash-table-count
                                (cl-quic-kit::quic-server-connections server)))
                        (eq (cl-quic-kit:connection-state first-connection)
                            :closed)
                        (eq (cl-quic-kit:connection-state second-connection)
                            :closed))
                   "shutdown deadline closes the server socket and removes all routes")
                  (let* ((shutdown-packet
                          (server-test-receive
                           (cl-quic-kit:quic-client-udp-socket second-client)))
                         (shutdown-header
                          (cl-quic-kit:client-receive-datagram
                           second-client shutdown-packet))
                         (shutdown-reason
                          (map '(vector (unsigned-byte 8))
                               #'char-code "server shutdown")))
                    (check
                     (and shutdown-header
                          (eq (cl-quic-kit:connection-state
                               (cl-quic-kit:quic-client-connection second-client))
                              :draining)
                          (eq (cl-quic-kit:connection-close-kind
                               (cl-quic-kit:quic-client-connection second-client))
                              :transport)
                          (= (cl-quic-kit::quic-connection-closed-error
                              (cl-quic-kit:quic-client-connection second-client))
                             1)
                          (equalp
                           (cl-quic-kit:quic-connection-closed-reason
                            (cl-quic-kit:quic-client-connection second-client))
                           shutdown-reason))
                     "deadline close reaches the remaining client with shutdown details"))))))
        (when new-client
          (cl-quic-kit:client-close new-client))
        (when second-client
          (cl-quic-kit:client-close second-client))
        (when client
          (cl-quic-kit:client-close client))
        (if server
            (cl-quic-kit:quic-server-close server)
          (when socket
            (cl-quic-kit:udp-close socket)))
        (server-test-remove-temp-directory directory))))

  (server-test-shutdown-and-connection-close)

  (defun server-test-server-close-send-failure-cleans-up ()
    (let* ((socket
            (cl-quic-kit:make-udp-socket
             :local-host "127.0.0.1" :local-port 0))
           (server
            (cl-quic-kit:make-quic-server
             :udp-socket socket :max-connections 1 :retry-policy :never))
           (path
            (cl-quic-kit::%make-server-amplification-state
             :received 1200 :validated-p t))
           (server-route
            (cl-quic-kit::%make-server-connection
             :server server :path path :address :test-peer))
           (local-cid
            (make-array 4 :element-type '(unsigned-byte 8)
                        :initial-contents '(1 2 3 4)))
           (remote-cid
            (make-array 4 :element-type '(unsigned-byte 8)
                        :initial-contents '(5 6 7 8)))
           (connection
            (cl-quic-kit:make-quic-connection
             :role :server :local-connection-id local-cid
             :io-write
             (lambda (candidate bytes)
               (declare (ignore candidate))
               (cl-quic-kit::%server-engine-write server-route bytes))))
           (engine
            (cl-quic-kit:make-quic-client
             :connection connection :disable-hostname-verification-p t
             :local-connection-id local-cid
             :destination-connection-id remote-cid))
           (send-symbol (find-symbol "UDP-SEND" "CL-QUIC-KIT"))
           (original-send (symbol-function send-symbol))
           (send-failed-p nil)
           (close-error-p nil))
      (unwind-protect
          (progn
            (progn
              (cl-quic-kit:connection-set-state connection :established)
              (cl-quic-kit::%client-set-key
               engine :1-rtt :write
               (cl-quic-kit.protection:make-key-set
                (make-array 32 :element-type (quote (unsigned-byte 8))
                            :initial-element 7))))
            (setf (cl-quic-kit::quic-connection-stream-engine connection)
                  engine
                  (cl-quic-kit::server-connection-connection server-route)
                  connection
                  (cl-quic-kit::server-connection-engine server-route)
                  engine
                  (cl-quic-kit::server-connection-local-connection-id server-route)
                  local-cid
                  (gethash local-cid
                           (cl-quic-kit::quic-server-connections server))
                  server-route)
            (setf
             (symbol-function send-symbol)
             (lambda (candidate-socket bytes &key address)
               (if (eq candidate-socket socket)
                   (progn
                     (setf send-failed-p t)
                     (error 'cl-quic-kit:quic-error
                            :message "injected server UDP send failure"))
                 (funcall original-send candidate-socket bytes
                          :address address))))
            (setf close-error-p
                  (handler-case
                      (progn (cl-quic-kit:quic-server-close server) nil)
                    (cl-quic-kit:quic-error () t)))
            (setf (symbol-function send-symbol) original-send)
            (check
             (and send-failed-p close-error-p
                  (cl-quic-kit::quic-server-closed-p server)
                  (cl-quic-kit::udp-socket-closed-p socket)
                  (zerop (hash-table-count
                          (cl-quic-kit::quic-server-connections server)))
                  (eq (cl-quic-kit:connection-state connection) :closed))
             "server close cleans up and closes UDP after a send failure"))
        (setf (symbol-function send-symbol) original-send)
        (unless (cl-quic-kit::udp-socket-closed-p socket)
          (ignore-errors (cl-quic-kit:quic-server-close server)))
        (unless (cl-quic-kit::udp-socket-closed-p socket)
          (cl-quic-kit:udp-close socket)))))

  (defun server-test-server-close-retries-incomplete-close ()
    (labels ((run-case (retry-function label)
               (let* ((socket
                        (cl-quic-kit:make-udp-socket
                         :local-host "127.0.0.1" :local-port 0))
                      (server
                        (cl-quic-kit:make-quic-server
                         :udp-socket socket :max-connections 1
                         :retry-policy :never))
                      (close-symbol (find-symbol "SOCKET-CLOSE" "SB-BSD-SOCKETS"))
                      (original-close (symbol-function close-symbol))
                      (injected-p nil)
                      (close-attempts 0)
                      (real-close-count 0))
                 (unwind-protect
                      (progn
                        (setf (symbol-function close-symbol)
                              (lambda (candidate-socket &key abort)
                                (if (eq candidate-socket
                                        (cl-quic-kit::udp-socket-socket socket))
                                    (progn
                                      (incf close-attempts)
                                      (if injected-p
                                          (progn
                                            (incf real-close-count)
                                            (funcall original-close candidate-socket
                                                     :abort abort))
                                          (progn
                                            (setf injected-p t)
                                            (error "injected pre-syscall close failure"))))
                                    (funcall original-close candidate-socket
                                             :abort abort))))
                        (let ((close-error-p
                                (handler-case
                                    (progn
                                      (cl-quic-kit:quic-server-close server)
                                      nil)
                                  (cl-quic-kit:quic-error () t))))
                          (check
                           (and close-error-p injected-p
                                (cl-quic-kit::quic-server-closed-p server)
                                (cl-quic-kit::udp-socket-closed-p socket)
                                (not (cl-quic-kit::udp-socket-close-complete-p socket))
                                (= close-attempts 1)
                                (zerop real-close-count))
                           (format nil "server close records a pre-syscall failure before ~A retry"
                                   label))
                          (check
                           (and (funcall retry-function server)
                                (cl-quic-kit::udp-socket-close-complete-p socket)
                                (= close-attempts 2)
                                (= real-close-count 1))
                           (format nil "~A retries the incomplete UDP descriptor close" label))
                          (let ((attempts-after-close close-attempts))
                            (check
                             (and (cl-quic-kit:quic-server-close server)
                                  (= close-attempts attempts-after-close)
                                  (= real-close-count 1))
                             (format nil "confirmed UDP descriptor close is idempotent after ~A"
                                     label))))
                   (setf (symbol-function close-symbol) original-close)
                   (unless (cl-quic-kit::udp-socket-close-complete-p socket)
                     (ignore-errors (cl-quic-kit:quic-server-close server)))))))
      (run-case (function cl-quic-kit:quic-server-close) "repeated close")
      (run-case (function cl-quic-kit:quic-server-poll) "poll")))
  (server-test-server-close-retries-incomplete-close))
  (let* ((secret (make-array 12 :element-type t
                             :initial-contents #(83 69 67 82 69 84 45 68 85 77 77 89)))
         (secret-report (format nil "~{~D~^ ~}" (coerce secret 'list)))
         (server (cl-quic-kit::%make-quic-server
                  :tls-server-options (list :private-key secret)))
         (retry-token
          (cl-quic-kit::%make-server-retry-token
           :retry-source-connection-id secret))
         (server-connection
          (cl-quic-kit::%make-server-connection :server server)))
    (labels ((safe-print-p (object)
                           (let ((report (princ-to-string object)))
                             (and (search "redacted" report)
                                  (not (search secret-report report))))))
      (check (safe-print-p server)
             "server printer redacts private TLS options")
      (check (safe-print-p retry-token)
             "Retry token record printer redacts connection identifiers")
      (check (safe-print-p server-connection)
             "server connection printer redacts TLS state"))
    (let ((condition nil))
      (handler-case
          (cl-quic-kit::%server-copy-plist
           (list :private-key secret :orphan))
        (type-error (caught) (setf condition caught)))
      (progn
        (let ((report (and condition (princ-to-string condition))))
          (check (and condition
                      (eq (type-error-datum condition) :invalid-server-options)
                      (not (search secret-report report)))
                 "malformed server options use a safe datum"))
        (let ((condition nil))
          (handler-case
              (cl-quic-kit::%server-copy-plist (list secret :value))
            (type-error (caught) (setf condition caught)))
          (let ((report (and condition (princ-to-string condition))))
            (check (and condition
                        (eq (type-error-datum condition) :invalid-server-option-key)
                        (not (search secret-report report)))
                   "invalid server option keys use safe type-error data")))))
    (let ((condition nil))
      (handler-case
          (cl-quic-kit:make-quic-server
           :max-connections 1 :max-handshakes 2)
        (type-error (caught) (setf condition caught)))
      (check (and condition
                  (eq (type-error-datum condition) :invalid-handshake-limit))
             "server admission type errors use a stable classification")))
  (progn
  (defun server-test-f7-secret-redaction ()
    (let* ((marker "PRIVATE-MARKER-QUIC-REDACTION")
           (input (list marker))
           (streams (make-hash-table))
           (client (cl-quic-kit::%make-quic-client
                    :streams streams :clock (lambda () 0)))
           (stream (cl-quic-kit:make-stream 0))
           (token-frame (cl-quic-kit:make-frame :new-token :token marker))
           (crypto-frame
            (cl-quic-kit:make-frame :crypto :offset 0
                                    :data (map '(vector (unsigned-byte 8))
                                               #'char-code marker)))
           (receive-stream (cl-quic-kit:make-stream 1)))
      (setf (gethash 0 streams) stream)
      (cl-quic-kit:stream-receive-data
       receive-stream 0
       (cl-quic-kit:frame-field crypto-frame :data))
      (check (equal marker (cl-quic-kit:frame-field token-frame :token))
             "printer test stores the marker in a NEW_TOKEN frame")
      (check (equalp (cl-quic-kit:frame-field crypto-frame :data)
                     (cl-quic-kit::stream-read-buffer receive-stream))
             "printer test stores the marker bytes in a CRYPTO frame and received stream")
      (let ((token-report (princ-to-string token-frame))
            (crypto-report (princ-to-string crypto-frame))
            (stream-report (princ-to-string receive-stream)))
        (check (and (not (search marker token-report))
                    (not (search "#(" token-report))
                    (search (format nil "token-length ~D" (length marker))
                            token-report))
               "frame printer exposes only NEW_TOKEN length metadata")
        (check (and
                (not (search marker crypto-report))
                (not (search (format nil "~{~D~^ ~}"
                                     (coerce (cl-quic-kit:frame-field crypto-frame :data)
                                             (quote list)))
                             crypto-report))
                (not (search "#(" crypto-report))
                (search (format nil "data-length ~D"
                                (length (cl-quic-kit:frame-field crypto-frame :data)))
                        crypto-report))
               "frame printer redacts CRYPTO payload bytes and reports their length")
        (progn
          (check (and
                  (not (search marker stream-report))
                  (not (search (format nil "~{~D~^ ~}"
                                       (coerce (cl-quic-kit:frame-field crypto-frame :data)
                                               (quote list)))
                               stream-report))
                  (not (search "#(" stream-report))
                  (search (format nil "buffered-payload-length ~D retained-payload-length ~D"
                                  (length (cl-quic-kit::stream-read-buffer receive-stream))
                                  (loop for segment in (cl-quic-kit::stream-received-segments receive-stream)
                                        sum (length (cdr segment))))
                          stream-report))
                 "stream printer redacts received data and reports buffered length")
          (let* ((payload (map (quote (vector (unsigned-byte 8))) (function char-code) marker))
                 (secret-report (format nil "~{~D~^ ~}" (coerce payload (quote list))))
                 (reason-frame (cl-quic-kit:make-frame :connection-close :reason payload))
                 (connection-id-frame
                  (cl-quic-kit:make-frame :new-connection-id
                                          :connection-id payload
                                          :stateless-reset-token payload)))
            (check (and (equalp payload (cl-quic-kit:frame-field reason-frame :reason))
                        (equalp payload (cl-quic-kit:frame-field connection-id-frame :connection-id))
                        (equalp payload (cl-quic-kit:frame-field connection-id-frame :stateless-reset-token)))
                   "printer test stores marker bytes in CONNECTION_CLOSE and NEW_CONNECTION_ID frames")
            (let ((reason-report (princ-to-string reason-frame))
                  (connection-id-report (princ-to-string connection-id-frame)))
              (check (and (not (search marker reason-report))
                          (not (search secret-report reason-report))
                          (not (search "#(" reason-report))
                          (search (format nil "reason-length ~D" (length payload)) reason-report))
                     "frame printer redacts CONNECTION_CLOSE reason bytes and reports their length")
              (check (and (not (search marker connection-id-report))
                          (not (search secret-report connection-id-report))
                          (not (search "#(" connection-id-report))
                          (search (format nil "connection-id-length ~D" (length payload)) connection-id-report)
                          (search (format nil "stateless-reset-token-length ~D" (length payload)) connection-id-report))
                     "frame printer redacts connection ID and reset token bytes")))
          (let* ((payload (map (quote (vector (unsigned-byte 8))) (function char-code) marker))
                 (out-of-order-stream (cl-quic-kit:make-stream 3)))
            (cl-quic-kit:stream-receive-data out-of-order-stream 5 payload)
            (check (equalp payload (cdr (first (cl-quic-kit::stream-segments out-of-order-stream))))
                   "printer test stores bytes in an out-of-order stream segment")
            (let ((report (princ-to-string out-of-order-stream)))
              (check (and
                      (not (search marker report))
                      (not (search (format nil "~{~D~^ ~}" (coerce payload (quote list))) report))
                      (not (search "#(" report))
                      (search (format nil "buffered-payload-length ~D" (length payload)) report))
                     "stream printer redacts out-of-order segment bytes and reports their length")))))
      (labels ((redacted-type-error-p (action classification)
                                      (handler-case
                                          (progn (funcall action) nil)
                                        (type-error (condition)
                                                    (and (eq (type-error-datum condition) classification)
                                                         (not (search marker (princ-to-string condition))))))))
        (check (redacted-type-error-p
                (lambda () (cl-quic-kit::%stream-octets input))
                :invalid-stream-data)
               "stream octet type errors redact caller input")
        (check (redacted-type-error-p
                (lambda () (cl-quic-kit::%udp-octets input))
                :invalid-udp-data)
               "UDP octet type errors redact caller input")
        (check (redacted-type-error-p
                (lambda () (cl-quic-kit::%quic-close-reason input))
                :invalid-close-reason)
               "close reason type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:client-write-stream client stream input))
                :invalid-stream-data)
               "client stream write type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:client-accept-peer-stream client :type input))
                :invalid-peer-stream-type)
               "client peer stream selection type errors redact caller input")
        (check (redacted-type-error-p
                (lambda () (cl-quic-kit::%non-negative-integer input :limit))
                :invalid-non-negative-integer)
               "flow-control integer type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:make-quic-server
                   :udp-socket input :max-connections 1 :max-handshakes 1))
                :invalid-udp-socket)
               "server UDP socket type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:quic-connection-accept-stream nil :type input))
                :invalid-peer-stream-type)
               "connection accept stream type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:quic-connection-open-stream nil :type input))
                :invalid-stream-type)
               "connection open stream type errors redact caller input")
        (check (redacted-type-error-p
                (lambda () (cl-quic-kit::%quic-close-error-code input))
                :invalid-close-error-code)
               "close error code type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:make-stream 0 :local-initiator input))
                :invalid-stream-initiator)
               "stream initiator type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:make-stream 0 :flow-control input))
                :invalid-flow-control-state)
               "stream flow-control type errors redact caller input")
        (check (redacted-type-error-p
                (lambda () (cl-quic-kit::%udp-address input))
                :invalid-udp-address)
               "UDP address type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit.protection:reconstruct-packet-number 0 input -1))
                :invalid-packet-number-length)
               "packet number length type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit.recovery:recovery-space nil input))
                :invalid-recovery-space)
               "recovery space type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:make-quic-server
                   :max-connections input :max-handshakes 1))
                :invalid-max-connections)
               "max-connections type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:make-quic-server
                   :max-connections 1 :max-handshakes input))
                :invalid-max-handshakes)
               "max-handshakes type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:make-quic-server
                   :max-connections 1 :max-handshakes 1 :retry-policy input))
                :invalid-retry-policy)
               "retry policy type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:make-quic-server
                   :max-connections 1 :max-handshakes 1 :local-address input))
                :invalid-local-address)
               "local address type errors redact caller input")
        (check (redacted-type-error-p
                (lambda ()
                  (cl-quic-kit:make-quic-server
                   :max-connections 1 :max-handshakes 1 :local-port input))
                :invalid-local-port)
               "local port type errors redact caller input")
        (progn
          (check (redacted-type-error-p
                  (lambda ()
                    (cl-quic-kit:quic-server-shutdown nil :grace-period input))
                  :invalid-grace-period)
                 "shutdown grace period type errors redact caller input")
          (let ((result nil))
            (handler-bind ((type-error
                            (lambda (condition)
                              (when (eq (type-error-datum condition)
                                        :invalid-packet-number-length)
                                (invoke-restart
                                 (find-restart (quote store-value) condition)
                                 1)))))
              (setf result
                    (cl-quic-kit.protection:reconstruct-packet-number 0 input -1)))
            (check (eql result 0)
                   "redacted type checks retain the store-value restart"))))))
  (server-test-f7-secret-redaction))
  (server-test-server-close-send-failure-cleans-up))
#+linux (progn
  (defun server-test-server-close-completes-after-linux-syscall-error ()
    (let* ((socket
             (cl-quic-kit:make-udp-socket
              :local-host "127.0.0.1" :local-port 0))
           (server
             (cl-quic-kit:make-quic-server
              :udp-socket socket :max-connections 1 :retry-policy :never))
           (close-symbol (find-symbol "SOCKET-CLOSE" "SB-BSD-SOCKETS"))
           (original-close (symbol-function close-symbol))
           (close-attempts 0))
      (unwind-protect
           (progn
             (setf (symbol-function close-symbol)
                   (lambda (candidate-socket &key abort)
                     (if (eq candidate-socket
                             (cl-quic-kit::udp-socket-socket socket))
                         (progn
                           (incf close-attempts)
                           (funcall original-close candidate-socket :abort abort)
                           (sb-bsd-sockets:socket-error "close" 5))
                         (funcall original-close candidate-socket :abort abort))))
             (check
              (handler-case
                  (progn
                    (cl-quic-kit:quic-server-close server)
                    nil)
                (cl-quic-kit:quic-error () t))
              "server close reports a Linux close error")
             (check
              (and (cl-quic-kit::udp-socket-close-complete-p socket)
                   (= close-attempts 1))
              "Linux close error records the released descriptor")
             (let ((attempts-after-close close-attempts))
               (check
                (and (cl-quic-kit:quic-server-close server)
                     (= close-attempts attempts-after-close))
                "server close does not retry a released Linux descriptor")))
        (setf (symbol-function close-symbol) original-close)
        (unless (cl-quic-kit::udp-socket-close-complete-p socket)
          (ignore-errors (cl-quic-kit:quic-server-close server))))))
  (server-test-server-close-completes-after-linux-syscall-error))
