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

(defun server-test-receive (socket)
  (loop repeat 1000
        for bytes = (cl-quic-kit:udp-receive socket)
        when bytes
          return bytes
        do (sleep 0.001)
        finally (error "Timed out waiting for a UDP datagram")))

(defun server-test-poll-until (server predicate)
  (loop repeat 1000
        do (cl-quic-kit:quic-server-poll server)
        when (funcall predicate)
          return t
        do (sleep 0.001)
        finally (error "Timed out waiting for server activity")))
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
       (let ((first-path
               (cl-quic-kit::%server-path server :first first-cid 0 t))
             (second-path
               (cl-quic-kit::%server-path server :second second-cid 0 t)))
         (and first-path
              (null second-path)
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
            (cl-quic-kit:quic-server-poll server 2)
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
           :retry-tokens (make-hash-table :test #'equalp)))
        (forbidden #(1 2 3 4 5 6 7 8))
        (expected #(9 10 11 12 13 14 15 16))
        (calls 0)
        (original (symbol-function
                   'cl-quic-kit::%server-random-octets)))
   (unwind-protect
        (progn
          (setf (symbol-function 'cl-quic-kit::%server-random-octets)
                (lambda (length)
                  (declare (ignore length))
                  (incf calls)
                  (if (= calls 1) forbidden expected)))
          (and (equalp
                (cl-quic-kit::%server-new-retry-source-connection-id
                 server forbidden)
                expected)
               (= calls 2)))
     (setf (symbol-function 'cl-quic-kit::%server-random-octets)
           original)))
 "Retry source CID generation retries a collision with its Initial destination CID")
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
                  "Retry tokens expire at their finite lifetime")))
    (cl-quic-kit:client-close client)
    (cl-quic-kit:quic-server-close server)))

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
          (cl-quic-kit:udp-send peer (subseq packet 0 header-length)))
        (cl-quic-kit:quic-server-poll server)
        (multiple-value-bind (response length address)
            (cl-quic-kit:udp-receive peer)
          (declare (ignore length address))
          (check (null response)
                 "server drops a malformed Initial without replying"))
        (progn
          (cl-quic-kit:udp-send
           peer (server-test-initial-packet cl-quic-kit:*quic-version-1*
                                            destination-cid source-cid #() 1199))
          (let ((expected (+ 1199 7 (length destination-cid)
                             (length source-cid))))
            (server-test-poll-until
             server
             (lambda ()
               (loop for path being the hash-values of
                     (cl-quic-kit::quic-server-paths server)
                     thereis
                       (= (cl-quic-kit::server-amplification-state-received
                           path)
                          expected)))))
          (multiple-value-bind (response length address)
              (cl-quic-kit:udp-receive peer)
            (declare (ignore length address))
            (check (null response)
                   "server drops a 1199-byte Initial without replying"))
          (let ((path (loop for path being the hash-values of
                               (cl-quic-kit::quic-server-paths server)
                             return path))
                  (expected (+ 1199 7 (length destination-cid)
                               (length source-cid))))
              (check (and path
                          (= (cl-quic-kit::server-amplification-state-received
                              path)
                             expected))
                     "server counts malformed Initial bytes before dropping an undersized Initial"))
          (let* ((path (loop for path being the hash-values of
                               (cl-quic-kit::quic-server-paths server)
                             return path))
                  (received-before
                    (cl-quic-kit::server-amplification-state-received path)))
            (cl-quic-kit:udp-send
             peer (server-test-initial-packet
                   #xfaceb00c destination-cid source-cid #() 1199))
            (server-test-poll-until
             server
             (lambda ()
               (> (cl-quic-kit::server-amplification-state-received path)
                  received-before)))
            (multiple-value-bind (response length address)
                (cl-quic-kit:udp-receive peer)
              (declare (ignore length address))
              (check (null response)
                     "server drops an unknown-version 1199-byte Initial without Version Negotiation"))
            (cl-quic-kit:udp-send
             peer (server-test-initial-packet
                   #xfaceb00c destination-cid source-cid))))
        (server-test-poll-until
         server
         (lambda ()
           (loop for path being the hash-values of
                 (cl-quic-kit::quic-server-paths server)
                 thereis (plusp
                          (cl-quic-kit::server-amplification-state-sent
                           path)))))
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
            (check (and negotiation
                        (equalp (getf negotiation :source-connection-id)
                                destination-cid))
                   "Version Negotiation echoes the Initial destination connection ID")
            (let* ((path (loop for path being the hash-values of
                               (cl-quic-kit::quic-server-paths server)
                             return path))
                   (sent-before
                     (cl-quic-kit::server-amplification-state-sent path))
                   (retry-packet
                     (let ((packet
                      (cl-quic-kit:encode-packet-header
                       (cl-quic-kit:make-packet-header
                        :type :retry :version #xfaceb00c
                        :destination-connection-id destination-cid
                        :source-connection-id source-cid
                        :token (make-array
                                (- 1200 (+ 7 (length destination-cid)
                                           (length source-cid) 16))
                                :element-type '(unsigned-byte 8)
                                :initial-element 0)
                        :retry-integrity-tag
                        (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-element 0)))))
                 (setf (aref packet 0) (logand #xbf (aref packet 0)))
                 packet)))
              (check (= (length retry-packet) 1200)
                     "unsupported-version Retry fixture meets the 1200-byte minimum")
              (check (and (= (ldb (byte 2 4) (aref retry-packet 0)) 3)
               (not (logbitp 6 (aref retry-packet 0))))
          "unsupported-version fixture has Retry type bits and clears bit 6")
              (cl-quic-kit:udp-send peer retry-packet)
              (server-test-poll-until
               server
               (lambda ()
                 (> (cl-quic-kit::server-amplification-state-sent path)
                    sent-before)))
              (multiple-value-bind (response length address)
                  (server-test-receive peer)
                (declare (ignore length address))
                (let ((negotiation
                        (and response
                             (cl-quic-kit:decode-version-negotiation response))))
                  (check (and negotiation
                              (member cl-quic-kit:*quic-version-1*
                                      (getf negotiation :versions)))
                         "server negotiates for an unsupported version with Retry type bits")
                  (progn
                    (check (and negotiation
                                (equalp
                                 (getf negotiation :destination-connection-id)
                                 source-cid)
                                (equalp
                                 (getf negotiation :source-connection-id)
                                 destination-cid))
                           "unknown-version Version Negotiation echoes both connection IDs")
                    (let* ((wide-dcid
                             (make-array 24 :element-type '(unsigned-byte 8)
                                            :initial-element #xa1))
                           (wide-scid
                             (make-array 24 :element-type '(unsigned-byte 8)
                                            :initial-element #xb2))
                           (packet
                             (concatenate
                              '(vector (unsigned-byte 8))
                              (vector #xb0 #xfa #xce #xb0 #x0c
                                      (length wide-dcid))
                              wide-dcid
                              (vector (length wide-scid))
                              wide-scid
                              (make-array
                               (- 1200 (+ 7 (length wide-dcid)
                                          (length wide-scid)))
                               :element-type '(unsigned-byte 8)
                               :initial-element 0))))
                      (check (= (length packet) 1200)
                             "unknown-version long-CID fixture meets the 1200-byte minimum")
                      (cl-quic-kit:udp-send peer packet)
                      (server-test-poll-until
                       server
                       (lambda ()
                         (loop
                               for key being the hash-keys
                                 of (cl-quic-kit::quic-server-paths server)
                               using (hash-value path)
                               thereis
                                 (and (equalp (second key) wide-dcid)
                                      (plusp
                                       (cl-quic-kit::server-amplification-state-sent path))))))
                      (multiple-value-bind (response length address)
                          (server-test-receive peer)
                        (declare (ignore length address))
                        (let ((wide-negotiation
                                (and response
                                     (cl-quic-kit:decode-version-negotiation
                                      response))))
                          (progn
                              (check (and wide-negotiation
                                          (equalp
                                           (getf wide-negotiation
                                                 :destination-connection-id)
                                           wide-scid)
                                          (equalp
                                           (getf wide-negotiation
                                                 :source-connection-id)
                                           wide-dcid))
                                     "Version Negotiation accepts and echoes 24-octet connection IDs")
                              (let ((received-before
                                     (loop for path being the hash-values
                                           of (cl-quic-kit::quic-server-paths server)
                                           sum (cl-quic-kit::server-amplification-state-received path))))
                                (cl-quic-kit:udp-send
                                 peer
                                 (cl-quic-kit:encode-version-negotiation
                                  source-cid destination-cid
                                  (list cl-quic-kit:*quic-version-1*)))
                                (cl-quic-kit:udp-send
                                 peer
                                 (server-test-initial-packet
                                  #xfaceb00c destination-cid source-cid #() 1199))
                                (server-test-poll-until
                                 server
                                 (lambda ()
                                   (> (loop for path being the hash-values
                                              of (cl-quic-kit::quic-server-paths server)
                                            sum (cl-quic-kit::server-amplification-state-received path))
                                      received-before))))
                              (cl-quic-kit:quic-server-poll server)
                              (multiple-value-bind (response length address)
                                  (cl-quic-kit:udp-receive peer)
                                (declare (ignore length address))
                                (check (null response)
                                       "server sends no response to a received Version Negotiation packet")))))))))))))
    (cl-quic-kit:udp-close peer)
    (cl-quic-kit:quic-server-close server)))
(progn
  (defun server-test-issue-retry (server client)
    (cl-quic-kit:client-poll client 0)
    (server-test-poll-until
     server
     (lambda ()
       (plusp
        (hash-table-count
         (cl-quic-kit::quic-server-retry-tokens server)))))
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

  (let* ((server-socket
          (cl-quic-kit:make-udp-socket :local-host "127.0.0.1" :local-port 0))
         (server (cl-quic-kit:make-quic-server
                  :udp-socket server-socket :max-connections 1
                  :retry-policy :never))
         (client (cl-quic-kit:make-quic-client
                  :server-host "127.0.0.1"
                  :server-port (cl-quic-kit:udp-socket-local-port server-socket)
                  :hostname "localhost" :now-fn (lambda () 0))))
    (unwind-protect
        (progn
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
          (check (loop for path being the hash-values
                       of (cl-quic-kit::quic-server-paths server)
                       thereis (>=
                                (cl-quic-kit::server-amplification-state-received
                                 path)
                                1200))
                 "client Initial reaches the listener at the 1200-byte minimum")
          (multiple-value-bind (response length address)
              (cl-quic-kit:udp-receive
               (cl-quic-kit::quic-client-udp-socket client))
            (declare (ignore length address))
            (check (null response)
                   "retry-policy never sends no Retry for a valid 1200-byte Initial"))
          (check (zerop
                  (hash-table-count
                   (cl-quic-kit::quic-server-retry-tokens server)))
                 "retry-policy never records no Retry token"))
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
                     "a corrupted token for an issued Retry SCID receives a protected Initial")
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
                     "a corrupted token for an issued Retry SCID does not trigger a second Retry"))))
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
          (cl-quic-kit:client-poll client 0)
          (server-test-poll-until
           server
           (lambda ()
             (cl-quic-kit::server-retry-token-used-p record)))
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
            (server-test-poll-until
             server
             (lambda ()
               (>= (cl-quic-kit::server-amplification-state-received path)
                   (+ received-before (length duplicate)))))
            (multiple-value-bind (response length address)
                (cl-quic-kit:udp-receive
                 (cl-quic-kit::quic-client-udp-socket client))
              (declare (ignore length address))
              (check (null response)
                     "a repeated same-tuple Retry token Initial receives no close or second Retry")
              (check (not (cl-quic-kit:quic-client-closed-p client))
                     "a repeated same-tuple Retry token remains acceptable"))))
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
          (declare (ignore token record))
          (clrhash (cl-quic-kit::quic-server-retry-tokens server))
          (cl-quic-kit:client-poll client 0)
          (cl-quic-kit:quic-server-poll server)
          (multiple-value-bind (response length address)
              (cl-quic-kit:udp-receive
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
