(in-package #:cl-quic-kit)

(defparameter *quic-server-retry-token-lifetime* 30)
(defparameter *quic-server-retry-token-retention* 60)
(defparameter *quic-server-retry-cache-limit* 4096)
(defparameter *quic-server-path-cache-limit* 4096)

(defstruct (quic-server (:constructor %make-quic-server))
  udp-socket max-connections retry-policy retry-tokens paths transport-parameters
  tls-server-options connections accepted-connections closed-p)

(defstruct (server-amplification-state
            (:constructor %make-server-amplification-state
                (&key (received 0) (sent 0) expires-at validated-p)))
  received sent expires-at validated-p)

(defstruct (server-retry-token
            (:constructor %make-server-retry-token
                (&key address original-destination-connection-id
                      retry-source-connection-id client-source-connection-id
                      expires-at retain-until
                      (used-p nil) (next-packet-number 0))))
  address original-destination-connection-id retry-source-connection-id
  client-source-connection-id expires-at retain-until used-p
  next-packet-number)

(defun %server-random-octets (length &optional (operation :retry-token))
  (let ((random (%client-function "CRYPTO-KIT" "RANDOM-OCTETS")))
    (unless random
      (error 'randomness-unavailable :operation operation))
    (handler-case
        (let ((value (funcall random length)))
          (unless (and (typep value '(simple-array (unsigned-byte 8) (*)))
                       (= (length value) length))
            (error 'randomness-unavailable :operation operation))
          value)
      (randomness-unavailable (condition)
        (error condition))
      (error ()
        (error 'randomness-unavailable :operation operation)))))

(defun make-quic-server (&key (local-address "0.0.0.0") (local-port 443)
                              udp-socket max-connections (retry-policy :always)
                              transport-parameters tls-server-options)
  "Bind a QUIC UDP listener. The server takes ownership of UDP-SOCKET when supplied."
  (check-type max-connections (integer 1 *))
  (check-type retry-policy (member :always :never))
  (unless udp-socket
    (check-type local-address string)
    (check-type local-port (integer 0 65535)))
  (when (and udp-socket (not (udp-socket-p udp-socket)))
    (error 'type-error :datum udp-socket :expected-type 'udp-socket))
  (let ((socket (or udp-socket
                    (make-udp-socket :local-host local-address
                                     :local-port local-port))))
    (%make-quic-server :udp-socket socket
                       :max-connections max-connections
                       :retry-policy retry-policy
                       :retry-tokens (make-hash-table :test #'equalp)
                       :paths (make-hash-table :test #'equalp)
                       :transport-parameters
                       (%server-normalize-transport-parameters transport-parameters)
                       :tls-server-options (%server-copy-plist tls-server-options)
                       :connections (make-hash-table :test #'equalp)
                       :accepted-connections nil
                       :closed-p nil)))

(defun %server-copy-address (address)
  (if (consp address) (copy-tree address)
      (if (vectorp address) (copy-seq address) address)))
(defun %server-long-header-fields (bytes)
  (let ((packet (%octet-vector bytes)))
    (unless (plusp (length packet))
      (%packet-error "Truncated packet header"))
    (let ((first (aref packet 0)))
      (unless (logbitp 7 first)
        (return-from %server-long-header-fields nil))
      (multiple-value-bind (version next)
          (%read-u32 packet 1)
        (when (zerop version)
          (return-from %server-long-header-fields
            (values first version nil nil)))
        (unless (< next (length packet))
          (%packet-error "Missing destination connection ID length"))
        (let ((destination-length (aref packet next)))
          (multiple-value-bind (destination-cid next-destination)
              (%packet-slice packet (1+ next) destination-length)
            (unless (< next-destination (length packet))
              (%packet-error "Missing source connection ID length"))
            (let ((source-length (aref packet next-destination)))
              (multiple-value-bind (source-cid next-source)
                  (%packet-slice packet (1+ next-destination) source-length)
                (declare (ignore next-source))
                (when (= version *quic-version-1*)
                  (validate-connection-id destination-cid)
                  (validate-connection-id source-cid))
                (values first version destination-cid source-cid)))))))))

(defun %server-path-key (address original-destination-connection-id)
  (list (%server-copy-address address)
        (octets-copy original-destination-connection-id)))

(defun %server-path-for-key (server key now create-p)
  (or (gethash key (quic-server-paths server))
      (when (and create-p
                 (< (hash-table-count (quic-server-paths server))
                    *quic-server-path-cache-limit*))
        (setf (gethash key (quic-server-paths server))
              (%make-server-amplification-state
               :expires-at (+ now *quic-server-retry-token-retention*))))))

(defun %server-path (server address original-destination-connection-id now
                     &optional create-p)
  (%server-path-for-key
   server (%server-path-key address original-destination-connection-id)
   now create-p))

(defun %server-note-received (path byte-count now)
  (when path
    (incf (server-amplification-state-received path) byte-count)
    (setf (server-amplification-state-expires-at
           path)
          (+ now *quic-server-retry-token-retention*)))
  path)

(defun %server-prune-expired-state (server now)
  (let ((expired-tokens nil)
        (expired-paths nil))
    (maphash (lambda (token record)
               (when (<= (server-retry-token-retain-until record) now)
                 (push token expired-tokens)))
             (quic-server-retry-tokens server))
    (dolist (token expired-tokens)
      (remhash token (quic-server-retry-tokens server)))
    (maphash (lambda (key path)
               (when (<= (server-amplification-state-expires-at path) now)
                 (push key expired-paths)))
             (quic-server-paths server))
    (dolist (key expired-paths)
      (remhash key (quic-server-paths server)))))

(defun %server-send-permitted-p (path byte-count)
  (and path
       (or (server-amplification-state-validated-p path)
           (<= (+ (server-amplification-state-sent path) byte-count)
               (* 3 (server-amplification-state-received path))))))

(defun %server-emit (server path address bytes &optional send-function)
  (unless (%server-send-permitted-p path (length bytes))
    (return-from %server-emit nil))
  (if send-function
      (funcall send-function (quic-server-udp-socket server) bytes address)
      (udp-send (quic-server-udp-socket server) bytes :address address))
  (incf (server-amplification-state-sent path) (length bytes))
  t)

(defun %server-new-token (server)
  (loop repeat 4
        for candidate = (%server-random-octets 32)
        unless (gethash candidate (quic-server-retry-tokens server))
          do (return candidate)
        finally (error 'randomness-unavailable :operation :retry-token)))

(defun %server-new-retry-source-connection-id (server forbidden-cid)
  (loop repeat 4
        for candidate = (%server-random-octets 8)
        unless (or (equalp candidate forbidden-cid)
                   (loop for record being the hash-values
                           of (quic-server-retry-tokens server)
                         thereis (equalp
                                 candidate
                                 (server-retry-token-retry-source-connection-id
                                  record))))
          do (return candidate)
        finally (error 'randomness-unavailable
                       :operation :retry-source-connection-id)))

(defun %server-retry-packet (header retry-source-cid token original-dcid)
  (let* ((destination-cid (packet-header-source-connection-id header))
         (base (make-packet-header
                :type :retry :version (packet-header-version header)
                :destination-connection-id destination-cid
                :source-connection-id retry-source-cid :token token
                :retry-integrity-tag (make-array 16
                                                 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)))
         (pseudo-wire (encode-packet-header base))
         (pseudo (subseq pseudo-wire 0 (- (length pseudo-wire) 16)))
         (tag (retry-integrity-tag
               pseudo :original-destination-connection-id original-dcid)))
    (encode-packet-header
     (make-packet-header
      :type :retry :version (packet-header-version header)
      :destination-connection-id destination-cid
      :source-connection-id retry-source-cid :token token
      :retry-integrity-tag tag))))

(defun %server-send-retry (server header path address now)
  (when (or (>= (hash-table-count (quic-server-retry-tokens server))
             *quic-server-retry-cache-limit*)
            (not path))
    (return-from %server-send-retry nil))
  (let* ((token (%server-new-token server))
         (retry-source-cid (%server-new-retry-source-connection-id
           server
           (packet-header-destination-connection-id header)))
         (original-dcid
           (packet-header-destination-connection-id header))
         (packet (%server-retry-packet
                  header retry-source-cid token original-dcid))
         (record (%make-server-retry-token
                  :address (%server-copy-address address)
                  :original-destination-connection-id (octets-copy original-dcid)
                  :retry-source-connection-id retry-source-cid
                  :client-source-connection-id
                  (octets-copy (packet-header-source-connection-id header))
                  :expires-at (+ now *quic-server-retry-token-lifetime*)
                  :retain-until (+ now *quic-server-retry-token-retention*))))
    (when (%server-emit server path address packet)
      (setf (gethash token (quic-server-retry-tokens server)) record)
      (setf (server-amplification-state-expires-at path)
            (server-retry-token-retain-until record))
      t)))

(defun %server-version-negotiation-packet (destination-cid source-cid)
  (let ((packet (encode-version-negotiation
                 source-cid destination-cid (list *quic-version-1*)))
        (random-byte (%server-random-octets 1)))
    (setf (aref packet 0) (logior #x80 (logand #x3f (aref random-byte 0))))
    packet))

(defun %server-send-version-negotiation
    (server destination-cid source-cid path address)
  (when path
    (%server-emit server path address
                  (%server-version-negotiation-packet
                   destination-cid source-cid))))

(defun %server-token-status (server token address destination-cid source-cid now)
  (multiple-value-bind (token-record token-found-p)
      (gethash token (quic-server-retry-tokens server))
    (let ((record
            (or token-record
                (loop for candidate being the hash-values
                        of (quic-server-retry-tokens server)
                      when (equalp
                            destination-cid
                            (server-retry-token-retry-source-connection-id
                             candidate))
                        return candidate))))
      (cond
        ((null record) (values :unknown nil))
        ((not token-found-p) (values :invalid-token record))
        ((>= now (server-retry-token-expires-at record))
         (values :expired record))
        ((not (equalp address (server-retry-token-address record)))
         (values :address-mismatch record))
        ((or (not (equalp
                   destination-cid
                   (server-retry-token-retry-source-connection-id record)))
             (not (equalp
                   source-cid
                   (server-retry-token-client-source-connection-id record))))
         (values :connection-id-mismatch record))
        (t (values :valid record))))))

(defun %server-protected-initial (key-destination-cid destination-cid source-cid packet-number frames)
  (let* ((plaintext (encode-frames frames))
         (keys (cl-quic-kit.protection:derive-initial-secrets key-destination-cid))
         (write-key (getf keys :server))
         (packet-number-length 1)
         (cipher-length (+ (length plaintext) 16))
         (header (make-packet-header
                  :type :initial :version *quic-version-1*
                  :destination-connection-id destination-cid
                  :source-connection-id source-cid :token #()
                  :packet-number packet-number
                  :packet-number-length packet-number-length
                  :payload (make-array cipher-length
                                       :element-type '(unsigned-byte 8))))
         (wire (encode-packet-header header))
         (prefix-length (- (length wire) cipher-length))
         (packet-number-offset (- prefix-length packet-number-length))
         (associated-data (subseq wire 0 prefix-length))
         (ciphertext (cl-quic-kit.protection:protect-payload
                      write-key packet-number plaintext associated-data))
         (packet (concatenate '(vector (unsigned-byte 8))
                              associated-data ciphertext))
         (sample (subseq packet (+ packet-number-offset 4)
                         (+ packet-number-offset 20))))
    (cl-quic-kit.protection:apply-header-protection
     write-key packet sample packet-number-offset packet-number-length t)))

(defun %server-send-invalid-token (server header record path address)
  (unless path
    (return-from %server-send-invalid-token nil))
  (let* ((packet-number (if record
                            (server-retry-token-next-packet-number record)
                            0))
         (source-cid (if record
                         (server-retry-token-retry-source-connection-id record)
                         (packet-header-destination-connection-id header))))
    (when (>= packet-number (ash 1 62))
      (return-from %server-send-invalid-token nil))
    (let ((packet
            (%server-protected-initial
             (packet-header-destination-connection-id header)
             (packet-header-source-connection-id header)
             source-cid packet-number
             (list (make-frame :connection-close :error-code #x0b
                               :frame-type 0 :reason #())))))
      (when (%server-emit server path address packet)
        (when record
          (incf (server-retry-token-next-packet-number record)))
        t))))

(defun %server-handle-initial (server header path address now bytes)
  (let ((token (packet-header-token header))
        (destination-cid (packet-header-destination-connection-id header))
        (source-cid (packet-header-source-connection-id header)))
    (multiple-value-bind (status record)
        (%server-token-status server token address destination-cid source-cid now)
      (cond
        ((eq status :unknown)
         (cond
           ((eq (quic-server-retry-policy server) :always)
            (%server-send-retry server header path address now))
           ((zerop (length token))
            (%server-start-or-feed-initial server header path address nil bytes now))
           (t
            (%server-send-invalid-token server header nil path address))))
        ((eq status :valid)
         (when path
           (setf (server-amplification-state-validated-p path) t
                 (server-retry-token-used-p record) t))
         (%server-start-or-feed-initial server header path address record bytes now))
        (t
         (%server-send-invalid-token
          server header record path address))))))

(defun %server-handle-datagram (server bytes address byte-count now)
  (handler-case
      (labels ((route-existing ()
                 (let* ((layout (%client-layout
                                 bytes :short-header-dcid-length 8))
                        (server-connection
                          (gethash (getf layout :dcid)
                                   (quic-server-connections server))))
                   (when (and server-connection
                              (member (getf layout :type)
                                      '(:0-rtt :handshake :short))
                              (equalp address
                                      (server-connection-address
                                       server-connection)))
                     (%server-note-received
                      (server-connection-path server-connection)
                      byte-count now)
                     (%server-process-protected-datagram server-connection bytes now)))))
        (multiple-value-bind (first version destination-cid source-cid)
            (%server-long-header-fields bytes)
          (cond
            ((null first)
             (route-existing))
            ((zerop version)
             nil)
            ((/= version *quic-version-1*)
             (let ((path (%server-path
                          server address destination-cid now t)))
               (%server-note-received path byte-count now)
               (when (>= byte-count 1200)
                 (%server-send-version-negotiation
                  server destination-cid source-cid path address))))
            ((zerop (ldb (byte 2 4) first))
             (let* ((record
                      (loop for candidate being the hash-values
                              of (quic-server-retry-tokens server)
                            when (equalp
                                  destination-cid
                                  (server-retry-token-retry-source-connection-id
                                   candidate))
                              return candidate))
                    (original-dcid
                      (if record
                          (server-retry-token-original-destination-connection-id
                           record)
                          destination-cid))
                    (path (%server-path
                           server address original-dcid now t)))
               (%server-note-received path byte-count now)
               (when (>= byte-count 1200)
                 (multiple-value-bind (header end)
                     (decode-packet-header bytes)
                   (declare (ignore end))
                   (when (eq (packet-header-type header) :initial)
                     (%server-handle-initial
                      server header path address now bytes))))))
            (t
             (route-existing)))))
    (quic-encoding-error () nil)
    (invalid-connection-id () nil)))

(defun quic-server-poll (server &optional at)
  "Process available UDP datagrams and return true when SERVER is closed."
  (when (quic-server-closed-p server)
    (return-from quic-server-poll t))
  (let ((now (or at (%quic-real-time))))
    (%server-prune-expired-state server now)
    (loop
      (multiple-value-bind (bytes byte-count address)
          (udp-receive (quic-server-udp-socket server))
        (unless bytes
          (return))
        (%server-handle-datagram server bytes address byte-count now)))
    (%server-poll-connections server now))
  nil)

(defun quic-server-close (server)
  "Close SERVER and its owned UDP socket. Repeated calls are harmless."
  (unless (quic-server-closed-p server)
    (setf (quic-server-closed-p server) t)
    (maphash
     (lambda (connection-id server-connection)
       (declare (ignore connection-id))
       (connection-set-state
        (server-connection-connection server-connection) :closed))
     (quic-server-connections server))
    (clrhash (quic-server-connections server))
    (setf (quic-server-accepted-connections server) nil)
    (clrhash (quic-server-retry-tokens server))
    (clrhash (quic-server-paths server))
    (udp-close (quic-server-udp-socket server)))
  t)
(defstruct (server-connection
            (:constructor %make-server-connection))
  server connection engine tls-boundary tls-driver path address now
  original-destination-connection-id local-connection-id
  remote-connection-id cipher-suite transport-parameters
  peer-transport-parameters pending-datagrams
  (handshake-complete-p nil) (accepted-p nil))
(defun %server-new-connection-id (server forbidden-cid)
  (loop repeat 4
        for candidate = (%server-random-octets 8 :connection-id)
        unless (or (equalp candidate forbidden-cid)
                   (nth-value 1
                              (gethash candidate
                                       (quic-server-connections server)))
                   (loop for active being the hash-values
                           of (quic-server-connections server)
                         thereis (equalp
                                 candidate
                                 (server-connection-original-destination-connection-id
                                  active)))
                   (loop for record being the hash-values
                           of (quic-server-retry-tokens server)
                         thereis (equalp
                                 candidate
                                 (server-retry-token-retry-source-connection-id
                                  record))))
          do (return candidate)
        finally (error 'randomness-unavailable :operation :connection-id)))
(defun %server-copy-plist (plist)
  (let ((length (and (listp plist) (list-length plist)))
        (keys nil))
    (unless (and (or (null plist) length) (evenp (or length 0)))
      (error 'type-error :datum plist :expected-type 'list))
    (loop for tail on plist by #'cddr
          for key = (car tail)
          do (unless (keywordp key)
               (error 'type-error :datum key :expected-type 'keyword))
             (when (member key keys)
               (error 'quic-error :message "Duplicate server option"))
             (push key keys))
    (copy-list plist)))
(defun %server-normalize-transport-parameters (parameters)
  (let* ((options (%server-copy-plist parameters))
         (defaults '((:initial-max-data 1048576)
                     (:initial-max-stream-data-bidi-local 65536)
                     (:initial-max-stream-data-bidi-remote 65536)
                     (:initial-max-stream-data-uni 65536)
                     (:initial-max-streams-bidi 25)
                     (:initial-max-streams-uni 25))))
    (loop for tail on options by #'cddr
          for key = (car tail)
          unless (assoc key defaults)
            do (error 'quic-error :message "Unknown server transport parameter"))
    (loop with normalized = nil
          for (key default) in defaults
          for value = (getf options key default)
          do (unless (varint-p value)
               (error 'quic-error
                      :message "Invalid server transport parameter value"))
             (setf normalized (append normalized (list key value)))
          finally (return normalized))))
(defun %server-local-transport-parameters
    (server original-cid local-cid retry-cid)
  (let ((parameters (quic-server-transport-parameters server)))
    (encode-transport-parameters
     (append
      (when retry-cid
        (list (cons 0 (octets-copy original-cid))))
      (list (cons 1 30000)
            (cons 3 65527)
            (cons 4 (getf parameters :initial-max-data))
            (cons 5 (getf parameters :initial-max-stream-data-bidi-local))
            (cons 6 (getf parameters :initial-max-stream-data-bidi-remote))
            (cons 7 (getf parameters :initial-max-stream-data-uni))
            (cons 8 (getf parameters :initial-max-streams-bidi))
            (cons 9 (getf parameters :initial-max-streams-uni))
            (cons 10 3)
            (cons 11 25)
            (cons 14 2)
            (cons 15 (octets-copy local-cid)))
      (when retry-cid
        (list (cons 16 (octets-copy retry-cid))))))))
(defun %server-driver-options (server transport-parameters)
  (let* ((options (%server-copy-plist (quic-server-tls-server-options server)))
         (constructor (%client-function "CL-TLS-KIT"
                                        "MAKE-TLS13-SERVER-DRIVER"))
         (provider-constructor (%client-function "CL-TLS-KIT"
                                                 "MAKE-CL-CRYPTO-KIT-PROVIDER"))
         (cipher-suites (getf options :cipher-suites
                              #(#x1301 #x1302 #x1303))))
    (unless constructor
      (error 'crypto-unavailable :operation :tls13-server-driver))
    (unless (getf options :provider)
      (unless provider-constructor
        (error 'crypto-unavailable :operation :tls-provider))
      (setf (getf options :provider) (funcall provider-constructor)))
    (unless (member :alpn-protocols options)
      (setf options (append options (list :alpn-protocols '("h3")))))
    (unless (and (typep cipher-suites '(or list vector))
                 (plusp (length cipher-suites))
                 (every (lambda (suite)
                          (member suite '(#x1301 #x1302 #x1303)))
                        cipher-suites))
      (error 'quic-error :message "TLS cipher suite is not QUIC-compatible"))
    (setf (getf options :cipher-suites) cipher-suites
          (getf options :quic-transport-parameters) transport-parameters)
    options))
(defun %server-suite-cipher (suite)
  (case suite
    (#x1301 :aes-128-gcm)
    (#x1302 :aes-256-gcm)
    (#x1303 :chacha20-poly1305)
    (otherwise
     (error 'quic-error :message "Unsupported QUIC TLS cipher suite"))))
(defun %server-install-secret (server-connection level direction secret)
  (let* ((tls-level (%client-level-space level))
         (wire-level (%client-space-level tls-level))
         (engine (server-connection-engine server-connection))
         (boundary (server-connection-tls-boundary server-connection))
         (emit (%client-function "CL-TLS-KIT"
                                 "QUIC-TLS-BOUNDARY-EMIT-SECRET"))
         (key (cl-quic-kit.protection:make-key-set
               secret
               :cipher (%server-suite-cipher
                        (server-connection-cipher-suite server-connection)))))
    (%client-set-key engine wire-level direction key)
    (when (eq wire-level :1-rtt)
      (if (eq direction :read)
          (setf (quic-client-application-read-secret engine) secret)
          (setf (quic-client-application-write-secret engine) secret)))
    (when emit
      (funcall emit boundary tls-level direction secret)))
  server-connection)
(defun %server-queue-crypto (server-connection level wire)
  (let* ((engine (server-connection-engine server-connection))
         (offset (or (%client-level-value
                      (quic-client-crypto-send-offsets engine) level)
                     0)))
    (setf (quic-client-crypto-send-offsets engine)
          (%client-set-level-value
           (quic-client-crypto-send-offsets engine) level
           (+ offset (length wire))))
    (%client-queue-frame engine
                         (make-frame :crypto :offset offset :data wire)
                         level)
    (client-flush engine)))
(defun %server-engine-write (server-connection bytes)
  (unless (%server-emit
           (server-connection-server server-connection)
           (server-connection-path server-connection)
           (server-connection-address server-connection)
           bytes)
    (setf (server-connection-pending-datagrams server-connection)
          (nconc (server-connection-pending-datagrams server-connection)
                 (list bytes))))
  bytes)
(defun %server-complete-connection (server-connection)
  (unless (server-connection-handshake-complete-p server-connection)
    (let ((peer-bytes
           (server-connection-peer-transport-parameters server-connection)))
      (unless peer-bytes
        (error 'quic-error :message "TLS completed without peer transport parameters"))
      (let* ((peer-parameters
              (handler-case
                  (let ((parameters
                         (decode-transport-parameters
                          peer-bytes :sender-role :client)))
                    (let ((source-cid (assoc 15 parameters)))
                      (unless (and source-cid
                                   (equalp
                                    (cdr source-cid)
                                    (server-connection-remote-connection-id
                                     server-connection)))
                        (%packet-error
                         "Client initial_source_connection_id does not match the Initial source connection ID")))
                    parameters)
                (quic-encoding-error (condition)
                                     (let* ((connection
                                             (server-connection-connection server-connection))
                                            (engine (server-connection-engine server-connection))
                                            (frame
                                             (%connection-prepare-close
                                              connection :transport-parameter-error
                                              (quic-error-message condition))))
                                       (when frame
                                         (setf (quic-client-closed-p engine) t)
                                         (%client-queue-frame
                                          engine frame
                                          (if (%client-key engine :1-rtt :write) :1-rtt :initial))
                                         (client-flush engine)))
                                     (return-from %server-complete-connection server-connection))))
             (connection (server-connection-connection server-connection))
             (local-idle-timeout (quic-connection-idle-timeout connection))
             (peer-idle-timeout (cdr (assoc 1 peer-parameters))))
        (setf (quic-client-peer-transport-parameters
               (server-connection-engine server-connection))
              peer-parameters
              (quic-connection-idle-timeout connection)
              (if (and peer-idle-timeout (plusp peer-idle-timeout))
                  (min local-idle-timeout (/ peer-idle-timeout 1000))
                local-idle-timeout)
              (server-amplification-state-validated-p
               (server-connection-path server-connection))
              t))
      (connection-set-state (server-connection-connection server-connection)
                            :established)
      (setf (server-connection-handshake-complete-p server-connection) t)
      (unless (server-connection-accepted-p server-connection)
        (setf (server-connection-accepted-p server-connection) t
              (quic-server-accepted-connections
               (server-connection-server server-connection))
              (nconc (quic-server-accepted-connections
                      (server-connection-server server-connection))
                     (list (server-connection-connection
                            server-connection)))))
      (%client-queue-frame
       (server-connection-engine server-connection)
       (make-frame :handshake-done) :application)
      (client-flush (server-connection-engine server-connection))))
  server-connection)
(defun %server-handle-tls-events (server-connection events)
  (dolist (event events)
    (if (and (consp event)
             (eq (first event) :peer-quic-transport-parameters))
        (setf (server-connection-peer-transport-parameters server-connection)
              (octets-copy (second event)))
        (case (getf event :type)
          (:cipher-suite
           (let ((suite (getf event :suite))
                 (emit (%client-function
                        "CL-TLS-KIT"
                        "QUIC-TLS-BOUNDARY-EMIT-CIPHER-SUITE")))
             (when emit
               (funcall emit (server-connection-tls-boundary server-connection)
                        suite))
             (setf (server-connection-cipher-suite server-connection) suite)))
          (:send
           (%server-queue-crypto server-connection
                                 (getf event :level)
                                 (getf event :wire)))
          (:secret
           (%server-install-secret server-connection
                                   (getf event :level)
                                   (getf event :direction)
                                   (getf event :secret)))
          (:alpn
           (let* ((protocol (getf event :protocol))
                  (emit (%client-function
                         "CL-TLS-KIT" "QUIC-TLS-BOUNDARY-EMIT-ALPN")))
             (when emit
               (funcall emit
                        (server-connection-tls-boundary server-connection)
                        protocol))
             (setf (quic-connection-alpn
                    (server-connection-connection server-connection))
                   (and protocol (copy-seq protocol)))))
          (:ticket-issued nil)
          (:alert
           (error 'quic-error :message "TLS server driver returned an alert"))
          (:handshake-complete
           (%server-complete-connection server-connection))
          (otherwise
           (error 'quic-error :message "Unknown TLS server driver event")))))
  server-connection)
(defun %server-feed-crypto (server-connection level offset bytes)
  (let* ((tls-level (%client-level-space level))
         (boundary (server-connection-tls-boundary server-connection))
         (feed (%client-function "CL-TLS-KIT"
                                 "QUIC-TLS-BOUNDARY-FEED-CRYPTO"))
         (step (%client-function "CL-TLS-KIT"
                                 "TLS13-SERVER-DRIVER-STEP")))
    (unless (and feed step)
      (error 'crypto-unavailable :operation :tls13-server-driver))
    (dolist (message
              (funcall feed boundary tls-level offset bytes))
      (multiple-value-bind (driver events)
          (funcall step (server-connection-tls-driver server-connection)
                   (getf message :wire) :level tls-level)
        (setf (server-connection-tls-driver server-connection) driver)
        (%server-handle-tls-events server-connection events))))
  server-connection)
(defun %server-create-connection (server header path address record now)
  (let* ((original-cid
           (if record
               (server-retry-token-original-destination-connection-id record)
               (packet-header-destination-connection-id header)))
         (retry-cid
           (and record
                (server-retry-token-retry-source-connection-id record)))
         (local-cid
           (or retry-cid
               (%server-new-connection-id server original-cid)))
         (remote-cid (packet-header-source-connection-id header))
         (transport-parameters
           (%server-local-transport-parameters
            server original-cid local-cid retry-cid))
         (boundary-constructor
           (%client-function "CL-TLS-KIT" "MAKE-QUIC-TLS-BOUNDARY"))
         (driver-constructor
           (%client-function "CL-TLS-KIT" "MAKE-TLS13-SERVER-DRIVER"))
         (server-connection
           (%make-server-connection
            :server server :path path :address (%server-copy-address address)
            :now now
            :original-destination-connection-id (octets-copy original-cid)
            :local-connection-id (octets-copy local-cid)
            :remote-connection-id (octets-copy remote-cid)
            :transport-parameters transport-parameters
            :pending-datagrams nil)))
    (unless (and boundary-constructor driver-constructor)
      (error 'crypto-unavailable :operation :tls13-server-driver))
    (setf (server-connection-connection server-connection)
          (make-quic-connection
           :role :server :local-connection-id local-cid
           :now-fn (lambda () (server-connection-now server-connection))
           :io-write
           (lambda (connection bytes)
             (declare (ignore connection))
             (%server-engine-write server-connection bytes))))
    (setf (server-connection-engine server-connection)
          (make-quic-client
           :connection (server-connection-connection server-connection)
           :now-fn (lambda () (server-connection-now server-connection))
           :local-connection-id local-cid
           :destination-connection-id remote-cid
           :disable-hostname-verification-p t
           :transport-parameters transport-parameters))
    (let ((initial
            (cl-quic-kit.protection:derive-initial-secrets
             (packet-header-destination-connection-id header))))
      (%client-set-key (server-connection-engine server-connection)
                       :initial :read (getf initial :client))
      (%client-set-key (server-connection-engine server-connection)
                       :initial :write (getf initial :server)))
    (setf (server-connection-tls-boundary server-connection)
          (funcall boundary-constructor
                   :role :server
                   :transport-parameters transport-parameters
                   :hash-function
                   (lambda (bytes)
                     (let ((digest (%client-function "CRYPTO-KIT" "DIGEST")))
                       (unless digest
                         (error 'crypto-unavailable :operation :digest))
                       (funcall digest
                                (if (= (or (server-connection-cipher-suite
                                            server-connection)
                                           #x1301)
                                       #x1302)
                                    :sha384 :sha256)
                                bytes)))
                   :on-transport-parameters
                   (lambda (boundary parameters)
                     (declare (ignore boundary))
                     (setf (server-connection-peer-transport-parameters
                            server-connection)
                           (octets-copy parameters)))))
    (setf (server-connection-tls-driver server-connection)
          (apply driver-constructor
                 (%server-driver-options server transport-parameters)))
    (setf (gethash local-cid (quic-server-connections server))
          server-connection)
    server-connection))
(defun %server-find-initial-connection (server destination-cid source-cid)
  (or (gethash destination-cid (quic-server-connections server))
      (loop for server-connection being the hash-values
              of (quic-server-connections server)
            when (and
                  (equalp destination-cid
                          (server-connection-original-destination-connection-id
                           server-connection))
                  (equalp source-cid
                          (server-connection-remote-connection-id
                           server-connection)))
              return server-connection)))
(defun %server-start-or-feed-initial
    (server header path address record bytes now)
  (let ((server-connection
          (or (%server-find-initial-connection
               server
               (packet-header-destination-connection-id header)
               (packet-header-source-connection-id header))
              (when (< (hash-table-count (quic-server-connections server))
                       (quic-server-max-connections server))
                (%server-create-connection server header path address record now)))))
    (when server-connection
      (%server-process-protected-datagram server-connection bytes now)))
  server)
(defun %server-process-protected-datagram (server-connection bytes now)
  (setf (server-connection-now server-connection) now)
  (let ((engine (server-connection-engine server-connection))
        (at 0))
    (loop while (< at (length bytes)) do
      (let* ((slice (subseq bytes at))
             (layout (%client-layout
                      slice
                      :short-header-dcid-length
                      (length (server-connection-local-connection-id
                               server-connection))))
             (type (getf layout :type)))
        (unless (eq type :0-rtt)
          (multiple-value-bind (level number header)
              (handler-case
                  (%client-unprotect-packet engine slice layout)
                (crypto-kit:aead-authentication-failure ()
                  (values nil nil nil)))
            (when header
              (let* ((frames (decode-frames (packet-header-payload header)))
                     (space (%client-level-space level)))
                (setf (quic-client-received-packets engine)
                      (%client-set-level-value
                       (quic-client-received-packets engine) level
                       (cons number
                             (%client-level-value
                              (quic-client-received-packets engine) level))))
                (cl-quic-kit.recovery:on-packet-received
                 (quic-client-recovery engine) space number
                 :ack-eliciting-p (%client-ack-eliciting-p frames))
                (dolist (frame frames)
                  (case (frame-type frame)
                    (:crypto
                     (%server-feed-crypto
                      server-connection level
                      (frame-field frame :offset 0)
                      (frame-field frame :data #())))
                    ((:ack :ack-ecn)
                     (%client-handle-ack engine level frame))
                    ((:connection-close :application-close)
                     (connection-receive-frame
                      (server-connection-connection server-connection) frame
                      :touch-p nil))))
                (connection-touch
                 (server-connection-connection server-connection) now)))))
        (setf at (+ at (getf layout :end)))
        (when (not (getf layout :long-p))
          (return))))
  server-connection))
(defun %server-flush-pending-datagrams (server-connection)
  (let ((remaining (server-connection-pending-datagrams server-connection)))
    (loop while remaining do
      (if (%server-emit
           (server-connection-server server-connection)
           (server-connection-path server-connection)
           (server-connection-address server-connection)
           (first remaining))
          (setf remaining (rest remaining))
          (return)))
    (setf (server-connection-pending-datagrams server-connection) remaining))
  server-connection)
(defun %server-poll-connections (server now)
  (maphash
   (lambda (connection-id server-connection)
     (declare (ignore connection-id))
     (setf (server-connection-now server-connection) now)
     (%server-flush-pending-datagrams server-connection)
     (client-poll (server-connection-engine server-connection) now)
     (%server-flush-pending-datagrams server-connection))
   (quic-server-connections server))
  server)
(defun quic-server-accept-connection (server)
  "Return the next completed connection, or NIL when none is available."
  (pop (quic-server-accepted-connections server)))
