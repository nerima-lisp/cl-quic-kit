(in-package #:cl-quic-kit)

(defparameter *quic-server-retry-token-lifetime* 30)
(defparameter *quic-server-retry-token-retention* 60)
(defparameter *quic-server-retry-cache-limit* 4096)
(defparameter *quic-server-path-cache-limit* 4096)
(defun %server-valid-handshake-timeout-p (value)
  (and (realp value)
       (or (not (floatp value))
           (handler-case
               (<= (- most-positive-long-float)
                   value
                   most-positive-long-float)
             (arithmetic-error () nil)))
       (plusp value)))
(defun %server-exact-real (value)
  (if (floatp value)
      (rational value)
      value))

(defstruct (quic-server (:constructor %make-quic-server))
  udp-socket (udp-receive-packet-budget 64)
  max-connections max-handshakes handshake-timeout retry-policy retry-tokens
  (retired-retry-cids (make-hash-table :test #'equalp))
  (retired-local-cids (make-hash-table :test #'equalp))
  paths transport-parameters tls-server-options connections accepted-connections
  (shutdown-deadline nil) (shutdown-error-code :no-error) (shutdown-reason #())
  closed-p)
(defmethod print-object ((server quic-server) stream)
  (print-unreadable-object (server stream :type t)
    (write-string "redacted" stream)))

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
(defmethod print-object ((token server-retry-token) stream)
  (print-unreadable-object (token stream :type t)
    (write-string "redacted" stream)))

(defun %server-random-octets (length &optional (operation :retry-token))
  (handler-case
      (let ((value (crypto-kit:random-octets length)))
        (unless (and (typep value '(simple-array (unsigned-byte 8) (*)))
                     (= (length value) length))
          (error 'randomness-unavailable :operation operation))
        value)
    (randomness-unavailable (condition)
      (error condition))
    (error ()
      (error 'randomness-unavailable :operation operation))))

(defun make-quic-server (&key (udp-receive-packet-budget 64)
                              (local-address "0.0.0.0") (local-port 443)
                              udp-socket max-connections
                              (max-handshakes max-connections)
                              (handshake-timeout 10)
                              (retry-policy :always)
                              transport-parameters tls-server-options)
  "Bind a QUIC UDP listener. The server takes ownership of UDP-SOCKET when supplied.

The default UDP receive packet budget is 64 datagrams. This lets one poll
handle a multi-packet burst while capping UDP work during sustained input. The
default absolute handshake timeout is 10 seconds."
  (cl-quic-kit::%check-type-redacted
   udp-receive-packet-budget (integer 1 *)
   :invalid-udp-receive-packet-budget)
  (cl-quic-kit::%check-type-redacted max-connections (integer 1 *) :invalid-max-connections)
  (cl-quic-kit::%check-type-redacted max-handshakes (integer 1 *) :invalid-max-handshakes)
  (cl-quic-kit::%check-type-redacted
   handshake-timeout
   (satisfies %server-valid-handshake-timeout-p)
   :invalid-handshake-timeout)
  (unless (<= max-handshakes max-connections)
    (error 'type-error :datum :invalid-handshake-limit
           :expected-type `(integer 1 ,max-connections)))
  (cl-quic-kit::%check-type-redacted retry-policy (member :always :never) :invalid-retry-policy)
  (unless udp-socket
    (cl-quic-kit::%check-type-redacted local-address string :invalid-local-address)
    (cl-quic-kit::%check-type-redacted local-port (integer 0 65535) :invalid-local-port))
  (when (and udp-socket (not (udp-socket-p udp-socket)))
    (error 'type-error
           :datum :invalid-udp-socket
           :expected-type 'udp-socket))
  (let ((socket (or udp-socket
                    (make-udp-socket :local-host local-address
                                     :local-port local-port))))
    (%make-quic-server :udp-socket socket
                       :udp-receive-packet-budget udp-receive-packet-budget
                       :max-connections max-connections
                       :max-handshakes max-handshakes
                       :handshake-timeout handshake-timeout
                       :retry-policy retry-policy
                       :retry-tokens (make-hash-table :test #'equalp)
                       :retired-retry-cids (make-hash-table :test #'equalp)
                       :retired-local-cids (make-hash-table :test #'equalp)
                       :paths (make-hash-table :test #'equalp)
                       :transport-parameters
                       (%server-normalize-transport-parameters transport-parameters)
                       :tls-server-options (%server-copy-plist tls-server-options)
                       :connections (make-hash-table :test #'equalp)
                       :accepted-connections nil
                       :shutdown-deadline nil
                       :shutdown-error-code :no-error
                       :shutdown-reason #()
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
  (labels ((oldest-evictable-path-key ()
             (let ((oldest-key nil)
                   (oldest-expiry nil)
                   (active-paths (make-hash-table :test #'eq))
                   (used-token-paths (make-hash-table :test #'equalp)))
               (let ((connections (quic-server-connections server)))
                 (when connections
                   (maphash
                    (lambda (cid connection)
                      (declare (ignore cid))
                      (setf (gethash (server-connection-path connection)
                                     active-paths)
                            t))
                    connections)))
               (let ((tokens (quic-server-retry-tokens server)))
                 (when tokens
                   (maphash
                    (lambda (token record)
                      (declare (ignore token))
                      (when (and (server-retry-token-p record)
                                 (server-retry-token-used-p record))
                        (setf (gethash
                               (%server-path-key
                                (server-retry-token-address record)
                                (server-retry-token-original-destination-connection-id
                                 record))
                               used-token-paths)
                              t)))
                    tokens)))
               (maphash
                (lambda (path-key path)
                  (let ((expires-at
                          (or (server-amplification-state-expires-at path) 0)))
                    (when (and
                           (not (server-amplification-state-validated-p path))
                           (not (gethash path active-paths))
                           (not (gethash path-key used-token-paths))
                           (or (null oldest-expiry)
                               (< expires-at oldest-expiry)))
                      (setf oldest-key path-key
                            oldest-expiry expires-at))))
                (quic-server-paths server))
               oldest-key))
           (evict-oldest-path ()
             (let ((path-key (oldest-evictable-path-key)))
               (when path-key
                 (remhash path-key (quic-server-paths server))
                 (let ((tokens-to-remove nil))
                   (progn
                   (maphash
                    (lambda (token record)
                      (when (and
                             (server-retry-token-p record)
                             (equalp
                              path-key
                              (%server-path-key
                               (server-retry-token-address record)
                               (server-retry-token-original-destination-connection-id
                                record))))
                        (push token tokens-to-remove)))
                    (quic-server-retry-tokens server))
                   (dolist (token tokens-to-remove)
                     (let ((record (gethash token (quic-server-retry-tokens server))))
                       (when record
                         (%server-retire-retry-cid server (server-retry-token-retry-source-connection-id record) (server-retry-token-retain-until record)))
                       (remhash token (quic-server-retry-tokens server)))))
                 t)))))
    (or (gethash key (quic-server-paths server))
        (when create-p
          (loop while (>= (hash-table-count (quic-server-paths server))
                          *quic-server-path-cache-limit*)
                do (unless (evict-oldest-path)
                     (return)))
          (when (< (hash-table-count (quic-server-paths server))
                   *quic-server-path-cache-limit*)
            (setf (gethash key (quic-server-paths server))
                  (%make-server-amplification-state
                   :expires-at (+ now *quic-server-retry-token-retention*))))))))

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
      (remhash key (quic-server-paths server)))
    (dolist (table (list (quic-server-retired-retry-cids server)
                         (quic-server-retired-local-cids server)))
      (let ((expired-cids nil))
        (maphash (lambda (cid expires-at)
                   (when (<= expires-at now)
                     (push cid expired-cids)))
                 table)
        (dolist (cid expired-cids)
          (remhash cid table))))))

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

(progn
(defun %server-retire-cid (table cid expires-at limit &optional on-evict)
  (setf (gethash (octets-copy cid) table) expires-at)
  (loop while (> (hash-table-count table) limit) do
    (let ((oldest-cid nil)
          (oldest-expiry nil))
      (maphash (lambda (candidate expiry)
                 (when (or (null on-evict)
                           (not (equalp candidate cid)))
                   (when (or (null oldest-expiry) (< expiry oldest-expiry))
                     (setf oldest-cid candidate
                           oldest-expiry expiry))))
               table)
      (let ((evicted-cid (or oldest-cid cid)))
        (remhash evicted-cid table)
        (when on-evict
          (funcall on-evict evicted-cid))))))
(defun %server-remove-retry-tokens-for-cid (server cid)
  (let ((tokens-to-remove nil))
    (maphash
     (lambda (token record)
       (when (and (server-retry-token-p record)
                  (equalp cid
                          (server-retry-token-retry-source-connection-id record)))
         (push token tokens-to-remove)))
     (quic-server-retry-tokens server))
    (dolist (token tokens-to-remove)
      (remhash token (quic-server-retry-tokens server)))))
(defun %server-retire-retry-cid (server cid expires-at)
  (%server-retire-cid
   (quic-server-retired-retry-cids server) cid expires-at
   *quic-server-retry-cache-limit*
   (lambda (evicted-cid)
     (%server-remove-retry-tokens-for-cid server evicted-cid))))
(defun %server-retired-cid-active-p (table cid now)
  (let ((expires-at (gethash cid table)))
    (and expires-at (> expires-at now))))
(defun %server-new-token (server)
  (loop repeat 4
        for candidate = (%server-random-octets 32)
        unless (gethash candidate (quic-server-retry-tokens server))
          do (return candidate)
        finally (error 'randomness-unavailable :operation :retry-token)))
)

(defun %server-new-retry-source-connection-id (server forbidden-cid)
  (loop repeat 4
        for candidate = (%server-random-octets 8)
        unless (or
                (equalp candidate forbidden-cid)
                (gethash candidate (quic-server-retired-retry-cids server))
                (gethash candidate (quic-server-retired-local-cids server))
                (nth-value 1
                           (gethash candidate
                                    (quic-server-connections server)))
                (loop for active being the hash-values
                      of (quic-server-connections server)
                      thereis
                      (equalp
                       candidate
                       (server-connection-original-destination-connection-id
                        active)))
                (loop for record being the hash-values
                      of (quic-server-retry-tokens server)
                      thereis
                      (equalp
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
  (unless path
    (return-from %server-send-retry nil))
  (labels ((oldest-retry-token (excluded used-p)
             (let ((oldest-token nil)
                   (oldest-retain-until nil))
               (maphash
                (lambda (token record)
                  (when (and
                         (server-retry-token-p record)
                         (eql used-p (server-retry-token-used-p record))
                         (not (member token excluded :test (function equalp))))
                    (let ((retain-until
                            (or (server-retry-token-retain-until record) 0)))
                      (when (or (null oldest-retain-until)
                                (< retain-until oldest-retain-until))
                        (setf oldest-token token
                              oldest-retain-until retain-until)))))
                (quic-server-retry-tokens server))
               oldest-token)))
    (let* ((token-count
             (hash-table-count (quic-server-retry-tokens server)))
           (tokens-needed
             (max 0 (- (1+ token-count) *quic-server-retry-cache-limit*)))
           (tokens-to-evict nil))
      (dotimes (index tokens-needed)
        (declare (ignore index))
        (let ((token (or (oldest-retry-token tokens-to-evict nil)
                         (oldest-retry-token tokens-to-evict t))))
          (unless token
            (return-from %server-send-retry nil))
          (push token tokens-to-evict)))
      (let* ((token (%server-new-token server))
             (retry-source-cid
               (%server-new-retry-source-connection-id
                server (packet-header-destination-connection-id header)))
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
          (dolist (old-token tokens-to-evict)
            (let ((old-record (gethash old-token
                                       (quic-server-retry-tokens server))))
              (when old-record
                (%server-retire-retry-cid
                 server
                 (server-retry-token-retry-source-connection-id old-record)
                 (server-retry-token-retain-until old-record)))
              (remhash old-token (quic-server-retry-tokens server))))
          (setf (gethash token (quic-server-retry-tokens server)) record)
          (setf (server-amplification-state-expires-at path)
                (server-retry-token-retain-until record))
          t)))))


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
        ((and (null record)
              (%server-retired-cid-active-p
               (quic-server-retired-retry-cids server) destination-cid now))
         (values :invalid-token nil))
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
        ((and (server-retry-token-used-p record)
              (not (gethash
                    (server-retry-token-retry-source-connection-id record)
                    (quic-server-connections server))))
         (values :invalid-token record))
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
(defun %server-send-connection-refused (server header record path address)
  (unless path
    (return-from %server-send-connection-refused nil))
  (let ((packet-number (server-retry-token-next-packet-number record)))
    (when (>= packet-number (ash 1 62))
      (return-from %server-send-connection-refused nil))
    (let ((packet
           (%server-protected-initial
            (packet-header-destination-connection-id header)
            (packet-header-source-connection-id header)
            (server-retry-token-retry-source-connection-id record)
            packet-number
            (list (make-frame :connection-close :error-code 2
                              :frame-type 0 :reason #())))))
      (when (%server-emit server path address packet)
        (incf (server-retry-token-next-packet-number record))
        t))))

(defun %server-handle-initial
    (server header path address now bytes &optional path-created-p)
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
            (%server-start-or-feed-initial
             server header path address nil bytes now path-created-p))
           (t
            (%server-send-invalid-token server header nil path address))))
        ((eq status :valid)
         (%server-start-or-feed-initial
          server header path address record bytes now path-created-p))
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
                                   (%server-process-protected-datagram
                                    server-connection bytes now)))))
        (multiple-value-bind (first version destination-cid source-cid)
            (%server-long-header-fields bytes)
          (cond
           ((null first)
            (route-existing))
           ((zerop version)
            nil)
           ((/= version *quic-version-1*)
            (when (>= byte-count 1200)
              (%server-send-version-negotiation
               server destination-cid source-cid
               (%make-server-amplification-state :received byte-count)
               address)))
           ((zerop (ldb (byte 2 4) first))
            (when (>= byte-count 1200)
              (multiple-value-bind (header end)
                  (decode-packet-header bytes)
                (declare (ignore end))
                (when (eq (packet-header-type header) :initial)
                  (let ((existing
                         (%server-find-initial-connection
                          server destination-cid source-cid)))
                    (unless (or (and existing
                                     (server-connection-handshake-complete-p
                                      existing))
                                (and (null existing)
                                     (or (gethash destination-cid
                                                  (quic-server-connections server))
                                         (loop for active being the hash-values
                                               of (quic-server-connections server)
                                               thereis
                                               (equalp
                                                destination-cid
                                                (server-connection-original-destination-connection-id
                                                 active)))
                                         (%server-retired-cid-active-p
                                          (quic-server-retired-local-cids server)
                                          destination-cid now)))
        (and (null existing) (quic-server-shutdown-deadline server)))
                      (let* ((record
                              (loop for candidate being the hash-values
                                    of (quic-server-retry-tokens server)
                                    when (equalp
                                          destination-cid
                                          (server-retry-token-retry-source-connection-id
                                           candidate))
                                    return candidate))
                             (original-dcid
                              (cond
                               (existing
                                (server-connection-original-destination-connection-id existing))
                               (record
                                (server-retry-token-original-destination-connection-id record))
                               (t destination-cid)))
                             (path-key
                              (%server-path-key address original-dcid))
                             (path-existed-p
                              (nth-value
                               1
                               (gethash path-key (quic-server-paths server))))
                             (path (or
                                    (and existing
                                         (equalp address
                                                 (server-connection-address existing))
                                         (server-connection-path existing))
                                    (%server-path
                                     server address original-dcid now t)))
                             (path-created-p
                              (and (null existing)
                                   (not path-existed-p)
                                   (not (null path)))))
                        (%server-note-received path byte-count now)
                        (if (and existing
                                 (not (server-connection-handshake-complete-p existing))
                                 (equalp address (server-connection-address existing)))
                            (%server-process-protected-datagram existing bytes now)
                          (%server-handle-initial server header path address now bytes path-created-p)))))))))
           (t
            (route-existing)))))
    (quic-encoding-error () nil)
    (invalid-connection-id () nil)))

(defun quic-server-poll (server &optional at)
  "Process available UDP datagrams and return true when SERVER is closed."
  (when (quic-server-closed-p server)
    (progn
      (udp-close (quic-server-udp-socket server))
      (return-from quic-server-poll t)))
  (let ((now (or at (%quic-real-time))))
    (%server-prune-expired-state server now)
    (dolist (server-connection (%server-routed-connections server))
      (let* ((connection (server-connection-connection server-connection))
             (handshake-deadline
               (server-connection-handshake-deadline server-connection))
             (draining-deadline (connection-draining-deadline connection)))
        (cond
          ((and (not (server-connection-handshake-complete-p server-connection))
                handshake-deadline
                (>= (%server-exact-real now)
                    (%server-exact-real handshake-deadline)))
           (%server-release-connection-state server-connection))
          ((and draining-deadline
                (member (connection-state connection) '(:closing :draining))
                (>= now draining-deadline))
           (connection-poll connection now)
           (when (eq (connection-state connection) :closed)
             (%server-release-connection-state server-connection))))))
    (let ((shutdown-deadline (quic-server-shutdown-deadline server)))
      (when (and shutdown-deadline
                 (or (>= now shutdown-deadline)
                     (zerop (%server-connection-count server))))
        (quic-server-close
         server :error-code (quic-server-shutdown-error-code server)
         :reason (quic-server-shutdown-reason server))
        (return-from quic-server-poll t)))
    (loop repeat (quic-server-udp-receive-packet-budget server)
          do (multiple-value-bind (bytes byte-count address)
                 (udp-receive (quic-server-udp-socket server))
               (unless bytes
                 (return))
               (%server-handle-datagram
                server bytes address byte-count now)))
    (%server-poll-connections server now)
    (let ((shutdown-deadline (quic-server-shutdown-deadline server)))
      (when (and shutdown-deadline
                 (or (>= now shutdown-deadline)
                     (zerop (%server-connection-count server))))
        (quic-server-close
         server :error-code (quic-server-shutdown-error-code server)
         :reason (quic-server-shutdown-reason server))
        (return-from quic-server-poll t))))
  nil)


(defun quic-server-close (server &key (error-code :no-error) reason)
  "Send best-effort connection closes, then close SERVER and its UDP socket."
  (%quic-close-error-code error-code)
  (let ((reason-octets (%quic-close-reason reason)) (already-closed-p (quic-server-closed-p server)))
    (unless already-closed-p
      (let ((connections (%server-routed-connections server))
            (first-error nil))
        (labels ((remember-error (condition)
                   (unless first-error
                     (setf first-error condition))))
          (setf (quic-server-closed-p server) t)
          (unwind-protect
               (dolist (server-connection connections)
                 (let ((connection
                         (server-connection-connection server-connection)))
                   (unless (member (connection-state connection)
                                   '(:draining :closed))
                     (handler-case
                         (quic-connection-close
                          connection :error-code error-code
                          :reason reason-octets)
                       (error (condition)
                         (remember-error condition))))
                   (handler-case
                       (%server-flush-pending-datagrams server-connection)
                     (error (condition)
                       (remember-error condition)))))
            (dolist (server-connection connections)
              (handler-case
                  (%server-release-connection-state server-connection)
                (error (condition)
                  (remember-error condition))))
            (clrhash (quic-server-connections server))
            (setf (quic-server-accepted-connections server) nil)
            (clrhash (quic-server-retry-tokens server))
            (clrhash (quic-server-retired-retry-cids server))
            (clrhash (quic-server-retired-local-cids server))
            (clrhash (quic-server-paths server))
            (handler-case
                (udp-close (quic-server-udp-socket server))
              (error (condition)
                (remember-error condition))))
          (when first-error
            (if (typep first-error 'quic-error)
                (error first-error)
                (error 'quic-error :message (princ-to-string first-error)))))))
  t
  (if already-closed-p
      (udp-close (quic-server-udp-socket server))
      t)))
(progn
  (defstruct (server-connection
              (:constructor %make-server-connection))
    server connection engine tls-boundary tls-driver path address now handshake-deadline
    original-destination-connection-id local-connection-id
    remote-connection-id cipher-suite transport-parameters
    peer-transport-parameters pending-datagrams
    (handshake-complete-p nil) (accepted-p nil) (close-response-attempted-p nil))
  (defmethod print-object ((server-connection server-connection) stream)
  (print-unreadable-object (server-connection stream :type t)
    (write-string "redacted" stream)))

  (defun %server-routed-connections (server)
    (let ((seen (make-hash-table :test #'eq))
          (connections nil))
      (maphash
       (lambda (connection-id server-connection)
         (declare (ignore connection-id))
         (unless (gethash server-connection seen)
           (setf (gethash server-connection seen) t)
           (push server-connection connections)))
       (quic-server-connections server))
      (nreverse connections)))

  (defun %server-connection-count (server)
    (length (%server-routed-connections server)))
  (defun %server-handshaking-count (server)
    (count-if
     (lambda (server-connection)
       (and (not (server-connection-handshake-complete-p server-connection))
            (eq (connection-state
                 (server-connection-connection server-connection))
                :handshaking)))
     (%server-routed-connections server)))

  (defun %server-remove-connection-routes (server-connection)
    (let* ((server (server-connection-server server-connection))
           (routes (quic-server-connections server))
           (connection-ids nil))
      (maphash
       (lambda (connection-id candidate)
         (when (eq candidate server-connection)
           (push connection-id connection-ids)))
       routes)
      (dolist (connection-id connection-ids)
        (remhash connection-id routes))
      (setf (quic-server-accepted-connections server)
            (delete (server-connection-connection server-connection)
                    (quic-server-accepted-connections server)
                    :test #'eq))
      server-connection))
  (defun %server-release-connection-state (server-connection)
    (let ((connection (server-connection-connection server-connection))
          (engine (server-connection-engine server-connection))
          (tls-boundary (server-connection-tls-boundary server-connection))
          (tls-driver (server-connection-tls-driver server-connection))
          (close-driver #'cl-tls-kit:tls13-server-driver-close)
          (first-error nil))
      (labels ((attempt (thunk)
                        (handler-case
                            (funcall thunk)
                          (error (condition)
                                 (unless first-error
                                   (setf first-error condition)))))
               (clear-octets (value)
                             (when (typep value (quote (vector (unsigned-byte 8) *)))
                               (attempt (lambda () (fill value 0)))))
               (clear-key (key-set)
                          (when key-set
                            (attempt
                             (lambda ()
                               (clear-octets
                                (cl-quic-kit.protection:key-set-key key-set))))
                            (attempt
                             (lambda ()
                               (clear-octets
                                (cl-quic-kit.protection:key-set-iv key-set))))
                            (attempt
                             (lambda ()
                               (clear-octets
                                (cl-quic-kit.protection:key-set-hp key-set)))))))
        (when tls-driver
          (attempt
           (lambda ()
             (funcall close-driver tls-driver))))
        (let ((transcript-reader
               #'cl-tls-kit:quic-tls-boundary-transcript))
          (when tls-boundary (attempt
                              (lambda ()
                                (dolist (wire (funcall transcript-reader tls-boundary))
                                  (clear-octets wire))))))
        (when engine
          (attempt
           (lambda ()
             (dolist (level-keys (quic-client-keys engine))
               (dolist (direction (list :read :write))
                 (clear-key (getf (cdr level-keys) direction))))))
          (attempt
           (lambda ()
             (dolist (key-set
                      (list (quic-client-application-read-old-key engine)
                            (quic-client-application-read-next-key engine)))
               (clear-key key-set))))
          (attempt
           (lambda ()
             (dolist (secret
                      (list (quic-client-application-read-next-secret engine)
                            (quic-client-application-read-secret engine)
                            (quic-client-application-write-secret engine)))
               (clear-octets secret))))
          (attempt
           (lambda ()
             (clear-octets (quic-client-client-hello-wire engine))))
          (attempt
           (lambda ()
             (setf (quic-client-keys engine) nil
                   (quic-client-application-read-old-key engine) nil
                   (quic-client-application-read-next-key engine) nil
                   (quic-client-application-read-next-secret engine) nil
                   (quic-client-application-read-secret engine) nil
                   (quic-client-application-write-secret engine) nil
                   (quic-client-client-hello-wire engine) nil
                   (quic-client-tls-boundary engine) nil
                   (quic-client-tls-driver engine) nil
                   (quic-client-tls-key-exchange engine) nil
                   (quic-client-tls-provider engine) nil
                   (quic-client-tls-trust-anchors engine) nil
                   (quic-client-tls-verify-signature engine) nil
                   (quic-client-tls-signature-algorithms engine) nil
                   (quic-client-streams engine) nil
                   (quic-client-accepted-peer-streams engine) nil
                   (quic-client-pending-frames engine) nil
                   (quic-client-pending-stream-writes engine) nil
                   (quic-client-crypto-send-offsets engine) nil
                   (quic-client-packet-numbers engine) nil
                   (quic-client-received-packets engine) nil
                   (quic-client-recovery engine) nil
                   (quic-client-sent-packets engine) nil
                   (quic-client-pto-probe-budgets engine) nil
                   (quic-client-pto-probe-frames engine) nil
                   (quic-client-closed-p engine) t
                   (quic-client-connection engine) nil
                   (quic-client-clock engine) nil))))
        (attempt
         (lambda ()
           (setf (server-connection-pending-datagrams server-connection) nil
                 (server-connection-peer-transport-parameters server-connection) nil
                 (server-connection-engine server-connection) nil
                 (server-connection-tls-boundary server-connection) nil
                 (server-connection-tls-driver server-connection) nil
                 (server-connection-accepted-p server-connection) nil)))
        (when connection
          (attempt (lambda () (connection-set-state connection :closed)))
          (attempt
           (lambda ()
             (setf (quic-connection-stream-engine connection) nil
                   (quic-connection-tls-input connection) nil
                   (quic-connection-tls-output connection) nil
                   (quic-connection-io-read connection) nil
                   (quic-connection-io-write connection) nil
                   (quic-connection-on-close connection) nil
                   (quic-connection-now-fn connection)
                   (function %quic-real-time)))))
        (attempt (lambda () (%server-remove-connection-routes server-connection)))
        (when first-error
          (error first-error))
        server-connection))))
(defun %server-new-connection-id (server forbidden-cid)
  (loop repeat 4
        for candidate = (%server-random-octets 8 :connection-id)
        unless (or (equalp candidate forbidden-cid)
                   (gethash candidate (quic-server-retired-local-cids server))
                   (gethash candidate (quic-server-retired-retry-cids server))
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
      (error 'type-error :datum :invalid-server-options :expected-type 'list))
    (loop for tail on plist by #'cddr
          for key = (car tail)
          do (unless (keywordp key)
               (error 'type-error :datum :invalid-server-option-key :expected-type 'keyword))
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
         (cipher-suites (getf options :cipher-suites
                              #(#x1301 #x1302 #x1303))))
    (unless (getf options :provider)
      (setf (getf options :provider)
            (cl-tls-kit:make-cl-crypto-kit-provider)))
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
         (emit #'cl-tls-kit:quic-tls-boundary-emit-secret)
         (key (cl-quic-kit.protection:make-key-set
               secret
               :cipher (%server-suite-cipher
                        (server-connection-cipher-suite server-connection)))))
    (%client-set-key engine wire-level direction key)
    (when (eq wire-level :1-rtt)
      (if (eq direction :read)
          (setf (quic-client-application-read-secret engine) secret)
        (setf (quic-client-application-write-secret engine) secret)))
    (funcall emit boundary tls-level direction secret))
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
                  (declare (ignore condition))
                  (let* ((connection
                           (server-connection-connection server-connection))
                         (engine (server-connection-engine server-connection))
                         (frame
                           (%connection-prepare-close
                            connection :transport-parameter-error
                            "invalid peer transport parameters")))
                    (when frame
                      (setf (quic-client-closed-p engine) t)
                      (%client-queue-frame
                       engine frame
                       (if (%client-key engine :1-rtt :write) :1-rtt :initial))
                      (client-flush engine)))
                  (return-from %server-complete-connection
                    server-connection))))
             (connection (server-connection-connection server-connection))
             (local-idle-timeout (quic-connection-idle-timeout connection))
             (peer-idle-timeout (cdr (assoc 1 peer-parameters))))
        (progn
  (%client-set-peer-transport-parameters
   (server-connection-engine server-connection) peer-parameters)
  (setf (quic-connection-idle-timeout connection)
        (if (and peer-idle-timeout (plusp peer-idle-timeout))
            (min local-idle-timeout (/ peer-idle-timeout 1000))
            local-idle-timeout)
        (server-amplification-state-validated-p
         (server-connection-path server-connection))
        t)))
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
(progn
  (defun %server-close-on-frame-error (server-connection error-code)
    (let* ((connection (server-connection-connection server-connection))
           (engine (server-connection-engine server-connection))
           (frame (%connection-prepare-close
                   connection error-code "peer sent an invalid frame"))
           (level (or (and (%client-key engine :1-rtt :write) :1-rtt)
                      (and (%client-key engine :handshake :write) :handshake)
                      (and (%client-key engine :initial :write) :initial))))
      (when frame
        (setf (quic-client-closed-p engine) t
              (quic-client-pending-frames engine) nil
              (quic-client-pending-stream-writes engine) nil)
        (when level
          (%client-queue-frame engine frame level)
          (client-flush engine))))
    server-connection)

  (defun %server-frame-error-code (condition)
    (typecase condition
      (stream-limit-error 4)
      (flow-control-error
       (if (typep condition 'final-size-error) 6 3))
      (stream-id-error 5)
      (quic-encoding-error 7)
      (cl-tls-kit:quic-tls-boundary-error 10)
      (quic-error 10)))

  (defun %server-handle-frame-error (server-connection condition)
    (let ((error-code (%server-frame-error-code condition)))
      (if error-code
          (%server-close-on-frame-error server-connection error-code)
          (error condition)))))
(defun %server-handle-tls-events (server-connection events)
  (dolist (event events)
    (if (and (consp event)
             (eq (first event) :peer-quic-transport-parameters))
        (setf (server-connection-peer-transport-parameters server-connection)
              (octets-copy (second event)))
      (case (getf event :type)
        (:cipher-suite
         (let* ((suite (getf event :suite))
                (engine (server-connection-engine server-connection))
                (emit #'cl-tls-kit:quic-tls-boundary-emit-cipher-suite))
           (setf (server-connection-cipher-suite server-connection) suite)
           (%client-set-authentication-cipher engine (%server-suite-cipher suite))
           (when (quic-client-closed-p engine)
             (return-from %server-handle-tls-events server-connection))
           (funcall emit (server-connection-tls-boundary server-connection)
                    suite)))
        (:send
         (unless (eq (getf event :content-type) :alert)
           (%server-queue-crypto server-connection
                                 (getf event :level)
                                 (getf event :wire))))
        (:secret
         (%server-install-secret server-connection
                                 (getf event :level)
                                 (getf event :direction)
                                 (getf event :secret)))
        (:alpn
         (let* ((protocol (getf event :protocol))
                (emit #'cl-tls-kit:quic-tls-boundary-emit-alpn))
           (funcall emit
                    (server-connection-tls-boundary server-connection)
                    protocol)
           (setf (quic-connection-alpn (server-connection-connection server-connection))
                 (and protocol (copy-seq protocol)))))
        (:ticket-issued nil)
        (:alert
         (let* ((alert (getf event :description))
                (connection
                 (server-connection-connection server-connection))
                (engine (server-connection-engine server-connection))
                (frame (%connection-prepare-close
                        connection (+ #x0100 alert) "TLS fatal alert")))
           (setf (quic-client-closed-p engine) t)
           (when frame
             (%client-queue-frame
              engine frame
              (if (%client-key engine :1-rtt :write) :1-rtt :initial))
             (client-flush engine))
           (%server-retire-cid
            (quic-server-retired-local-cids
             (server-connection-server server-connection))
            (server-connection-local-connection-id server-connection)
            (+ (or (server-connection-now server-connection)
                   (%quic-real-time))
               *quic-server-retry-token-retention*)
            *quic-server-path-cache-limit*)
           (%server-retire-cid
            (quic-server-retired-local-cids
             (server-connection-server server-connection))
            (server-connection-original-destination-connection-id
             server-connection)
            (+ (or (server-connection-now server-connection)
                   (%quic-real-time))
               *quic-server-retry-token-retention*)
            *quic-server-path-cache-limit*)
           (return-from %server-handle-tls-events server-connection)))
        (:handshake-complete
         (%server-complete-connection server-connection))
        (otherwise
         (error 'quic-error :message "Unknown TLS server driver event")))))
  server-connection)
(defun %server-feed-crypto (server-connection level offset bytes)
  (let* ((tls-level (%client-level-space level))
         (boundary (server-connection-tls-boundary server-connection))
         (feed #'cl-tls-kit:quic-tls-boundary-feed-crypto)
         (step #'cl-tls-kit:tls13-server-driver-step))
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
          #'cl-tls-kit:make-quic-tls-boundary)
         (driver-constructor
          #'cl-tls-kit:make-tls13-server-driver)
         (server-connection
          (%make-server-connection
           :server server :path path :address (%server-copy-address address)
           :now now
           :handshake-deadline (+ (%server-exact-real now) (%server-exact-real (quic-server-handshake-timeout server)))
           :original-destination-connection-id (octets-copy original-cid)
           :local-connection-id (octets-copy local-cid)
           :remote-connection-id (octets-copy remote-cid)
           :transport-parameters transport-parameters
           :pending-datagrams nil)))
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
                     (let ((digest #'crypto-kit:digest))
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
  (let ((connection (gethash destination-cid (quic-server-connections server))))
    (or (and connection
             (equalp source-cid
                     (server-connection-remote-connection-id connection))
             connection)
        (loop for server-connection being the hash-values
                of (quic-server-connections server)
              when (and
                    (equalp destination-cid
                            (server-connection-original-destination-connection-id
                             server-connection))
                    (equalp source-cid
                            (server-connection-remote-connection-id
                             server-connection)))
                return server-connection))))
(defun %server-start-or-feed-initial
    (server header path address record bytes now &optional path-created-p)
  (let* ((existing
          (%server-find-initial-connection
           server
           (packet-header-destination-connection-id header)
           (packet-header-source-connection-id header)))
         (existing-address-p
          (and existing
               (equalp address (server-connection-address existing))))
         (capacity-p
          (and (< (%server-connection-count server)
                  (quic-server-max-connections server))
               (< (%server-handshaking-count server)
                  (quic-server-max-handshakes server))))
         (server-connection
          (cond
           (existing-address-p
            existing)
           ((and (null existing) capacity-p)
            (%server-create-connection
             server header path address record now))
           (t nil))))
    (when server-connection
      (when record
        (when path
          (setf (server-amplification-state-validated-p path) t))
        (setf (server-retry-token-used-p record) t))
      (%server-process-protected-datagram server-connection bytes now))
    (when (and (null existing) (null server-connection) record)
      (when path
        (setf (server-amplification-state-validated-p path) t))
      (unwind-protect
           (%server-send-connection-refused server header record path address)
        (when path-created-p
          (let ((path-key
                  (%server-path-key
                   address
                   (server-retry-token-original-destination-connection-id
                    record))))
            (when (eq path (gethash path-key (quic-server-paths server)))
              (remhash path-key (quic-server-paths server)))))))
  server))
(defun %server-process-protected-datagram (server-connection bytes now)
  (setf (server-connection-now server-connection) now)
  (let ((connection (server-connection-connection server-connection)))
    (case (connection-state connection)
      (:draining
       (setf (server-connection-pending-datagrams server-connection) nil)
       (return-from %server-process-protected-datagram server-connection))
      (:closed
       (return-from %server-process-protected-datagram server-connection))
      (:closing
       (let* ((engine (server-connection-engine server-connection))
              (frame (connection-close-frame connection))
              (frame-type (and frame (frame-type frame)))
              (level
               (or (and (%client-key engine :1-rtt :write) :1-rtt)
                   (and (%client-key engine :handshake :write) :handshake)
                   (and (%client-key engine :initial :write) :initial))))
         (when (and (not (server-connection-close-response-attempted-p
                          server-connection))
                    (null (server-connection-pending-datagrams
                           server-connection))
                    frame level
                    (or (eq frame-type :connection-close)
                        (and (eq frame-type :application-close)
                             (eq level :1-rtt))))
           (let ((packet (%client-build-packet engine level (list frame))))
             (when packet
               (setf (server-connection-close-response-attempted-p
                      server-connection)
                     t)
               (connection-write connection packet)))))
       (return-from %server-process-protected-datagram server-connection)))
    (when (and (server-connection-handshake-complete-p server-connection)
               (eq (getf (%client-layout bytes) :type) :initial))
      (return-from %server-process-protected-datagram server-connection))
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
                  (when (member (connection-state connection)
                            '(:closing :draining :closed))
                    (return-from %server-process-protected-datagram server-connection))
                  (when header
                    (let* ((frames (handler-case
                                       (decode-frames (packet-header-payload header))
                                     (quic-encoding-error (condition)
                                                          (declare (ignore condition))
                                                          (%server-close-on-frame-error server-connection 7)
                                                          (return-from %server-process-protected-datagram server-connection))))
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
                      (let ((flush-p nil))
                        (dolist (frame frames)
                          (handler-case
                              (when (%client-process-received-frame
                                     engine level frame
                                     :crypto-handler
                                     (lambda (client crypto-level crypto-frame)
                                       (declare (ignore client))
                                       (%server-feed-crypto
                                        server-connection crypto-level
                                        (frame-field crypto-frame :offset 0)
                                        (frame-field crypto-frame :data #()))
                                       nil)
                                     :touch-p nil)
                                (setf flush-p t))
                            (error (condition)
                              (%server-handle-frame-error
                               server-connection condition)))
                          (when (member (connection-state connection)
                                        '(:closing :draining :closed))
                            (return-from %server-process-protected-datagram server-connection)))
                        (when flush-p
                          (handler-case
                              (client-flush engine)
                            (error (condition)
                              (%server-handle-frame-error
                               server-connection condition)))))
                      (connection-touch connection now)))))
              (setf at (+ at (getf layout :end)))
              (when (not (getf layout :long-p))
                (return))))
      server-connection)))
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
  (dolist (server-connection (%server-routed-connections server))
    (let ((connection (server-connection-connection server-connection)))
      (setf (server-connection-now server-connection) now)
      (connection-poll connection now)
      (case (connection-state connection)
        (:closed
         (%server-release-connection-state server-connection))
        (:draining
         (setf (server-connection-pending-datagrams server-connection) nil))
        (:closing
         (%server-flush-pending-datagrams server-connection))
        (otherwise
         (%server-flush-pending-datagrams server-connection)
         (handler-case
             (client-poll (server-connection-engine server-connection) now)
           (error (condition)
             (%server-handle-frame-error server-connection condition)))
         (case (connection-state connection)
           ((:closed :draining)
            (setf (server-connection-pending-datagrams server-connection) nil)
            (when (eq (connection-state connection) :closed)
              (%server-release-connection-state server-connection)))
           (otherwise
            (%server-flush-pending-datagrams server-connection)))))))
  server)
(defun quic-server-accept-connection (server)
  "Return the next completed connection, or NIL when none is available."
  (pop (quic-server-accepted-connections server)))
(defun %quic-connection-stream-engine (connection)
  (let ((engine (quic-connection-stream-engine connection)))
    (unless engine
      (error 'quic-error :message "Connection has no QUIC stream engine"))
    engine))
(defun quic-connection-accept-stream (connection &key (type :any))
  (unless (member type '(:any :bidirectional :unidirectional))
    (error 'type-error
           :datum :invalid-peer-stream-type
           :expected-type '(member :any :bidirectional :unidirectional)))
  (let ((engine (%quic-connection-stream-engine connection)))
    (if (member (connection-state connection) '(:closing :draining :closed))
        nil
      (client-accept-peer-stream engine :type type))))
(defun quic-connection-open-stream (connection &key (type :bidirectional))
  (unless (member type '(:bidirectional :unidirectional))
    (error 'type-error
           :datum :invalid-stream-type
           :expected-type '(member :bidirectional :unidirectional)))
  (let ((engine (%quic-connection-stream-engine connection)))
    (when (member (connection-state connection) '(:closing :draining :closed))
      (error 'connection-closed
             :error-code (or (quic-connection-closed-error connection) 0)
             :reason (or (quic-connection-closed-reason connection) #())))
    (client-open-stream engine nil :stream-type type)))
(defun quic-connection-read-stream (connection stream)
  (let ((engine (%quic-connection-stream-engine connection)))
    (unless (eq (gethash (stream-id stream) (quic-client-streams engine)) stream)
      (error 'quic-error
             :message "Cannot read a stream that is not registered with the connection"))
    (unless (%stream-can-receive-p stream)
      (error 'stream-id-error :stream-id (stream-id stream)))
    (client-read-stream engine stream)))
(defun quic-connection-write-stream (connection stream octets &key (fin-p nil))
  (let ((engine (%quic-connection-stream-engine connection)))
    (when (member (connection-state connection) '(:closing :draining :closed))
      (error 'connection-closed
             :error-code (or (quic-connection-closed-error connection) 0)
             :reason (or (quic-connection-closed-reason connection) #())))
    (client-write-stream engine stream octets :fin-p fin-p)))
(progn
  (defun quic-connection-flush (connection)
    (client-flush (%quic-connection-stream-engine connection)))

  (defun quic-connection-close-stream (connection stream)
  "Remove STREAM from CONNECTION and discard its pending writes.
Does not enqueue FIN or RESET_STREAM. Already queued frames may still be sent."
  (client-close-stream (%quic-connection-stream-engine connection) stream)))
(progn
  (defun %quic-close-error-code (error-code)
    (let ((wire-code (%connection-error-code error-code)))
      (unless (and (integerp wire-code)
                   (<= 0 wire-code)
                   (< wire-code (ash 1 62)))
        (error 'type-error
               :datum :invalid-close-error-code
               :expected-type `(or (integer 0 ,(1- (ash 1 62)))
                                   (member :no-error :internal-error :frame-encoding-error
                                           :transport-parameter-error :protocol-violation
                                           :connection-id-limit :application-error))))
      wire-code))

  (defun %quic-close-reason (reason)
    (cond
     ((or (null reason)
          (and (vectorp reason)
               (zerop (length reason))
               (eq (array-element-type reason) t)))
      (make-array 0 :element-type '(unsigned-byte 8)))
     ((stringp reason)
      (%connection-reason-octets reason))
     ((and (arrayp reason)
           (= (array-rank reason) 1)
           (nth-value 0
                      (subtypep (array-element-type reason) '(unsigned-byte 8))))
      (%connection-reason-octets
       (make-array (length reason)
                   :element-type '(unsigned-byte 8)
                   :initial-contents reason)))
     (t
      (error 'type-error
             :datum :invalid-close-reason
             :expected-type '(or null string (array (unsigned-byte 8) (*)) (vector t 0))))))

  (defun quic-connection-close (connection &key (error-code :no-error) reason)
    "Queue a protected CONNECTION_CLOSE frame and return true."
    (%quic-close-error-code error-code)
    (let ((reason-octets (%quic-close-reason reason)))
      (unless (member (connection-state connection)
                      '(:closing :draining :closed))
        (let* ((engine (%quic-connection-stream-engine connection))
               (application-close-p (eq error-code :application-error))
               (level (if application-close-p
                          (and (%client-key engine :1-rtt :write) :1-rtt)
                          (or (and (%client-key engine :1-rtt :write) :1-rtt)
                              (and (%client-key engine :handshake :write) :handshake)
                              (and (%client-key engine :initial :write) :initial)))))
          (unless level
            (error 'quic-error
                   :message "No packet protection key is available for CONNECTION_CLOSE"))
          (let ((frame (%connection-prepare-close connection error-code reason-octets)))
            (when frame
              (setf (quic-client-closed-p engine) t)
              (%client-queue-frame engine frame level)
              (client-flush engine)))))
      t))

  (defun quic-server-shutdown (server &key (grace-period 30)
                                      (error-code :no-error) reason)
    "Stop admitting new connections and close SERVER after draining or GRACE-PERIOD."
    (cl-quic-kit::%check-type-redacted grace-period (real 0 *) :invalid-grace-period)
    (%quic-close-error-code error-code)
    (let ((reason-octets (%quic-close-reason reason)))
      (unless (or (quic-server-shutdown-deadline server)
                  (quic-server-closed-p server))
        (setf (quic-server-shutdown-deadline server)
              (+ (%quic-real-time) grace-period)
              (quic-server-shutdown-error-code server) error-code
              (quic-server-shutdown-reason server) reason-octets))
      (when (and (not (quic-server-closed-p server))
                 (quic-server-shutdown-deadline server)
                 (zerop (%server-connection-count server)))
        (quic-server-close
         server :error-code (quic-server-shutdown-error-code server)
         :reason (quic-server-shutdown-reason server)))
      server)))
