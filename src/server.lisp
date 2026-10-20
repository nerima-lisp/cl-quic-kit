(in-package #:cl-quic-kit)

(defparameter *quic-server-retry-token-lifetime* 30)
(defparameter *quic-server-retry-token-retention* 60)
(defparameter *quic-server-retry-cache-limit* 4096)
(defparameter *quic-server-path-cache-limit* 4096)

(defstruct (quic-server (:constructor %make-quic-server))
  udp-socket max-connections retry-policy retry-tokens paths closed-p)

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

(defun %server-random-octets (length)
  (let ((random (%client-function "CRYPTO-KIT" "RANDOM-OCTETS")))
    (unless random
      (error 'randomness-unavailable :operation :retry-token))
    (handler-case
        (let ((value (funcall random length)))
          (unless (and (typep value '(simple-array (unsigned-byte 8) (*)))
                       (= (length value) length))
            (error 'randomness-unavailable :operation :retry-token))
          value)
      (randomness-unavailable (condition)
        (error condition))
      (error ()
        (error 'randomness-unavailable :operation :retry-token)))))

(defun make-quic-server (&key (local-address "0.0.0.0") (local-port 443)
                              udp-socket max-connections (retry-policy :always))
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

(defun %server-handle-initial (server header path address now)
  (let ((token (packet-header-token header))
        (destination-cid (packet-header-destination-connection-id header))
        (source-cid (packet-header-source-connection-id header)))
    (multiple-value-bind (status record)
        (%server-token-status server token address destination-cid source-cid now)
      (cond
        ((eq status :unknown)
         (when (eq (quic-server-retry-policy server) :always)
           (%server-send-retry server header path address now)))
        ((eq status :valid)
         (when path
           (setf (server-amplification-state-validated-p path) t
                 (server-retry-token-used-p record) t)))
        (t
         (%server-send-invalid-token
          server header record path address))))))

(defun %server-handle-datagram (server bytes address byte-count now)
  (handler-case
      (multiple-value-bind (first version destination-cid source-cid)
          (%server-long-header-fields bytes)
        (when (and first (not (zerop version)))
          (if (/= version *quic-version-1*)
              (let ((path (%server-path server address destination-cid now t)))
                (%server-note-received path byte-count now)
                (when (>= byte-count 1200)
                  (%server-send-version-negotiation
                   server destination-cid source-cid path address)))
              (when (zerop (ldb (byte 2 4) first))
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
                       (path (%server-path server address original-dcid now t)))
                  (%server-note-received path byte-count now)
                  (when (>= byte-count 1200)
                    (multiple-value-bind (header end)
                        (decode-packet-header bytes)
                      (declare (ignore end))
                      (when (eq (packet-header-type header) :initial)
                        (%server-handle-initial
                         server header path address now)))))))))
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
        (%server-handle-datagram server bytes address byte-count now))))
  nil)

(defun quic-server-close (server)
  "Close SERVER and its owned UDP socket. Repeated calls are harmless."
  (unless (quic-server-closed-p server)
    (setf (quic-server-closed-p server) t)
    (clrhash (quic-server-retry-tokens server))
    (clrhash (quic-server-paths server))
    (udp-close (quic-server-udp-socket server)))
  t)
