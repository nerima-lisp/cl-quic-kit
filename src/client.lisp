(in-package #:cl-quic-kit)

;;;; QUIC client packet engine and HTTP stream facade.

(defstruct (quic-client (:constructor %make-quic-client))
  connection udp-socket tls-boundary tls-driver
  streams next-bidi-stream next-uni-stream
  pending-frames crypto-send-offsets tls-secrets
  peer-transport-parameters closed-p started-p
  initial-destination-connection-id remote-connection-id retry-token
  packet-numbers received-packets keys recovery sent-packets clock
  local-connection-id server-host server-port hostname alpn
  transport-parameters tls-key-exchange tls-provider tls-trust-anchors
  tls-verify-signature tls-signature-algorithms client-hello-wire)

(declaim (ftype function client-tls-feed client-receive-datagram
                        client-flush %client-find-or-create-peer-stream
                        %client-protocol-close))

(defun %client-level-value (alist key)
  (cdr (assoc key alist)))

(defun %client-set-level-value (alist key value)
  (let ((cell (assoc key alist)))
    (if cell (setf (cdr cell) value) (push (cons key value) alist))
    alist))

(defun %client-level-space (level)
  (if (eq level :1-rtt) :application level))

(defun %client-space-level (space)
  (if (eq space :application) :1-rtt space))

(defun %client-key (client level direction)
  (getf (%client-level-value (quic-client-keys client) level) direction))

(defun %client-set-key (client level direction key)
  (let ((keys (copy-list (%client-level-value (quic-client-keys client) level))))
    (setf (getf keys direction) key)
    (setf (quic-client-keys client)
          (%client-set-level-value (quic-client-keys client) level keys))))

(defun %client-queue-frame (client frame &optional (level :application))
  (setf (quic-client-pending-frames client)
        (nconc (quic-client-pending-frames client) (list (cons level frame))))
  frame)

(defun %client-octets (value)
  (ensure-octets (or value #())))

(defun %client-function (package-name symbol-name)
  (let* ((package (find-package package-name))
         (symbol (and package (find-symbol symbol-name package))))
    (and symbol (fboundp symbol) (symbol-function symbol))))

(defun %client-driver-slot (driver name)
  (let ((reader (%client-function "CL-TLS-KIT" name)))
    (and reader (funcall reader driver))))

(defun %client-driver-set-slot (driver name value)
  (let* ((package (find-package "CL-TLS-KIT"))
         (symbol (and package (find-symbol name package)))
         (setter (and symbol (fdefinition (list 'setf symbol)))))
    (when setter (funcall setter value driver))))

(defun %client-random-octets (length)
  (let ((random (%client-function "CRYPTO-KIT" "RANDOM-OCTETS")))
    (if random
        (funcall random length)
        (make-array length :element-type '(unsigned-byte 8)
                    :initial-element 0))))

(defun %client-reason-octets (reason)
  (cond ((null reason) #())
        ((stringp reason) (map '(vector (unsigned-byte 8)) #'char-code reason))
        (t (%client-octets reason))))

(defun %client-stream-type (stream-type)
  (case stream-type
    (:control 0) (:qpack-encoder 2) (:qpack-decoder 3) (otherwise nil)))

(defun %client-driver-suite-cipher (driver)
  (case (%client-driver-slot driver "TLS13-CLIENT-DRIVER-SUITE")
    (#x1302 :aes-256-gcm)
    (#x1303 :chacha20-poly1305)
    (otherwise :aes-128-gcm)))

(defun %client-install-secret (client level direction secret)
  (unless (%client-key client level direction)
    (%client-set-key
     client level direction
     (cl-quic-kit.protection:make-key-set
      secret :cipher (%client-driver-suite-cipher (quic-client-tls-driver client))))
    (let ((boundary (quic-client-tls-boundary client))
          (emit (%client-function "CL-TLS-KIT" "QUIC-TLS-BOUNDARY-EMIT-SECRET")))
      (when (and boundary emit) (funcall emit boundary level direction secret)))))

(defun %client-sync-tls-secrets (client)
  (let ((driver (quic-client-tls-driver client))
        (secret-reader (%client-function "CL-TLS-KIT"
                                         "TLS13-TRAFFIC-STATE-SECRET")))
    (when (and driver secret-reader)
      (dolist (spec '(("TLS13-CLIENT-DRIVER-HANDSHAKE-READ-STATE" :handshake :read)
                      ("TLS13-CLIENT-DRIVER-HANDSHAKE-WRITE-STATE" :handshake :write)
                      ("TLS13-CLIENT-DRIVER-APPLICATION-READ-STATE" :1-rtt :read)
                      ("TLS13-CLIENT-DRIVER-APPLICATION-WRITE-STATE" :1-rtt :write)))
        (destructuring-bind (slot level direction) spec
          (let ((state (%client-driver-slot driver slot)))
            (when state
              (%client-install-secret client level direction
                                       (funcall secret-reader state)))))))))

(defun %client-transport-parameters (local-connection-id)
  (encode-transport-parameters
   `((1 . 30) (3 . 65527) (4 . 1048576)
     (5 . 65536) (6 . 65536) (7 . 65536)
     (8 . 25) (9 . 25) (10 . 3) (11 . 25)
     (14 . 2) (15 . ,local-connection-id))))

(defun %client-packet-number (client level)
  (let ((number (or (%client-level-value (quic-client-packet-numbers client) level) 0)))
    (setf (quic-client-packet-numbers client)
          (%client-set-level-value (quic-client-packet-numbers client) level (1+ number)))
    number))

(defun %client-read-u32 (bytes at)
  (when (> (+ at 4) (length bytes))
    (error 'quic-encoding-error :message "truncated QUIC version"))
  (values (+ (ash (aref bytes at) 24) (ash (aref bytes (+ at 1)) 16)
             (ash (aref bytes (+ at 2)) 8) (aref bytes (+ at 3))) (+ at 4)))

(defun %client-read-varint (bytes at)
  (handler-case
      (multiple-value-bind (value size) (decode-varint bytes at)
        (values value (+ at size)))
    (error (condition)
      (error 'quic-encoding-error :message (princ-to-string condition)))))

(defun %client-slice (bytes at size)
  (when (or (< at 0) (< size 0) (> (+ at size) (length bytes)))
    (error 'quic-encoding-error :message "truncated QUIC packet"))
  (values (subseq bytes at (+ at size)) (+ at size)))

(defun %client-layout (bytes &key (short-header-dcid-length 0))
  "Parse the unprotected outer header and return packet offsets."
  (when (zerop (length bytes))
    (error 'quic-encoding-error :message "empty QUIC datagram"))
  (labels ((slice-values (at size)
             (multiple-value-list (%client-slice bytes at size)))
           (varint-values (at)
             (multiple-value-list (%client-read-varint bytes at))))
    (let ((first (aref bytes 0)))
      (if (not (logbitp 7 first))
          (let ((values (slice-values 1 short-header-dcid-length)))
            (list :type :short :version 0 :dcid (first values) :scid #()
                  :pn-offset (second values)
                  :length (- (length bytes) (second values))
                  :end (length bytes) :long-p nil))
          (multiple-value-bind (version after-version) (%client-read-u32 bytes 1)
            (when (>= after-version (length bytes))
              (error 'quic-encoding-error :message "missing destination CID length"))
            (let* ((dlen (aref bytes after-version))
                   (dcid-values (slice-values (1+ after-version) dlen))
                   (dcid (first dcid-values))
                   (after-dcid (second dcid-values))
                   (slen (and (< after-dcid (length bytes)) (aref bytes after-dcid))))
              (unless slen
                (error 'quic-encoding-error :message "missing source CID length"))
              (let* ((scid-values (slice-values (1+ after-dcid) slen))
                     (scid (first scid-values))
                     (after-cids (second scid-values))
                     (type (case (ldb (byte 2 4) first)
                             (0 :initial) (1 :0-rtt) (2 :handshake) (3 :retry))))
                (cond
                  ((zerop version)
                   (list :type :version-negotiation :version 0 :dcid dcid :scid scid
                         :end (length bytes) :long-p t))
                  ((eq type :retry)
                   (when (< (- (length bytes) after-cids) 16)
                     (error 'quic-encoding-error :message "truncated Retry"))
                   (list :type type :version version :dcid dcid :scid scid
                         :token (subseq bytes after-cids (- (length bytes) 16))
                         :tag (subseq bytes (- (length bytes) 16))
                         :end (length bytes) :long-p t))
                  (t
                   (let* ((token-length-values
                            (if (eq type :initial)
                                (varint-values after-cids)
                                (list 0 after-cids)))
                          (token-length (first token-length-values))
                          (after-token-length (second token-length-values))
                          (token-values (slice-values after-token-length token-length))
                          (token (first token-values))
                          (after-token (second token-values))
                          (length-values (varint-values after-token))
                          (length-value (first length-values))
                          (pn-offset (second length-values))
                          (end (+ pn-offset length-value)))
                     (when (< length-value 1)
                       (error 'quic-encoding-error :message "invalid QUIC length"))
                     (when (> end (length bytes))
                       (error 'quic-encoding-error :message "truncated QUIC payload"))
                     (list :type type :version version :dcid dcid :scid scid
                           :token token :pn-offset pn-offset :length length-value
                           :end end :long-p t)))))))))))

(defun %client-truncated-number (bytes at length)
  (let ((number 0))
    (dotimes (index length number)
      (setf number (+ (ash number 8) (aref bytes (+ at index)))))))

(defun %client-unprotect-packet (client bytes layout)
  (let* ((type (getf layout :type))
         (level (case type (:initial :initial) (:handshake :handshake)
                 (:0-rtt :0-rtt) (:short :1-rtt)))
         (key (%client-key client level :read))
         (pn-offset (getf layout :pn-offset))
         (packet (subseq bytes 0 (getf layout :end))))
    (unless key (return-from %client-unprotect-packet nil))
    (when (< (length packet) (+ pn-offset 20))
      (error 'quic-encoding-error :message "packet is too short for header protection"))
    (let* ((sample (subseq packet (+ pn-offset 4) (+ pn-offset 20)))
           (unmasked4 (cl-quic-kit.protection:remove-header-protection
                       key packet sample pn-offset 4 (getf layout :long-p)))
           (first (aref unmasked4 0))
           (pn-length (1+ (logand first 3))))
      (when (> (+ pn-offset pn-length) (length packet))
        (error 'quic-encoding-error :message "truncated packet number"))
      (let* ((unmasked (cl-quic-kit.protection:remove-header-protection
                        key packet sample pn-offset pn-length (getf layout :long-p)))
             (truncated (%client-truncated-number unmasked pn-offset pn-length))
             (largest (or (first (%client-level-value
                                  (quic-client-received-packets client) level))
                          -1))
             (number (cl-quic-kit.protection:reconstruct-packet-number
                      truncated pn-length largest))
             (associated (subseq unmasked 0 (+ pn-offset pn-length)))
             (ciphertext (subseq unmasked (+ pn-offset pn-length)))
             (plaintext (cl-quic-kit.protection:unprotect-payload
                        key number ciphertext associated)))
        (values level number
                (make-packet-header
                 :type type :version (getf layout :version)
                 :destination-connection-id (getf layout :dcid)
                 :source-connection-id (getf layout :scid)
                 :packet-number number :packet-number-length pn-length
                 :reserved-bits (ldb (byte 2 2) first)
                 :key-phase (and (eq type :short) (logbitp 2 first))
                 :payload plaintext))))))

(defun %client-packet-header-prefix (header cipher-length)
  (let* ((header (make-packet-header
                  :type (packet-header-type header)
                  :version (packet-header-version header)
                  :destination-connection-id
                  (packet-header-destination-connection-id header)
                  :source-connection-id (packet-header-source-connection-id header)
                  :token (packet-header-token header)
                  :packet-number (packet-header-packet-number header)
                  :packet-number-length (packet-header-packet-number-length header)
                  :payload (make-array cipher-length
                                        :element-type '(unsigned-byte 8))
                  :key-phase (packet-header-key-phase header)))
         (wire (encode-packet-header header))
         (layout (%client-layout wire
                                 :short-header-dcid-length
                                 (length (packet-header-destination-connection-id header)))))
    (values wire (getf layout :pn-offset))))

(defun %client-build-packet (client level frames)
  (let* ((wire-level (if (eq level :application) :1-rtt level))
         (type (if (eq wire-level :1-rtt) :short wire-level))
         (key (%client-key client wire-level :write))
         (number (%client-packet-number client wire-level))
         (pn-length 2)
         (plaintext (encode-frames frames))
         (dcid (or (quic-client-remote-connection-id client) #()))
         (scid (if (eq type :short) #() (quic-client-local-connection-id client)))
         (token (if (eq type :initial) (quic-client-retry-token client) #())))
    (unless key (return-from %client-build-packet nil))
    (labels ((make-wire (payload)
               (let ((header (make-packet-header
                              :type type :version *quic-version-1*
                              :destination-connection-id dcid
                              :source-connection-id scid :token token
                              :packet-number number
                              :packet-number-length pn-length
                              :payload (make-array (+ (length payload) 16)
                                                   :element-type '(unsigned-byte 8)))))
                 (multiple-value-bind (wire pn-offset)
                     (%client-packet-header-prefix header (+ (length payload) 16))
                   (let* ((associated (subseq wire 0 (+ pn-offset pn-length)))
                          (ciphertext (cl-quic-kit.protection:protect-payload
                                       key number payload associated))
                          (packet (concatenate '(vector (unsigned-byte 8))
                                               associated ciphertext))
                          (sample (subseq packet (+ pn-offset 4) (+ pn-offset 20))))
                     (cl-quic-kit.protection:apply-header-protection
                      key packet sample pn-offset pn-length
                      (not (eq type :short))))))))
      (when (eq type :initial)
        (let ((header (make-packet-header
                       :type type :version *quic-version-1*
                       :destination-connection-id dcid
                       :source-connection-id scid :token token
                       :packet-number number :packet-number-length pn-length
                       :payload (make-array (+ (length plaintext) 16)
                                            :element-type '(unsigned-byte 8)))))
          (multiple-value-bind (ignored-wire pn-offset)
              (%client-packet-header-prefix header (+ (length plaintext) 16))
            (declare (ignore ignored-wire))
            (let ((needed (- 1200 (+ pn-offset pn-length
                                     (length plaintext) 16))))
              (when (plusp needed)
                (setf plaintext
                      (concatenate '(vector (unsigned-byte 8)) plaintext
                                   (make-array needed
                                               :element-type '(unsigned-byte 8)))))))))
      (when (< (length plaintext) 4)
        (setf plaintext
              (concatenate '(vector (unsigned-byte 8)) plaintext
                           (make-array (- 4 (length plaintext))
                                       :element-type '(unsigned-byte 8)))))
      (make-wire plaintext))))

(defun %client-ack-eliciting-p (frames)
  (some (lambda (frame)
          (not (member (frame-type frame) '(:ack :ack-ecn :padding)))) frames))

(defun %client-frame-ranges (numbers)
  (let ((sorted (sort (remove-duplicates (copy-list numbers)) #'>)) (ranges nil))
    (loop while sorted do
      (let* ((high (pop sorted)) (low high))
        (loop while (and sorted (= (1- low) (first sorted)))
              do (setf low (pop sorted)))
        (push (cons high (- high low)) ranges)))
    (nreverse ranges)))

(defun %client-ack-frame (client level)
  (let ((ranges (%client-frame-ranges
                 (%client-level-value (quic-client-received-packets client) level))))
    (when ranges
      (let ((previous-smallest (- (caar ranges) (cdar ranges))))
        (make-frame :ack :largest-acknowledged (caar ranges) :ack-delay 0
                    :ranges
                    (cons (car ranges)
                          (mapcar
                           (lambda (range)
                             (prog1 (list :gap (- previous-smallest
                                                   (car range) 2)
                                          :range-length (cdr range))
                               (setf previous-smallest
                                     (- (car range) (cdr range)))))
                           (cdr ranges))))))))

(defun %client-sent-packet-number (packet)
  (let ((reader (%client-function "CL-QUIC-KIT.RECOVERY" "SENT-PACKET-NUMBER")))
    (and reader (funcall reader packet))))

(defun %client-record-sent (client level number frames sent-at)
  (push (list :level level :number number :frames frames :sent-at sent-at
              :requeued-p nil)
        (quic-client-sent-packets client)))

(defun %client-requeue-record (client record)
  (unless (getf record :requeued-p)
    (setf (getf record :requeued-p) t)
    (dolist (frame (getf record :frames))
      (%client-queue-frame client frame (%client-space-level (getf record :level))))))

(defun %client-drop-records (client packets requeue-p)
  (dolist (packet packets)
    (let ((number (%client-sent-packet-number packet)))
      (when number
        (let ((record (find number (quic-client-sent-packets client)
                            :key (lambda (entry) (getf entry :number)))))
          (when record
            (when requeue-p (%client-requeue-record client record))
            (setf (quic-client-sent-packets client)
                  (delete record (quic-client-sent-packets client)
                          :test #'eq))))))))

(defun %client-reset-space (client space)
  (setf (quic-client-packet-numbers client)
        (%client-set-level-value (quic-client-packet-numbers client) space 0)
        (quic-client-received-packets client)
        (%client-set-level-value (quic-client-received-packets client) space nil)
        (quic-client-sent-packets client)
        (delete-if (lambda (record) (eq (getf record :level) space))
                   (quic-client-sent-packets client)))
  (cl-quic-kit.recovery:reset-packet-number-space
   (quic-client-recovery client) space))

(defun %client-send-frames (client level frames)
  (let* ((space (%client-level-space level))
         (number (or (1- (or (%client-level-value
                              (quic-client-packet-numbers client) level) 0)) 0))
         (packet (%client-build-packet client level frames)))
    (when packet
      (connection-write (quic-client-connection client) packet)
      (let ((sent-at (funcall (quic-client-clock client))))
        (cl-quic-kit.recovery:record-sent-packet
         (quic-client-recovery client) space number (length packet)
         :ack-eliciting-p (%client-ack-eliciting-p frames)
         :in-flight-p (%client-ack-eliciting-p frames) :sent-at sent-at)
        (%client-record-sent client space number frames sent-at))
      packet)))

(defun %client-handle-ack (client level frame)
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame
       (quic-client-recovery client) (%client-level-space level)
       (frame-field frame :largest-acknowledged)
       (frame-field frame :ranges)
       :ack-delay (frame-field frame :ack-delay 0))
    (%client-drop-records client acked nil)
    (%client-drop-records client lost t)))

(defun %client-receive-frames (client level number frames)
  (let ((space (%client-level-space level)))
    (connection-touch (quic-client-connection client))
    (setf (quic-client-received-packets client)
          (%client-set-level-value
           (quic-client-received-packets client) level
           (cons number (%client-level-value
                         (quic-client-received-packets client) level))))
    (cl-quic-kit.recovery:on-packet-received
     (quic-client-recovery client) space number
     :ack-eliciting-p (%client-ack-eliciting-p frames)))
  (dolist (frame frames)
    (case (frame-type frame)
      ((:ack :ack-ecn) (%client-handle-ack client level frame))
      (:stream
       (let ((stream (%client-find-or-create-peer-stream
                      client (frame-field frame :stream-id))))
         (stream-receive-data stream (frame-field frame :offset 0)
                              (frame-field frame :data #())
                              :fin (frame-field frame :fin nil))))
      (:crypto (client-tls-feed client level (frame-field frame :offset 0)
                                (frame-field frame :data #())))
      ((:connection-close :application-close)
       (connection-receive-frame (quic-client-connection client) frame))
      (:handshake-done
       (connection-set-state (quic-client-connection client) :established))
      (otherwise nil))))

(defun make-quic-client (&key connection udp-socket tls-boundary tls-driver
                              local-connection-id destination-connection-id
                              server-host server-port hostname (alpn '("h3"))
                              transport-parameters tls-key-exchange tls-provider
                              tls-trust-anchors tls-verify-signature now-fn
                              tls-signature-algorithms
                              idle-timeout io-write on-close)
  "Create a protected QUIC client and its HTTP stream facade."
  (let* ((udp (or udp-socket
                  (and server-host server-port
                       (make-udp-socket :remote-host server-host
                                        :remote-port server-port))))
         (local (or local-connection-id (%client-random-octets 8)))
         (destination (or destination-connection-id (%client-random-octets 8)))
         (clock (or now-fn #'get-internal-real-time))
         (write (or io-write
                    (and udp (lambda (ignored bytes)
                               (declare (ignore ignored)) (udp-send udp bytes)))))
         (connection (or connection
                         (make-quic-connection
                          :role :client :local-connection-id local :now-fn clock
                          :idle-timeout (or idle-timeout *quic-idle-timeout-default*)
                          :io-write write :on-close on-close)))
         (client (%make-quic-client
                  :connection connection :udp-socket udp :tls-boundary tls-boundary
                  :tls-driver tls-driver :streams (make-hash-table :test #'eql)
                  :next-bidi-stream 0 :next-uni-stream 2 :pending-frames nil
                  :crypto-send-offsets nil :tls-secrets nil
                  :peer-transport-parameters nil :closed-p nil :started-p nil
                  :initial-destination-connection-id destination
                  :remote-connection-id destination :retry-token #()
                  :packet-numbers nil :received-packets nil :keys nil
                  :recovery (cl-quic-kit.recovery:make-recovery-state :clock clock)
                  :sent-packets nil :clock clock :local-connection-id local
                  :server-host server-host :server-port server-port
                  :hostname hostname :alpn alpn
                  :transport-parameters (or transport-parameters
                                            (%client-transport-parameters local))
                  :tls-key-exchange tls-key-exchange :tls-provider tls-provider
                  :tls-trust-anchors tls-trust-anchors
                  :tls-verify-signature tls-verify-signature
                  :tls-signature-algorithms tls-signature-algorithms)))
    (handler-case
        (let ((initial (cl-quic-kit.protection:derive-initial-secrets destination)))
          (%client-set-key client :initial :write (getf initial :client))
          (%client-set-key client :initial :read (getf initial :server)))
      (error () nil))
    client))

(defun client-open-stream (client request &key stream-type timeout deadline)
  (declare (ignore request timeout deadline))
  (when (quic-client-closed-p client)
    (error 'connection-closed :error-code 0 :reason #()))
  (let* ((uni-type (%client-stream-type stream-type))
         (id (if uni-type
                 (prog1 (quic-client-next-uni-stream client)
                   (incf (quic-client-next-uni-stream client) 4))
                 (prog1 (quic-client-next-bidi-stream client)
                   (incf (quic-client-next-bidi-stream client) 4))))
         (stream (make-stream id :local-initiator :client)))
    (setf (gethash id (quic-client-streams client)) stream)
    (when uni-type
      (incf (stream-send-offset stream) (length (encode-varint uni-type)))
      (%client-queue-frame client
                           (make-frame :stream :stream-id id :offset 0
                                       :data (encode-varint uni-type)
                                       :fin nil :len-present t)
                           :1-rtt))
    stream))

(defun client-write-stream (client stream octets &key (fin-p nil) timeout deadline)
  (declare (ignore timeout deadline))
  (unless (eq (gethash (stream-id stream) (quic-client-streams client)) stream)
    (error 'quic-error))
  (let* ((result (stream-write stream octets))
         (frame (make-frame :stream :stream-id (stream-id stream)
                            :offset (getf result :offset) :data (getf result :data)
                            :fin fin-p :len-present t)))
    (%client-queue-frame client frame :1-rtt)
    (when fin-p (stream-finish stream))
    frame))

(defun client-read-stream (client stream &key timeout deadline)
  (declare (ignore client timeout deadline)) (stream-read stream))

(defun client-close-stream (client stream &key condition)
  (declare (ignore condition))
  (when (gethash (stream-id stream) (quic-client-streams client))
    (unless (stream-finished-p stream) (ignore-errors (stream-finish stream)))
    (remhash (stream-id stream) (quic-client-streams client)))
  t)

(defun client-flush (client)
  "Packetize all queued frames, preserving their QUIC encryption level."
  (let ((pending (prog1 (quic-client-pending-frames client)
                  (setf (quic-client-pending-frames client) nil)))
        (groups nil))
    (dolist (entry pending)
      (let ((group (assoc (car entry) groups)))
        (if group (push (cdr entry) (cdr group))
            (push (cons (car entry) (list (cdr entry))) groups))))
    (dolist (group groups)
      (let ((frames (reverse (cdr group))))
        (unless (%client-send-frames client (car group) frames)
          (dolist (frame frames)
            (connection-write (quic-client-connection client) (encode-frame frame)))))))
  t)

(defun %client-find-or-create-peer-stream (client id)
  (or (gethash id (quic-client-streams client))
      (setf (gethash id (quic-client-streams client))
            (make-stream id :local-initiator :client))))

(defun client-receive-frame (client frame)
  (%client-receive-frames client :initial 0 (list frame))
  frame)

(defun %client-retry-header (bytes)
  (multiple-value-bind (header end) (decode-packet-header bytes)
    (declare (ignore end)) header))

(defun %client-handle-retry (client bytes)
  (let* ((header (%client-retry-header bytes))
         (tag (packet-header-retry-integrity-tag header))
         (pseudo (subseq bytes 0 (- (length bytes) 16))))
    (unless (verify-retry-integrity
             pseudo tag :original-destination-connection-id
             (quic-client-initial-destination-connection-id client))
      (error 'quic-encoding-error :message "Retry integrity tag mismatch"))
    (setf (quic-client-retry-token client) (packet-header-token header)
          (quic-client-remote-connection-id client)
          (packet-header-source-connection-id header))
    (let ((initial (cl-quic-kit.protection:derive-initial-secrets
                    (quic-client-remote-connection-id client))))
      (%client-set-key client :initial :write (getf initial :client))
      (%client-set-key client :initial :read (getf initial :server)))
    (%client-reset-space client :initial)
    (when (quic-client-client-hello-wire client)
      (%client-queue-frame
       client (make-frame :crypto :offset 0
                          :data (quic-client-client-hello-wire client)) :initial))))

(defun %client-handle-version-negotiation (client bytes)
  (declare (ignore client))
  (let ((decoded (decode-version-negotiation bytes)))
    (unless (member *quic-version-1* (getf decoded :versions))
      (error 'quic-encoding-error :message "peer does not support QUIC v1"))))

(defun client-receive-datagram (client bytes &key (short-header-dcid-length 8))
  "Decrypt and dispatch all packets in one UDP datagram."
  (handler-case
      (let ((bytes (ensure-octets bytes)) (at 0) (last-header nil))
        (loop while (< at (length bytes)) do
          (let* ((slice (subseq bytes at))
                 (layout (%client-layout
                           slice :short-header-dcid-length short-header-dcid-length)))
            (case (getf layout :type)
              (:version-negotiation (%client-handle-version-negotiation client slice)
                                    (return))
              (:retry (%client-handle-retry client slice) (return)))
            (multiple-value-bind (level number header)
                (%client-unprotect-packet client slice layout)
              (when header
                (when (and (member level '(:initial :handshake))
                           (plusp (length (packet-header-source-connection-id header))))
                  (setf (quic-client-remote-connection-id client)
                        (packet-header-source-connection-id header)))
                (let ((frames (decode-frames (packet-header-payload header))))
                  (%client-receive-frames client level number frames)
                  (setf last-header header)))
              (setf at (+ at (getf layout :end)))
              (when (not (getf layout :long-p)) (return)))))
        last-header)
    (quic-error (condition)
      (%client-protocol-close client 7 (quic-error-message condition)) nil)
    (error (condition)
      (%client-protocol-close client 7 (princ-to-string condition)) nil)))

(defun make-client-tls-boundary (client &key transport-parameters)
  "Attach cl-tls-kit's QUIC CRYPTO boundary."
  (let ((constructor (%client-function "CL-TLS-KIT" "MAKE-QUIC-TLS-BOUNDARY")))
    (unless constructor (error 'crypto-unavailable :operation :quic-tls-boundary))
    (setf (quic-client-tls-boundary client)
          (funcall constructor
                   :role :client
                   :hash-function
                   (let ((digest (%client-function "CRYPTO-KIT" "DIGEST")))
                     (and digest
                          (lambda (bytes) (funcall digest :sha256 bytes))))
                   :transport-parameters
                   (or transport-parameters (quic-client-transport-parameters client))
                   :on-crypto
                   (lambda (boundary level wire)
                     (declare (ignore boundary))
                     (let ((offset (or (%client-level-value
                                        (quic-client-crypto-send-offsets client) level) 0)))
                       (setf (quic-client-crypto-send-offsets client)
                             (%client-set-level-value
                              (quic-client-crypto-send-offsets client) level
                              (+ offset (length wire))))
                       (%client-queue-frame client
                                            (make-frame :crypto :offset offset
                                                        :data wire) level)))
                   :on-secret
                   (lambda (boundary level direction secret)
                     (declare (ignore boundary))
                     (push (list level direction secret)
                           (quic-client-tls-secrets client)))
                   :on-transport-parameters
                   (lambda (boundary parameters)
                     (declare (ignore boundary))
                     (setf (quic-client-peer-transport-parameters client) parameters))))
    (quic-client-tls-boundary client)))

(defun %client-driver-key-exchange (client)
  (or (quic-client-tls-key-exchange client)
      (let ((x25519 (%client-function "CRYPTO-KIT" "X25519"))
            (base (%client-function "CRYPTO-KIT" "X25519-BASE"))
            (random (%client-function "CRYPTO-KIT" "RANDOM-OCTETS")))
        (unless (and x25519 base random)
          (error 'crypto-unavailable :operation :x25519))
        (list :generate
              (lambda (group)
                (unless (= group #x001d) (error 'quic-error))
                (let ((private (funcall random 32)))
                  (values private (funcall base private))))
              :shared-secret
              (lambda (group private public)
                (declare (ignore group))
                (multiple-value-bind (secret all-zero) (funcall x25519 private public)
                  (when all-zero
                    (error 'quic-crypto-error :message "X25519 all-zero"))
                  secret))
              :random (lambda (length) (funcall random length))))))

(defun make-client-tls-driver (client)
  (let ((constructor (%client-function "CL-TLS-KIT" "MAKE-TLS13-CLIENT-DRIVER")))
    (unless constructor (error 'crypto-unavailable :operation :tls13-client-driver))
    (let* ((provider (or (quic-client-tls-provider client)
                         (let ((make-provider (%client-function
                                               "CL-TLS-KIT"
                                               "MAKE-CL-CRYPTO-KIT-PROVIDER")))
                           (unless make-provider
                             (error 'crypto-unavailable :operation :tls-provider))
                           (funcall make-provider))))
           (driver nil))
      (setf driver
            (funcall constructor
                     :provider provider
                     :key-exchange (%client-driver-key-exchange client)
                     :hostname (quic-client-hostname client)
                     :alpn (quic-client-alpn client)
                     :trust-anchors (quic-client-tls-trust-anchors client)
                     :verify-signature (quic-client-tls-verify-signature client)
                     :on-send
                     (lambda (driver wire)
                       (let* ((type (aref wire 0))
                              (level (if (= type 1) :initial
                                         (if (= type 20) :handshake :1-rtt)))
                              (boundary (quic-client-tls-boundary client))
                              (before (length (quic-client-pending-frames client))))
                         (unless boundary (error 'quic-error))
                         (if (and (= type 1)
                                  (%client-function "CL-TLS-KIT"
                                                    "QUIC-TLS-BOUNDARY-SEND-WITH-TRANSPORT-PARAMETERS"))
                             (funcall (%client-function
                                       "CL-TLS-KIT"
                                       "QUIC-TLS-BOUNDARY-SEND-WITH-TRANSPORT-PARAMETERS")
                                      boundary level type (subseq wire 4)
                                      (quic-client-transport-parameters client))
                             (funcall (%client-function "CL-TLS-KIT"
                                                        "QUIC-TLS-BOUNDARY-SEND")
                                      boundary level type (subseq wire 4)))
                         (when (and (= type 1)
                                    (> (length (quic-client-pending-frames client)) before))
                           (setf (quic-client-client-hello-wire client)
                                 (frame-field
                                  (cdar (quic-client-pending-frames client)) :data))
                           ;; The boundary-added transport-parameters extension is
                           ;; part of the TLS transcript seen by the peer.
                           (let ((transcript (%client-driver-slot
                                              driver "TLS13-CLIENT-DRIVER-TRANSCRIPT")))
                             (when transcript
                               (let ((sent (quic-client-client-hello-wire client)))
                                 (%client-driver-set-slot
                                  driver "TLS13-CLIENT-DRIVER-TRANSCRIPT"
                                  (concatenate '(vector (unsigned-byte 8))
                                               (subseq transcript 0
                                                       (- (length transcript)
                                                          (length wire)))
                                     sent))))))))))
      (when (quic-client-tls-signature-algorithms client)
        (%client-driver-set-slot
         driver "TLS13-CLIENT-DRIVER-SIGNATURE-ALGORITHMS"
         (quic-client-tls-signature-algorithms client)))
      (setf (quic-client-tls-driver client) driver)
      driver)))

(defun client-tls-feed (client level offset bytes)
  "Feed one protected CRYPTO frame through the TLS boundary and driver."
  (let ((feed (%client-function "CL-TLS-KIT" "QUIC-TLS-BOUNDARY-FEED-CRYPTO"))
        (step (%client-function "CL-TLS-KIT" "TLS13-CLIENT-DRIVER-STEP")))
    (when (and feed step (quic-client-tls-boundary client)
               (quic-client-tls-driver client))
      (dolist (message (funcall feed (quic-client-tls-boundary client)
                                level offset bytes))
        (funcall step (quic-client-tls-driver client) (getf message :wire))
        (%client-sync-tls-secrets client)))))

(defun client-start (client)
  "Start TLS and send ClientHello in a protected Initial packet."
  (unless (quic-client-started-p client)
    (unless (quic-client-tls-boundary client) (make-client-tls-boundary client))
    (unless (quic-client-tls-driver client) (make-client-tls-driver client))
    (let ((start (%client-function "CL-TLS-KIT" "TLS13-CLIENT-DRIVER-START")))
      (unless start (error 'crypto-unavailable :operation :tls-start))
      (funcall start (quic-client-tls-driver client)))
    (setf (quic-client-started-p client) t)
    (client-flush client))
  client)

(defun %client-protocol-close (client code reason)
  (unless (quic-client-closed-p client)
    (setf (quic-client-closed-p client) t)
    (%client-queue-frame
     client (make-frame :connection-close :error-code code :frame-type 0
                        :reason (%client-reason-octets reason))
     (if (%client-key client :1-rtt :write) :1-rtt :initial))
    (connection-set-state (quic-client-connection client) :closing)
    (client-flush client)))

(defun %client-poll-udp (client)
  (when (quic-client-udp-socket client)
    (loop
      (multiple-value-bind (bytes length address) (udp-receive (quic-client-udp-socket client))
        (declare (ignore length address))
        (unless bytes (return))
        (client-receive-datagram
         client bytes :short-header-dcid-length
         (length (quic-client-local-connection-id client)))))))

(defun %client-poll-recovery (client at)
  (dolist (space '(:initial :handshake :application))
    (multiple-value-bind (lost loss)
        (cl-quic-kit.recovery:on-loss-timeout
         (quic-client-recovery client) space :now at)
      (declare (ignore loss))
      (%client-drop-records client lost t))
    (let ((pto (cl-quic-kit.recovery:pto-deadline
                (quic-client-recovery client) space :now at)))
      (when (and pto (>= at pto))
        (cl-quic-kit.recovery:on-pto-expired (quic-client-recovery client))
        (%client-queue-frame client (make-frame :ping)
                             (%client-space-level space))))))

(defun client-poll (client &optional at)
  "Drive UDP receive, ACK generation, loss/PTO probes, and idle timeout."
  (let ((now (or at (funcall (quic-client-clock client)))))
    (when (and (not (quic-client-started-p client))
               (or (quic-client-tls-driver client)
                   (quic-client-tls-boundary client)
                   (and (quic-client-server-host client)
                        (quic-client-server-port client))))
      (client-start client))
    (%client-poll-udp client)
    (dolist (level '(:initial :handshake :1-rtt))
      (when (cl-quic-kit.recovery:ack-needed-p
             (quic-client-recovery client) (%client-level-space level) :now now)
        (let ((ack (%client-ack-frame client level)))
          (when ack
            (%client-queue-frame client ack level)
            (cl-quic-kit.recovery:on-ack-sent
             (quic-client-recovery client) (%client-level-space level))))))
    (%client-poll-recovery client now)
    (when (connection-idle-expired-p (quic-client-connection client) now)
      (%client-protocol-close client 0 "idle timeout"))
    (client-flush client)
    (connection-poll (quic-client-connection client) now)))

(defun client-close (client &key (error-code :no-error) reason)
  (%client-protocol-close
   client (if (integerp error-code) error-code (%connection-error-code error-code)) reason)
  (when (quic-client-udp-socket client) (udp-close (quic-client-udp-socket client)))
  t)
