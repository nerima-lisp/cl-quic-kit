(in-package #:cl-quic-kit)

;;;; QUIC client packet engine and HTTP stream facade.

(defstruct (quic-client (:constructor %make-quic-client))
  connection udp-socket tls-boundary tls-driver
  streams next-bidi-stream next-uni-stream
  pending-frames pending-stream-writes crypto-send-offsets
  peer-transport-parameters closed-p started-p
  flow-control
  initial-destination-connection-id remote-connection-id retry-token
  packet-numbers received-packets keys recovery sent-packets clock
  (application-read-key-phase 0)
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

(defparameter *client-packet-payload-limit* 1100)

(defun %client-frame-data (frame)
  (frame-field frame :data #()))

(defun %client-split-frame (frame)
  (if (not (member (frame-type frame) '(:stream :crypto)))
      (list frame)
      (let* ((data (%client-frame-data frame))
             (length (length data))
             (chunks nil)
             (at 0))
        (if (zerop length)
            (list frame)
            (progn
              (loop while (< at length) do
              (let* ((remaining (- length at)) (low 1) (high remaining) (best 0))
                (loop while (<= low high) do
                  (let* ((middle (floor (+ low high) 2))
                         (fields (copy-list (frame-fields frame))))
                    (setf (getf fields :data) (subseq data at (+ at middle))
                          (getf fields :offset)
                          (+ (or (getf fields :offset) 0) at)
                          (getf fields :fin)
                          (and (getf fields :fin) (= (+ at middle) length)))
                    (if (<= (length (encode-frame
                                     (apply #'make-frame (frame-type frame) fields)))
                            *client-packet-payload-limit*)
                        (setf best middle low (1+ middle))
                        (setf high (1- middle)))))
                (when (zerop best)
                  (error 'quic-encoding-error
                         :message "Frame cannot fit in a QUIC packet"))
                (let ((fields (copy-list (frame-fields frame))))
                  (setf (getf fields :data) (subseq data at (+ at best))
                        (getf fields :offset)
                        (+ (or (getf fields :offset) 0) at)
                        (getf fields :fin)
                        (and (getf fields :fin) (= (+ at best) length)))
                  (push (apply #'make-frame (frame-type frame) fields) chunks))
                (incf at best)))
              (nreverse chunks))))))

(defun %client-frame-packet-groups (frames)
  (let ((groups nil) (current nil) (size 0))
    (dolist (frame frames)
      (dolist (part (%client-split-frame frame))
        (let ((part-size (length (encode-frame part))))
          (when (> part-size *client-packet-payload-limit*)
            (error 'quic-encoding-error
                   :message "Frame exceeds the QUIC packet payload limit"))
          (if (and current
                   (> (+ size part-size) *client-packet-payload-limit*))
              (progn
                (push (nreverse current) groups)
                (setf current (list part) size part-size))
              (progn
                (push part current)
                (incf size part-size))))))
    (when current (push (nreverse current) groups))
    (nreverse groups)))

(defun %client-octets (value)
  (ensure-octets (or value #())))

(defun %client-function (package-name symbol-name)
  (let* ((package (find-package package-name))
         (symbol (and package (find-symbol symbol-name package))))
    (and symbol (fboundp symbol) (symbol-function symbol))))

(defun %client-tls-boundary-error-p (condition)
  (let ((type (find-symbol "QUIC-TLS-BOUNDARY-ERROR" "CL-TLS-KIT")))
    (and type (typep condition type))))

(defun %client-tls-level-call (level function)
  (handler-case
      (funcall function level)
    (error (condition)
      (if (and (eq level :application)
               (%client-tls-boundary-error-p condition))
          (funcall function :1-rtt)
          (error condition)))))

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
    (unless random
      (error 'randomness-unavailable :operation :connection-id))
    (handler-case
        (let ((value (funcall random length)))
          (unless (and (typep value '(simple-array (unsigned-byte 8) (*)))
                       (= (length value) length))
            (error 'randomness-unavailable :operation :connection-id))
          value)
      (randomness-unavailable (condition)
        (error condition))
      (error ()
        (error 'randomness-unavailable :operation :connection-id)))))

(defun %client-reason-octets (reason)
  (%connection-reason-octets reason))

(defun %client-crypto-signature-scheme (scheme)
  (case scheme
    (:ecdsa-secp256r1-sha256 :ecdsa-p256-sha256)
    (:ecdsa-secp384r1-sha384 :ecdsa-p384-sha384)
    (:ecdsa-secp521r1-sha512 :ecdsa-p521-sha512)
    (otherwise scheme)))

(defun %client-signature-verifier (client)
  (let ((verify (or (quic-client-tls-verify-signature client)
                    (%client-function "CRYPTO-KIT" "VERIFY-SIGNATURE"))))
    (when verify
      (lambda (scheme public-key message signature)
        (funcall verify (%client-crypto-signature-scheme scheme)
                 public-key message signature)))))

(defun %client-stream-type (stream-type)
  (case stream-type
    (:control 0) (:qpack-encoder 2) (:qpack-decoder 3) (otherwise nil)))

(defun %client-transport-parameter (parameters id default)
  (let ((value (cdr (assoc id parameters))))
    (if (integerp value) value default)))

(defun %client-stream-send-limit (client id)
  (let ((parameters (quic-client-peer-transport-parameters client)))
    (if (eq (stream-id-direction id) :bidirectional)
        (%client-transport-parameter parameters 6 *quic-max-offset*)
        (%client-transport-parameter parameters 7 *quic-max-offset*))))

(defun %client-stream-receive-limit (client id)
  (declare (ignore client))
  (if (eq (stream-id-direction id) :bidirectional) 65536 65536))

(defun %client-check-deadline (client timeout deadline)
  (let ((now (funcall (quic-client-clock client))))
    (when (and timeout (not (and (numberp timeout) (>= timeout 0))))
      (error 'quic-error))
    (when (and deadline (not (numberp deadline)))
      (error 'quic-error))
    (when (and (or deadline timeout)
               (<= (or deadline (+ now timeout)) now))
      (error 'quic-error))))

(defun %client-apply-max-data (client maximum)
  (let ((flow (quic-client-flow-control client)))
    (if (and (null (quic-client-peer-transport-parameters client))
             (zerop (flow-control-connection-sent flow)))
        (setf (flow-control-state-connection-max-data flow) maximum)
        (flow-control-update-max-data flow maximum))))

(defun %client-apply-max-streams (client direction maximum)
  (let ((flow (quic-client-flow-control client)))
    (if (and (null (quic-client-peer-transport-parameters client))
             (zerop (flow-control-stream-count flow direction)))
        (ecase direction
          (:bidirectional (setf (flow-control-state-max-streams-bidi flow) maximum))
          (:unidirectional (setf (flow-control-state-max-streams-uni flow) maximum)))
        (flow-control-update-max-streams flow direction maximum))))

(defun %client-driver-suite-cipher (driver)
  (case (%client-driver-slot driver "TLS13-CLIENT-DRIVER-SUITE")
    (#x1302 :aes-256-gcm)
    (#x1303 :chacha20-poly1305)
    (otherwise :aes-128-gcm)))

(defun %client-install-secret (client level direction secret &key replace-p)
  (let ((wire-level (%client-space-level level)))
    (when (or replace-p (not (%client-key client wire-level direction)))
      (%client-set-key
       client wire-level direction
       (cl-quic-kit.protection:make-key-set
        secret :cipher (%client-driver-suite-cipher (quic-client-tls-driver client))))
      (let ((boundary (quic-client-tls-boundary client))
            (emit (%client-function "CL-TLS-KIT" "QUIC-TLS-BOUNDARY-EMIT-SECRET")))
        (when (and boundary emit)
          (%client-tls-level-call
           (%client-level-space level) (lambda (tls-level)
                   (funcall emit boundary tls-level direction secret))))))))

(defun %client-rotate-application-read-key (client)
  (let* ((driver (quic-client-tls-driver client))
         (state (%client-driver-slot driver
                                     "TLS13-CLIENT-DRIVER-APPLICATION-READ-STATE"))
         (update (%client-function "CL-TLS-KIT" "TLS13-UPDATE-TRAFFIC-SECRET"))
         (secret-reader (%client-function "CL-TLS-KIT"
                                          "TLS13-TRAFFIC-STATE-SECRET")))
    (when (and driver state update secret-reader)
      (funcall update state)
      (%client-install-secret client :1-rtt :read (funcall secret-reader state)
                              :replace-p t)
      t)))

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

(defun %client-unprotect-packet (client bytes layout &optional retried-p)
  (let* ((type (getf layout :type))
         (level (case type (:initial :initial) (:handshake :handshake)
                 (:0-rtt :0-rtt) (:short :1-rtt)))
         (key (%client-key client level :read))
         (pn-offset (getf layout :pn-offset))
         (packet (subseq bytes 0 (getf layout :end))))
    (unless key (return-from %client-unprotect-packet nil))
    (when (< (length packet) (+ pn-offset 20))
      (error 'quic-encoding-error :message "packet is too short for header protection"))
    (handler-case
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
                 (plaintext
                   (cl-quic-kit.protection:unprotect-payload
                    key number ciphertext associated)))
            (let ((key-phase (and (eq type :short) (logbitp 2 first))))
              (when (and (eq level :1-rtt) key-phase)
                (setf (quic-client-application-read-key-phase client) 1))
              (values level number
                      (make-packet-header
                       :type type :version (getf layout :version)
                       :destination-connection-id (getf layout :dcid)
                       :source-connection-id (getf layout :scid)
                       :packet-number number :packet-number-length pn-length
                       :reserved-bits (ldb (byte 2 2) first)
                       :key-phase key-phase
                       :payload plaintext)))))
      (error (caught)
        (if (and (eq level :1-rtt) (not retried-p)
                 (%client-rotate-application-read-key client))
            (%client-unprotect-packet client bytes layout t)
            (error caught))))))

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

(defun %client-requeue-pto-probe (client space)
  (let ((record (find-if
                 (lambda (entry)
                   (and (eq (getf entry :level) space)
                        (not (getf entry :requeued-p))
                        (some (lambda (frame)
                                (not (member (frame-type frame)
                                             '(:ack :ack-ecn :padding))))
                              (getf entry :frames))))
                 (quic-client-sent-packets client))))
    (when record
      (%client-requeue-record client record))))

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
  (let* ((wire-level (if (eq level :application) :1-rtt level))
         (space (%client-level-space wire-level))
         (number (or (1- (or (%client-level-value
                              (quic-client-packet-numbers client) wire-level)
                         0))))
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
      (:max-data
       (%client-apply-max-data client (frame-field frame :maximum 0)))
      (:max-streams-bidi
       (%client-apply-max-streams client :bidirectional
                                  (frame-field frame :maximum 0)))
      (:max-streams-uni
       (%client-apply-max-streams client :unidirectional
                                  (frame-field frame :maximum 0)))
      (:max-stream-data
       (let ((stream (gethash (frame-field frame :stream-id)
                              (quic-client-streams client))))
         (unless stream
           (error 'quic-encoding-error :message "MAX_STREAM_DATA for unknown stream"))
         (if (and (null (quic-client-peer-transport-parameters client))
                  (zerop (stream-send-offset stream)))
             (setf (stream-send-max-offset stream) (frame-field frame :maximum 0))
             (stream-set-max-send-offset stream (frame-field frame :maximum 0)))))
      (:reset-stream
       (let ((stream (gethash (frame-field frame :stream-id)
                              (quic-client-streams client))))
         (unless stream
           (error 'quic-encoding-error :message "RESET_STREAM for unknown stream"))
         (stream-reset-receive
          stream (frame-field frame :application-protocol-error-code 0)
          (frame-field frame :final-size 0))))
      (:stop-sending
       (let ((stream (gethash (frame-field frame :stream-id)
                              (quic-client-streams client))))
         (unless stream
           (error 'quic-encoding-error :message "STOP_SENDING for unknown stream"))
         (stream-stop-sending-receive
          stream (frame-field frame :application-protocol-error-code 0))
         (loop for event = (stream-next-event stream)
               while event
               when (eq (getf event :type) :reset-stream)
                 do (%client-queue-frame
                     client (make-frame :reset-stream
                                        :stream-id (stream-id stream)
                                        :application-protocol-error-code
                                        (getf event :error-code 0)
                                        :final-size (getf event :final-size 0))
                     :1-rtt))))
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
       (unless (quic-client-closed-p client)
         (connection-set-state (quic-client-connection client) :established)))
      (otherwise nil))))

(defun make-quic-client (&key connection udp-socket tls-boundary tls-driver
                              local-connection-id destination-connection-id
                              server-host server-port hostname
                              disable-hostname-verification-p (alpn '("h3"))
                              transport-parameters tls-key-exchange tls-provider
                              tls-trust-anchors tls-verify-signature now-fn
                              tls-signature-algorithms
                              idle-timeout io-write on-close)
  "Create a protected QUIC client and its HTTP stream facade."
  (unless (or hostname disable-hostname-verification-p)
    (error 'hostname-required))
  (let* ((udp (or udp-socket
                  (and server-host server-port
                       (make-udp-socket :remote-host server-host
                                        :remote-port server-port))))
         (local (or local-connection-id (%client-random-octets 8)))
         (destination (or destination-connection-id (%client-random-octets 8)))
         (clock (or now-fn #'%quic-real-time))
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
                  :pending-stream-writes nil
                  :application-read-key-phase 0
                  :crypto-send-offsets nil
                  :peer-transport-parameters nil :closed-p nil :started-p nil
                  :flow-control
                  (make-flow-control-state
                   :max-data *quic-max-offset*
                   :max-receive-data 1048576
                   :max-streams-bidi *quic-max-streams*
                   :max-streams-uni *quic-max-streams*)
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
    (let ((initial (cl-quic-kit.protection:derive-initial-secrets destination)))
      (%client-set-key client :initial :write (getf initial :client))
      (%client-set-key client :initial :read (getf initial :server)))
    client))

(defun client-open-stream (client request &key stream-type timeout deadline)
  (declare (ignore request))
  (%client-check-deadline client timeout deadline)
  (when (quic-client-closed-p client)
    (error 'connection-closed :error-code 0 :reason #()))
  (let* ((uni-type (%client-stream-type stream-type))
         (direction (if uni-type :unidirectional :bidirectional)))
    (handler-case
        (flow-control-open-stream (quic-client-flow-control client) direction)
      (flow-control-limit-error (condition)
        (%client-queue-frame
         client (make-frame (if uni-type :streams-blocked-uni
                                :streams-blocked-bidi)
                            :maximum (flow-control-error-limit condition))
         :1-rtt)
        (error condition)))
  (let* ((uni-type (%client-stream-type stream-type))
         (id (if uni-type
                 (prog1 (quic-client-next-uni-stream client)
                   (incf (quic-client-next-uni-stream client) 4))
                 (prog1 (quic-client-next-bidi-stream client)
                   (incf (quic-client-next-bidi-stream client) 4))))
         (stream (make-stream id :local-initiator :client
                              :flow-control (quic-client-flow-control client)
                              :max-send-data (%client-stream-send-limit client id)
                              :max-receive-data (%client-stream-receive-limit client id))))
    (setf (gethash id (quic-client-streams client)) stream)
    (when uni-type
      (incf (stream-send-offset stream) (length (encode-varint uni-type)))
      (%client-queue-frame client
                           (make-frame :stream :stream-id id :offset 0
                                       :data (encode-varint uni-type)
                                       :fin nil :len-present t)
                           :1-rtt))
    stream)))

(defun %client-stream-send-credit (client stream)
  (min (- (stream-send-max-offset stream) (stream-send-offset stream))
       (- (flow-control-connection-max-data (quic-client-flow-control client))
          (flow-control-connection-sent (quic-client-flow-control client)))))

(defun %client-queue-pending-stream-write (client stream octets fin-p)
  (setf (quic-client-pending-stream-writes client)
        (nconc (quic-client-pending-stream-writes client)
               (list (list stream octets fin-p)))))

(defun %client-write-stream-available (client stream octets fin-p)
  (let* ((credit (max 0 (%client-stream-send-credit client stream)))
         (count (min credit (length octets)))
         (data (subseq octets 0 count)))
    (when (and (zerop count) (plusp (length octets)))
      (%client-queue-frame
       client (make-frame :data-blocked
                          :maximum (flow-control-connection-max-data
                                    (quic-client-flow-control client)))
       :1-rtt)
      (%client-queue-pending-stream-write client stream octets fin-p)
      (return-from %client-write-stream-available nil))
    (let* ((result (handler-case
                       (stream-write stream data)
                     (flow-control-limit-error (condition)
                       (%client-queue-frame
                        client (make-frame :data-blocked
                                           :maximum (flow-control-error-limit condition))
                        :1-rtt)
                       (error condition))))
           (remaining (subseq octets count))
           (complete (zerop (length remaining)))
           (frame (make-frame :stream :stream-id (stream-id stream)
                              :offset (getf result :offset) :data (getf result :data)
                              :fin (and fin-p complete) :len-present t)))
      (%client-queue-frame client frame :1-rtt)
      (if complete
          (when fin-p (stream-finish stream))
          (%client-queue-pending-stream-write client stream remaining fin-p))
      frame)))

(defun %client-drain-pending-stream-writes (client)
  (loop while (quic-client-pending-stream-writes client) do
    (let* ((entry (pop (quic-client-pending-stream-writes client)))
           (stream (first entry))
           (octets (second entry))
           (fin-p (third entry)))
      (if (plusp (%client-stream-send-credit client stream))
          (%client-write-stream-available client stream octets fin-p)
          (progn
            (%client-queue-frame
             client (make-frame :data-blocked
                                :maximum (flow-control-connection-max-data
                                          (quic-client-flow-control client)))
             :1-rtt)
            (push entry (quic-client-pending-stream-writes client))
            (return)))))
  client)

(defun client-write-stream (client stream octets &key (fin-p nil) timeout deadline)
  (%client-check-deadline client timeout deadline)
  (unless (eq (gethash (stream-id stream) (quic-client-streams client)) stream)
    (error 'quic-error))
  (unless (and (arrayp octets) (= (array-rank octets) 1)
               (subtypep (array-element-type octets) '(unsigned-byte 8)))
    (error 'type-error :datum octets :expected-type '(vector (unsigned-byte 8))))
  (%client-write-stream-available client stream octets fin-p))

(defun client-read-stream (client stream &key timeout deadline)
  (%client-check-deadline client timeout deadline)
  (multiple-value-bind (data fin) (stream-read stream)
    (let ((maximum (+ (stream-read-offset stream) 65536)))
      (stream-set-max-receive-offset stream maximum)
      (%client-queue-frame
       client (make-frame :max-stream-data :stream-id (stream-id stream)
                          :maximum maximum) :1-rtt)
      (flow-control-update-max-receive-data
       (quic-client-flow-control client)
       (max maximum (flow-control-connection-receive-limit
                     (quic-client-flow-control client)))))
    (values data fin)))

(defun client-close-stream (client stream &key condition)
  (declare (ignore condition))
  (when (gethash (stream-id stream) (quic-client-streams client))
    (unless (stream-finished-p stream) (ignore-errors (stream-finish stream)))
    (remhash (stream-id stream) (quic-client-streams client)))
  t)

(defun client-flush (client)
  "Packetize all queued frames, preserving their QUIC encryption level."
  (%client-drain-pending-stream-writes client)
  (let ((pending (prog1 (quic-client-pending-frames client)
                  (setf (quic-client-pending-frames client) nil)))
        (groups nil))
    (dolist (entry pending)
      (let ((group (assoc (car entry) groups)))
        (if group (push (cdr entry) (cdr group))
            (push (cons (car entry) (list (cdr entry))) groups))))
    (dolist (group groups)
      (let ((frames (reverse (cdr group))))
        (dolist (packet-frames (%client-frame-packet-groups frames))
          (unless (%client-send-frames client (car group) packet-frames)
            (dolist (frame packet-frames)
              (connection-write (quic-client-connection client)
                                (encode-frame frame))))))))
  t)

(defun %client-find-or-create-peer-stream (client id)
  (or (gethash id (quic-client-streams client))
      (setf (gethash id (quic-client-streams client))
            (make-stream id :local-initiator :client
                         :flow-control (quic-client-flow-control client)
                         :max-receive-data (%client-stream-receive-limit client id)
                         :max-send-data (%client-stream-send-limit client id)))))

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
    (unless (and (equalp (packet-header-destination-connection-id header)
                         (quic-client-local-connection-id client)))
      (error 'quic-encoding-error :message "Retry connection ID mismatch"))
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
  (let ((decoded (decode-version-negotiation bytes)))
    (unless (and (equalp (getf decoded :destination-connection-id)
                         (quic-client-local-connection-id client))
                 (equalp (getf decoded :source-connection-id)
                         (quic-client-initial-destination-connection-id client)))
      (error 'quic-encoding-error :message "Version Negotiation connection ID mismatch"))
    (unless (member *quic-version-1* (getf decoded :versions))
      (error 'quic-encoding-error :message "peer does not support QUIC v1"))))

(defun client-receive-datagram (client bytes &key (short-header-dcid-length 8))
  "Decrypt and dispatch all packets in one UDP datagram."
  (when (quic-client-closed-p client)
    (return-from client-receive-datagram nil))
  (handler-case
      (let ((bytes (ensure-octets bytes)) (at 0) (last-header nil))
        (when (> (length bytes) +max-quic-packet-size+)
          (error 'quic-encoding-error
                 :message "QUIC datagram exceeds the maximum UDP payload size"))
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
                     (declare (ignore boundary level direction secret)))
                   :on-transport-parameters
                   (lambda (boundary parameters)
                     (declare (ignore boundary))
                     (let ((parameters (if (listp parameters)
                                           parameters
                                           (decode-transport-parameters parameters))))
                       (setf (quic-client-peer-transport-parameters client) parameters)
                       (let ((flow (quic-client-flow-control client)))
                         (when (zerop (flow-control-connection-sent flow))
                           (setf (flow-control-state-connection-max-data flow)
                                 (%client-transport-parameter parameters 4 0)))
                         (when (zerop (flow-control-stream-count flow :bidirectional))
                           (setf (flow-control-state-max-streams-bidi flow)
                                 (%client-transport-parameter parameters 8 0)))
                         (when (zerop (flow-control-stream-count flow :unidirectional))
                           (setf (flow-control-state-max-streams-uni flow)
                                 (%client-transport-parameter parameters 9 0))))
                       (maphash
                        (lambda (id stream)
                          (stream-set-max-send-offset
                           stream (%client-stream-send-limit client id))
                          (stream-set-max-receive-offset
                           stream (%client-stream-receive-limit client id)))
                        (quic-client-streams client)))))))
    (quic-client-tls-boundary client))

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
                     :verify-signature (%client-signature-verifier client)
                     :on-send
                     (lambda (driver wire)
                       (let* ((type (aref wire 0))
                              (level (if (= type 1) :initial
                                         (if (= type 20) :handshake :application)))
                              (boundary (quic-client-tls-boundary client))
                              (before (length (quic-client-pending-frames client))))
                         (unless boundary (error 'quic-error))
                         (%client-tls-level-call
                          level
                          (lambda (tls-level)
                            (if (and (= type 1)
                                     (%client-function
                                      "CL-TLS-KIT"
                                      "QUIC-TLS-BOUNDARY-SEND-WITH-TRANSPORT-PARAMETERS"))
                                (funcall (%client-function
                                          "CL-TLS-KIT"
                                          "QUIC-TLS-BOUNDARY-SEND-WITH-TRANSPORT-PARAMETERS")
                                         boundary tls-level type (subseq wire 4)
                                         (quic-client-transport-parameters client))
                                (funcall (%client-function "CL-TLS-KIT"
                                                           "QUIC-TLS-BOUNDARY-SEND")
                                         boundary tls-level type (subseq wire 4)))))
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
      (dolist (message
                (%client-tls-level-call
                 (%client-level-space level)
                 (lambda (tls-level)
                   (funcall feed (quic-client-tls-boundary client)
                            tls-level offset bytes))))
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
        (%client-requeue-pto-probe client space)
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
