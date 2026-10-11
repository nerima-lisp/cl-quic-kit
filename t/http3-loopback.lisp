(require :asdf)
(push (truename "./") asdf:*central-registry*)
(asdf:load-system "cl-quic-kit")

(let ((protection (find-package "CL-QUIC-KIT.PROTECTION"))
      (crypto (find-package "CRYPTO-KIT")))
  (funcall (find-symbol "CONFIGURE-CRYPTO-BACKEND" protection)
           :hkdf-extract (symbol-function (find-symbol "HKDF-EXTRACT" crypto))
           :hkdf-expand (symbol-function (find-symbol "HKDF-EXPAND" crypto))
           :aead-seal (symbol-function (find-symbol "AEAD-SEAL" crypto))
           :aead-open (symbol-function (find-symbol "AEAD-OPEN" crypto))
           :aes-ecb (symbol-function (find-symbol "AES-ENCRYPT-BLOCK" crypto))
           :chacha20 (symbol-function (find-symbol "CHACHA20-KEYSTREAM" crypto))
           :constant-time-equal
           (symbol-function (find-symbol "CONSTANT-TIME-EQUAL" crypto))))

(defun %env (name &optional default)
  (or (sb-ext:posix-getenv name) default))

(defun %env-integer (name default)
  (parse-integer (%env name (princ-to-string default))))

(defun %env-flag (name)
  (string= (%env name "0") "1"))

(defparameter *body-size*
  (%env-integer "QUIC_BODY_SIZE"
                (if (= (%env-integer "QUIC_PORT" 8443) 18443)
                    (* 1024 1024)
                    0)))

(defparameter *unknown-length-p* (%env-flag "QUIC_UNKNOWN_LENGTH"))
(defparameter *mutation-mode* (%env-integer "QUIC_MUTATION_MODE" 0))
(defparameter *checks* 0)
(defparameter *mutation-received* 0)

(defun %check (value label)
  (incf *checks*)
  (unless value
    (format t "HTTP3_CASE_FAIL selected=1 assertions=~D mode=~D check=~A~%"
            *checks* *mutation-mode* label)
    (error "HTTP/3 check failed: ~A" label)))

(defun %octets (string)
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun %bytes (&rest bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8)
              :initial-contents bytes))

(defun %append-octets (&rest parts)
  (apply #'concatenate '(vector (unsigned-byte 8)) parts))

(defun %h3-frame (type payload)
  (%append-octets (cl-quic-kit:encode-varint type)
                  (cl-quic-kit:encode-varint (length payload))
                  payload))

(defun %contains-octets-p (bytes needle)
  (loop for start from 0 to (- (length bytes) (length needle))
        thereis (loop for index below (length needle)
                      always (= (aref bytes (+ start index))
                                (aref needle index)))))

(defun %read-anchor ()
  (let* ((blocks (cl-tls-kit:pem-decode
                  (uiop:read-file-string (%env "CADDY_ROOT"))))
         (certificate (find-if (lambda (block)
                                (string= (cl-tls-kit:pem-block-label block)
                                         "CERTIFICATE"))
                              blocks)))
    (unless certificate
      (error "CADDY_ROOT contains no certificate"))
    (cl-tls-kit.x509:parse-certificate-der
     (cl-tls-kit:pem-block-der certificate))))

(defun %wait-for-handshake (client)
  (loop repeat 3000 do
    (cl-quic-kit:client-poll client)
    (let ((state (cl-quic-kit:connection-state
                  (cl-quic-kit:quic-client-connection client))))
      (when (eq state :established)
        (return-from %wait-for-handshake t))
      (when (cl-quic-kit::quic-client-closed-p client)
        (error "QUIC handshake closed: ~S" state)))
    (sleep 0.005))
  (error "QUIC handshake timed out"))

(defun %response-body (response)
  (let ((offset 0) (headers-p nil) (body (%bytes)))
    (loop while (< offset (length response)) do
      (multiple-value-bind (type type-size)
          (cl-quic-kit:decode-varint response offset)
        (incf offset type-size)
        (multiple-value-bind (size size-size)
            (cl-quic-kit:decode-varint response offset)
          (incf offset size-size)
          (when (> (+ offset size) (length response))
            (error "Truncated HTTP/3 response frame"))
          (case type
            (1 (when (zerop size) (error "Empty HTTP/3 response HEADERS"))
               (setf headers-p t))
            (0 (unless headers-p (error "HTTP/3 DATA before HEADERS"))
               (setf body (%append-octets body (subseq response offset (+ offset size))))))
          (incf offset size))))
    (values body headers-p)))

(defun %receive-state (client)
  (list
   (copy-tree (cl-quic-kit::quic-client-received-packets client))
   (cl-quic-kit::quic-connection-last-activity
    (cl-quic-kit:quic-client-connection client))
   (loop for level in '(:initial :handshake :application)
         for space = (cl-quic-kit.recovery:recovery-space
                      (cl-quic-kit::quic-client-recovery client) level)
         collect (list
                  (cl-quic-kit.recovery::packet-number-space-largest-received space)
                  (cl-quic-kit.recovery::packet-number-space-largest-acked space)
                  (cl-quic-kit.recovery::packet-number-space-ack-eliciting-count space)
                  (cl-quic-kit.recovery::packet-number-space-ack-pending space)
                  (cl-quic-kit.recovery::packet-number-space-ack-deadline space)
                  (sort (loop for number being the hash-keys of
                              (cl-quic-kit.recovery::packet-number-space-sent space)
                              collect number) #'<)))
   (loop for id in (sort (loop for id being the hash-keys of
                              (cl-quic-kit::quic-client-streams client)
                              collect id) #'<)
         for stream = (gethash id (cl-quic-kit::quic-client-streams client))
         collect (list id (cl-quic-kit:stream-receive-offset stream)
                       (cl-quic-kit::stream-receive-highest-offset stream)
                       (cl-quic-kit::stream-receive-final-size stream)
                       (copy-seq (cl-quic-kit::stream-read-buffer stream))
                       (copy-tree (cl-quic-kit::stream-receive-ranges stream))
                       (copy-tree (cl-quic-kit::stream-events stream))))
   (copy-tree (cl-quic-kit::quic-client-pending-frames client))))

(defun %preauthentication-drop (client bytes)
  (let* ((key (getf (cdr (assoc :1-rtt (cl-quic-kit::quic-client-keys client))) :read))
         (pn-offset (1+ (length (cl-quic-kit::quic-client-local-connection-id client)))))
    (cond
      ((null key) :no-read-key)
      ((< (length bytes) (+ pn-offset 20)) :short-hp-sample)
      (t
       (let* ((sample (subseq bytes (+ pn-offset 4) (+ pn-offset 20)))
              (header (cl-quic-kit.protection:remove-header-protection
                       key bytes sample pn-offset 4 nil)))
         (when (and (not (eq (logbitp 2 (aref header 0))
                            (= (cl-quic-kit::quic-client-application-read-key-phase client) 1)))
                    (null (cl-quic-kit::quic-client-application-read-old-key client))
                    (not (and (cl-quic-kit::quic-client-application-read-next-secret client)
                              (cl-quic-kit::quic-client-application-read-next-key client))))
           :unavailable-key-phase))))))

(defun %check-mutation (client bytes size)
  (let* ((prefix (format nil "udp-proxy mutated server 1-rtt packet mode=~D ("
                         *mutation-mode*))
         (markers (remove-if-not
                   (lambda (line) (uiop:string-prefix-p prefix line))
                   (uiop:read-file-lines (%env "QUIC_MUTATION_LOG")))))
    (%check (= (length markers) 1) "exactly one matching mutation marker")
    (let* ((marker (first markers))
           (end (search " bytes)" marker))
           (marked-size (and end (parse-integer marker :start (length prefix) :end end)))
           (before (%receive-state client))
           (failures (cl-quic-kit::quic-client-authentication-failures client))
           (preauth (%preauthentication-drop client bytes)))
      (%check (and marked-size (= marked-size size (length bytes)) (> size 20))
              "first eligible received datagram matches proxy marker")
      (%check (null (cl-quic-kit:client-receive-datagram
                     client bytes :short-header-dcid-length
                     (length (cl-quic-kit::quic-client-local-connection-id client))))
              "mutated datagram rejected by public receive")
      (%check (and (not (cl-quic-kit::quic-client-closed-p client)))
              "receive rejection leaves connection open")
      (%check (= (- (cl-quic-kit::quic-client-authentication-failures client) failures)
                 (if preauth 0 1)) "exact target authentication counter delta")
      (let ((after (%receive-state client)))
        (%check (equalp (subseq before 0 2) (subseq after 0 2))
                "packet history and activity unchanged")
        (%check (equalp (third before) (third after)) "ACK state unchanged")
        (%check (equalp (nthcdr 3 before) (nthcdr 3 after))
                "stream frame and pending frame state unchanged"))
      (incf *mutation-received*)
      (format t "MUTATION_RECEIVE mode=~D packet-length=~D auth-delta=~D boundary=~A history=unchanged ack=unchanged frames=unchanged~%"
              *mutation-mode* size (if preauth 0 1) (or preauth :aead)))))

(let* ((now (lambda () (/ (get-internal-real-time)
                          internal-time-units-per-second)))
       (client (cl-quic-kit:make-quic-client
                :server-host (%env "QUIC_HOST" "127.0.0.1")
                :server-port (%env-integer "QUIC_PORT" 8443)
                :hostname "localhost"
                :alpn (list "h3")
                :tls-trust-anchors (list (%read-anchor))
                :tls-verify-signature #'crypto-kit:verify-signature
                :tls-signature-algorithms #(1027)
                :now-fn now
                :idle-timeout 30))
       (original-receive (symbol-function 'cl-quic-kit:udp-receive)))
  (unwind-protect
       (progn
         (when (plusp *mutation-mode*)
           ;; The proxy mutates exactly the first eligible server short packet.
           ;; Consume its real UDP bytes once through the public receive API;
           ;; returning no datagram avoids processing the rejected packet twice.
           (setf (symbol-function 'cl-quic-kit:udp-receive)
                 (lambda (socket &rest options)
                   (multiple-value-bind (bytes size address)
                       (apply original-receive socket options)
                     (if (and bytes (zerop *mutation-received*) (> size 20)
                              (not (logbitp 7 (aref bytes 0)))
                              (eq socket (cl-quic-kit::quic-client-udp-socket client)))
                         (progn (%check-mutation client bytes size)
                                (values nil nil nil))
                         (values bytes size address))))))
         (cl-quic-kit:client-start client)
         (unless (<= 0 *mutation-mode* 7) (error "Invalid mutation mode"))
         (%wait-for-handshake client)
         (let ((control (cl-quic-kit:client-open-stream
                               client nil :stream-type :control)))
           (cl-quic-kit:client-write-stream
            client control
            ;; SETTINGS and MAX_PUSH_ID as emitted by a conventional H3
            ;; client.  The QPACK table is static-only in the request below.
            (%bytes #x04 #x0f #x01 #x80 #x01 #x00 #x00 #x06 #x80 #x04
                    #x00 #x00 #x07 #x40 #x64 #x21 #x01
                    #x0d #x01 #x08))
           (cl-quic-kit:client-flush client)
           (loop repeat 200 do
             (cl-quic-kit:client-poll client)
             (let ((peer-control (gethash 3
                                          (cl-quic-kit::quic-client-streams client))))
               (when (and peer-control
                          (plusp (cl-quic-kit:stream-readable-bytes peer-control)))
                 (cl-quic-kit:client-read-stream client peer-control)
                 (return)))
             (sleep 0.005))
                 (let ((qpack-encoder (cl-quic-kit:client-open-stream
                                       client nil :stream-type :qpack-encoder))
                       (qpack-decoder (cl-quic-kit:client-open-stream
                                       client nil :stream-type :qpack-decoder))
                       (request (cl-quic-kit:client-open-stream client nil)))
                   (declare (ignore qpack-encoder qpack-decoder))
                   (cl-quic-kit:client-write-stream
                    client request
                    (%append-octets
                     (%h3-frame
                      1
                      (%append-octets
                       ;; QPACK static entries 17/20, 23, 0, and 1 encode
                       ;; :method GET/POST, :scheme https, :authority, and :path /.
                       (%append-octets
                        (%bytes 0 0 (if (plusp *body-size*) #xd4 #xd1)
                                #xd7 #x50 #x8a #xa0 #xe4 #x1d #x13
                                #x9d #x09 #xb8 #xf3 #x4d #x33 #xc1)
                        (if (and (plusp *body-size*) (not *unknown-length-p*))
                            (%append-octets
                             (%bytes #x54 (length (princ-to-string *body-size*)))
                             (%octets (princ-to-string *body-size*)))
                            #()))))
                     (%h3-frame 0
                                (make-array *body-size*
                                            :element-type '(unsigned-byte 8)
                                            :initial-element #x5a)))
                    :fin-p t)
                   (cl-quic-kit:client-flush client)
                   (let ((response (make-array 0 :element-type '(unsigned-byte 8)))
                         (succeeded nil))
                     (loop repeat 5000 do
                       (cl-quic-kit:client-poll client)
                       (let ((stream (gethash 0
                                              (cl-quic-kit::quic-client-streams client))))
                         (when stream
                           (multiple-value-bind (data fin)
                               (cl-quic-kit:client-read-stream client stream)
                             (when (plusp (length data))
                               (setf response (%append-octets response data)))
                             (when (and fin
                                        (%contains-octets-p response (%octets "ok")))
                               (setf succeeded t)
                               (return)))))
                       (when (cl-quic-kit::quic-client-closed-p client)
                         (error "QUIC connection closed before HTTP/3 response"))
                       (sleep 0.005))
                     (%check succeeded "response FIN received")
                     (multiple-value-bind (body headers-p) (%response-body response)
                       (%check headers-p "response HEADERS received")
                       (%check (equalp body (%octets "ok")) "exact HTTP/3 response DATA"))
                     (%check (not (cl-quic-kit::quic-client-closed-p client))
                             "connection remains open after unauthenticated packet")
                     (%check (eq (cl-quic-kit:connection-state
                                  (cl-quic-kit:quic-client-connection client))
                                 :established)
                             "same connection remains established")
                     (if (plusp *mutation-mode*)
                         (%check (= *mutation-received* 1) "exactly one target receive observed")
                         (%check (zerop (cl-quic-kit::quic-client-authentication-failures client))
                                 "known-good authentication control"))
                     (unless (= *checks* (if (plusp *mutation-mode*) 14 6))
                       (error "Unexpected HTTP/3 assertion count"))
                     (format t "HTTP/3 request succeeded: ~D response octets~%"
                             (length response))
                     (format t "HTTP3_CASE_PASS selected=1 assertions=~D mode=~D~%"
                             *checks* *mutation-mode*)))))
    (setf (symbol-function 'cl-quic-kit:udp-receive) original-receive)
    (assert (eq original-receive (symbol-function 'cl-quic-kit:udp-receive)))
    (format t "SPY_TRANSPORT_RESTORE_EQ=T~%")
    (cl-quic-kit:client-close client)))
