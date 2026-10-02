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

(defun %verify-signature (scheme public-key message signature)
  (crypto-kit:verify-signature
   (case scheme
     (:ecdsa-secp256r1-sha256 :ecdsa-p256-sha256)
     (:ecdsa-secp384r1-sha384 :ecdsa-p384-sha384)
     (otherwise scheme))
   public-key message signature))

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

(let* ((now (lambda () (/ (get-internal-real-time)
                          internal-time-units-per-second)))
       (client (cl-quic-kit:make-quic-client
                :server-host (%env "QUIC_HOST" "127.0.0.1")
                :server-port (%env-integer "QUIC_PORT" 8443)
                :hostname "localhost"
                :alpn (list "h3")
                :tls-trust-anchors (list (%read-anchor))
                :tls-verify-signature #'%verify-signature
                :tls-signature-algorithms #(1027)
                :now-fn now
                :idle-timeout 30)))
  (unwind-protect
       (progn
         (cl-quic-kit:client-start client)
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
              (%h3-frame
               1
               (%append-octets
                ;; QPACK static entries 17, 23, 0, and 1 encode
                ;; :method GET, :scheme https, :authority, and :path /.
                (%bytes 0 0 #xd1 #xd7 #x50 #x8a #xa0 #xe4 #x1d #x13
                        #x9d #x09 #xb8 #xf3 #x4d #x33 #xc1)))
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
               (if succeeded
                   (format t "HTTP/3 GET succeeded: ~D response octets~%"
                           (length response))
                   (error "HTTP/3 response timed out")))))
    (ignore-errors (cl-quic-kit:client-close client)))))
