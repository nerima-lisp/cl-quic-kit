(in-package #:cl-quic-kit)

(defstruct (quic-client (:constructor %make-quic-client))
  connection udp-socket tls-boundary
  streams next-bidi-stream next-uni-stream
  pending-frames crypto-send-offsets tls-secrets
  peer-transport-parameters closed-p)

(declaim (ftype function client-tls-feed))

(defun %client-level-value (alist key)
  (cdr (assoc key alist)))

(defun %client-set-level-value (alist key value)
  (let ((cell (assoc key alist)))
    (if cell
        (setf (cdr cell) value)
        (push (cons key value) alist))
    alist))

(defun %client-queue-frame (client frame)
  (setf (quic-client-pending-frames client)
        (nconc (quic-client-pending-frames client) (list frame)))
  frame)

(defun %client-stream-type (stream-type)
  (case stream-type
    (:control 2)
    (:qpack-encoder 6)
    (:qpack-decoder 10)
    (otherwise nil)))

(defun make-quic-client (&key connection udp-socket tls-boundary
                              local-connection-id now-fn idle-timeout
                              io-write on-close)
  "Create a client-side stream facade over a QUIC connection.

The connection, UDP socket, and TLS boundary remain injectable.  This keeps
the HTTP/3 callback surface independent from the event loop while making
CRYPTO and STREAM frames observable through the existing frame codec."
  (let* ((udp udp-socket)
         (write (or io-write
                    (and udp
                         (lambda (ignored-connection bytes)
                           (declare (ignore ignored-connection))
                           (udp-send udp bytes)))))
         (connection (or connection
                         (make-quic-connection
                          :role :client
                          :local-connection-id local-connection-id
                          :now-fn (or now-fn #'get-internal-real-time)
                          :idle-timeout (or idle-timeout *quic-idle-timeout-default*)
                          :io-write write
                          :on-close on-close))))
    (%make-quic-client :connection connection :udp-socket udp
                       :tls-boundary tls-boundary
                       :streams (make-hash-table :test #'eql)
                       :next-bidi-stream 0 :next-uni-stream 2
                       :pending-frames nil :crypto-send-offsets nil
                       :tls-secrets nil :peer-transport-parameters nil
                       :closed-p nil)))

(defun client-open-stream (client request &key stream-type timeout deadline)
  "Open a request or HTTP/3 unidirectional stream.

REQUEST, TIMEOUT, and DEADLINE are accepted to match cl-http-kit's callback
contract; transport scheduling is owned by CLIENT-POLL."
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
      (%client-queue-frame
       client
       (make-frame :stream :stream-id id :offset 0
                   :data (encode-varint uni-type) :fin nil :len-present t)))
    stream))

(defun client-write-stream (client stream octets &key (fin-p nil) timeout deadline)
  "Queue a STREAM frame and optionally finish STREAM.

The returned value is the queued frame.  Use CLIENT-POLL to hand queued bytes
to the injected connection I/O callback."
  (declare (ignore timeout deadline))
  (unless (eq (gethash (stream-id stream) (quic-client-streams client)) stream)
    (error 'quic-error))
  (let* ((result (stream-write stream octets))
         (frame (make-frame :stream :stream-id (stream-id stream)
                            :offset (getf result :offset)
                            :data (getf result :data)
                            :fin fin-p :len-present t)))
    (%client-queue-frame client frame)
    (when fin-p (stream-finish stream))
    frame))

(defun client-read-stream (client stream &key timeout deadline)
  "Return buffered STREAM data and FIN as two values.

This is deliberately non-blocking.  Call CLIENT-POLL from the surrounding
event loop when the first value is empty and FIN is false."
  (declare (ignore client timeout deadline))
  (stream-read stream))

(defun client-close-stream (client stream &key condition)
  (declare (ignore condition))
  (when (gethash (stream-id stream) (quic-client-streams client))
    (unless (stream-finished-p stream)
      (ignore-errors (stream-finish stream)))
    (remhash (stream-id stream) (quic-client-streams client)))
  t)

(defun client-flush (client)
  "Encode and write all queued frames through the connection I/O seam."
  (loop for frame = (pop (quic-client-pending-frames client))
        while frame
        do (connection-write (quic-client-connection client)
                             (encode-frame frame)))
  t)

(defun %client-find-or-create-peer-stream (client id)
  (or (gethash id (quic-client-streams client))
      (setf (gethash id (quic-client-streams client))
            (make-stream id :local-initiator :client))))

(defun client-receive-frame (client frame)
  "Deliver one decoded QUIC frame to the stream/TLS facade."
  (case (frame-type frame)
    (:stream
     (let ((stream (%client-find-or-create-peer-stream
                    client (frame-field frame :stream-id))))
       (stream-receive-data stream (frame-field frame :offset 0)
                            (frame-field frame :data #())
                            :fin (frame-field frame :fin nil))))
    (:crypto
     (client-tls-feed client :initial (frame-field frame :offset 0)
                      (frame-field frame :data #())))
    ((:connection-close :application-close)
     (connection-receive-frame (quic-client-connection client) frame))
    (otherwise nil))
  frame)

(defun client-receive-datagram (client bytes &key (short-header-dcid-length 0))
  "Decode an unprotected datagram and dispatch its frames.

Packet protection is installed at the connection layer before this facade is
used for a live QUIC peer; this entry point is also useful for deterministic
codec and loopback tests."
  (multiple-value-bind (header end)
      (decode-packet-header bytes :short-header-dcid-length short-header-dcid-length)
    (declare (ignore end))
    (dolist (frame (decode-frames (packet-header-payload header)))
      (client-receive-frame client frame))
    header))

(defun make-client-tls-boundary (client &key transport-parameters)
  "Attach cl-tls-kit's RFC 9001 CRYPTO boundary to CLIENT."
  (let* ((package (find-package "CL-TLS-KIT"))
         (constructor (and package (find-symbol "MAKE-QUIC-TLS-BOUNDARY" package))))
    (unless (and constructor (fboundp constructor))
      (error 'crypto-unavailable :operation :quic-tls-boundary))
    (setf (quic-client-tls-boundary client)
          (funcall (symbol-function constructor)
                   :role :client
                   :transport-parameters transport-parameters
                   :on-crypto
                   (lambda (boundary level wire)
                     (declare (ignore boundary))
                     (let* ((offset (or (%client-level-value
                                         (quic-client-crypto-send-offsets client) level)
                                        0))
                            (frame (make-frame :crypto :offset offset :data wire)))
                       (setf (quic-client-crypto-send-offsets client)
                             (%client-set-level-value
                              (quic-client-crypto-send-offsets client)
                              level (+ offset (length wire))))
                       (%client-queue-frame client frame)))
                   :on-secret
                   (lambda (boundary level direction secret)
                     (declare (ignore boundary))
                     (push (list level direction secret)
                           (quic-client-tls-secrets client)))
                   :on-transport-parameters
                   (lambda (boundary parameters)
                     (declare (ignore boundary))
                     (setf (quic-client-peer-transport-parameters client)
                           parameters))))
    (quic-client-tls-boundary client)))

(defun client-tls-feed (client level offset bytes)
  "Feed a CRYPTO frame into the attached cl-tls-kit boundary."
  (let* ((boundary (quic-client-tls-boundary client))
         (package (find-package "CL-TLS-KIT"))
         (function (and package (find-symbol "QUIC-TLS-BOUNDARY-FEED-CRYPTO"
                                             package))))
    (unless (and boundary function (fboundp function))
      (error 'quic-crypto-error :message "No QUIC TLS boundary is attached"))
    (funcall (symbol-function function) boundary level offset bytes)))

(defun client-poll (client &optional at)
  "Flush queued frames, poll connection timers, and return closed status."
  (client-flush client)
  (connection-poll (quic-client-connection client) at))

(defun client-close (client &key (error-code :no-error) reason)
  (unless (quic-client-closed-p client)
    (setf (quic-client-closed-p client) t)
    (connection-close (quic-client-connection client) error-code reason)
    (client-flush client)
    (when (quic-client-udp-socket client)
      (udp-close (quic-client-udp-socket client))))
  t)
