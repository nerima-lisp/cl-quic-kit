(in-package #:cl-user)

(let* ((writes nil)
       (connection (cl-quic-kit:make-quic-connection
                    :io-write (lambda (ignored bytes)
                                (declare (ignore ignored))
                                (push bytes writes)))))
  (let* ((client (cl-quic-kit:make-quic-client :connection connection))
         (stream (cl-quic-kit:client-open-stream client nil))
         (payload (make-array 3 :element-type '(unsigned-byte 8)
                              :initial-contents '(7 8 9))))
    (cl-quic-kit:client-write-stream client stream payload)
    (cl-quic-kit:client-poll client)
    (let ((frame (cl-quic-kit:decode-frame (first writes))))
      (check (and (eq (cl-quic-kit:frame-type frame) :stream)
                  (= (cl-quic-kit:frame-field frame :stream-id) 0)
                  (equalp (cl-quic-kit:frame-field frame :data) payload))
             "client stream writes are encoded through the injected connection I/O"))))

(let ((server (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                           :local-port 0
                                           :non-blocking-p nil))
      (client nil))
  (unwind-protect
       (progn
         (setf client
               (cl-quic-kit:make-udp-socket
                :local-host "127.0.0.1" :local-port 0
                :remote-host "127.0.0.1"
                :remote-port (cl-quic-kit:udp-socket-local-port server)
                :non-blocking-p nil))
         (let ((payload (make-array 4 :element-type '(unsigned-byte 8)
                                     :initial-contents '(1 3 3 7))))
           (check (= (cl-quic-kit:udp-send client payload) 4)
                  "UDP sends one complete datagram")
           (multiple-value-bind (received length peer)
               (cl-quic-kit:udp-receive server :wait-p t)
             (check (and (= length 4) (equalp received payload) peer)
                    "UDP receives the datagram and peer address"))))
    (when client (cl-quic-kit:udp-close client))
    (cl-quic-kit:udp-close server)))
