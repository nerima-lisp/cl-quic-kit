(in-package #:cl-quic-kit)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-bsd-sockets))

(defstruct (udp-socket (:constructor %make-udp-socket))
  socket peer-address peer-port non-blocking-p closed-p)

(defun %udp-octets (value)
  (unless (typep value '(simple-array (unsigned-byte 8) (*)))
    (error 'type-error :datum value
           :expected-type '(simple-array (unsigned-byte 8) (*))))
  value)

(defun %udp-address (host)
  (cond
    ((null host) #(0 0 0 0))
    ((stringp host) (sb-bsd-sockets:make-inet-address host))
    ((and (vectorp host) (= (length host) 4)) host)
    (t (error 'type-error :datum host
              :expected-type '(or null string (vector (unsigned-byte 8)))))))

(defun make-udp-socket (&key (local-host "0.0.0.0") (local-port 0)
                              remote-host remote-port (non-blocking-p t))
  "Create an IPv4 UDP socket with injectable local and remote endpoints.

When REMOTE-HOST and REMOTE-PORT are supplied the socket is connected, which
lets the caller use recvfrom-compatible I/O without relying on a Lisp socket
library.  An unconnected socket accepts the opaque peer address returned by
UDP-RECEIVE as the ADDRESS argument to UDP-SEND."
  (unless (and (integerp local-port) (<= 0 local-port 65535))
    (error 'quic-error))
  (when (and remote-host
             (or (null remote-port) (not (and (integerp remote-port)
                                               (<= 0 remote-port 65535)))))
    (error 'quic-error))
  (let* ((socket (make-instance 'sb-bsd-sockets:inet-socket
                                :type :datagram :protocol :udp))
         (local-address (%udp-address local-host))
         (peer-address (and remote-host (%udp-address remote-host))))
    (handler-case
        (progn
          (sb-bsd-sockets:socket-bind socket local-address local-port)
          (when remote-host
            (sb-bsd-sockets:socket-connect socket peer-address remote-port))
          (setf (sb-bsd-sockets:non-blocking-mode socket) non-blocking-p)
          (%make-udp-socket :socket socket :peer-address peer-address
                            :peer-port remote-port
                            :non-blocking-p non-blocking-p))
      (error (condition)
        (ignore-errors (sb-bsd-sockets:socket-close socket))
        (error condition)))))

(defun udp-socket-local-port (socket)
  "Return the port assigned to SOCKET, including an ephemeral port."
  (multiple-value-bind (address port)
      (sb-bsd-sockets:socket-name (udp-socket-socket socket))
    (declare (ignore address))
    port))

(defun udp-send (socket data &key address)
  "Send DATA, optionally to the opaque ADDRESS returned by UDP-RECEIVE."
  (when (udp-socket-closed-p socket)
    (error 'quic-error))
  (let ((data (%udp-octets data)))
    (if (or address (null (udp-socket-peer-address socket)))
        (sb-bsd-sockets:socket-send
         (udp-socket-socket socket) data (length data)
         :address (or address
                       (list (udp-socket-peer-address socket)
                             (udp-socket-peer-port socket))))
        (sb-bsd-sockets:socket-send
         (udp-socket-socket socket) data (length data)))))

(defun udp-receive (socket &key (size 65535) wait-p)
  "Receive one datagram and return DATA, LENGTH, and an opaque peer address.

On a non-blocking socket with no datagram available, return three NIL values.
SIZE is bounded to a valid UDP receive buffer size."
  (when (udp-socket-closed-p socket)
    (error 'quic-error))
  (unless (and (integerp size) (plusp size) (<= size 65535))
    (error 'quic-error))
  (handler-case
      (multiple-value-bind (data length address)
          (sb-bsd-sockets:socket-receive
           (udp-socket-socket socket)
           (make-array size :element-type '(unsigned-byte 8)) size
           :dontwait (not wait-p))
        (values (if (= length (length data)) data (subseq data 0 length))
                length address))
    (sb-bsd-sockets:socket-error (condition)
      (if (and (not wait-p) (udp-socket-non-blocking-p socket))
          (values nil nil nil)
          (error condition)))))

(defun udp-close (socket)
  "Close SOCKET exactly once and return T."
  (unless (udp-socket-closed-p socket)
    (setf (udp-socket-closed-p socket) t)
    (sb-bsd-sockets:socket-close (udp-socket-socket socket)))
  t)
