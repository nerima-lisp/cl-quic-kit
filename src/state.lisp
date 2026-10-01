(in-package #:cl-quic-kit)

(defparameter *quic-idle-timeout-default* 30000)

(define-condition connection-closed (quic-error)
  ((error-code :initarg :error-code :reader connection-close-error-code)
   (reason :initarg :reason :reader connection-close-reason)))

(defstruct (quic-connection (:constructor %make-quic-connection))
  role state now-fn idle-timeout last-activity
  local-connection-ids remote-connection-ids active-local-id
  tls-input tls-output on-close closed-error closed-reason)

(defun make-quic-connection (&key (role :client) (now-fn #'get-internal-real-time)
                                  (idle-timeout *quic-idle-timeout-default*)
                                  local-connection-id tls-input tls-output on-close)
  (unless (member role '(:client :server))
    (error 'quic-error))
  (unless (and (functionp now-fn) (integerp idle-timeout) (plusp idle-timeout))
    (error 'quic-error))
  (let ((cid (or local-connection-id (make-array 0 :element-type '(unsigned-byte 8)))))
    (validate-connection-id cid)
    (%make-quic-connection :role role :state :handshaking :now-fn now-fn
                           :idle-timeout idle-timeout
                           :last-activity (funcall now-fn)
                           :local-connection-ids (list (octets-copy cid))
                           :remote-connection-ids nil
                           :active-local-id (octets-copy cid)
                           :tls-input tls-input :tls-output tls-output
                           :on-close on-close)))

(defun connection-touch (connection &optional (at (funcall (quic-connection-now-fn connection))))
  (setf (quic-connection-last-activity connection) at)
  at)

(defun connection-id-known-p (connection cid &key (local-p t))
  (let ((ids (if local-p (quic-connection-local-connection-ids connection)
                 (quic-connection-remote-connection-ids connection))))
    (some (lambda (known) (equalp known cid)) ids)))

(defun connection-add-connection-id (connection cid &key (local-p t))
  (validate-connection-id cid)
  (unless (connection-id-known-p connection cid :local-p local-p)
    (if local-p
        (push (octets-copy cid) (quic-connection-local-connection-ids connection))
        (push (octets-copy cid) (quic-connection-remote-connection-ids connection))))
  connection)

(defun connection-retire-connection-id (connection cid &key (local-p t))
  (if local-p
      (setf (quic-connection-local-connection-ids connection)
            (remove cid (quic-connection-local-connection-ids connection) :test #'equalp))
      (setf (quic-connection-remote-connection-ids connection)
            (remove cid (quic-connection-remote-connection-ids connection) :test #'equalp)))
  (when (and local-p (equalp cid (quic-connection-active-local-id connection)))
    (let ((replacement (first (quic-connection-local-connection-ids connection))))
      (unless replacement (error 'quic-error))
      (setf (quic-connection-active-local-id connection) replacement)))
  connection)

(defun connection-idle-expired-p (connection &optional (at (funcall (quic-connection-now-fn connection))))
  (and (eq (quic-connection-state connection) :established)
       (>= (- at (quic-connection-last-activity connection))
           (quic-connection-idle-timeout connection))))

(defun connection-close (connection error-code &optional reason)
  (unless (quic-connection-closed-error connection)
    (setf (quic-connection-state connection) :closed
          (quic-connection-closed-error connection) error-code
          (quic-connection-closed-reason connection) (or reason "") )
    (when (functionp (quic-connection-on-close connection))
      (funcall (quic-connection-on-close connection) connection error-code reason)))
  connection)

(defun connection-check-idle-timeout (connection &optional at)
  (when (connection-idle-expired-p connection at)
    (connection-close connection :no-error "idle timeout"))
  (eq (quic-connection-state connection) :closed))

(defun connection-set-state (connection state)
  (unless (member state '(:handshaking :established :closing :draining :closed))
    (error 'quic-error))
  (setf (quic-connection-state connection) state)
  connection)

(defun connection-tls-feed (connection bytes &key fin)
  (unless (functionp (quic-connection-tls-input connection))
    (error 'quic-crypto-error :message "No QUIC TLS input callback installed"))
  (connection-touch connection)
  (funcall (quic-connection-tls-input connection) bytes :fin-p fin))

(defun connection-tls-poll (connection)
  (when (functionp (quic-connection-tls-output connection))
    (funcall (quic-connection-tls-output connection))))
