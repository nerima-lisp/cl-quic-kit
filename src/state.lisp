(in-package #:cl-quic-kit)

(declaim (ftype function connection-close connection-retire-connection-id
                        connection-write connection-poll))

(defparameter *quic-idle-timeout-default* 30)
(defparameter *quic-active-connection-id-limit-default* 2)
(defconstant +max-quic-close-reason-size+ (- +max-quic-packet-size+ 64))

(defun %connection-error-code (code)
  (if (integerp code) code
      (cdr (assoc code '((:no-error . 0) (:internal-error . 1)
                         (:protocol-violation . 10) (:frame-encoding-error . 7)
                         (:connection-id-limit . 12) (:application-error . 16))))))

(define-condition connection-closed (quic-error)
  ((error-code :initarg :error-code :reader connection-close-error-code)
   (reason :initarg :reason :reader connection-close-reason)))

(defstruct (quic-connection (:constructor %make-quic-connection))
  role state now-fn idle-timeout last-activity
  local-connection-ids remote-connection-ids active-local-id
  local-cid-sequences remote-cid-sequences next-local-sequence
  remote-retire-prior-to active-connection-id-limit
  tls-input tls-output io-read io-write on-close
  closed-error closed-reason close-kind close-frame draining-deadline)

(defun connection-state (connection)
  (quic-connection-state connection))

(defun connection-local-connection-ids (connection)
  (quic-connection-local-connection-ids connection))

(defun connection-remote-connection-ids (connection)
  (quic-connection-remote-connection-ids connection))

(defun connection-active-local-id (connection)
  (quic-connection-active-local-id connection))

(defun connection-active-connection-id-limit (connection)
  (quic-connection-active-connection-id-limit connection))

(defun connection-close-frame (connection)
  (quic-connection-close-frame connection))

(defun connection-close-kind (connection)
  (quic-connection-close-kind connection))

(defun connection-draining-deadline (connection)
  (quic-connection-draining-deadline connection))

(defun %quic-real-time ()
  (/ (get-internal-real-time) internal-time-units-per-second))

(defun make-quic-connection (&key (role :client) (now-fn #'%quic-real-time)
                                  (idle-timeout *quic-idle-timeout-default*)
                                  local-connection-id tls-input tls-output
                                  io-read io-write read-fn write-fn on-close
                                  (active-connection-id-limit *quic-active-connection-id-limit-default*))
  (unless (member role '(:client :server))
    (error 'quic-error))
  (unless (and (functionp now-fn) (integerp idle-timeout) (plusp idle-timeout)
               (integerp active-connection-id-limit) (>= active-connection-id-limit 2)
               (<= active-connection-id-limit (1- (ash 1 8))))
    (error 'quic-error))
  (let ((cid (or local-connection-id (make-array 0 :element-type '(unsigned-byte 8)))))
    (validate-connection-id cid)
    (%make-quic-connection :role role :state :handshaking :now-fn now-fn
                           :idle-timeout idle-timeout
                           :last-activity (funcall now-fn)
                           :local-connection-ids (list (octets-copy cid))
                           :remote-connection-ids nil
                           :active-local-id (octets-copy cid)
                           :local-cid-sequences (list (cons 0 (octets-copy cid)))
                           :remote-cid-sequences nil :next-local-sequence 1
                           :remote-retire-prior-to 0
                           :active-connection-id-limit active-connection-id-limit
                           :tls-input tls-input :tls-output tls-output
                           :io-read (or io-read read-fn) :io-write (or io-write write-fn)
                           :on-close on-close)))

(defun connection-touch (connection &optional (at (funcall (quic-connection-now-fn connection))))
  (unless (numberp at)
    (error 'quic-error))
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

(defun %connection-add-sequenced-id (connection cid sequence local-p)
  (validate-connection-id cid)
  (when (zerop (length cid))
    (connection-close connection :frame-encoding-error
                      "NEW_CONNECTION_ID has a zero-length connection ID")
    (return-from %connection-add-sequenced-id connection))
  (when (some (lambda (entry) (= sequence (car entry)))
              (if local-p (quic-connection-local-cid-sequences connection)
                  (quic-connection-remote-cid-sequences connection)))
    (error 'quic-error))
  (when (and (not local-p)
             (>= (length (quic-connection-remote-cid-sequences connection))
                 (quic-connection-active-connection-id-limit connection)))
    (connection-close connection :connection-id-limit "active connection ID limit exceeded")
    (return-from %connection-add-sequenced-id connection))
  (if local-p
      (push (cons sequence (octets-copy cid)) (quic-connection-local-cid-sequences connection))
      (push (cons sequence (octets-copy cid)) (quic-connection-remote-cid-sequences connection)))
  (if local-p
      (push (octets-copy cid) (quic-connection-local-connection-ids connection))
      (push (octets-copy cid) (quic-connection-remote-connection-ids connection)))
  connection)

(defun connection-handle-new-connection-id (connection sequence cid
                                             &key (retire-prior-to 0)
                                               (stateless-reset-token
                                                (make-array 16 :element-type '(unsigned-byte 8)
                                                            :initial-element 0)))
  (unless (and (varint-p sequence)
               (varint-p retire-prior-to)
               (<= retire-prior-to sequence)
               (connection-id-p cid)
               (plusp (length cid))
               (typep stateless-reset-token '(simple-array (unsigned-byte 8) (*)))
               (= (length stateless-reset-token) 16))
    (connection-close connection :frame-encoding-error "invalid NEW_CONNECTION_ID")
    (return-from connection-handle-new-connection-id connection))
  (let ((existing (find sequence (quic-connection-remote-cid-sequences connection)
                         :key #'car)))
    (when existing
      (unless (equalp (cdr existing) cid)
        (connection-close connection :protocol-violation
                          "NEW_CONNECTION_ID sequence was reused"))
      (return-from connection-handle-new-connection-id connection)))
  (when (> retire-prior-to (quic-connection-remote-retire-prior-to connection))
    (setf (quic-connection-remote-retire-prior-to connection) retire-prior-to)
    (dolist (entry (copy-list (quic-connection-remote-cid-sequences connection)))
      (when (< (car entry) retire-prior-to)
        (connection-retire-connection-id connection (cdr entry) :local-p nil))))
  (if (< sequence (quic-connection-remote-retire-prior-to connection))
      (connection-write connection
                        (encode-frame (make-frame :retire-connection-id :sequence sequence)))
      (%connection-add-sequenced-id connection cid sequence nil)))

(defun connection-retire-connection-id (connection cid &key (local-p t))
  (if local-p
      (setf (quic-connection-local-connection-ids connection)
            (remove cid (quic-connection-local-connection-ids connection) :test #'equalp))
      (setf (quic-connection-remote-connection-ids connection)
            (remove cid (quic-connection-remote-connection-ids connection) :test #'equalp)))
  (if local-p
      (setf (quic-connection-local-cid-sequences connection)
            (delete-if (lambda (entry) (equalp cid (cdr entry)))
                       (quic-connection-local-cid-sequences connection)))
      (setf (quic-connection-remote-cid-sequences connection)
            (delete-if (lambda (entry) (equalp cid (cdr entry)))
                       (quic-connection-remote-cid-sequences connection))))
  (when (and local-p (equalp cid (quic-connection-active-local-id connection)))
    (let ((replacement (first (quic-connection-local-connection-ids connection))))
      (unless replacement
        (let ((sequence (quic-connection-next-local-sequence connection))
              (new-cid (make-array 8 :element-type '(unsigned-byte 8))))
          (dotimes (index 8)
            (setf (aref new-cid (- 7 index))
                  (logand #xff (ash sequence (* -8 index)))))
          (%connection-add-sequenced-id connection new-cid sequence t)
          (incf (quic-connection-next-local-sequence connection))
          (setf replacement new-cid)))
      (setf (quic-connection-active-local-id connection) replacement)))
  connection)

(defun connection-handle-retire-connection-id (connection sequence)
  (when (zerop sequence)
    (connection-close connection :protocol-violation
                      "RETIRE_CONNECTION_ID cannot retire the original connection ID")
    (error 'quic-error))
  (let ((entry (find sequence (quic-connection-local-cid-sequences connection) :key #'car)))
    (unless entry
      (when (>= sequence (quic-connection-next-local-sequence connection))
        (connection-close connection :protocol-violation
                          "RETIRE_CONNECTION_ID has an unknown sequence"))
      (return-from connection-handle-retire-connection-id connection))
    (let* ((cid (cdr entry))
           (cid-length (length cid)))
      (connection-retire-connection-id connection cid)
      (when (and (plusp cid-length)
                 (< (length (quic-connection-local-cid-sequences connection))
                    (quic-connection-active-connection-id-limit connection)))
        (let* ((next (quic-connection-next-local-sequence connection))
               (replacement (make-array cid-length :element-type '(unsigned-byte 8))))
          (dotimes (index cid-length)
            (setf (aref replacement index)
                  (ldb (byte 8 (* 8 (mod index 8))) next)))
          (%connection-add-sequenced-id connection replacement next t)
          (setf (quic-connection-active-local-id connection) replacement)
          (incf (quic-connection-next-local-sequence connection))
          (connection-write
           connection
           (encode-frame
            (make-frame :new-connection-id :sequence next :retire-prior-to 0
                        :connection-id replacement
                        :stateless-reset-token
                        (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-element 0)))))))
    connection))

(defun connection-idle-expired-p (connection &optional (at (funcall (quic-connection-now-fn connection))))
  (and (numberp at)
       (member (quic-connection-state connection) '(:handshaking :established))
       (>= (- at (quic-connection-last-activity connection))
           (quic-connection-idle-timeout connection))))

(defun %connection-reason-octets (reason)
  (let ((limit +max-quic-close-reason-size+))
    (cond
      ((null reason) #())
      ((stringp reason)
       (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                              :adjustable t :fill-pointer 0)))
         (loop for character across reason
               for code = (char-code character)
               for encoded = (cond
                                ((<= code #x7f) (vector code))
                                ((<= code #x7ff)
                                 (vector (logior #xc0 (ash code -6))
                                         (logior #x80 (logand code #x3f))))
                                ((<= code #xffff)
                                 (vector (logior #xe0 (ash code -12))
                                         (logior #x80 (logand (ash code -6) #x3f))
                                         (logior #x80 (logand code #x3f))))
                                (t
                                 (vector (logior #xf0 (ash code -18))
                                         (logior #x80 (logand (ash code -12) #x3f))
                                         (logior #x80 (logand (ash code -6) #x3f))
                                         (logior #x80 (logand code #x3f)))))
               while (<= (+ (length out) (length encoded)) limit)
               do (map nil (lambda (byte) (vector-push-extend byte out)) encoded))
         (copy-seq out)))
      (t
       (let* ((octets (octets-copy reason))
              (end (min limit (length octets))))
         (loop while (and (plusp end)
                          (= (logand (aref octets (1- end)) #xc0) #x80))
               do (decf end))
         (subseq octets 0 end))))))

(defun connection-close (connection error-code &optional reason &rest options)
  (unless (or (eq (quic-connection-state connection) :closed)
              (quic-connection-close-frame connection))
    (let* ((kind (or (getf options :kind)
                     (if (eq error-code :application-error) :application :transport)))
           (wire-code (or (%connection-error-code error-code) 1)))
      (setf (quic-connection-state connection) :closing
          (quic-connection-closed-error connection) wire-code
          (quic-connection-closed-reason connection) (%connection-reason-octets reason)
          (quic-connection-close-kind connection) kind
          (quic-connection-close-frame connection)
          (make-frame (if (eq kind :application)
                          :application-close :connection-close)
                      :error-code wire-code :frame-type 0
                      :reason (quic-connection-closed-reason connection)))
      (connection-write connection (encode-frame (quic-connection-close-frame connection)))
      (setf (quic-connection-draining-deadline connection)
            (+ (funcall (quic-connection-now-fn connection))
               (* 3 (quic-connection-idle-timeout connection))))))
  connection)

(defun connection-check-idle-timeout (connection &optional at)
  (let ((now (or at (funcall (quic-connection-now-fn connection)))))
    (when (connection-idle-expired-p connection now)
      (connection-close connection :no-error "idle timeout"))
    (or (connection-poll connection now)
        (not (eq (quic-connection-state connection) :established)))))

(defun connection-set-state (connection state)
  (unless (member state '(:handshaking :established :closing :draining :closed))
    (error 'quic-error))
  (setf (quic-connection-state connection) state)
  connection)

(defun connection-read (connection)
  (when (functionp (quic-connection-io-read connection))
    (funcall (quic-connection-io-read connection) connection)))

(defun connection-write (connection bytes)
  (when (functionp (quic-connection-io-write connection))
    (funcall (quic-connection-io-write connection) connection (ensure-octets bytes)))
  bytes)

(defun connection-receive-frame (connection frame)
  (when (member (quic-connection-state connection) '(:draining :closed))
    (return-from connection-receive-frame connection))
  (connection-touch connection)
  (case (frame-type frame)
    (:connection-close
     (setf (quic-connection-close-kind connection) :transport)
     (setf (quic-connection-closed-error connection) (frame-field frame :error-code 0)
           (quic-connection-closed-reason connection) (frame-field frame :reason #()))
     (setf (quic-connection-draining-deadline connection)
           (+ (funcall (quic-connection-now-fn connection))
              (* 3 (quic-connection-idle-timeout connection))))
     (connection-set-state connection :draining))
    (:application-close
     (setf (quic-connection-close-kind connection) :application)
     (setf (quic-connection-closed-error connection) (frame-field frame :error-code 0)
           (quic-connection-closed-reason connection) (frame-field frame :reason #()))
     (setf (quic-connection-draining-deadline connection)
           (+ (funcall (quic-connection-now-fn connection))
              (* 3 (quic-connection-idle-timeout connection))))
     (connection-set-state connection :draining))
    (:new-connection-id
     (connection-handle-new-connection-id connection (frame-field frame :sequence 0)
                                          (frame-field frame :connection-id #())
                                          :retire-prior-to (frame-field frame :retire-prior-to 0)
                                          :stateless-reset-token (frame-field frame :stateless-reset-token #())))
    (:retire-connection-id
     (connection-handle-retire-connection-id connection (frame-field frame :sequence 0))))
  connection)

(defun connection-receive-packet (connection bytes &key (short-header-dcid-length 0))
  (handler-case
      (multiple-value-bind (header end)
          (decode-packet-header bytes :short-header-dcid-length short-header-dcid-length)
        (declare (ignore end))
        (connection-touch connection)
        (when (packet-header-payload header)
          (dolist (frame (decode-frames (packet-header-payload header)))
            (connection-receive-frame connection frame)))
        header)
    (quic-encoding-error (condition)
      (connection-close connection :frame-encoding-error (quic-error-message condition))
      nil)
    (quic-error (condition)
      (declare (ignore condition))
      (connection-close connection :frame-encoding-error "invalid QUIC packet")
      nil)))

(defun connection-poll (connection &optional at)
  (let ((now (or at (funcall (quic-connection-now-fn connection)))))
    (when (and (eq (quic-connection-state connection) :established)
               (connection-idle-expired-p connection now))
      (connection-close connection :no-error "idle timeout"))
    (when (and (member (quic-connection-state connection) '(:closing :draining))
               (quic-connection-draining-deadline connection)
               (>= now (quic-connection-draining-deadline connection)))
      (connection-set-state connection :closed)
      (when (functionp (quic-connection-on-close connection))
        (funcall (quic-connection-on-close connection)
                 connection (quic-connection-closed-error connection)
                 (quic-connection-closed-reason connection))))
    (eq (quic-connection-state connection) :closed)))

(defun connection-tls-feed (connection bytes &key fin)
  (unless (functionp (quic-connection-tls-input connection))
    (error 'quic-crypto-error :message "No QUIC TLS input callback installed"))
  (connection-touch connection)
  (funcall (quic-connection-tls-input connection) bytes :fin-p fin))

(defun connection-tls-poll (connection)
  (when (functionp (quic-connection-tls-output connection))
    (funcall (quic-connection-tls-output connection))))
