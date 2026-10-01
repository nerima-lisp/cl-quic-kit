(load (merge-pathnames "../package.lisp"
                       (or *load-truename* *default-pathname-defaults*)))

(dolist (file '("src/varint.lisp" "src/packet.lisp" "src/frame.lisp"
                "src/flow-control.lisp" "src/stream.lisp" "src/state.lisp"
                "src/protection.lisp" "src/recovery.lisp"))
  (load (merge-pathnames (concatenate 'string "../" file)
                         (or *load-truename* *default-pathname-defaults*))))

(in-package #:cl-user)

(defparameter *tests-run* 0)

(defun check (condition description)
  (incf *tests-run*)
  (unless condition
    (error "Test failed: ~A" description)))

(check (= cl-quic-kit:*quic-version-1* #x00000001)
       "QUIC v1 has the RFC 9000 version number")
(check (cl-quic-kit:connection-id-p (make-array 0 :element-type '(unsigned-byte 8)))
       "an empty connection ID is valid")
(check (cl-quic-kit:connection-id-p (make-array 20 :element-type '(unsigned-byte 8)))
       "a twenty-octet connection ID is valid")
(check (not (cl-quic-kit:connection-id-p (make-array 21 :element-type '(unsigned-byte 8))))
       "a twenty-one-octet connection ID is invalid")
(let ((rejected nil))
  (handler-case
      (cl-quic-kit:validate-connection-id "not-octets")
    (cl-quic-kit:invalid-connection-id () (setf rejected t)))
  (check rejected "malformed connection IDs are rejected"))
(let ((encoded (cl-quic-kit:encode-varint 494)))
  (multiple-value-bind (value size) (cl-quic-kit:decode-varint encoded)
    (check (and (= value 494) (= size 2)) "varint round trip")))
(let* ((frame (cl-quic-kit:make-frame :ping))
       (decoded (cl-quic-kit:decode-frame (cl-quic-kit:encode-frame frame))))
  (check (eq (cl-quic-kit:frame-type decoded) :ping) "PING frame round trip"))
(let* ((stream (cl-quic-kit:make-stream 0 :local-initiator :client))
       (payload (make-array 3 :element-type '(unsigned-byte 8)
                            :initial-contents '(1 2 3))))
  (cl-quic-kit:stream-receive-data stream 0 payload :fin t)
  (multiple-value-bind (data fin) (cl-quic-kit:stream-read stream)
    (check (and fin (equalp data payload)) "ordered stream data and FIN")))
(let ((clock 0) (connection nil))
  (setf connection (cl-quic-kit:make-quic-connection
                    :now-fn (lambda () clock) :idle-timeout 10))
  (cl-quic-kit:connection-set-state connection :established)
  (setf clock 10)
  (check (cl-quic-kit:connection-check-idle-timeout connection clock)
         "idle timeout closes established connection"))
(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (cl-quic-kit.recovery:on-packet-received state :initial 1)
  (check (cl-quic-kit.recovery:ack-needed-p state :initial :now 0)
         "ack eliciting packet schedules ACK"))
(format t "~D tests passed.~%" *tests-run*)
