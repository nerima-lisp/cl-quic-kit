(ignore-errors (require :asdf))
(load (merge-pathnames "../package.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/varint.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/packet.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/frame.fasl"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/state.lisp"
                       (or *load-truename* *default-pathname-defaults*)))

(in-package #:cl-user)

(defparameter *state-tests-run* 0)

(defun state-check (condition description)
  (incf *state-tests-run*)
  (unless condition
    (error "State test failed: ~A" description)))

(let ((clock 0))
  (let ((connection (cl-quic-kit:make-quic-connection :now-fn (lambda () clock)
                                                       :idle-timeout 10)))
    (setf clock 10)
  (cl-quic-kit:connection-set-state connection :established)
  (state-check (cl-quic-kit:connection-check-idle-timeout connection)
               "idle timeout uses the injected clock when AT is omitted")
  (state-check (eq (cl-quic-kit:connection-state connection) :closing)
               "idle timeout enters closing")))

(let ((clock 0))
  (let ((connection (cl-quic-kit:make-quic-connection :now-fn (lambda () clock))))
    (cl-quic-kit:connection-set-state connection :established)
    (cl-quic-kit:connection-handle-new-connection-id
     connection 1 (make-array 8 :element-type '(unsigned-byte 8) :initial-element 1))
    (cl-quic-kit:connection-handle-new-connection-id
     connection 1 (make-array 8 :element-type '(unsigned-byte 8) :initial-element 1))
    (state-check (= (length (cl-quic-kit:connection-remote-connection-ids connection)) 1)
                 "duplicate NEW_CONNECTION_ID is idempotent")
    (cl-quic-kit:connection-handle-new-connection-id
     connection 2 (make-array 8 :element-type '(unsigned-byte 8) :initial-element 2))
    (cl-quic-kit:connection-handle-new-connection-id
     connection 3 (make-array 8 :element-type '(unsigned-byte 8) :initial-element 3))
    (state-check (eq (cl-quic-kit:connection-state connection) :closing)
                 "active_connection_id_limit starts a transport close")))

(let ((connection (cl-quic-kit:make-quic-connection
                   :local-connection-id
                   (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0))))
  (cl-quic-kit:connection-retire-connection-id
   connection (cl-quic-kit:connection-active-local-id connection))
  (state-check (and (cl-quic-kit:connection-active-local-id connection)
                    (= (length (cl-quic-kit:connection-local-connection-ids connection)) 1))
               "retiring the active local CID creates a replacement"))

(let ((clock 0))
  (let ((connection (cl-quic-kit:make-quic-connection :now-fn (lambda () clock))))
    (cl-quic-kit:connection-close connection :application-error "done")
    (state-check (eq (cl-quic-kit:connection-close-kind connection) :application)
                 "application close selects APPLICATION_CLOSE")
    (setf clock 90000)
    (state-check (cl-quic-kit:connection-poll connection clock)
                 "closing timeout reaches closed")))

(let ((connection (cl-quic-kit:make-quic-connection :now-fn (lambda () 0)))
      (bad-packet (make-array 1 :element-type '(unsigned-byte 8) :initial-element 255)))
  (state-check (null (cl-quic-kit:connection-receive-packet connection bad-packet))
               "invalid packets return NIL")
  (state-check (eq (cl-quic-kit:connection-state connection) :closing)
               "invalid packets schedule a transport close"))

(format t "~D state tests passed.~%" *state-tests-run*)
