(load (merge-pathnames "../package.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/flow-control.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/stream.lisp"
                       (or *load-truename* *default-pathname-defaults*)))

(in-package #:cl-user)

(defparameter *stream-flow-tests* 0)

(defun stream-flow-check (condition description)
  (incf *stream-flow-tests*)
  (unless condition (error "Test failed: ~A" description)))

(defun octets (&rest values)
  (make-array (length values) :element-type '(unsigned-byte 8)
              :initial-contents values))

(let* ((flow (cl-quic-kit:make-flow-control-state
              :max-data 6 :max-receive-data 6 :max-streams-bidi 1
              :max-streams-uni 1))
       (stream (cl-quic-kit:make-stream 0 :local-initiator :client
                                        :flow-control flow
                                        :max-receive-data 6)))
  (cl-quic-kit:stream-receive-data stream 3 (octets 4 5 6))
  (cl-quic-kit:stream-receive-data stream 0 (octets 1 2 3))
  (cl-quic-kit:stream-receive-data stream 0 (octets 1 2 3))
  (stream-flow-check (= (cl-quic-kit:flow-control-connection-received flow) 6)
                     "duplicate stream data is counted once")
  (multiple-value-bind (data fin) (cl-quic-kit:stream-read stream)
    (stream-flow-check (and (equalp data (octets 1 2 3 4 5 6)) (not fin))
                       "out-of-order data is drained in order")))

(let ((stream (cl-quic-kit:make-stream 0 :local-initiator :client)))
  (cl-quic-kit:stream-receive-data stream 2 (octets 3 4))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-receive-data stream 3 (octets 9))
      (cl-quic-kit:flow-control-error () (setf rejected t)))
    (stream-flow-check rejected "conflicting overlapping data is rejected"))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-receive-data stream 0 (octets 1 2 3) :fin t)
      (cl-quic-kit:flow-control-error () (setf rejected t)))
    (stream-flow-check rejected "a FIN below an already received end is rejected")))

(let ((stream (cl-quic-kit:make-stream 0 :local-initiator :client)))
  (cl-quic-kit:stream-reset-receive stream 42 0)
  (stream-flow-check (cl-quic-kit:stream-reset-p stream)
                     "received RESET_STREAM changes stream state")
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-reset-receive stream 42 1)
      (cl-quic-kit:flow-control-error () (setf rejected t)))
    (stream-flow-check rejected "RESET_STREAM final size is immutable")))

(let ((stream (cl-quic-kit:make-stream 1 :local-initiator :client)))
  (cl-quic-kit:stream-stop-sending-receive stream 7)
  (stream-flow-check (cl-quic-kit:stream-stopped-p stream)
                     "received STOP_SENDING changes stream state")
  (stream-flow-check (getf (cl-quic-kit:stream-receive-data stream 0 (octets 1)) :discarded)
                     "data after STOP_SENDING is discarded"))

(let ((flow (cl-quic-kit:make-flow-control-state :max-data 2
                                                 :max-streams-bidi 1)))
  (cl-quic-kit:flow-control-open-stream flow :bidirectional)
  (let ((rejected nil))
    (handler-case (cl-quic-kit:flow-control-open-stream flow :bidirectional)
      (cl-quic-kit:flow-control-limit-error () (setf rejected t)))
    (stream-flow-check rejected "MAX_STREAMS blocks new streams"))
  (cl-quic-kit:flow-control-update-max-streams flow :bidirectional 2)
  (cl-quic-kit:flow-control-open-stream flow :bidirectional)
  (stream-flow-check (= (cl-quic-kit:flow-control-stream-count flow :bidirectional) 2)
                     "MAX_STREAMS increases cumulatively"))

(let ((flow (cl-quic-kit:make-flow-control-state :max-data 2))
      (stream nil))
  (setf stream (cl-quic-kit:make-stream 0 :local-initiator :client
                                         :flow-control flow
                                         :max-send-data 10))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-write stream (octets 1 2 3))
      (cl-quic-kit:flow-control-limit-error () (setf rejected t)))
    (stream-flow-check rejected "MAX_DATA blocks stream writes")
    (stream-flow-check (eq (getf (cl-quic-kit:stream-next-event stream) :type)
                           :data-blocked)
                       "blocked send emits DATA_BLOCKED event")))

(format t "~D stream/flow-control tests passed.~%" *stream-flow-tests*)
