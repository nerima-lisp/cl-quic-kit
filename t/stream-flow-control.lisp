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
  (cl-quic-kit:stream-next-event stream)
  (stream-flow-check (eq (getf (cl-quic-kit:stream-next-event stream) :type)
                         :reset-stream)
                     "peer STOP_SENDING elicits RESET_STREAM"))

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

(let* ((flow (cl-quic-kit:make-flow-control-state :max-data 10
                                                  :max-receive-data 10))
       (stream (cl-quic-kit:make-stream 0 :local-initiator :client
                                        :flow-control flow)))
  (cl-quic-kit:stream-receive-data stream 5 (octets 5 6 7 8 9))
  (stream-flow-check (= (cl-quic-kit:flow-control-connection-received flow) 10)
                     "sparse stream data consumes flow credit through its highest offset")
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-receive-data stream 0 (octets 0 1 2 3 4 5 6 7 8 9))
      (cl-quic-kit:flow-control-error () (setf rejected t)))
    (stream-flow-check (not rejected) "retransmitted sparse stream data is accepted")))

(let ((stream (cl-quic-kit:make-stream 0 :local-initiator :client
                                       :max-receive-data 4)))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-reset-receive stream 9 5)
      (cl-quic-kit:flow-control-limit-error () (setf rejected t)))
    (stream-flow-check rejected "RESET_STREAM final size obeys stream flow control")))

(let ((stream (cl-quic-kit:make-stream 0 :local-initiator :client)))
  (cl-quic-kit:stream-receive-data stream 0 (octets 1 2))
  (cl-quic-kit:stream-reset-receive stream 42 2)
  (stream-flow-check (= (cl-quic-kit:stream-readable-bytes stream) 0)
                     "RESET_STREAM discards buffered receive data")
  (stream-flow-check (cl-quic-kit:stream-finished-p stream)
                     "RESET_STREAM leaves the receive side terminal"))

(let ((stream (cl-quic-kit:make-stream 2 :local-initiator :client)))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-reset-receive stream 1 0)
      (cl-quic-kit:stream-id-error () (setf rejected t)))
    (stream-flow-check rejected "RESET_STREAM is rejected for a local unidirectional stream"))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-stop-sending stream 1)
      (cl-quic-kit:stream-id-error () (setf rejected t)))
    (stream-flow-check rejected "STOP_SENDING is rejected for a local unidirectional stream")))

(let ((flow (cl-quic-kit:make-flow-control-state :max-data 2)))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:flow-control-update-max-data flow 3)
      (cl-quic-kit:flow-control-error () (setf rejected t)))
    (stream-flow-check (not rejected) "MAX_DATA increases the send limit")
    (stream-flow-check (= (cl-quic-kit:flow-control-connection-max-data flow) 3)
                       "MAX_DATA stores the increased limit")))

(let ((rejected nil))
  (handler-case (cl-quic-kit:make-stream 0 :max-send-data (1+ (expt 2 62)))
    (cl-quic-kit:flow-control-error () (setf rejected t)))
  (stream-flow-check rejected "stream flow limits reject offsets above 2^62-1"))

(let ((rejected nil))
  (handler-case
      (cl-quic-kit:make-flow-control-state :max-streams-bidi (1+ (expt 2 60)))
    (cl-quic-kit:flow-control-error () (setf rejected t)))
  (stream-flow-check rejected "MAX_STREAMS rejects counts above 2^60"))

(let ((stream (cl-quic-kit:make-stream 0 :local-initiator :client)))
  (cl-quic-kit:stream-receive-data stream 0 (octets 1 2))
  (multiple-value-bind (data fin) (cl-quic-kit:stream-read stream)
    (declare (ignore data fin)))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-receive-data stream 0 (octets 9 2))
      (cl-quic-kit:flow-control-error () (setf rejected t)))
    (stream-flow-check rejected
                       "conflicting retransmission is rejected after data is read")))

(let ((stream (cl-quic-kit:make-stream 0 :local-initiator :client)))
  (cl-quic-kit:stream-receive-data stream 3 (octets 4 5))
  (cl-quic-kit:stream-reset-receive stream 42 5)
  (multiple-value-bind (data fin) (cl-quic-kit:stream-read stream)
    (stream-flow-check (and (zerop (length data)) fin)
                       "RESET_STREAM is terminal even with an undelivered gap"))
  (stream-flow-check (cl-quic-kit:stream-finished-p stream)
                     "RESET_STREAM finalizes a sparse receive side"))

(let ((stream (cl-quic-kit:make-stream 2 :local-initiator :client)))
  (cl-quic-kit:stream-stop-sending-receive stream 7)
  (stream-flow-check (eq (getf (cl-quic-kit:stream-next-event stream) :type)
                         :stop-sending)
                     "STOP_SENDING is accepted on a local unidirectional sender")
  (stream-flow-check (eq (getf (cl-quic-kit:stream-next-event stream) :type)
                         :reset-stream)
                     "STOP_SENDING resets the local sending part"))

(let ((stream (cl-quic-kit:make-stream 3 :local-initiator :client))
      (rejected nil))
  (handler-case (cl-quic-kit:stream-stop-sending-receive stream 7)
    (cl-quic-kit:stream-id-error () (setf rejected t)))
  (stream-flow-check rejected
                     "STOP_SENDING is rejected on a peer unidirectional receiver"))

(let ((stream (cl-quic-kit:make-stream 0 :local-initiator :client
                                       :max-send-data 2)))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-write stream (octets 1 2 3))
      (cl-quic-kit:flow-control-limit-error () (setf rejected t)))
    (stream-flow-check rejected "stream flow control blocks an oversized write")
    (stream-flow-check
     (eq (getf (cl-quic-kit:stream-next-event stream) :type)
         :stream-data-blocked)
     "stream flow control emits STREAM_DATA_BLOCKED"))
  (cl-quic-kit:stream-set-max-send-offset stream 3)
  (stream-flow-check (= (getf (cl-quic-kit:stream-write stream (octets 8)) :offset) 0)
                     "MAX_STREAM_DATA permits a later write"))

(let ((flow (cl-quic-kit:make-flow-control-state :max-data 2
                                                 :max-streams-bidi 1)))
  (cl-quic-kit:flow-control-open-stream flow :bidirectional)
  (let ((rejected nil))
    (handler-case (cl-quic-kit:flow-control-open-stream flow :bidirectional)
      (cl-quic-kit:flow-control-limit-error () (setf rejected t)))
    (stream-flow-check rejected "MAX_STREAMS records a blocked opener")
    (stream-flow-check (cl-quic-kit:flow-control-streams-blocked-p
                        flow :bidirectional)
                       "MAX_STREAMS exposes blocked signaling"))
  (stream-flow-check (= (cl-quic-kit:flow-control-update-max-streams
                         flow :bidirectional 0) 1)
                       "a smaller MAX_STREAMS value is ignored")
  (stream-flow-check (cl-quic-kit:flow-control-streams-blocked-p
                      flow :bidirectional)
                     "a smaller MAX_STREAMS does not clear blocked signaling")
  (cl-quic-kit:flow-control-update-max-streams flow :bidirectional 2)
  (stream-flow-check (not (cl-quic-kit:flow-control-streams-blocked-p
                           flow :bidirectional))
                     "an increased MAX_STREAMS clears blocked signaling"))

(let ((flow (cl-quic-kit:make-flow-control-state :max-data 1))
      (stream nil))
  (setf stream (cl-quic-kit:make-stream 0 :local-initiator :client
                                         :flow-control flow))
  (let ((rejected nil))
    (handler-case (cl-quic-kit:stream-write stream (octets 1 2))
      (cl-quic-kit:flow-control-limit-error () (setf rejected t)))
    (stream-flow-check rejected "connection flow control blocks a write")
    (stream-flow-check (cl-quic-kit:flow-control-data-blocked-p flow)
                       "connection flow control exposes DATA_BLOCKED"))
  (cl-quic-kit:flow-control-update-max-data flow 2)
  (stream-flow-check (not (cl-quic-kit:flow-control-data-blocked-p flow))
                     "MAX_DATA clears DATA_BLOCKED signaling"))

(let ((rejected nil))
  (handler-case (cl-quic-kit:make-stream 0 :max-send-data 1.5)
    (type-error () (setf rejected t)))
  (stream-flow-check rejected "stream flow limits require integer offsets"))

(let ((stream (cl-quic-kit:make-stream 0 :max-send-data 4
                                       :max-receive-data 4)))
  (stream-flow-check (= (cl-quic-kit:stream-set-max-send-offset stream 2) 4)
                     "a smaller MAX_STREAM_DATA does not reduce send credit")
  (stream-flow-check (= (cl-quic-kit:stream-set-max-receive-offset stream 2) 4)
                     "a smaller receive limit does not reduce stream credit"))

(format t "~D stream/flow-control tests passed.~%" *stream-flow-tests*)
