(in-package #:cl-quic-kit)

(shadow 'stream)

(export '(stream
          make-stream
          stream-id stream-direction stream-initiator stream-local-p
          stream-send-offset stream-receive-offset stream-read-offset
          stream-readable-bytes
          stream-finished-p stream-reset-p stream-stopped-p
          stream-write stream-finish stream-read stream-receive-data
          stream-reset-send stream-stop-sending
          stream-set-max-send-offset stream-set-max-receive-offset
          stream-pending-events stream-next-event
          stream-id-direction stream-id-initiator))

(defun stream-id-direction (id)
  (unless (and (integerp id) (<= 0 id))
    (error 'stream-id-error :stream-id id))
  (if (logbitp 1 id) :unidirectional :bidirectional))

(defun stream-id-initiator (id)
  (unless (and (integerp id) (<= 0 id))
    (error 'stream-id-error :stream-id id))
  (if (zerop (logand id 1)) :client :server))

(defun %octets (data)
  (unless (and (arrayp data) (= (array-rank data) 1)
               (subtypep (array-element-type data) '(unsigned-byte 8)))
    (error 'type-error :datum data :expected-type '(vector (unsigned-byte 8))))
  data)

(defun %copy-octets (data start end)
  (let ((result (make-array (- end start) :element-type '(unsigned-byte 8))))
    (replace result data :start1 0 :start2 start :end2 end)
    result))

(defun %same-octets-p (a b)
  (and (= (length a) (length b))
       (loop for i below (length a) always (= (aref a i) (aref b i)))))

(defstruct (stream (:constructor %make-stream))
  id direction initiator local-p
  (send-offset 0)
  (receive-offset 0)
  (read-offset 0)
  (send-final-size nil)
  (receive-final-size nil)
  (send-max-offset most-positive-fixnum)
  (receive-max-offset most-positive-fixnum)
  (segments nil)
  (read-buffer (make-array 0 :element-type '(unsigned-byte 8)))
  (reset-error-code nil)
  (stop-error-code nil)
  (events nil)
  flow-control)

(defun make-stream (id &key (local-initiator :client) flow-control
                              max-send-data max-receive-data)
  (let ((direction (stream-id-direction id))
        (initiator (stream-id-initiator id)))
    (unless (member local-initiator '(:client :server))
      (error 'type-error :datum local-initiator :expected-type '(member :client :server)))
    (when (and max-send-data (< max-send-data 0)) (error 'type-error))
    (when (and max-receive-data (< max-receive-data 0)) (error 'type-error))
    (when (and flow-control (not (typep flow-control 'flow-control-state)))
      (error 'type-error :datum flow-control :expected-type 'flow-control-state))
    (when (and flow-control (not (eq initiator local-initiator)))
      (error 'stream-id-error :stream-id id))
    (%make-stream :id id :direction direction :initiator initiator
                  :local-p (eq initiator local-initiator)
                  :send-max-offset (or max-send-data most-positive-fixnum)
                  :receive-max-offset (or max-receive-data most-positive-fixnum)
                  :flow-control flow-control)))

(defun stream-readable-bytes (stream)
  (length (stream-read-buffer stream)))

(defun stream-reset-p (stream)
  (not (null (stream-reset-error-code stream))))

(defun stream-stopped-p (stream)
  (not (null (stream-stop-error-code stream))))

(defun %queue-event (stream type &rest properties)
  (setf (stream-events stream)
        (nconc (stream-events stream) (list (list* :type type properties))))
  (car (last (stream-events stream))))

(defun stream-pending-events (stream)
  (copy-list (stream-events stream)))

(defun stream-next-event (stream)
  (pop (stream-events stream)))

(defun stream-set-max-send-offset (stream maximum)
  (unless (and (integerp maximum) (>= maximum (stream-send-offset stream)))
    (error 'flow-control-error))
  (when (< maximum (stream-send-max-offset stream))
    (error 'flow-control-error))
  (setf (stream-send-max-offset stream) maximum)
  maximum)

(defun stream-set-max-receive-offset (stream maximum)
  (unless (and (integerp maximum) (>= maximum (stream-receive-offset stream)))
    (error 'flow-control-error))
  (when (< maximum (stream-receive-max-offset stream))
    (error 'flow-control-error))
  (setf (stream-receive-max-offset stream) maximum)
  maximum)

(defun stream-write (stream data)
  (%octets data)
  (unless (stream-local-p stream) (error 'stream-id-error :stream-id (stream-id stream)))
  (when (or (stream-send-final-size stream) (stream-reset-p stream))
    (error 'flow-control-error))
  (let* ((size (length data))
         (end (+ (stream-send-offset stream) size)))
    (when (> end (stream-send-max-offset stream))
      (%raise-limit (stream-send-max-offset stream) end))
    (when (stream-flow-control stream)
      (flow-control-reserve-send (stream-flow-control stream) size))
    (incf (stream-send-offset stream) size)
    (list :offset (- (stream-send-offset stream) size) :data data :fin nil)))

(defun stream-finish (stream)
  (when (or (stream-send-final-size stream) (stream-reset-p stream))
    (error 'flow-control-error))
  (setf (stream-send-final-size stream) (stream-send-offset stream))
  (%queue-event stream :fin :offset (stream-send-offset stream)))

(defun stream-reset-send (stream error-code)
  (%non-negative-integer error-code :error-code)
  (when (stream-send-final-size stream) (error 'flow-control-error))
  (setf (stream-reset-error-code stream) error-code)
  (%queue-event stream :reset-stream :error-code error-code
                :final-size (stream-send-offset stream)))

(defun stream-stop-sending (stream error-code)
  (%non-negative-integer error-code :error-code)
  (setf (stream-stop-error-code stream) error-code)
  (%queue-event stream :stop-sending :error-code error-code))

(defun %merge-segments (previous current)
  (let* ((previous-start (car previous))
         (previous-data (cdr previous))
         (previous-end (+ previous-start (length previous-data)))
         (current-start (car current))
         (current-data (cdr current))
         (current-end (+ current-start (length current-data))))
    (if (> current-start previous-end)
        (values previous t)
        (progn
          (when (and (< current-start previous-end)
                     (not (%same-octets-p
                           (subseq previous-data (- current-start previous-start)
                                   (min (length previous-data)
                                        (- current-end previous-start)))
                           (subseq current-data 0
                                   (min (length current-data)
                                        (- previous-end current-start))))))
            (error 'flow-control-error))
          (values (if (> current-end previous-end)
                      (cons previous-start
                            (concatenate '(vector (unsigned-byte 8))
                                         previous-data
                                         (subseq current-data
                                                 (- previous-end current-start))))
                      previous)
                  nil)))))

(defun %insert-segment (stream start data)
  (let ((all (sort (cons (cons start data) (copy-list (stream-segments stream)))
                   #'< :key #'car))
        (result nil))
    (dolist (segment all)
      (if (null result)
          (push (cons (car segment) (copy-seq (cdr segment))) result)
          (multiple-value-bind (merged separate)
              (%merge-segments (car result) segment)
            (if separate
                (push (cons (car segment) (copy-seq (cdr segment))) result)
                (setf (car result) merged)))))
    (setf (stream-segments stream) (nreverse result))))

(defun %drain-contiguous (stream)
  (loop while (stream-segments stream)
        for segment = (first (stream-segments stream))
        for start = (car segment)
        for data = (cdr segment)
        while (= start (stream-receive-offset stream))
        do (setf (stream-segments stream) (rest (stream-segments stream)))
           (setf (stream-read-buffer stream)
                 (concatenate '(vector (unsigned-byte 8))
                              (stream-read-buffer stream) data))
           (incf (stream-receive-offset stream) (length data))))

(defun stream-receive-data (stream offset data &key fin)
  (%non-negative-integer offset :offset)
  (%octets data)
  (let ((end (+ offset (length data))))
    (when (> end (stream-receive-max-offset stream))
      (%raise-limit (stream-receive-max-offset stream) end))
    (when (stream-receive-final-size stream)
      (when (> end (stream-receive-final-size stream))
        (error 'flow-control-error)))
    (when fin
      (when (and (stream-receive-final-size stream)
                 (/= (stream-receive-final-size stream) end))
        (error 'flow-control-error))
      (setf (stream-receive-final-size stream) end))
    (when (> offset (stream-receive-offset stream))
      (%insert-segment stream offset (copy-seq data)))
    (when (= offset (stream-receive-offset stream))
      (%insert-segment stream offset (copy-seq data)))
    (%drain-contiguous stream)
    (list :offset offset :length (length data) :fin (not (null fin)))))

(defun stream-read (stream &optional (maximum most-positive-fixnum))
  (%non-negative-integer maximum :maximum)
  (let* ((count (min maximum (length (stream-read-buffer stream))))
         (data (%copy-octets (stream-read-buffer stream) 0 count)))
    (setf (stream-read-buffer stream)
          (%copy-octets (stream-read-buffer stream) count
                        (length (stream-read-buffer stream))))
    (incf (stream-read-offset stream) count)
    (values data (and (zerop (length (stream-read-buffer stream)))
                      (stream-receive-final-size stream)
                      (= (stream-receive-offset stream)
                         (stream-receive-final-size stream))))))

(defun stream-finished-p (stream)
  (and (zerop (length (stream-read-buffer stream)))
       (stream-receive-final-size stream)
       (= (stream-receive-offset stream) (stream-receive-final-size stream))))
