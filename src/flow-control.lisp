(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (find-package :cl-quic-kit)
    (defpackage #:cl-quic-kit
      (:use #:cl)
      (:export
       #:flow-control-state
       #:make-flow-control-state
       #:flow-control-connection-max-data
       #:flow-control-connection-sent
       #:flow-control-connection-received
       #:flow-control-connection-receive-limit
       #:flow-control-max-streams-bidi
       #:flow-control-max-streams-uni
       #:flow-control-open-stream
       #:flow-control-close-stream
       #:flow-control-stream-count
       #:flow-control-can-send-p
       #:flow-control-reserve-send
       #:flow-control-note-received
       #:flow-control-update-max-data
       #:flow-control-update-max-receive-data
       #:flow-control-update-max-streams
       #:flow-control-data-blocked-p
       #:flow-control-streams-blocked-p
       #:flow-control-mark-data-blocked
       #:flow-control-mark-streams-blocked
       #:flow-control-error
       #:flow-control-limit-error
       #:stream-id-error))))

(in-package #:cl-quic-kit)

(define-condition flow-control-error (error) ())
(define-condition flow-control-limit-error (flow-control-error)
  ((limit :initarg :limit :reader flow-control-error-limit)
   (attempted :initarg :attempted :reader flow-control-error-attempted)))
(define-condition stream-id-error (error)
  ((stream-id :initarg :stream-id :reader invalid-stream-id)))

(defun %non-negative-integer (value name)
  (declare (ignore name))
  (unless (and (integerp value) (<= 0 value))
    (error 'type-error :datum value :expected-type `(integer 0)))
  value)

(defun %raise-limit (limit attempted)
  (error 'flow-control-limit-error :limit limit :attempted attempted))

(defstruct (flow-control-state
            (:constructor %make-flow-control-state))
  (connection-max-data 0 :type integer)
  (connection-sent 0 :type integer)
  (connection-received 0 :type integer)
  (connection-receive-limit 0 :type integer)
  (max-streams-bidi 0 :type integer)
  (max-streams-uni 0 :type integer)
  (stream-count-bidi 0 :type integer)
  (stream-count-uni 0 :type integer)
  (data-blocked-p nil)
  (streams-blocked-bidi-p nil)
  (streams-blocked-uni-p nil))

(defun make-flow-control-state (&key (max-data 0) max-receive-data
                                     (max-streams-bidi 0) (max-streams-uni 0))
  (mapc (lambda (x) (%non-negative-integer (car x) (cdr x)))
        (list (cons max-data :max-data)
              (cons max-streams-bidi :max-streams-bidi)
              (cons max-streams-uni :max-streams-uni)))
  (when (and max-receive-data
             (not (and (integerp max-receive-data) (>= max-receive-data 0))))
    (error 'type-error :datum max-receive-data :expected-type '(integer 0)))
  (%make-flow-control-state :connection-max-data max-data
                            :connection-receive-limit (or max-receive-data max-data)
                            :max-streams-bidi max-streams-bidi
                            :max-streams-uni max-streams-uni))

(defun flow-control-connection-max-data (state)
  (flow-control-state-connection-max-data state))

(defun flow-control-connection-sent (state)
  (flow-control-state-connection-sent state))

(defun flow-control-connection-received (state)
  (flow-control-state-connection-received state))

(defun flow-control-connection-receive-limit (state)
  (flow-control-state-connection-receive-limit state))

(defun flow-control-max-streams-bidi (state)
  (flow-control-state-max-streams-bidi state))

(defun flow-control-max-streams-uni (state)
  (flow-control-state-max-streams-uni state))

(defun flow-control-stream-count (state direction)
  (ecase direction
    (:bidirectional (flow-control-state-stream-count-bidi state))
    (:unidirectional (flow-control-state-stream-count-uni state))))

(defun flow-control-open-stream (state direction)
  (ecase direction
    (:bidirectional
     (when (>= (flow-control-state-stream-count-bidi state)
               (flow-control-state-max-streams-bidi state))
       (setf (flow-control-state-streams-blocked-bidi-p state) t)
       (%raise-limit (flow-control-state-max-streams-bidi state)
                     (1+ (flow-control-state-stream-count-bidi state))))
     (incf (flow-control-state-stream-count-bidi state)))
    (:unidirectional
     (when (>= (flow-control-state-stream-count-uni state)
               (flow-control-state-max-streams-uni state))
       (setf (flow-control-state-streams-blocked-uni-p state) t)
       (%raise-limit (flow-control-state-max-streams-uni state)
                     (1+ (flow-control-state-stream-count-uni state))))
     (incf (flow-control-state-stream-count-uni state))))
  t)

(defun flow-control-close-stream (state direction)
  ;; MAX_STREAMS limits the number of streams ever opened, not live streams.
  (ecase direction (:bidirectional state) (:unidirectional state))
  t)

(defun flow-control-can-send-p (state octets)
  (%non-negative-integer octets :octets)
  (<= (+ (flow-control-state-connection-sent state) octets)
      (flow-control-state-connection-max-data state)))

(defun flow-control-reserve-send (state octets)
  (%non-negative-integer octets :octets)
  (let ((attempted (+ (flow-control-state-connection-sent state) octets)))
    (if (<= attempted (flow-control-state-connection-max-data state))
        (progn (incf (flow-control-state-connection-sent state) octets) t)
        (progn (setf (flow-control-state-data-blocked-p state) t)
               (%raise-limit (flow-control-state-connection-max-data state)
                             attempted)))))

(defun flow-control-note-received (state octets)
  (%non-negative-integer octets :octets)
  (let ((attempted (+ (flow-control-state-connection-received state) octets)))
    (when (> attempted (flow-control-state-connection-receive-limit state))
      (%raise-limit (flow-control-state-connection-receive-limit state) attempted))
    (setf (flow-control-state-connection-received state) attempted)
    attempted))

(defun flow-control-update-max-data (state maximum)
  (%non-negative-integer maximum :maximum)
  (when (< maximum (flow-control-state-connection-max-data state))
    (error 'flow-control-error))
  (setf (flow-control-state-connection-max-data state) maximum
        (flow-control-state-data-blocked-p state) nil)
  maximum)

(defun flow-control-update-max-receive-data (state maximum)
  (%non-negative-integer maximum :maximum)
  (when (< maximum (flow-control-state-connection-receive-limit state))
    (error 'flow-control-error))
  (setf (flow-control-state-connection-receive-limit state) maximum)
  maximum)

(defun flow-control-update-max-streams (state direction maximum)
  (%non-negative-integer maximum :maximum)
  (ecase direction
    (:bidirectional
     (when (< maximum (flow-control-state-max-streams-bidi state))
       (error 'flow-control-error))
     (setf (flow-control-state-max-streams-bidi state) maximum
           (flow-control-state-streams-blocked-bidi-p state) nil))
    (:unidirectional
     (when (< maximum (flow-control-state-max-streams-uni state))
       (error 'flow-control-error))
     (setf (flow-control-state-max-streams-uni state) maximum
           (flow-control-state-streams-blocked-uni-p state) nil)))
  maximum)

(defun flow-control-data-blocked-p (state)
  (flow-control-state-data-blocked-p state))

(defun flow-control-streams-blocked-p (state direction)
  (ecase direction
    (:bidirectional (flow-control-state-streams-blocked-bidi-p state))
    (:unidirectional (flow-control-state-streams-blocked-uni-p state))))

(defun flow-control-mark-data-blocked (state)
  (setf (flow-control-state-data-blocked-p state) t))

(defun flow-control-mark-streams-blocked (state direction)
  (ecase direction
    (:bidirectional (setf (flow-control-state-streams-blocked-bidi-p state) t))
    (:unidirectional (setf (flow-control-state-streams-blocked-uni-p state) t))))
