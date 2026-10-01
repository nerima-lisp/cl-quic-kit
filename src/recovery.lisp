;;;; QUIC loss detection and congestion control (RFC 9002).

(defpackage #:cl-quic-kit.recovery
  (:use #:cl)
  (:export #:make-recovery-state #:recovery-space #:record-sent-packet
           #:on-packet-received #:ack-needed-p #:on-ack-frame #:loss-timeout
           #:pto-deadline #:on-pto-expired #:newreno-on-ack #:newreno-on-loss
           #:recovery-state-smoothed-rtt #:recovery-state-rtt-variance
           #:recovery-state-cwnd #:recovery-state-bytes-in-flight
           #:recovery-state-pto-count #:packet-number-space-name))

(in-package #:cl-quic-kit.recovery)

(defconstant +initial-rtt+ 333/1000)
(defconstant +granularity+ 1/1000)
(defconstant +max-ack-delay+ 25/1000)
(defconstant +packet-threshold+ 3)
(defconstant +time-threshold+ 9/8)
(defconstant +minimum-window+ 2)

(defstruct (packet-number-space (:constructor %make-space (name)))
  name (largest-received -1) (largest-acked -1) (ack-eliciting-count 0)
  (ack-pending nil) (ack-deadline nil)
  (sent (make-hash-table :test #'eql)) (loss-time nil))

(defstruct (sent-packet (:constructor %make-sent (number sent-at bytes ack-eliciting in-flight)))
  number sent-at bytes ack-eliciting in-flight)

(defstruct (recovery-state (:constructor %make-recovery-state))
  clock (spaces (make-hash-table :test #'eq))
  (smoothed-rtt nil) (rtt-variance nil) (latest-rtt nil) (min-rtt nil)
  (max-ack-delay +max-ack-delay+) (ack-delay-exponent 3)
  (cwnd 12000) (ssthresh most-positive-fixnum) (bytes-in-flight 0)
  (recovery-start-time nil) (pto-count 0))

(defun %now (state)
  (if (recovery-state-clock state)
      (funcall (recovery-state-clock state))
      (error "A deterministic recovery clock is required.")))

(defun %space (state name)
  (or (gethash name (recovery-state-spaces state))
      (setf (gethash name (recovery-state-spaces state)) (%make-space name))))

(defun make-recovery-state (&key clock (max-ack-delay +max-ack-delay+)
                                  (ack-delay-exponent 3) (initial-cwnd 12000))
  (let ((state (%make-recovery-state :clock clock :max-ack-delay max-ack-delay
                                     :ack-delay-exponent ack-delay-exponent
                                     :cwnd initial-cwnd)))
    (dolist (name '(:initial :handshake :application)) (%space state name))
    state))

(defun recovery-space (state name)
  (check-type name (member :initial :handshake :application))
  (%space state name))

(defun record-sent-packet (state space-name packet-number bytes
                            &key (ack-eliciting-p t) (in-flight-p ack-eliciting-p)
                              (sent-at (%now state)))
  (let* ((space (%space state space-name))
         (packet (%make-sent packet-number sent-at bytes ack-eliciting-p in-flight-p)))
    (setf (gethash packet-number (packet-number-space-sent space)) packet)
    (when in-flight-p (incf (recovery-state-bytes-in-flight state) bytes))
    packet))

(defun on-packet-received (state space-name packet-number &key (ack-eliciting-p t)
                                             (received-at (%now state)))
  (let ((space (%space state space-name)))
    (when (> packet-number (packet-number-space-largest-received space))
      (setf (packet-number-space-largest-received space) packet-number))
    (when ack-eliciting-p
      (incf (packet-number-space-ack-eliciting-count space))
      (setf (packet-number-space-ack-pending space) t)
      (when (null (packet-number-space-ack-deadline space))
        (setf (packet-number-space-ack-deadline space)
              (+ received-at (if (eq space-name :application)
                                 (recovery-state-max-ack-delay state) 0)))))
    space))

(defun ack-needed-p (state space-name &key (now (%now state)))
  (let ((space (%space state space-name)))
    (and (packet-number-space-ack-pending space)
         (or (>= (packet-number-space-ack-eliciting-count space) 2)
             (and (packet-number-space-ack-deadline space)
                  (>= now (packet-number-space-ack-deadline space)))))))

(defun %ack-ranges (ranges)
  (cond ((null ranges) nil)
        ((and (consp (first ranges)) (= 2 (length (first ranges)))) ranges)
        (t (mapcar (lambda (number) (list number number)) ranges))))

(defun %acked-p (number ranges)
  (some (lambda (range) (<= (first range) number (second range))) (%ack-ranges ranges)))

(defun %rtt-update (state latest ack-delay)
  (let* ((min-rtt (recovery-state-min-rtt state))
         (adjusted (if (and min-rtt (> latest (+ min-rtt ack-delay)))
                       (- latest ack-delay) latest))
         (old (recovery-state-smoothed-rtt state)))
    (setf (recovery-state-latest-rtt state) latest
          (recovery-state-min-rtt state) (if min-rtt (min min-rtt latest) latest))
    (if (null old)
        (setf (recovery-state-smoothed-rtt state) latest
              (recovery-state-rtt-variance state) (/ latest 2))
        (setf (recovery-state-rtt-variance state)
              (+ (* 3/4 (recovery-state-rtt-variance state))
                 (* 1/4 (abs (- old adjusted))))
              (recovery-state-smoothed-rtt state)
              (+ (* 7/8 old) (* 1/8 adjusted))))))

(defun %pto (state)
  (if (recovery-state-smoothed-rtt state)
      (+ (recovery-state-smoothed-rtt state)
         (max +granularity+ (* 4 (recovery-state-rtt-variance state)))
         (recovery-state-max-ack-delay state))
      (* 2 +initial-rtt+)))

(defun on-ack-frame (state space-name largest-acked ack-ranges
                     &key (ack-delay 0) (received-at (%now state)))
  "Process an ACK, returning (values acked-packets lost-packets)."
  (let* ((space (%space state space-name)) (acked nil) (lost nil)
         (latest-sample nil)
         (loss-delay (* +time-threshold+
                        (max (or (recovery-state-smoothed-rtt state) +initial-rtt+)
                             (or (recovery-state-latest-rtt state) +initial-rtt+)))))
    (maphash (lambda (number packet)
               (when (%acked-p number ack-ranges)
                 (push packet acked)
                 (when (and (sent-packet-ack-eliciting packet)
                            (= number largest-acked))
                   (setf latest-sample (- received-at (sent-packet-sent-at packet))))
                 (remhash number (packet-number-space-sent space)))
               (when (and (sent-packet-ack-eliciting packet)
                          (< number largest-acked)
                          (or (>= (- largest-acked number) +packet-threshold+)
                              (>= (- received-at (sent-packet-sent-at packet)) loss-delay)))
                 (push packet lost)
                 (remhash number (packet-number-space-sent space))))
             (packet-number-space-sent space))
    (dolist (packet acked)
      (when (sent-packet-in-flight packet)
        (decf (recovery-state-bytes-in-flight state) (sent-packet-bytes packet)))
      (newreno-on-ack state (sent-packet-bytes packet)))
    (dolist (packet lost)
      (when (sent-packet-in-flight packet)
        (decf (recovery-state-bytes-in-flight state) (sent-packet-bytes packet)))
      (newreno-on-loss state))
    (when latest-sample
      (%rtt-update state latest-sample
                   (min ack-delay (recovery-state-max-ack-delay state))))
    (setf (packet-number-space-largest-acked space)
          (max largest-acked (packet-number-space-largest-acked space))
          (recovery-state-pto-count state) 0)
    (values (nreverse acked) (nreverse lost))))

(defun pto-deadline (state space-name &key (now (%now state)))
  (let ((space (%space state space-name)))
    (when (> (hash-table-count (packet-number-space-sent space)) 0)
      (+ now (* (%pto state) (expt 2 (recovery-state-pto-count state)))))))

(defun loss-timeout (state space-name &key (now (%now state)))
  (let* ((space (%space state space-name))
         (rtt (max (or (recovery-state-smoothed-rtt state) +initial-rtt+)
                   (or (recovery-state-latest-rtt state) +initial-rtt+)))
         (deadline nil))
    (maphash (lambda (number packet)
               (declare (ignore number))
               (let ((candidate (+ (sent-packet-sent-at packet) (* +time-threshold+ rtt))))
                 (when (and (<= candidate now)
                            (or (null deadline) (< candidate deadline)))
                   (setf deadline candidate))))
             (packet-number-space-sent space))
    deadline))

(defun on-pto-expired (state)
  (incf (recovery-state-pto-count state))
  (list :probe-count 2 :pto-count (recovery-state-pto-count state) :at (%now state)))

(defun newreno-on-ack (state bytes)
  (if (< (recovery-state-cwnd state) (recovery-state-ssthresh state))
      (incf (recovery-state-cwnd state) bytes)
      (incf (recovery-state-cwnd state)
            (max 1 (floor (* 1200 bytes) (recovery-state-cwnd state))))))

(defun newreno-on-loss (state)
  (setf (recovery-state-ssthresh state)
        (max (* (recovery-state-cwnd state) 1/2) (* +minimum-window+ 1200))
        (recovery-state-cwnd state) (recovery-state-ssthresh state)
        (recovery-state-recovery-start-time state) (%now state))
  (recovery-state-cwnd state))
