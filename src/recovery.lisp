;;;; QUIC loss detection and congestion control (RFC 9002).

(defpackage #:cl-quic-kit.recovery
  (:use #:cl)
  (:export #:make-recovery-state #:recovery-space #:record-sent-packet
           #:on-packet-received #:ack-needed-p #:on-ack-frame #:loss-timeout
           #:pto-deadline #:on-pto-expired #:newreno-on-ack #:newreno-on-loss
           #:recovery-state-smoothed-rtt #:recovery-state-rtt-variance
           #:recovery-state-latest-rtt #:recovery-state-min-rtt
           #:recovery-state-ssthresh #:recovery-state-recovery-start-time
           #:recovery-state-persistent-congestion-p
           #:recovery-state-cwnd #:recovery-state-bytes-in-flight
           #:recovery-state-pto-count #:packet-number-space-name))

(in-package #:cl-quic-kit.recovery)

(declaim (ftype function newreno-on-ack newreno-on-loss %newreno-on-loss))

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
  (first-rtt-sample-time nil) (acked-sent-times nil) (lost-sent-times nil)
  (max-ack-delay +max-ack-delay+) (ack-delay-exponent 3)
  (cwnd 12000) (ssthresh most-positive-fixnum) (bytes-in-flight 0)
  (recovery-start-time nil) (pto-count 0)
  (persistent-congestion-p nil))

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
        ((and (consp (first ranges))
              (or (and (listp (first ranges)) (= 2 (length (first ranges))))
                  (and (consp (first ranges)) (numberp (car (first ranges)))
                       (numberp (cdr (first ranges))))))
         (mapcar (lambda (range)
                   (if (and (listp range) (= 2 (length range)))
                       range
                       (list (car range) (cdr range))))
                 ranges))
        (t (mapcar (lambda (number) (list number number)) ranges))))

(defun %acked-p (number ranges)
  (some (lambda (range) (<= (first range) number (second range))) (%ack-ranges ranges)))

(defun %rtt-update (state latest ack-delay sampled-at)
  (let* ((min-rtt (recovery-state-min-rtt state))
         (adjusted (if (and min-rtt (>= latest (+ min-rtt ack-delay)))
                       (- latest ack-delay) latest))
         (old (recovery-state-smoothed-rtt state)))
    (setf (recovery-state-latest-rtt state) latest
          (recovery-state-min-rtt state) (if min-rtt (min min-rtt latest) latest))
    (if (null old)
        (setf (recovery-state-smoothed-rtt state) latest
              (recovery-state-rtt-variance state) (/ latest 2)
              (recovery-state-first-rtt-sample-time state) sampled-at)
        (setf (recovery-state-rtt-variance state)
              (+ (* 3/4 (recovery-state-rtt-variance state))
                 (* 1/4 (abs (- old adjusted))))
              (recovery-state-smoothed-rtt state)
              (+ (* 7/8 old) (* 1/8 adjusted))))))

(defun %pto (state &optional space-name)
  (if (recovery-state-smoothed-rtt state)
      (+ (recovery-state-smoothed-rtt state)
         (max +granularity+ (* 4 (recovery-state-rtt-variance state)))
         (if (member space-name '(:initial :handshake))
             0
             (recovery-state-max-ack-delay state)))
      (* 2 +initial-rtt+)))

(defun %ack-eliciting-in-flight-p (packet)
  (and (sent-packet-ack-eliciting packet)
       (sent-packet-in-flight packet)))

(defun %persistent-congestion-duration (state)
  (when (recovery-state-smoothed-rtt state)
    (* 3 (+ (recovery-state-smoothed-rtt state)
            (max +granularity+ (* 4 (recovery-state-rtt-variance state)))
            (recovery-state-max-ack-delay state)))))

(defun %persistent-congestion-p (state)
  (let ((sample-time (recovery-state-first-rtt-sample-time state))
        (duration (%persistent-congestion-duration state)))
    (when (and sample-time duration)
      (let ((times (sort (copy-list (remove-if-not
                                      (lambda (time) (> time sample-time))
                                      (recovery-state-lost-sent-times state)))
                         #'<)))
        (some (lambda (first)
                (some (lambda (last)
                        (and (> (- last first) duration)
                             (not (some (lambda (acked)
                                          (and (> acked first) (< acked last)))
                                        (recovery-state-acked-sent-times state)))))
                      (cdr (member first times))))
              times)))))

(defun %loss-delay (state)
  (max +granularity+
       (* +time-threshold+
          (max (or (recovery-state-smoothed-rtt state) +initial-rtt+)
               (or (recovery-state-latest-rtt state) +initial-rtt+)))))

(defun on-ack-frame (state space-name largest-acked ack-ranges
                     &key (ack-delay 0) (received-at (%now state)))
  "Process an ACK, returning (values acked-packets lost-packets)."
  (let* ((space (%space state space-name)) (acked nil) (lost nil)
         (latest-sample nil)
         (ack-eliciting-acked-p nil)
         (largest-acked-packet nil)
         (ranges (%ack-ranges ack-ranges)))
    (maphash (lambda (number packet)
               (when (%acked-p number ranges)
                 (push packet acked)
                 (when (sent-packet-ack-eliciting packet)
                   (setf ack-eliciting-acked-p t))
                 (when (= number largest-acked)
                   (setf largest-acked-packet packet))))
             (packet-number-space-sent space))
    (setf (packet-number-space-largest-acked space)
          (max largest-acked (packet-number-space-largest-acked space)))
    (unless acked
      (return-from on-ack-frame (values nil nil)))
    (when (and largest-acked-packet ack-eliciting-acked-p)
      (setf latest-sample (- received-at (sent-packet-sent-at largest-acked-packet))))
    (dolist (packet acked)
      (remhash (sent-packet-number packet) (packet-number-space-sent space)))
    (dolist (packet acked)
      (push (sent-packet-sent-at packet) (recovery-state-acked-sent-times state)))
    (when latest-sample
      (%rtt-update state latest-sample
                   (if (eq space-name :application)
                       (min ack-delay (recovery-state-max-ack-delay state))
                       0)
                   received-at))
    (let ((loss-delay (%loss-delay state)))
      (maphash (lambda (number packet)
                 (when (and (%ack-eliciting-in-flight-p packet)
                            (< number largest-acked)
                            (or (>= (- largest-acked number) +packet-threshold+)
                                (>= (- received-at (sent-packet-sent-at packet))
                                    loss-delay)))
                   (push packet lost)))
               (packet-number-space-sent space)))
    (dolist (packet lost)
      (remhash (sent-packet-number packet) (packet-number-space-sent space)))
    (dolist (packet lost)
      (push (sent-packet-sent-at packet) (recovery-state-lost-sent-times state)))
    (when (some #'%ack-eliciting-in-flight-p lost)
      (let ((last-loss-sent-at (reduce #'max lost
                                       :key #'sent-packet-sent-at)))
        (%newreno-on-loss state received-at last-loss-sent-at)))
    (dolist (packet acked)
      (when (sent-packet-in-flight packet)
        (decf (recovery-state-bytes-in-flight state) (sent-packet-bytes packet)))
      (when (sent-packet-in-flight packet)
        (newreno-on-ack state (sent-packet-bytes packet)
                        :sent-at (sent-packet-sent-at packet))))
    (dolist (packet lost)
      (when (sent-packet-in-flight packet)
        (decf (recovery-state-bytes-in-flight state) (sent-packet-bytes packet))))
    (when (%persistent-congestion-p state)
      (setf (recovery-state-persistent-congestion-p state) t
            (recovery-state-cwnd state) (* +minimum-window+ 1200)
            (recovery-state-recovery-start-time state) nil))
    (when ack-eliciting-acked-p
      (setf (recovery-state-pto-count state) 0))
    (values (nreverse acked) (nreverse lost))))

(defun %loss-deadline (state space)
  (let ((largest-acked (packet-number-space-largest-acked space))
        (loss-delay (%loss-delay state))
        (deadline nil))
    (when (>= largest-acked 0)
      (maphash (lambda (number packet)
                 (when (and (%ack-eliciting-in-flight-p packet)
                            (< number largest-acked))
                   (let ((candidate (+ (sent-packet-sent-at packet) loss-delay)))
                     (when (or (null deadline) (< candidate deadline))
                       (setf deadline candidate)))))
               (packet-number-space-sent space)))
    deadline))

(defun pto-deadline (state space-name &key (now (%now state)))
  (declare (ignore now))
  (let ((space (%space state space-name)) (last-sent nil))
    (when (%loss-deadline state space)
      (return-from pto-deadline nil))
    (maphash (lambda (number packet)
               (declare (ignore number))
               (when (%ack-eliciting-in-flight-p packet)
                 (when (or (null last-sent)
                           (> (sent-packet-sent-at packet) last-sent))
                   (setf last-sent (sent-packet-sent-at packet)))))
             (packet-number-space-sent space))
    (when last-sent
      (+ last-sent (* (%pto state space-name)
                      (expt 2 (recovery-state-pto-count state)))))))

(defun loss-timeout (state space-name &key (now (%now state)))
  (declare (ignore now))
  (%loss-deadline state (%space state space-name)))

(defun on-pto-expired (state)
  (incf (recovery-state-pto-count state))
  (list :probe-count 2 :pto-count (recovery-state-pto-count state) :at (%now state)))

(defun newreno-on-ack (state bytes &key sent-at)
  (unless (and (recovery-state-recovery-start-time state)
               sent-at
               (<= sent-at (recovery-state-recovery-start-time state)))
    (if (< (recovery-state-cwnd state) (recovery-state-ssthresh state))
        (incf (recovery-state-cwnd state) bytes)
        (incf (recovery-state-cwnd state)
              (max 1 (floor (* bytes 1200) (recovery-state-cwnd state)))))))

(defun %newreno-on-loss (state at last-loss-sent-at)
  (unless (and (recovery-state-recovery-start-time state)
               (<= last-loss-sent-at (recovery-state-recovery-start-time state)))
    (setf (recovery-state-ssthresh state)
          (max (floor (* (recovery-state-cwnd state) 1/2))
               (* +minimum-window+ 1200))
          (recovery-state-cwnd state) (recovery-state-ssthresh state)
          (recovery-state-recovery-start-time state) at))
  (recovery-state-cwnd state))

(defun newreno-on-loss (state &key (at (%now state)))
  (%newreno-on-loss state at at))
