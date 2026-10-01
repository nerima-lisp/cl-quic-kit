(load (merge-pathnames "../package.lisp"
                       (or *load-truename* *default-pathname-defaults*)))
(load (merge-pathnames "../src/recovery.lisp"
                       (or *load-truename* *default-pathname-defaults*)))

(in-package #:cl-user)

(defparameter *recovery-tests-run* 0)

(defun recovery-check (condition description)
  (incf *recovery-tests-run*)
  (unless condition
    (error "Recovery test failed: ~A" description)))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 20))))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 10)
  (recovery-check (= (cl-quic-kit.recovery:pto-deadline state :application)
                     (+ 10 (* 2 333/1000)))
                  "PTO is anchored to the last ack-eliciting send time"))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 1))))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 1 '((1 1))
                                     :received-at 1/10000)
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200 :sent-at 0)
  (recovery-check (= (cl-quic-kit.recovery:loss-timeout state :application)
                     1/1000)
                  "time-threshold loss uses kGranularity as a lower bound"))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (cl-quic-kit.recovery:newreno-on-loss state :at 1)
  (cl-quic-kit.recovery:newreno-on-ack state 600 :sent-at 2)
  (recovery-check (= (cl-quic-kit.recovery:recovery-state-cwnd state) 6120)
                  "NewReno congestion avoidance scales by acknowledged bytes"))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 4))))
  (dotimes (number 4)
    (cl-quic-kit.recovery:record-sent-packet state :application (1+ number) 1200
                                             :sent-at number))
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame state :application 4 '((4 4))
                                         :received-at 4)
    (declare (ignore acked))
    (recovery-check (and (= (length lost) 3)
                         (cl-quic-kit.recovery:recovery-state-persistent-congestion-p state))
                    "persistent congestion follows a three-PTO loss span")))

(let ((state (cl-quic-kit.recovery:make-recovery-state
              :clock (lambda () 0) :max-ack-delay 1/40)))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 1 '((1 1))
                                      :received-at 1/10)
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200 :sent-at 1)
  (cl-quic-kit.recovery:on-ack-frame state :application 2 '((2 2))
                                      :ack-delay 1/100 :received-at 111/100)
  (cl-quic-kit.recovery:record-sent-packet state :application 3 1200 :sent-at 1)
  (cl-quic-kit.recovery:record-sent-packet state :handshake 3 1200 :sent-at 1)
  (recovery-check (and (= (cl-quic-kit.recovery:recovery-state-smoothed-rtt state) 1/10)
                       (= (cl-quic-kit.recovery:recovery-state-rtt-variance state) 3/80))
                  "RTT correction accepts an acknowledgment delay at the min-RTT boundary")
  (let ((handshake (cl-quic-kit.recovery:pto-deadline state :handshake))
        (application (cl-quic-kit.recovery:pto-deadline state :application)))
    (recovery-check (= handshake (+ 1 1/4))
                    "Initial and Handshake PTO omit max_ack_delay")
    (recovery-check (= (- application handshake) 1/40)
                    "Application PTO includes max_ack_delay")))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0
                                           :ack-eliciting-p nil :in-flight-p nil)
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200 :sent-at 0)
  (cl-quic-kit.recovery:on-pto-expired state)
  (recovery-check (= (cl-quic-kit.recovery:recovery-state-cwnd state) 12000)
                  "PTO does not reduce the congestion window"))

(format t "~D recovery tests passed.~%" *recovery-tests-run*)
