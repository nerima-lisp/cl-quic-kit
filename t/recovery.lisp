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
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200 :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 2 '((2 2))
                                     :received-at 1/10000)
  (recovery-check (= (cl-quic-kit.recovery:loss-timeout state :application)
                     1/1000)
                  "time-threshold loss uses kGranularity as a lower bound"))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (cl-quic-kit.recovery:newreno-on-loss state :at 1)
  (cl-quic-kit.recovery:newreno-on-ack state 600 :sent-at 2)
  (recovery-check (= (cl-quic-kit.recovery:recovery-state-cwnd state) 6120)
                  "NewReno congestion avoidance scales by acknowledged bytes"))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (dotimes (number 4)
    (cl-quic-kit.recovery:record-sent-packet state :application (1+ number) 1200
                                             :sent-at 0))
  (cl-quic-kit.recovery:on-ack-frame state :application 4 '((4 4))
                                     :received-at 0)
  (recovery-check (= (cl-quic-kit.recovery:recovery-state-cwnd state) 6000)
                  "NewReno processes a loss event before ACK growth"))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 3))))
  (cl-quic-kit.recovery:record-sent-packet state :application 0 1200 :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 0 '((0 0))
                                     :received-at 1/10)
  (dolist (packet '((1 1) (2 3/2) (3 21/10) (4 3)))
    (cl-quic-kit.recovery:record-sent-packet state :application (first packet) 1200
                                             :sent-at (second packet)))
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame state :application 4 '((4 4))
                                         :received-at 3)
    (declare (ignore acked))
    (recovery-check (and (= (length lost) 3)
                         (cl-quic-kit.recovery:recovery-state-persistent-congestion-p state))
                    "persistent congestion follows a three-PTO loss span")))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 4))))
  (dotimes (number 4)
    (cl-quic-kit.recovery:record-sent-packet state :application (1+ number) 1200
                                             :sent-at number))
  (cl-quic-kit.recovery:on-ack-frame state :application 4 '((4 4))
                                     :received-at 4)
  (recovery-check (not (cl-quic-kit.recovery:recovery-state-persistent-congestion-p state))
                  "persistent congestion waits for a prior RTT sample"))

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

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 1/10))))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0)
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200
                                           :ack-eliciting-p nil :in-flight-p nil
                                           :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 2 '((1 2))
                                     :received-at 1/10)
  (recovery-check (= (cl-quic-kit.recovery:recovery-state-latest-rtt state) 1/10)
                  "RTT sampling uses the largest newly acknowledged packet"))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 1))))
  (cl-quic-kit.recovery:record-sent-packet state :application 0 1200 :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 0 '((0 0))
                                     :received-at 1/10)
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0)
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200 :sent-at 0)
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame state :application 2 '((2 2))
                                         :received-at 1)
    (declare (ignore acked))
    (recovery-check (and (= (cl-quic-kit.recovery:recovery-state-latest-rtt state) 1)
                         (null lost))
                    "loss detection uses the RTT sample from the same ACK")))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 1))))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0)
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200
                                           :ack-eliciting-p nil :in-flight-p nil
                                           :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 2 '((2 2))
                                     :received-at 0)
  (recovery-check (= (cl-quic-kit.recovery:loss-timeout state :application)
                     (* 9/8 333/1000))
                  "loss timeout exposes a future time-threshold deadline")
  (recovery-check (null (cl-quic-kit.recovery:pto-deadline state :application))
                  "PTO is suppressed while time-threshold loss is armed"))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 4))))
  (cl-quic-kit.recovery:record-sent-packet state :application 0 1200 :sent-at 0)
  (cl-quic-kit.recovery:on-ack-frame state :application 0 '((0 0))
                                     :received-at 1/10)
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 1)
  (cl-quic-kit.recovery:record-sent-packet state :application 3 1200
                                           :ack-eliciting-p nil :in-flight-p nil
                                           :sent-at 3)
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame state :application 3 '((3 3))
                                         :received-at 3)
    (declare (ignore acked))
    (recovery-check (= (length lost) 1) "time threshold loss is tracked per space"))
  (cl-quic-kit.recovery:record-sent-packet state :handshake 1 1200 :sent-at 2)
  (cl-quic-kit.recovery:record-sent-packet state :handshake 2 1200
                                           :ack-eliciting-p nil :in-flight-p nil
                                           :sent-at 4)
  (multiple-value-bind (acked lost)
      (cl-quic-kit.recovery:on-ack-frame state :handshake 2 '((2 2))
                                         :received-at 4)
    (declare (ignore acked))
    (recovery-check (and (= (length lost) 1)
                         (cl-quic-kit.recovery:recovery-state-persistent-congestion-p state))
                    "persistent congestion spans packet number spaces")))

(let ((state (cl-quic-kit.recovery:make-recovery-state :clock (lambda () 0))))
  (cl-quic-kit.recovery:record-sent-packet state :application 1 1200 :sent-at 0
                                           :ack-eliciting-p nil :in-flight-p nil)
  (cl-quic-kit.recovery:record-sent-packet state :application 2 1200 :sent-at 0)
  (cl-quic-kit.recovery:on-pto-expired state)
  (recovery-check (= (cl-quic-kit.recovery:recovery-state-cwnd state) 12000)
                  "PTO does not reduce the congestion window"))

(format t "~D recovery tests passed.~%" *recovery-tests-run*)
