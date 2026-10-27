(in-package #:cl-user)

(defun udp-poll-budget-test-type-error-p (thunk)
  (handler-case
      (progn (funcall thunk) nil)
    (type-error () t)))

(defun udp-poll-budget-test-datagrams (count)
  (loop repeat count
        collect (list (make-array 1 :element-type '(unsigned-byte 8)
                                  :initial-element 0)
                      1 '(:peer 443))))

(defun udp-poll-budget-test-with-queue (socket handler-name datagrams thunk)
  (let* ((receive-symbol (find-symbol "UDP-RECEIVE" "CL-QUIC-KIT"))
         (handler-symbol (find-symbol handler-name "CL-QUIC-KIT"))
         (original-receive (symbol-function receive-symbol))
         (original-handler (symbol-function handler-symbol))
         (queue (copy-list datagrams))
         (receive-calls 0)
         (datagrams-returned 0)
         (datagrams-handled 0))
    (unwind-protect
         (progn
           (setf (symbol-function receive-symbol)
                 (lambda (candidate-socket &rest arguments)
                   (if (eq candidate-socket socket)
                       (progn
                         (incf receive-calls)
                         (if queue
                             (let ((datagram (pop queue)))
                               (incf datagrams-returned)
                               (values-list datagram))
                             (values nil nil nil)))
                       (apply original-receive candidate-socket arguments)))
                 (symbol-function handler-symbol)
                 (lambda (&rest arguments)
                   (declare (ignore arguments))
                   (incf datagrams-handled)
                   nil))
           (funcall thunk
                    (lambda () receive-calls)
                    (lambda () datagrams-returned)
                    (lambda () datagrams-handled)
                    (lambda () (length queue))))
      (setf (symbol-function receive-symbol) original-receive
            (symbol-function handler-symbol) original-handler))))

(let* ((socket (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                            :local-port 0))
       (client (cl-quic-kit:make-quic-client
                :udp-socket socket :disable-hostname-verification-p t)))
  (unwind-protect
       (check (= (cl-quic-kit::quic-client-udp-receive-packet-budget client) 64)
              "client UDP receive packet budget defaults to 64")
    (cl-quic-kit:udp-close socket)))
(check
 (every (lambda (budget)
          (udp-poll-budget-test-type-error-p
           (lambda ()
             (cl-quic-kit:make-quic-client
              :disable-hostname-verification-p t
              :udp-receive-packet-budget budget))))
        '(0 -1 1.5))
 "client rejects non-positive and non-integer UDP receive packet budgets")

(let* ((socket (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                            :local-port 0))
       (client (cl-quic-kit:make-quic-client
                :udp-socket socket :udp-receive-packet-budget 2
                :disable-hostname-verification-p t
                :now-fn (lambda () 0))))
  (unwind-protect
       (udp-poll-budget-test-with-queue
        socket "CLIENT-RECEIVE-DATAGRAM"
        (udp-poll-budget-test-datagrams 3)
        (lambda (receive-calls datagrams-returned datagrams-handled remaining)
          (cl-quic-kit:client-poll client 0)
          (check (and (= (funcall receive-calls) 2)
                      (= (funcall datagrams-returned) 2)
                      (= (funcall datagrams-handled) 2)
                      (= (funcall remaining) 1))
                 "client poll handles its packet budget and leaves the remaining datagram queued")
          (cl-quic-kit:client-poll client 0)
          (check (and (= (funcall receive-calls) 4)
                      (= (funcall datagrams-returned) 3)
                      (= (funcall datagrams-handled) 3)
                      (zerop (funcall remaining)))
                 "the next client poll handles the remaining datagram")))
    (cl-quic-kit:udp-close socket)))

(let* ((server (cl-quic-kit:make-quic-server :local-address "127.0.0.1"
                                            :local-port 0
                                            :max-connections 1
                                            :retry-policy :never))
       (socket (cl-quic-kit::quic-server-udp-socket server)))
  (unwind-protect
       (check (= (cl-quic-kit::quic-server-udp-receive-packet-budget server)
                 64)
              "server UDP receive packet budget defaults to 64")
    (cl-quic-kit:quic-server-close server)))
(check
 (every (lambda (budget)
          (udp-poll-budget-test-type-error-p
           (lambda ()
             (cl-quic-kit:make-quic-server
              :local-address "127.0.0.1" :local-port 0 :max-connections 1
              :udp-receive-packet-budget budget))))
        '(0 -1 1.5))
 "server rejects non-positive and non-integer UDP receive packet budgets")

(let* ((server (cl-quic-kit:make-quic-server
                :local-address "127.0.0.1" :local-port 0 :max-connections 1
                :retry-policy :never :udp-receive-packet-budget 2))
       (socket (cl-quic-kit::quic-server-udp-socket server)))
  (unwind-protect
       (udp-poll-budget-test-with-queue
        socket "%SERVER-HANDLE-DATAGRAM"
        (udp-poll-budget-test-datagrams 3)
        (lambda (receive-calls datagrams-returned datagrams-handled remaining)
          (cl-quic-kit:quic-server-poll server 0)
          (check (and (= (funcall receive-calls) 2)
                      (= (funcall datagrams-returned) 2)
                      (= (funcall datagrams-handled) 2)
                      (= (funcall remaining) 1))
                 "server poll handles its packet budget and leaves the remaining datagram queued")
          (cl-quic-kit:quic-server-poll server 0)
          (check (and (= (funcall receive-calls) 4)
                      (= (funcall datagrams-returned) 3)
                      (= (funcall datagrams-handled) 3)
                      (zerop (funcall remaining)))
                 "the next server poll handles the remaining datagram")))
    (cl-quic-kit:quic-server-close server)))
(let* ((default-socket (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                                    :local-port 0))
       (blocking-socket (cl-quic-kit:make-udp-socket :local-host "127.0.0.1"
                                                     :local-port 0
                                                     :non-blocking-p nil)))
  (unwind-protect
       (check (and (eq t (cl-quic-kit:udp-socket-non-blocking-p default-socket))
                   (null (cl-quic-kit:udp-socket-non-blocking-p blocking-socket)))
              "public UDP socket predicate reports nonblocking mode")
    (unwind-protect
         (cl-quic-kit:udp-close default-socket)
      (cl-quic-kit:udp-close blocking-socket))))
