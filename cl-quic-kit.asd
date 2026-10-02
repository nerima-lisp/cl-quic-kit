(asdf:defsystem "cl-quic-kit"
  :description "A Common Lisp QUIC toolkit based on RFC 9000, RFC 9001, and RFC 9002."
  :version "0.1.0"
  :author "nerima-lisp"
  :license "MIT"
  :depends-on ("cl-crypto-kit" "cl-tls-kit")
  :serial t
  :components ((:file "package")
               (:module "src" :serial t
                :components ((:file "varint")
                             (:file "packet")
                             (:file "frame")
                             (:file "flow-control")
                             (:file "stream")
                             (:file "state")
                             (:file "udp")
                             (:file "client")
                             (:file "protection")
                             (:file "recovery"))))
  :in-order-to ((test-op (test-op "cl-quic-kit/tests"))))

(asdf:defsystem "cl-quic-kit/tests"
  :depends-on ("cl-quic-kit")
  :serial t
  :components ((:file "t/run")))
