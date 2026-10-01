;;;; QUIC packet protection (RFC 9001).

(defpackage #:cl-quic-kit.protection
  (:use #:cl)
  (:export #:crypto-not-implemented #:configure-crypto-backend
           #:derive-initial-secrets #:make-key-set #:key-set-key #:key-set-iv #:key-set-hp
           #:key-set-cipher
           #:protect-payload #:unprotect-payload #:apply-header-protection
           #:remove-header-protection))

(in-package #:cl-quic-kit.protection)

(define-condition crypto-not-implemented (error)
  ((operation :initarg :operation :reader crypto-operation))
  (:report (lambda (condition stream)
             (format stream "cl-crypto-kit operation is not configured: ~A"
                     (crypto-operation condition)))))

(defparameter *initial-salt*
  #(56 118 44 247 241 59 97 204 30 144 8 149 227 202 74 214 0 185 113 53))
(defvar *hkdf-extract* nil)
(defvar *hkdf-expand* nil)
(defvar *aead-seal* nil)
(defvar *aead-open* nil)
(defvar *aes-ecb* nil)
(defvar *chacha20* nil)

(defun configure-crypto-backend (&key hkdf-extract hkdf-expand aead-seal aead-open
                                      aes-ecb chacha20)
  "Install cl-crypto-kit adapters.
HKDF expand receives (prk info length), AEAD receives (key nonce data aad), and
header protection receives (key sample) for AES or (key sample counter) for ChaCha."
  (setf *hkdf-extract* hkdf-extract *hkdf-expand* hkdf-expand
        *aead-seal* aead-seal *aead-open* aead-open *aes-ecb* aes-ecb
        *chacha20* chacha20)
  t)

(defun %require-crypto (operation function)
  (or function (error 'crypto-not-implemented :operation operation)))

(defun %octets (value name)
  (declare (ignore name))
  (unless (and (vectorp value)
               (every (lambda (x) (typep x '(unsigned-byte 8))) value))
    (error 'type-error :datum value :expected-type '(vector (unsigned-byte 8))))
  value)

(defun %concat (&rest vectors)
  (let ((result (make-array (reduce #'+ vectors :key #'length :initial-value 0)
                            :element-type '(unsigned-byte 8)))
        (at 0))
    (dolist (vector vectors result)
      (replace result vector :start1 at)
      (incf at (length vector)))))

(defun %ascii (string)
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun %u16 (number)
  (vector (ldb (byte 8 8) number) (ldb (byte 8 0) number)))

(defun %hkdf-label (label context length)
  (let* ((full (%concat (%ascii "quic ") (%ascii label)))
         (ctx (%octets context "context")))
    (%concat (%u16 length) (vector (length full)) full
             (vector (length ctx)) ctx)))

(defun %expand-label (secret label context length)
  (funcall (%require-crypto :hkdf-expand *hkdf-expand*)
           secret (%hkdf-label label context length) length))

(defstruct (key-set (:constructor %make-key-set (key iv hp cipher)))
  key iv hp cipher)

(defun make-key-set (secret &key (cipher :aes-128-gcm) (key-length 16)
                             (iv-length 12) (hp-length 16))
  (let ((secret (%octets secret "secret")))
    (%make-key-set (%expand-label secret "quic key" #() key-length)
                   (%expand-label secret "quic iv" #() iv-length)
                   (%expand-label secret "quic hp" #() hp-length)
                   cipher)))

(defun derive-initial-secrets (destination-connection-id
                               &key (salt *initial-salt*) (hash-length 16)
                                 (cipher :aes-128-gcm) (key-length 16)
                                 (iv-length 12) (hp-length 16))
  "Derive RFC 9001 section 5.2 client/server Initial packet keys."
  (let* ((dcid (%octets destination-connection-id "destination-connection-id"))
         (salt (%octets salt "salt"))
         (initial (funcall (%require-crypto :hkdf-extract *hkdf-extract*) salt dcid))
         (client-secret (%expand-label initial "client in" #() hash-length))
         (server-secret (%expand-label initial "server in" #() hash-length)))
    (list :initial-secret initial :client-secret client-secret :server-secret server-secret
          :client (make-key-set client-secret :cipher cipher :key-length key-length
                                :iv-length iv-length :hp-length hp-length)
          :server (make-key-set server-secret :cipher cipher :key-length key-length
                                :iv-length iv-length :hp-length hp-length))))

(defun %nonce (iv packet-number)
  (let ((nonce (copy-seq iv)) (value packet-number))
    (loop for i from (1- (length nonce)) downto 0 while (plusp value)
          do (setf (aref nonce i)
                   (logxor (aref nonce i) (ldb (byte 8 0) value)))
             (setf value (ash value -8)))
    nonce))

(defun protect-payload (key-set packet-number plaintext associated-data)
  (funcall (%require-crypto :aead-seal *aead-seal*)
           (key-set-key key-set) (%nonce (key-set-iv key-set) packet-number)
           (%octets plaintext "plaintext") (%octets associated-data "associated-data")))

(defun unprotect-payload (key-set packet-number ciphertext associated-data)
  (funcall (%require-crypto :aead-open *aead-open*)
           (key-set-key key-set) (%nonce (key-set-iv key-set) packet-number)
           (%octets ciphertext "ciphertext") (%octets associated-data "associated-data")))

(defun %header-mask (key-set sample)
  (subseq (ecase (key-set-cipher key-set)
            ((:aes-128-gcm :aes-256-gcm)
             (funcall (%require-crypto :aes-ecb *aes-ecb*)
                      (key-set-hp key-set) (%octets sample "sample")))
            (:chacha20
             (funcall (%require-crypto :chacha20 *chacha20*)
                      (key-set-hp key-set) (%octets sample "sample") 0)))
          0 5))

(defun apply-header-protection (key-set packet sample packet-number-offset
                                 packet-number-length long-header-p)
  (let* ((result (copy-seq (%octets packet "packet")))
         (mask (%header-mask key-set sample))
         (first-mask (if long-header-p #x0f #x1f)))
    (setf (aref result 0) (logxor (aref result 0)
                                  (logand first-mask (aref mask 0))))
    (loop for i below packet-number-length
          do (setf (aref result (+ packet-number-offset i))
                   (logxor (aref result (+ packet-number-offset i))
                           (aref mask (1+ i)))))
    result))

(defun remove-header-protection (&rest arguments)
  "Header protection is XOR and therefore uses the same operation to remove it."
  (apply #'apply-header-protection arguments))
