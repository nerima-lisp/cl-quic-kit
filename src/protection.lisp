;;;; QUIC packet protection (RFC 9001).

(defpackage #:cl-quic-kit.protection
  (:use #:cl)
  (:export #:crypto-not-implemented #:configure-crypto-backend
           #:derive-initial-secrets #:make-key-set #:key-set-key #:key-set-iv #:key-set-hp
           #:key-set-cipher
           #:protect-payload #:unprotect-payload #:apply-header-protection
           #:remove-header-protection #:reconstruct-packet-number
           #:retry-integrity-tag #:verify-retry-integrity))

(in-package #:cl-quic-kit.protection)

(declaim (ftype function retry-integrity-tag))

(define-condition crypto-not-implemented (error)
  ((operation :initarg :operation :reader crypto-operation))
  (:report (lambda (condition stream)
             (format stream "cl-crypto-kit operation is not configured: ~A"
                     (crypto-operation condition)))))

(defparameter *initial-salt*
  (make-array 20 :element-type '(unsigned-byte 8)
              :initial-contents '(56 118 44 247 245 89 52 179 77 23
                                  154 230 164 200 12 173 204 203 127 10)))
(defvar *hkdf-extract* nil)
(defvar *hkdf-expand* nil)
(defvar *aead-seal* nil)
(defvar *aead-open* nil)
(defvar *aes-ecb* nil)
(defvar *chacha20* nil)
(defvar *constant-time-equal* nil)

(defun configure-crypto-backend (&key hkdf-extract hkdf-expand aead-seal aead-open
                                      aes-ecb chacha20 constant-time-equal)
  "Install cl-crypto-kit adapters.
HKDF receives (algorithm salt ikm) and (algorithm prk info length),
AEAD receives (algorithm key nonce data aad),
and header protection receives (key block16) for AES or (key counter nonce length)
for ChaCha."
  (setf *hkdf-extract* hkdf-extract *hkdf-expand* hkdf-expand
        *aead-seal* aead-seal *aead-open* aead-open *aes-ecb* aes-ecb
        *chacha20* chacha20 *constant-time-equal* constant-time-equal)
  (setf cl-quic-kit::*retry-integrity-tag-function*
        (lambda (retry-packet original-destination-connection-id)
          (retry-integrity-tag retry-packet
                               :original-destination-connection-id
                               original-destination-connection-id)))
  t)

(defun %require-crypto (operation function)
  (or function (error 'crypto-not-implemented :operation operation)))

(defun %protection-octets (value name)
  (declare (ignore name))
  (unless (or (typep value '(simple-array (unsigned-byte 8) (*)))
              (and (vectorp value) (zerop (length value))))
    (error 'type-error :datum value
           :expected-type '(simple-array (unsigned-byte 8) (*))))
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
  (unless (and (integerp number) (<= 0 number #xffff))
    (error "TLS vector length is outside the uint16 range: ~S" number))
  (vector (ldb (byte 8 8) number) (ldb (byte 8 0) number)))

(defun %hkdf-label (label context length)
  (let* ((full (%concat (%ascii "tls13 ") (%ascii label)))
         (ctx (%protection-octets context "context")))
    (%concat (%u16 length) (vector (length full)) full
             (vector (length ctx)) ctx)))

(defun %expand-label (hash-algorithm secret label context length)
  (funcall (%require-crypto :hkdf-expand *hkdf-expand*)
           hash-algorithm secret (%hkdf-label label context length) length))

(defstruct (key-set (:constructor %make-key-set (key iv hp cipher)))
  key iv hp cipher)

(defun make-key-set (secret &key (cipher :aes-128-gcm) (hash-algorithm :sha256)
                             (key-length 16)
                             (iv-length 12) (hp-length 16))
  (unless (member cipher '(:aes-128-gcm :aes-256-gcm :chacha20))
    (error "Unsupported QUIC packet protection cipher: ~S" cipher))
  (let ((secret (%protection-octets secret "secret")))
    (%make-key-set (%expand-label hash-algorithm secret "quic key" #() key-length)
                   (%expand-label hash-algorithm secret "quic iv" #() iv-length)
                   (%expand-label hash-algorithm secret "quic hp" #() hp-length)
                   cipher)))

(defun derive-initial-secrets (destination-connection-id
                               &key (salt *initial-salt*) (hash-algorithm :sha256)
                                 (hash-length 32)
                                 (cipher :aes-128-gcm) (key-length 16)
                                 (iv-length 12) (hp-length 16))
  "Derive RFC 9001 section 5.2 client/server Initial packet keys."
  (let* ((dcid (%protection-octets destination-connection-id "destination-connection-id"))
         (salt (%protection-octets salt "salt"))
         (initial (funcall (%require-crypto :hkdf-extract *hkdf-extract*)
                           hash-algorithm salt dcid))
         (client-secret (%expand-label hash-algorithm initial "client in" #() hash-length))
         (server-secret (%expand-label hash-algorithm initial "server in" #() hash-length)))
    (list :initial-secret initial :client-secret client-secret :server-secret server-secret
          :client (make-key-set client-secret :cipher cipher :hash-algorithm hash-algorithm
                                :key-length key-length
                                :iv-length iv-length :hp-length hp-length)
          :server (make-key-set server-secret :cipher cipher :hash-algorithm hash-algorithm
                                :key-length key-length
                                :iv-length iv-length :hp-length hp-length))))

(defun %nonce (iv packet-number)
  (unless (and (integerp packet-number) (<= 0 packet-number) (< packet-number (ash 1 62)))
    (error "QUIC packet number must be an integer in [0, 2^62): ~S" packet-number))
  (let ((nonce (copy-seq (%protection-octets iv "iv"))) (value packet-number))
    (unless (= (length nonce) 12)
      (error "QUIC AEAD IV must be 12 octets, got ~D" (length nonce)))
    (loop for i from (1- (length nonce)) downto 0 while (plusp value)
          do (setf (aref nonce i)
                   (logxor (aref nonce i) (ldb (byte 8 0) value)))
             (setf value (ash value -8)))
    nonce))

(defun protect-payload (key-set packet-number plaintext associated-data)
  (funcall (%require-crypto :aead-seal *aead-seal*)
           (key-set-cipher key-set) (key-set-key key-set)
           (%nonce (key-set-iv key-set) packet-number)
           (%protection-octets plaintext "plaintext") (%protection-octets associated-data "associated-data")))

(defun unprotect-payload (key-set packet-number ciphertext associated-data)
  (funcall (%require-crypto :aead-open *aead-open*)
           (key-set-cipher key-set) (key-set-key key-set)
           (%nonce (key-set-iv key-set) packet-number)
           (%protection-octets ciphertext "ciphertext") (%protection-octets associated-data "associated-data")))

(defun %header-mask (key-set sample)
  (let ((sample (%protection-octets sample "sample")))
    (when (< (length sample) 16)
      (error "QUIC header protection sample must be 16 octets"))
    (let ((mask (ecase (key-set-cipher key-set)
                  ((:aes-128-gcm :aes-256-gcm)
                   (funcall (%require-crypto :aes-ecb *aes-ecb*)
                            (key-set-hp key-set) sample))
                  (:chacha20
                   (funcall (%require-crypto :chacha20 *chacha20*)
                            (key-set-hp key-set)
                            (+ (aref sample 12)
                               (ash (aref sample 13) 8)
                               (ash (aref sample 14) 16)
                               (ash (aref sample 15) 24))
                            (subseq sample 0 12) 5)))))
      (unless (and (vectorp mask) (>= (length mask) 5))
        (error "Header protection backend must return at least 5 octets"))
      (subseq mask 0 5))))
(defun apply-header-protection (key-set packet sample packet-number-offset
                                 packet-number-length long-header-p)
  (unless (member packet-number-length '(1 2 3 4))
    (error "Packet number length must be 1, 2, 3, or 4: ~S" packet-number-length))
  (unless (and (integerp packet-number-offset) (>= packet-number-offset 1))
    (error "Packet number offset must be a positive integer: ~S" packet-number-offset))
  (let* ((packet (%protection-octets packet "packet"))
         (sample (%protection-octets sample "sample"))
         (result (copy-seq packet)))
    (when (< (length sample) 16)
      (error "QUIC header protection sample must be 16 octets"))
    (when (> (+ packet-number-offset packet-number-length) (length result))
      (error "Packet number field is outside packet"))
    (when (< (length result) 1)
      (error "QUIC packet must contain a first header octet"))
    (let* ((mask (%header-mask key-set sample))
           (first-mask (if long-header-p #x0f #x1f)))
      (setf (aref result 0) (logxor (aref result 0)
                                    (logand first-mask (aref mask 0))))
      (loop for i below packet-number-length
            do (setf (aref result (+ packet-number-offset i))
                     (logxor (aref result (+ packet-number-offset i))
                             (aref mask (1+ i)))))
      result)))

(defun remove-header-protection (&rest arguments)
  "Header protection is XOR and therefore uses the same operation to remove it."
  (apply #'apply-header-protection arguments))

(defun reconstruct-packet-number (truncated-packet-number packet-number-length
                                  largest-received-packet-number)
  "Reconstruct a full packet number as specified by RFC 9000 Appendix A."
  (check-type packet-number-length (integer 1 4))
  (unless (and (integerp truncated-packet-number)
               (<= 0 truncated-packet-number))
    (error "Truncated packet number must be a non-negative integer: ~S"
           truncated-packet-number))
  (unless (and (integerp largest-received-packet-number)
               (>= largest-received-packet-number -1)
               (< largest-received-packet-number (ash 1 62)))
    (error "Largest received packet number is outside the QUIC range: ~S"
           largest-received-packet-number))
  (let* ((pn-bits (* 8 packet-number-length))
         (pn-window (ash 1 pn-bits))
         (pn-half-window (ash pn-window -1))
         (pn-mask (1- pn-window))
         (expected (1+ largest-received-packet-number))
         (candidate (logior (logand truncated-packet-number pn-mask)
                            (logand expected (lognot pn-mask)))))
    (unless (< truncated-packet-number pn-window)
      (error "Truncated packet number does not fit packet-number-length"))
    (cond ((and (<= candidate (- expected pn-half-window))
                (< candidate (- (ash 1 62) pn-window)))
           (+ candidate pn-window))
          ((and (> candidate (+ expected pn-half-window))
                (>= candidate pn-window))
           (- candidate pn-window))
          (t candidate))))

(defparameter *retry-integrity-key*
  (make-array 16 :element-type '(unsigned-byte 8)
              :initial-contents '(190 12 105 11 159 102 87 90 29 118 107 84 227 104 200 78)))
(defparameter *retry-integrity-nonce*
  (make-array 12 :element-type '(unsigned-byte 8)
              :initial-contents '(70 21 153 211 93 99 43 242 35 152 37 187)))

(defun retry-integrity-tag (retry-packet &key original-destination-connection-id)
  "Return the RFC 9001 v1 Retry Integrity Tag for RETRY-PACKET.
RETRY-PACKET excludes its 16-octet tag; the ODCID is prepended to form AAD."
  (let* ((odcid (%protection-octets original-destination-connection-id
                                  "original-destination-connection-id"))
         (tag (funcall (%require-crypto :retry-integrity-aead *aead-seal*)
                       :aes-128-gcm *retry-integrity-key* *retry-integrity-nonce* #()
                       (%concat (vector (length odcid)) odcid
                                (%protection-octets retry-packet "retry-packet")))))
    (unless (and (vectorp tag) (= (length tag) 16))
      (error "Retry integrity AEAD must return a 16-octet tag"))
    tag))

(defun verify-retry-integrity (retry-packet tag &key original-destination-connection-id)
  (let ((expected (retry-integrity-tag retry-packet
                                       :original-destination-connection-id
                                       original-destination-connection-id))
         (actual (%protection-octets tag "tag")))
    (unless (= (length actual) 16)
      (return-from verify-retry-integrity nil))
    (if *constant-time-equal*
        (funcall *constant-time-equal* expected actual)
        (let ((difference (logxor (length expected) (length actual))))
          (dotimes (i (max (length expected) (length actual)))
            (setf difference
                  (logior difference
                          (logxor (if (< i (length expected)) (aref expected i) 0)
                                  (if (< i (length actual)) (aref actual i) 0))))
          (zerop difference))))))
