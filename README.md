# cl-quic-kit

Common Lisp building blocks for QUIC version 1.

The packet, TLS, and loss-recovery code draws on these specifications:

- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9002: QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002)

The package provides QUIC varints, packet and frame codecs, stream and flow-control state, loss recovery and
NewReno state, connection lifecycle management, and an explicit `cl-crypto-kit` backend boundary.

Rational smoothed RTT and RTT variance estimates are rounded to a nanosecond grid to bound arithmetic
precision across repeated ACKs. Raw latest and minimum samples are retained; floating-point estimates
keep their existing recurrence.

Configure the QUIC packet-protection backend before constructing a client or processing Initial packets
with a server. The client derives Initial secrets during construction; the server derives them when it
handles an Initial packet. Call `cl-quic-kit.protection:configure-crypto-backend` with callbacks for
`:hkdf-extract`,
`:hkdf-expand`, `:aead-seal`, `:aead-open`, and `:constant-time-equal`. Provide `:aes-ecb` for AES cipher
suites and `:chacha20` for the ChaCha20-Poly1305 suite. `:hkdf-extract` receives `(algorithm salt ikm)`;
`:hkdf-expand` receives `(algorithm prk info length)`. `:aead-seal` and `:aead-open` receive
`(algorithm key nonce data aad)`. `:aes-ecb` receives `(key block16)`, and `:chacha20` receives
`(key counter nonce length)`. Byte-producing callbacks return simple `(unsigned-byte 8)` vectors;
header-protection callbacks return at least five octets. `:constant-time-equal` receives two octet vectors and
returns true when they match. `t/run.lisp` shows how the test
runner connects these callbacks to `cl-crypto-kit`. This packet-protection backend is separate from TLS
provider selection. The client accepts a cl-tls-kit provider object as `:tls-provider`; set the server
provider as `:provider` within `:tls-server-options`.

## Client API

```lisp
(cl-quic-kit:make-quic-client
 :server-host host
 :server-port port
 :hostname hostname
 :tls-trust-anchors (list trust-anchor))
```

`server-host` and `hostname` are strings; `server-port` is an integer UDP port from 0 through 65535.
`server-host` sets the UDP destination, while `hostname` is used for TLS certificate verification. Supply
parsed certificate objects in `:tls-trust-anchors`; parse a DER root certificate with
`(cl-tls-kit.x509:parse-certificate-der root-certificate-der)`. The client does not load system trust roots.
The default signature verifier uses cl-crypto-kit's `verify-signature`. The default client socket uses
nonblocking UDP. Call `(cl-quic-kit:client-poll client)` from the application's event loop to start and drive
the TLS handshake. Continue polling until
`(cl-quic-kit:connection-state (cl-quic-kit:quic-client-connection client))` is `:established`;
the client enters that state after it receives the server's `HANDSHAKE_DONE` frame.
The `:alpn` option takes a list of protocol names and defaults to `("h3")`; set it to `NIL` to omit ALPN.
The optional `:idle-timeout` value uses seconds and defaults to 30; the client advertises it in milliseconds.

After the handshake, `(cl-quic-kit:client-open-stream client nil)` opens a locally initiated bidirectional
stream. Its second argument is currently unused. Pass the returned stream to
`cl-quic-kit:client-write-stream` or `cl-quic-kit:client-read-stream`.
Both operations require a stream registered with that client.

- `cl-quic-kit:client-accept-peer-stream (client)` returns one available peer stream. Call
  `(cl-quic-kit:client-poll client)` to send queued frames and process available UDP datagrams, then call
  `(cl-quic-kit:client-accept-peer-stream client)` until it returns `NIL`. Poll again to process later
  datagrams. Each peer-initiated stream is returned once; locally opened streams are excluded. After
  `(cl-quic-kit:client-close client)`, `cl-quic-kit:client-accept-peer-stream` returns `NIL`; use
  `(cl-quic-kit:quic-client-closed-p client)` to distinguish that case from no available stream. Pass a
  returned stream to `(cl-quic-kit:client-read-stream client stream)` to consume available octets. It
  returns an octet vector, which is empty when no data is buffered. The second return value is true when
  all data through the peer's FIN has been consumed, or after a peer reset, which discards unread buffered
  octets.
  To send FIN, write the final octets with
  `(cl-quic-kit:client-write-stream client stream octets :fin-p t)`. This marks
  the last STREAM frame with FIN. Call `(cl-quic-kit:client-poll client)` to send
  queued frames. The predicate
  `(cl-quic-kit:client-stream-write-pending-p client stream)` reports queued or
  unsent data. `(cl-quic-kit:client-close-stream client stream)` removes a stream
  from the client and does not enqueue FIN. It drops writes waiting for flow control.
  STREAM frames already queued remain queued and may be sent by a later
  `(cl-quic-kit:client-poll client)` call.
- `cl-quic-kit:client-receive-frames (client level packet-number frames)` applies the complete decoded
  `frames` list from one packet. The caller passes that packet's `level` (`:initial`, `:handshake`, `:0-rtt`,
  or `:1-rtt`) and `packet-number` for the whole list. A separate call with the same packet number is recorded
  again for ACK processing and its frames are processed again. Use it when a custom transport has decoded
  packet frames and needs to preserve their packet number. For full datagrams, use
  `cl-quic-kit:client-receive-datagram`.
- `cl-quic-kit:client-receive-frame (client frame &key (level :initial))` applies an already-decoded frame
  directly to a client with packet number 0. The `:level` keyword selects the encryption level for
  frame-permission checks and defaults to `:initial`; pass `:level :1-rtt` for stream or flow-control frames.
  Use it for frame-level tests; call
  `cl-quic-kit:client-receive-frames` when the packet number matters. Obtain a frame with
  `cl-quic-kit:decode-frame` or construct one with
  `cl-quic-kit:make-frame`. Normal clients should call `cl-quic-kit:client-poll`, which receives UDP
  datagrams and decodes their packets and frames.
- `cl-quic-kit:quic-connection-closed-reason (connection)` returns the peer's recorded `CONNECTION_CLOSE`
  reason as octets. It is `NIL` if no peer reason was recorded, and `#()` if the recorded reason is empty.
  For a client, read it with
  `(cl-quic-kit:quic-connection-closed-reason (cl-quic-kit:quic-client-connection client))`. The optional
  `:reason` passed to `cl-quic-kit:client-close` is sent to the peer but does not populate this field.

The client checks reserved bits after payload authentication. Nonzero reserved bits close the connection
with `PROTOCOL_VIOLATION` (`#x0a`). AEAD authentication failures are counted across connection keys;
successful packets do not reset the counter. Exceeding the selected cipher's integrity limit closes the
connection with `AEAD_LIMIT_REACHED` (`#x0f`): `2^52` for AES-128/256-GCM or `2^36` for
ChaCha20-Poly1305. Malformed packets caught by `client-receive-datagram` use the fixed reason
`invalid packet`. A frame received in a packet-number space where QUIC forbids it closes with
`PROTOCOL_VIOLATION` (`#x0a`). The client does not send provider diagnostics to the peer.

When called on an open client, `cl-quic-kit:client-close` attempts to send `CONNECTION_CLOSE`. It closes
the UDP socket even if sending fails, including a supplied socket. Call it when finished, including after a
protocol close, to ensure socket cleanup. If sending and socket cleanup both fail, the send error is
re-signaled. A cleanup-only error also propagates. Repeated calls do not send another close or repeat socket
cleanup.

## Server API

Create a listener with a positive `:max-connections` value. Supply the certificate chain and matching private
key through `:tls-server-options`. The chain is a list of DER-encoded certificates with the leaf first; the
private key must be a cl-crypto-kit ECDSA P-256 or Ed25519 private-key object. The API accepts DER
certificate octets and private-key objects; it does not parse PEM files.
In the example, `bind-address` is the IPv4 interface and `port` is its UDP port.

```lisp
(cl-quic-kit:make-quic-server
 :local-address bind-address
 :local-port port
 :max-connections 256
 :transport-parameters
 '(:initial-max-data 1048576
   :initial-max-stream-data-bidi-local 65536
   :initial-max-stream-data-bidi-remote 65536
   :initial-max-stream-data-uni 65536
   :initial-max-streams-bidi 25
   :initial-max-streams-uni 25)
 :tls-server-options
 (list :certificate-chain certificate-chain-der
       :private-key private-key))
```

The listener defaults to IPv4 address `0.0.0.0` and UDP port `443`. Set `:local-address` to an IPv4
address string and `:local-port` to an integer from 0 through 65535; port 0 binds an ephemeral port.
The `:retry-policy` option accepts `:always` (the default) or `:never`; with `:never`, a tokenless Initial
proceeds without a Retry packet.
The `:handshake-timeout` option accepts a positive real duration in seconds and defaults to 10. Its absolute
deadline starts when the server creates connection state; later traffic does not extend it. At the first
`cl-quic-kit:quic-server-poll` at or after the deadline, the server silently discards an incomplete handshake,
releases its routes and admission slots, and never returns it from `cl-quic-kit:quic-server-accept-connection`.
This timeout is a local policy, not a timeout prescribed by QUIC. RFC 9000 §10.2.3 warns that a
`CONNECTION_CLOSE` in response to unauthenticated handshake information can expose legitimate connections to
denial of service and permits discarding packets when an error is detected in an unauthenticated packet
instead of immediately closing ([RFC 9000 §10.2.3](https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3)).
`:local-address` applies when the listener creates its socket. When supplying a socket, configure it with
`:local-host` in `cl-quic-kit:make-udp-socket`. To read the assigned port, create a socket and pass it to the listener:

```lisp
(let* ((socket (cl-quic-kit:make-udp-socket
                :local-host bind-address :local-port 0))
       (server (cl-quic-kit:make-quic-server
                :udp-socket socket
                :max-connections 256
                :tls-server-options
                (list :certificate-chain certificate-chain-der
                      :private-key private-key)))
  (values server (cl-quic-kit:udp-socket-local-port socket)))
```

The server takes ownership of the supplied socket. The `cl-quic-kit:udp-socket-non-blocking-p` accessor
returns true when a socket uses nonblocking mode. Give clients a reachable server address and the returned
port.

The server passes `:tls-server-options` to cl-tls-kit's public
[`make-tls13-server-driver`](https://github.com/nerima-lisp/cl-tls-kit/blob/d6cf61a9ac2c/docs/tls13-server-driver.md)
constructor. Within that plist, `:alpn-protocols` defaults to `("h3")` and `:cipher-suites` defaults to
`#(#x1301 #x1302 #x1303)`. The server creates a cl-crypto-kit provider when `:provider` is omitted and sets
the driver's `:quic-transport-parameters` option from the encoded server parameters. The server buffers peer
QUIC transport parameters as opaque bytes and decodes and validates them only after cl-tls-kit verifies the
client's Finished and emits `:handshake-complete`. Invalid parameters cause a
`TRANSPORT_PARAMETER_ERROR`; the server does not return that connection from
`cl-quic-kit:quic-server-accept-connection`.

The `crypto-kit:` package is provided by the `cl-crypto-kit` system. For a P-256 key, pass a 32-octet private
scalar to
`(crypto-kit:make-ec-private-key :p256 scalar-octets)`. For Ed25519, pass a 32-octet seed to
`(crypto-kit:make-ed25519-private-key seed-octets)`.

With the default nonblocking UDP socket, `cl-quic-kit:quic-server-poll` drains available datagrams,
drives handshakes, and returns; call it from the application's event loop. It returns `NIL` while the server
is open and true after it is closed. `cl-quic-kit:quic-server-close` closes the server immediately: it attempts
to send a protected CONNECTION_CLOSE for each active connection, clears routes and completed connections
waiting in the accept queue, and closes its owned UDP socket. It completes cleanup even if sending or closing
the socket fails, then re-signals the first error. Repeated calls are safe.

After each poll, call `cl-quic-kit:quic-server-accept-connection` repeatedly until it returns `NIL`. Each call
returns one handshake-complete `cl-quic-kit:quic-connection`, and each connection is returned once.

For graceful shutdown, call `cl-quic-kit:quic-server-shutdown`. It stops admitting new connections while
existing connections remain usable, so the application can finish work and close connections with
`cl-quic-kit:quic-connection-close`. The default grace period is 30 seconds. Pass `:grace-period` to
`cl-quic-kit:quic-server-shutdown` to choose another nonnegative duration. The first call sets the shutdown
deadline; repeated calls do not change it. Continue polling until `cl-quic-kit:quic-server-poll` returns true.
The server closes sooner if all routed connections have ended, or at the deadline it attempts to send
CONNECTION_CLOSE to remaining active connections and closes its socket.

`cl-quic-kit:quic-connection-close` sends a protected CONNECTION_CLOSE and moves an active connection to
closing. Its `:error-code` defaults to `:no-error` and accepts an integer from 0 through 2^62-1 or one of
`:no-error`, `:internal-error`, `:frame-encoding-error`, `:transport-parameter-error`,
`:protocol-violation`, `:connection-id-limit`, and `:application-error`. `:reason` may be `NIL`, a string,
or an octet vector and is truncated to the QUIC reason limit. Repeated calls on a closing, draining, or closed
connection do not send another close frame.

A client that omits ALPN can complete the handshake without selecting a protocol, so an accepted connection
can have no negotiated ALPN. Use `cl-quic-kit:quic-connection-alpn` to read the selected protocol; it returns
`NIL` when none was selected.
The client and server stream APIs expose QUIC stream octets without adding HTTP/3 framing. An application
using `h3` needs an HTTP/3 layer above these streams. Streams preserve byte order, but reads do not preserve
write or STREAM-frame boundaries. An empty read with a false completion value means no data is buffered now;
poll and read again.
The connection-level stream functions below take a `cl-quic-kit:quic-connection`. They work with a server
connection returned by `cl-quic-kit:quic-server-accept-connection` and a client connection returned by
`cl-quic-kit:quic-client-connection`; client code can also use the client-specific helpers described above.
`cl-quic-kit:quic-connection-accept-stream` returns the next peer-initiated stream, or `NIL` when none is
available. Pass `:type :bidirectional` or `:type :unidirectional` to filter the queue; the default `:any`
accepts either direction. Each peer stream is returned once. `NIL` only means that no matching stream is available
from that call. Use `(cl-quic-kit:connection-state connection)` to inspect whether the connection is
established, closing, draining, or closed.

`cl-quic-kit:quic-connection-open-stream` opens a local bidirectional stream by default. Pass
`:type :unidirectional` for a unidirectional stream. `cl-quic-kit:quic-connection-read-stream` returns
buffered octets, which are empty when none are available. Its second value is true after peer FIN arrives
and all data through FIN has been read, or after peer reset, which discards unread buffered octets.
`cl-quic-kit:quic-connection-write-stream` accepts
an octet vector and optional `:fin-p t`; data beyond current flow-control credit remains queued until more
credit arrives. For server connections, `cl-quic-kit:quic-server-poll` packetizes queued control frames and
stream data with available credit, then sends pending datagrams. For client connections, use
`cl-quic-kit:client-poll`; polling alone is sufficient after writes.
`cl-quic-kit:quic-connection-flush` attempts to packetize queued writes and send resulting datagrams
immediately. Congestion control can leave frames queued, and a server's amplification limit can defer
datagrams. Polling retries packetization and
sending. Call flush between polls when an immediate send attempt is needed.

Use `cl-quic-kit:quic-connection-close-stream` to remove a stream from a connection and
discard its pending writes. It does not enqueue FIN or RESET_STREAM. Frames already
queued for packetization may still be sent.
A locally opened unidirectional stream is
send-only, while a peer-initiated unidirectional stream is receive-only. Reading from a send-only stream or
writing to a receive-only stream signals `cl-quic-kit:stream-id-error`.

`:max-connections` counts handshaking and established connections. Closing and draining connections remain in
the count until they reach `:closed` and their routes are removed. `:max-handshakes` limits incomplete
handshakes; it defaults to `:max-connections` and must be a positive integer no greater than that limit.
`:transport-parameters` accepts a keyword plist containing the six parameters shown above. The values in the
constructor example are the defaults; omitted keys use them. Unknown keys signal an error. Each supplied value
must be a non-negative QUIC varint.

## Development

The ASDF system is named `cl-quic-kit` and declares `cl-crypto-kit` and `cl-tls-kit` as dependencies. Add the
three checkout directories to the ASDF source registry. For example, use this form in a source-registry
configuration file, replacing each placeholder path with its checkout directory:

```lisp
(:source-registry
 (:tree "/path/to/cl-quic-kit/")
 (:tree "/path/to/cl-crypto-kit/")
 (:tree "/path/to/cl-tls-kit/")
 :inherit-configuration)
```

After configuring the registry, applications can load the system with `(asdf:load-system "cl-quic-kit")`.

The Nix development shell and test command are defined only for x86_64-linux. Run the suite from the repository
root; the shell sets the
ASDF source registry for those dependencies and provides OpenSSL for the loopback TLS test, which creates
temporary credentials:

```sh
nix develop --command sbcl --non-interactive --load t/run.lisp
```

When no TLS provider is supplied, the QUIC client uses cl-tls-kit's cl-crypto-kit provider.
