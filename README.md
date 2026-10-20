# cl-quic-kit

Common Lisp building blocks for QUIC version 1.

The packet, TLS, and loss-recovery code draws on these specifications:

- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9002: QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002)

The package provides QUIC varints, packet and frame codecs, stream and flow-control state, loss recovery and
NewReno state, connection lifecycle management, and an explicit `cl-crypto-kit` backend boundary under `src/`.
Before sending protected traffic, applications must call
`cl-quic-kit.protection:configure-crypto-backend` with callbacks for `:hkdf-extract`, `:hkdf-expand`,
`:aead-seal`, `:aead-open`, `:aes-ecb` or `:chacha20`, and `:constant-time-equal`. This setting is separate
from TLS provider selection. `t/run.lisp` shows the test runner's adapter mapping.

## Client API

Create a network client with:

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
The default signature verifier uses cl-crypto-kit's `verify-signature`. The first
`(cl-quic-kit:client-poll client)` call starts the TLS handshake for a client created with these network arguments.
The `:alpn` option takes a list of protocol names and defaults to `("h3")`; set it to `NIL` to omit ALPN.
The optional `:idle-timeout` value uses seconds and defaults to 30; the client advertises it in milliseconds.
Continue polling until
`(cl-quic-kit:connection-state (cl-quic-kit:quic-client-connection client))` is `:established`;
the client enters that state after it receives the server's `HANDSHAKE_DONE` frame.

After the handshake, `(cl-quic-kit:client-open-stream client nil)` opens a locally initiated bidirectional
stream. Its second argument is currently unused. Pass the returned stream to `client-write-stream` or
`client-read-stream`.

- `cl-quic-kit:client-accept-peer-stream (client)` returns one available peer stream. Call
  `(cl-quic-kit:client-poll client)` to send queued frames and process available UDP datagrams, then call
  `(cl-quic-kit:client-accept-peer-stream client)` until it returns `NIL`. Poll again to process later
  datagrams. Each peer-initiated stream is returned once; locally opened streams are excluded. After
  `(cl-quic-kit:client-close client)`, `client-accept-peer-stream` returns `NIL`; use
  `(cl-quic-kit:quic-client-closed-p client)` to distinguish that case from no available stream. Pass a
  returned stream to `(cl-quic-kit:client-read-stream client stream)` to consume available octets. It
  returns an octet vector, which is empty when no data is buffered. The second return value is true when
  the peer's FIN or reset has arrived and all buffered octets are consumed.
  To send FIN, write the final octets with
  `(cl-quic-kit:client-write-stream client stream octets :fin-p t)`. This marks
  the last STREAM frame with FIN. Call `(cl-quic-kit:client-poll client)` to send
  queued frames. The predicate
  `(cl-quic-kit:client-stream-write-pending-p client stream)` reports queued or
  unsent data. `(cl-quic-kit:client-close-stream client stream)` removes a stream
  from the client and does not enqueue FIN. It drops writes waiting for flow control.
  STREAM frames already queued remain queued and may be sent by a later
  `(cl-quic-kit:client-poll client)` call.
- `cl-quic-kit:quic-connection-closed-reason (connection)` returns a reason recorded on the connection as
  octets. It is `NIL` if no connection reason was recorded, and `#()` if a recorded reason is empty. The
  client's `(cl-quic-kit:client-close client :reason "client shutdown")` sends the optional `:reason` but
  does not populate this field, so the accessor can still return `NIL` after local close. For a client, read
  its reason with
  `(cl-quic-kit:quic-connection-closed-reason (cl-quic-kit:quic-client-connection client))`.

## Server API

Create a listener with a positive `:max-connections` value. Supply the certificate chain and matching private
key through `:tls-server-options`. The chain is a list of DER-encoded certificates with the leaf first; the
private key must be a cl-crypto-kit ECDSA P-256 or Ed25519 private-key object. The API accepts DER
certificate octets and private-key objects; it does not parse PEM files.
The [test credential helper](t/server.lisp#L913) creates a temporary self-signed P-256 certificate with OpenSSL.

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
       :private-key private-key
       :alpn-protocols '("h3")))
```

The listener defaults to IPv4 address `0.0.0.0` and UDP port `443`. Set `:local-address` to an IPv4
address string and `:local-port` to an integer from 0 through 65535; port 0 binds an ephemeral port.
`:local-address` applies when the listener creates its socket. When supplying a socket, configure it with
`:local-host` in `make-udp-socket`. To read the assigned port, create a socket and pass it to the listener:

```lisp
(let* ((socket (cl-quic-kit:make-udp-socket
                :local-host bind-address :local-port 0))
       (server (cl-quic-kit:make-quic-server
                :udp-socket socket
                :max-connections 256
                :tls-server-options
                (list :certificate-chain certificate-chain-der
                      :private-key private-key
                      :alpn-protocols '("h3")))))
  (values server (cl-quic-kit:udp-socket-local-port socket)))
```

The server takes ownership of the supplied socket. Give clients a reachable server address and the returned
port.

The server passes `:tls-server-options` to cl-tls-kit's public
[`make-tls13-server-driver`](https://github.com/nerima-lisp/cl-tls-kit/blob/7ed1e3eb1edd891066c15951fe282f89dafef81b/docs/tls13-server-driver.md)
constructor. The server defaults `:alpn-protocols` to `("h3")`, creates a cl-crypto-kit provider when
`:provider` is omitted, and sets the driver's `:quic-transport-parameters` option from the encoded server
parameters.

The `crypto-kit:` package is provided by the `cl-crypto-kit` system. For a P-256 key, pass a 32-octet private
scalar to
`(crypto-kit:make-ec-private-key :p256 scalar-octets)`. For Ed25519, pass a 32-octet seed to
`(crypto-kit:make-ed25519-private-key seed-octets)`.

With the default nonblocking UDP socket, `cl-quic-kit:quic-server-poll` drains available datagrams,
drives handshakes, and returns; call it from the application's event loop. It returns `NIL` while the server
is open and true after it is closed. After each poll,
`cl-quic-kit:quic-server-accept-connection` returns one handshake-complete `quic-connection` or `NIL` if
none is ready. Each connection is returned once.
A client that omits ALPN can complete the handshake without selecting a protocol, so an accepted connection
can have no negotiated ALPN. Use `cl-quic-kit:quic-connection-alpn` to read the selected protocol; it returns
`NIL` when none was selected.
This API supports accepting connections and inspecting ALPN; it does not yet expose server-side stream
operations or per-connection close.

`:max-connections` counts both handshaking and established connections. `:transport-parameters` accepts
a keyword plist containing these six parameters. The values in the constructor example are the defaults;
omitted keys use them. Unknown keys signal an error. Each supplied value must be a non-negative QUIC varint.

`cl-quic-kit:quic-server-close` marks tracked connections closed locally and closes the listener's owned
UDP socket. It does not send QUIC `CONNECTION_CLOSE` frames.

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

The Nix development shell and test command are defined for x86_64-linux. Run the suite from the repository
root; the shell sets the
ASDF source registry for those dependencies and provides OpenSSL for the loopback TLS test, which creates
temporary credentials:

```sh
nix develop --command sbcl --non-interactive --load t/run.lisp
```

The test runner loads the dependencies and configures packet protection with
`cl-quic-kit.protection:configure-crypto-backend`. When no TLS provider is supplied, the QUIC client and server
use cl-tls-kit's cl-crypto-kit provider.
