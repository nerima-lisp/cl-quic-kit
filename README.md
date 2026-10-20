# cl-quic-kit

Common Lisp building blocks for QUIC version 1.

The implementation follows the protocol requirements in:

- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9002: QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002)

The package provides QUIC varints, packet and frame codecs, stream and flow-control state, loss recovery and
NewReno state, connection lifecycle management, and an explicit `cl-crypto-kit` backend boundary under `src/`.

## Client API

Create a network client with:

`(cl-quic-kit:make-quic-client :server-host host :server-port port :hostname hostname)`

`server-host` is the UDP destination; `hostname` is used for TLS. For a client created with those network
arguments, its first `(cl-quic-kit:client-poll client)` call starts the TLS handshake.

- `cl-quic-kit:client-accept-peer-stream (client)` returns one available peer stream. Call
  `(cl-quic-kit:client-poll client)` to send queued frames and process available UDP datagrams, then call
  `(cl-quic-kit:client-accept-peer-stream client)` until it returns `NIL`. Poll again to process later
  datagrams. Each peer-initiated stream is returned once; locally opened streams are excluded. After
  `(cl-quic-kit:client-close client)`, `client-accept-peer-stream` returns `NIL`; use
  `(cl-quic-kit:quic-client-closed-p client)` to distinguish that case from no available stream. Pass a
  returned stream to `(cl-quic-kit:client-read-stream client stream)` to consume available octets. The
  second return value is true when the peer's FIN or reset has arrived and all buffered octets are consumed.
  To send FIN, write the final octets with
  `(cl-quic-kit:client-write-stream client stream octets :fin-p t)`. This marks
  the last STREAM frame with FIN. Call `(cl-quic-kit:client-poll client)` to send
  queued frames. The predicate
  `(cl-quic-kit:client-stream-write-pending-p client stream)` reports queued or
  unsent data. `(cl-quic-kit:client-close-stream client stream)` removes a stream
  from the client and does not send FIN. It drops writes waiting for flow control;
  already queued frames remain queued.
- `cl-quic-kit:quic-connection-closed-reason (connection)` returns a reason recorded on the connection as
  octets. It is `NIL` if no connection reason was recorded, and `#()` if a recorded reason is empty. The
  client's `(cl-quic-kit:client-close client :reason "client shutdown")` sends the optional `:reason` but
  does not populate this field, so the accessor can still return `NIL` after local close. For a client, read
  its reason with
  `(cl-quic-kit:quic-connection-closed-reason (cl-quic-kit:quic-client-connection client))`.

## Development

Run the bootstrap tests with:

```sh
sbcl --non-interactive --load t/run.lisp
```

The ASDF system is `cl-quic-kit`; it declares `cl-crypto-kit` as its crypto dependency. Crypto operations signal
`cl-quic-kit:crypto-unavailable` until a backend implementation is connected.
