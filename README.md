# cl-quic-kit

Common Lisp building blocks for QUIC version 1.

Protocol references:

- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9002: QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002)

The package provides QUIC varints, packet and frame codecs, stream and flow-control state, loss recovery and
NewReno state, connection lifecycle management, and an explicit `cl-crypto-kit` backend boundary under `src/`.
The client uses `cl-tls-kit` for TLS 1.3. Consuming stream data replenishes the configured receive windows
without reducing previously advertised credit; connection and stream limits cannot exceed the QUIC varint maximum.

## Client use

The network implementation is a QUIC client, not a QUIC server listener or a TCP/TLS record transport.
Native UDP sockets use SBCL's `sb-bsd-sockets` and IPv4; `:server-host` takes a numeric IPv4 address,
not a DNS name. Pass the certificate name separately as `:hostname` to `make-quic-client`.
`:hostname` is required by default; configure `:tls-trust-anchors` for the peer.

Loading the ASDF dependencies does not install the packet-protection backend. Before constructing a client,
call `cl-quic-kit.protection:configure-crypto-backend` with the adapters shown in [t/run.lisp](t/run.lisp).
The TLS driver uses a `cl-tls-kit` crypto provider by default; `:tls-provider` selects a provider, while
`:tls-key-exchange` and `:tls-verify-signature` supply callbacks. Missing packet-protection operations signal
`cl-quic-kit.protection:crypto-not-implemented`; unavailable client crypto entry points signal
`cl-quic-kit:crypto-unavailable`, and connection-ID randomness failures signal `cl-quic-kit:randomness-unavailable`.

Call `client-start`, then keep calling `client-poll` to drive the handshake, UDP receive, ACKs, recovery,
and idle timeout. Wait for the client's connection state to become `:established` before application traffic.
Serialize operations on each client: there is no background poll thread or internal synchronization.
The [Caddy fixture](t/http3-loopback.lisp) shows the client lifecycle and stream I/O.

`client-open-stream` takes `(client request &key stream-type timeout deadline)`; `request` is currently ignored.
`client-write-stream` takes `(client stream octets &key fin-p timeout deadline)` with an unsigned-byte-8 vector.
Writes queue data; peer credit or congestion can defer sending. Drive `client-poll`/`client-flush` and use
`client-stream-write-pending-p` to check for unsent data, not peer acknowledgement. Bound queued data in the caller.
`client-read-stream` takes `(client stream &key timeout deadline)` and returns octets plus an end indicator
(FIN drained or reset). Empty octets alone do not mean end of stream. Reads and writes require a stream
registered with that client; consumed bytes replenish receive credit.

Stream-operation `:timeout` is relative and `:deadline` absolute in the client clock's units (seconds by default);
`:deadline` takes precedence. These keywords only check expiry on entry, not enforce a blocking wait budget.
The default idle timeout is 30 seconds and is checked by `client-poll`; enforce overall wait budgets in the caller.

Packet reserved bits (short-header mask `#x18`, long-header mask `#x0c`) are checked after payload authentication.
Authenticated nonzero bits close the connection with `PROTOCOL_VIOLATION` (`#x0a`). AEAD authentication failures
are discarded and counted across the connection's keys; successful packets do not reset the count. Exceeding
the failing packet's cipher limit (`2^52` for AES-128/256-GCM, `2^36` for ChaCha20-Poly1305) closes the connection
with `AEAD_LIMIT_REACHED` (`#x0f`).
Other errors caught by `client-receive-datagram` close with a fixed `QUIC receive failure` reason,
without sending provider diagnostics to the peer.

Arrange cleanup with `unwind-protect` and call `client-close` when finished, including after a protocol close;
it closes even an injected UDP socket. Socket cleanup is attempted even if sending the close fails.
The original send error is preserved if cleanup also fails; a cleanup-only error propagates.
Repeated calls do not resend the close or repeat socket cleanup.

## Development

Run the bootstrap tests with:

```sh
sbcl --no-userinit --no-sysinit --non-interactive --load t/run.lisp
```

The ASDF system is `cl-quic-kit`; it depends on `cl-crypto-kit` and `cl-tls-kit`.

On x86_64 Linux, `nix flake check` also runs HTTP/3 POST interoperability checks against Caddy,
including multi-megabyte uploads, packet loss, and malformed peer input. The flake pins `cl-tls-kit` v0.1.2.
