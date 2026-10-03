# cl-quic-kit

Common Lisp building blocks for QUIC version 1.

The implementation follows the protocol requirements in:

- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9002: QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002)

The package provides QUIC varints, packet and frame codecs, stream and flow-control state, loss recovery and
NewReno state, connection lifecycle management, and an explicit `cl-crypto-kit` backend boundary under `src/`.

## Development

Run the bootstrap tests with:

```sh
sbcl --non-interactive --load t/run.lisp
```

The ASDF system is `cl-quic-kit`; it declares `cl-crypto-kit` as its crypto dependency. Crypto operations signal
`cl-quic-kit:crypto-unavailable` until a backend implementation is connected.
